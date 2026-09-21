//! A single privileged request owns initial selection and independent recovery.
use super::*;
use sirinvpn_tunnel_model::{ConnectionPolicy, ReconnectCandidate, policy_transport_candidates};

#[tauri::command]
pub(super) async fn connect_server_with_policy(
    state: State<'_, AppState>,
    server_id: String,
    preferences: connection_preferences::ConnectionPreferences,
) -> Result<LocalTunnelStatus, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = crate::connection_controller::acquire_connection()?;
        connect_native(paths, &server_id, preferences, None, true)
    })
    .await
    .map_err(|_| "The network worker was interrupted.".to_owned())?
}

/// The caller holds the shared native operation gate, including any confirmation.
/// A handoff retains the active device policy; target-server drafts cannot relax it.
pub(crate) fn connect_native(
    paths: ClientPaths,
    server_id: &str,
    preferences: connection_preferences::ConnectionPreferences,
    active: Option<&LocalTunnelStatus>,
    interactive: bool,
) -> Result<LocalTunnelStatus, String> {
    let epoch = crate::connection_controller::epoch();
    crate::connection_controller::require_current(epoch)?;
    let mut preferences = preferences.validated()?;
    #[cfg(target_os = "linux")]
    helper::prepare_helper_for_connection(interactive).map_err(safe_error)?;
    #[cfg(not(target_os = "linux"))]
    let _ = interactive;
    let helper_status = invoke_helper("status", None).map_err(safe_error)?;
    if !helper_status.mtu_detection_supported {
        return Err("Update the local VPN component in Settings before using the new connection and MTU controls.".into());
    }
    if !helper_status.endpoint_updates_supported {
        return Err("Update the local VPN component in Settings to support signed endpoint updates and IPv6 addresses.".into());
    }
    if let Some(active) = active {
        if !active.connection_control_supported {
            return Err("Update the local VPN component before switching servers.".into());
        }
        preferences.manual_mtu = active.mtu.as_ref().and_then(|mtu| match mtu.policy {
            sirinvpn_protocol::MtuPolicy::Manual { value } => Some(value),
            sirinvpn_protocol::MtuPolicy::Automatic => None,
        });
        preferences.policy = active.policy.ok_or(
            "This session does not support a protected handoff. Open connection settings.",
        )?;
        preferences.routing = TunnelRoutingPolicy {
            mode: active.routing_mode,
            allow_lan: active.allow_lan,
            included_routes: active
                .included_routes
                .clone()
                .ok_or("Current routing could not be verified.")?,
        };
    }
    let profile = find_profile(&paths, server_id)?;
    if has_pending_key_rotation(&paths, profile.id).map_err(safe_error)? {
        return Err(
            "Finish this device's pending key rotation before connecting from the tray.".into(),
        );
    }
    let secret = paths
        .secret_store()
        .get(&profile.identity_reference)
        .map_err(safe_error)?;
    let network = NetworkContext::discover();
    let store = paths.network_policy_store();
    let _ = store.set_network_profile(preferences.network_profile);
    let cached = if preferences.network_profile == NetworkProfile::Automatic {
        network
            .as_ref()
            .and_then(|n| store.cached_transport(profile.id, n).ok().flatten())
    } else {
        None
    };
    let mut plan = if let Some(kind) = preferences.transport.concrete_kind() {
        vec![TransportEngine.select(&profile, kind).map_err(safe_error)?]
    } else {
        TransportEngine
            .automatic_plan(&profile, preferences.network_profile, cached)
            .map_err(safe_error)?
    };
    let mtu_policy = preferences
        .manual_mtu
        .map_or(sirinvpn_protocol::MtuPolicy::Automatic, |value| {
            sirinvpn_protocol::MtuPolicy::Manual { value }
        });
    mtu_policy
        .validate(profile.ipv6_tunnel_enabled)
        .map_err(str::to_owned)?;
    if let Some(value) = preferences.manual_mtu {
        for selection in &mut plan {
            selection.mtu = value;
        }
    }
    let first = plan
        .first()
        .ok_or("No supported transport is available.")?
        .clone();
    let mut request = tunnel_request(
        &profile,
        &secret,
        first,
        &preferences.routing,
        Some(preferences.policy),
        false,
        policy_transport_candidates(&plan),
    )
    .map_err(safe_error)?;
    if request.requires_https_support() && !helper_status.https_transport_supported {
        return Err("Update the local VPN component to use this server’s HTTPS transport.".into());
    }
    request.schema_version =
        if request.routing.mode == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications {
            11
        } else {
            10
        };
    request.mtu_policy = Some(mtu_policy);
    #[cfg(target_os = "linux")]
    let (command, input) = {
        let managed = sirinvpn_linux_helper::ManagedConnectRequest {
            expected_server_id: active.and_then(|status| status.server_id),
            request,
            profile: profile.clone(),
            secret: secret.clone(),
        };
        (
            "connect-managed",
            Zeroizing::new(serde_json::to_vec(&managed).map_err(safe_error)?),
        )
    };
    #[cfg(not(target_os = "linux"))]
    let (command, input) = if let Some(active) = active {
        let change = sirinvpn_tunnel_model::SwitchConnectRequest {
            expected_server_id: active.server_id.ok_or("The active connection changed.")?,
            request,
        };
        (
            "switch-session",
            Zeroizing::new(serde_json::to_vec(&change).map_err(safe_error)?),
        )
    } else {
        (
            "connect",
            Zeroizing::new(serde_json::to_vec(&request).map_err(safe_error)?),
        )
    };
    crate::connection_controller::require_current(epoch)?;
    #[cfg(target_os = "linux")]
    let result =
        helper::invoke_helper_with_interaction(command, Some(input.as_slice()), interactive)
            .map_err(safe_error);
    #[cfg(not(target_os = "linux"))]
    let result = invoke_helper(command, Some(input.as_slice())).map_err(safe_error);
    if crate::connection_controller::require_current(epoch).is_err() {
        // A helper invocation may finish after Cancel. Keep the operation gate
        // until its own candidate is gone; never acknowledge a late connection.
        let current = invoke_helper("status", None).map_err(safe_error)?;
        if current.server_id == Some(profile.id) {
            crate::connection::disconnect_candidate(profile.id)?;
        }
        return Err("The connection was cancelled.".into());
    }
    let status = result?;
    if !status.independent_policy_supported
        || status.server_id != Some(profile.id)
        || status.policy != Some(preferences.policy)
    {
        return Err("The local VPN component did not acknowledge the independent connection policy. Review its update in Settings.".into());
    }
    if preferences.transport == TransportPreference::Automatic {
        observe_transport_success(paths, profile.id, network);
    }
    Ok(status)
}

fn observe_transport_success(
    paths: ClientPaths,
    server_id: ServerId,
    network: Option<NetworkContext>,
) {
    let connection_epoch = crate::connection_controller::epoch();
    tauri::async_runtime::spawn_blocking(move || {
        let mut recorded = None;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let Ok(local) = invoke_helper("status", None) else {
                return;
            };
            if local.server_id != Some(server_id)
                || local.waiting_for_user
                || crate::connection_controller::require_current(connection_epoch).is_err()
            {
                return;
            }
            if local.state == ConnectionState::Connected
                && local.transport_quality.as_ref().is_none_or(|quality| {
                    matches!(
                        quality.selection,
                        sirinvpn_protocol::QualitySelection::Selected
                            | sirinvpn_protocol::QualitySelection::IcmpUnavailable
                            | sirinvpn_protocol::QualitySelection::ProtectionRequired
                            | sirinvpn_protocol::QualitySelection::Observing
                    )
                })
                && let (Some(network), Some(kind)) = (network.as_ref(), local.transport)
                && recorded != Some(kind)
                && NetworkContext::discover().as_ref() == Some(network)
            {
                let _ = paths
                    .network_policy_store()
                    .record_success(server_id, network, kind);
                recorded = Some(kind);
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) fn tunnel_request(
    profile: &ServerProfile,
    secret: &SecretIdentity,
    transport: TransportSelection,
    routing: &TunnelRoutingPolicy,
    policy: Option<ConnectionPolicy>,
    persistent_protection: bool,
    reconnect_candidates: Vec<ReconnectCandidate>,
) -> Result<TunnelConnectRequest> {
    let client_address = match profile.client_tunnel_address {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => bail!("SirinVPN requires an IPv4 tunnel address in this release"),
    };
    let dns_address = match profile.server_tunnel_address {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => bail!("SirinVPN requires an IPv4 DNS address in this release"),
    };
    Ok(TunnelConnectRequest {
        endpoint_identity: Some(profile.endpoint_identity()),
        endpoint_checkpoint: None,
        endpoint_publication_enabled: profile.role == ServerRole::Owner,
        endpoint_dns_servers: Vec::new(),
        mtu_policy: Some(sirinvpn_protocol::MtuPolicy::Automatic),
        policy: Some(policy.unwrap_or_else(|| ConnectionPolicy::legacy(persistent_protection))),
        schema_version: if routing.mode
            == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications
        {
            11
        } else {
            10
        },
        server_id: profile.id,
        endpoint_host: transport.network_endpoint.host,
        endpoint_port: transport.network_endpoint.wireguard_port,
        transport: transport.kind,
        server_transport_public_key: transport.server_transport_public_key,
        https: transport.https,
        server_certificate_sha256: transport.server_certificate_sha256,
        reconnect_candidates,
        client_address,
        server_public_key: profile.server_wireguard_public_key.clone(),
        private_key: secret.wireguard_private_key.clone(),
        dns_address,
        client_ipv6_address: if profile.ipv6_tunnel_enabled {
            Some(
                ipv6_tunnel_address(profile.id, client_address)
                    .ok_or_else(|| anyhow!("the profile cannot derive its IPv6 tunnel address"))?,
            )
        } else {
            None
        },
        mtu: transport.mtu,
        persistent_protection: false,
        routing: routing.clone(),
    })
}

#[tauri::command]
pub(super) async fn resume_server(server_id: String) -> Result<LocalTunnelStatus, String> {
    let id = server_id
        .parse::<ServerId>()
        .map_err(|_| "The local server ID is invalid.".to_owned())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = crate::connection_controller::acquire()?;
        let input = serde_json::to_vec(&id).map_err(safe_error)?;
        invoke_helper("resume", Some(&input)).map_err(safe_error)
    })
    .await
    .map_err(|_| "The network worker was interrupted.".to_owned())?
}
