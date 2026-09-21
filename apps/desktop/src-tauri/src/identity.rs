//! Identity.

use super::*;

#[tauri::command]
pub(super) fn key_rotation_pending(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<bool, String> {
    let server_id = server_id
        .parse::<ServerId>()
        .map_err(|_| "The local server ID is invalid.".to_owned())?;
    has_pending_key_rotation(&state.paths, server_id).map_err(safe_error)
}

#[tauri::command]
pub(super) async fn rotate_device_keys(
    state: State<'_, AppState>,
    input: KeyRotationInput,
) -> Result<KeyRotationResult, String> {
    let _operation = crate::connection_controller::acquire()?;
    if !input.confirmed {
        return Err("Confirm the current-device key rotation before continuing.".to_owned());
    }
    let profile = find_profile(&state.paths, &input.server_id)?;
    let pending = has_pending_key_rotation(&state.paths, profile.id).map_err(safe_error)?;
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.server_id.is_some() && local.server_id != Some(profile.id) {
        return Err("Disconnect the other SirinVPN server before rotating these keys.".to_owned());
    }
    if !pending
        && (local.server_id != Some(profile.id) || local.state == ConnectionState::Disconnected)
    {
        return Err("Connect to this server before rotating this device's keys.".to_owned());
    }
    let persistent_protection = local.kill_switch_enabled && local.auto_reconnect_enabled;
    let transport = local.transport.unwrap_or(TransportKind::DirectUdp);
    let transport_fallback_enabled = local.transport_fallback_enabled;
    let policy = (local.policy.is_some()
        || local.kill_switch_enabled
        || local.auto_reconnect_enabled)
        .then(|| RotationConnectionPolicy {
            mtu_policy: local.mtu.map(|mtu| mtu.policy),
            kill_switch: local.kill_switch_enabled,
            automatic_reconnect: local.auto_reconnect_enabled,
            connect_on_startup: local.connect_on_startup,
            selected_applications: local.routing_mode
                == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications,
            selected_routes: (local.routing_mode == TunnelRoutingMode::SelectedRoutes)
                .then(|| local.included_routes.clone().unwrap_or_default()),
            allow_lan: local.allow_lan,
        });
    rotate_current_device_keys_with_policy(
        &state.paths,
        profile.id,
        persistent_protection,
        transport,
        transport_fallback_enabled,
        policy,
        || {
            let current = invoke_helper("status", None).map_err(safe_error)?;
            if current.server_id.is_some() && current.server_id != Some(profile.id) {
                return Err("Another server became active. Its connection was preserved.".into());
            }
            if current.server_id.is_none() {
                return Ok(());
            }
            if current.policy.is_some() || current.kill_switch_enabled {
                let input = serde_json::to_vec(&profile.id).map_err(safe_error)?;
                invoke_helper("pause-for-key-rotation", Some(&input))
                    .map(|_| ())
                    .map_err(safe_error)
            } else {
                invoke_helper("disconnect", None)
                    .map(|_| ())
                    .map_err(safe_error)
            }
        },
        |profile, secret, persistent, transport, fallback_enabled, policy| {
            let reconnect_plan = if fallback_enabled {
                TransportEngine.plan(profile, TransportPreference::Automatic)
            } else {
                Ok(Vec::new())
            }
            .map_err(safe_error)?;
            let status = if let Some(policy) = policy {
                let routing = if policy.selected_applications {
                    TunnelRoutingPolicy::selected_applications(policy.allow_lan)
                } else {
                    match &policy.selected_routes {
                        Some(routes) => {
                            TunnelRoutingPolicy::selected_routes(routes.clone(), policy.allow_lan)
                                .map_err(safe_error)?
                        }
                        None => TunnelRoutingPolicy::full_tunnel(policy.allow_lan),
                    }
                };
                let selected = TransportEngine
                    .select(profile, transport)
                    .map_err(safe_error)?;
                let mut plan = vec![selected.clone()];
                plan.extend(
                    reconnect_plan
                        .into_iter()
                        .filter(|item| item.kind != transport),
                );
                let mut request = connection_policy::tunnel_request(
                    profile,
                    secret,
                    selected,
                    &routing,
                    Some(sirinvpn_tunnel_model::ConnectionPolicy {
                        kill_switch: policy.kill_switch,
                        automatic_reconnect: policy.automatic_reconnect,
                        connect_on_startup: policy.connect_on_startup,
                    }),
                    false,
                    sirinvpn_tunnel_model::policy_transport_candidates(&plan),
                )
                .map_err(safe_error)?;
                if let Some(mtu_policy) = policy.mtu_policy {
                    request.set_mtu_policy(mtu_policy).map_err(safe_error)?;
                }
                let input = Zeroizing::new(serde_json::to_vec(&request).map_err(safe_error)?);
                invoke_helper("connect", Some(input.as_slice())).map_err(safe_error)?
            } else {
                connect_profile_with_transport_plan(
                    profile,
                    secret,
                    persistent,
                    transport,
                    &reconnect_plan,
                )
                .map_err(safe_error)?
            };
            if status.server_id != Some(profile.id) || status.state == ConnectionState::Disconnected
            {
                return Err(
                    "The privileged helper did not activate the requested tunnel.".to_owned(),
                );
            }
            Ok(())
        },
    )
    .await
    .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn join_server(
    state: State<'_, AppState>,
    mut input: JoinInput,
) -> Result<ServerProfile, String> {
    let _operation = crate::connection_controller::acquire()?;
    let mut invitation = DecodedInvitation::decode(&input.code).map_err(safe_error)?;
    invitation.set_recipient_names(input.member_name.as_deref(), input.device_name.as_deref())
        .map_err(|_| "Review this invitation and provide valid display names. An existing member keeps its name.".to_owned())?;
    input.code.zeroize();
    if state
        .paths
        .profile_store()
        .load()
        .map_err(safe_error)?
        .iter()
        .any(|profile| profile.id == invitation.server_id())
    {
        return Err("This device already has a profile for the invited server.".to_owned());
    }
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.state != ConnectionState::Disconnected {
        return Err("Disconnect the current SirinVPN tunnel before joining.".to_owned());
    }

    let secrets = state.paths.secret_store();
    let mut pending = sirinvpn_core::PendingEnrollment::open(
        &state.paths,
        &secrets,
        invitation.server_id(),
        &format!(
            "invitation-{}",
            invitation.enrollment_binding().invitation_id
        ),
        invitation.device_name(),
    )
    .map_err(safe_error)?;

    pending
        .bind_invitation_names(invitation.enrollment_binding().names)
        .map_err(safe_error)?;
    let outcome = async {
        let profile = if let Some(profile) = pending.completed_profile() {
            profile
        } else {
            invitation.refresh_endpoint().await?;
            let bootstrap_profile = invitation.bootstrap_profile();
            connect_candidate_automatically(
                bootstrap_profile.clone(),
                invitation.bootstrap_secret().clone(),
            )
            .await
            .map_err(anyhow::Error::msg)?;
            let client = ManagementClient::new(&bootstrap_profile, invitation.bootstrap_secret())?;
            let request = invitation.enrollment_request(&pending.identity.public);
            let result = match client.enroll(&request).await {
                Err(ManagementError::ConnectionFailed) => client.enroll(&request).await?,
                result => result?,
            };
            invitation.permanent_profile(
                &result,
                &pending.identity.public,
                pending.identity_reference.clone(),
            )?
        };
        pending.commit_profile(&state.paths, profile.clone(), false)?;
        disconnect_candidate(profile.id).map_err(anyhow::Error::msg)?;
        connect_candidate_automatically(profile.clone(), pending.identity.secret.clone())
            .await
            .map_err(anyhow::Error::msg)?;
        Ok::<_, anyhow::Error>(profile)
    }
    .await;

    match outcome {
        Ok(profile) => Ok(profile),
        Err(error) => {
            let _ = disconnect_candidate(invitation.server_id());
            Err(safe_error(error))
        }
    }
}

pub(super) fn find_profile(paths: &ClientPaths, id: &str) -> Result<ServerProfile, String> {
    let id: ServerId = id
        .parse()
        .map_err(|_| "The local server ID is invalid.".to_owned())?;
    paths
        .profile_store()
        .load()
        .map_err(safe_error)?
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| "The local server profile was not found.".to_owned())
}
