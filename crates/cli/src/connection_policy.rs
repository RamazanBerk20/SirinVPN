//! CLI uses the same versioned helper policy and bounded initial plan as the GUI.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect(
    paths: &ClientPaths,
    selector: &str,
    policy: ConnectionPolicy,
    preference: TransportPreference,
    requested_network_profile: Option<NetworkProfile>,
    routing: TunnelRoutingPolicy,
    manual_mtu: Option<u16>,
    json: bool,
) -> Result<()> {
    let profile = resolve_profile(&paths.profile_store(), selector)?;
    let secret = paths.secret_store().get(&profile.identity_reference)?;
    let store = paths.network_policy_store();
    let network_profile =
        requested_network_profile.unwrap_or_else(|| store.network_profile().unwrap_or_default());
    let network = NetworkContext::discover();
    let plan = if let Some(kind) = preference.concrete_kind() {
        if requested_network_profile.is_some() {
            bail!("--network-profile applies to automatic transport selection");
        }
        vec![TransportEngine.select(&profile, kind)?]
    } else {
        let cached = if network_profile == NetworkProfile::Automatic {
            network
                .as_ref()
                .and_then(|n| store.cached_transport(profile.id, n).ok().flatten())
        } else {
            None
        };
        if requested_network_profile.is_some() {
            let _ = store.set_network_profile(network_profile);
        }
        TransportEngine.automatic_plan(&profile, network_profile, cached)?
    };
    let first = plan
        .first()
        .ok_or_else(|| anyhow!("no supported transport is available"))?
        .kind;
    let mut status = connect_managed_with_mtu(
        &profile, &secret, policy, first, &plan, &routing, manual_mtu,
    )?;
    for _ in 0..32 {
        if status.state == ConnectionState::Connected || status.waiting_for_user {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        status = invoke_helper("status", None)?;
        if let Some(head) = &status.endpoint_checkpoint {
            let _ = paths
                .profile_store()
                .apply_endpoint_checkpoint(head.clone());
        }
        if status.server_id != Some(profile.id) {
            bail!("the local session changed; no other connection was modified");
        }
    }
    if status.state == ConnectionState::Connected
        && let (Some(network), Some(transport)) = (network, status.transport)
        && NetworkContext::discover().as_ref() == Some(&network)
    {
        let _ = store.record_success(profile.id, &network, transport);
    }
    let message = if status.state == ConnectionState::Connected {
        "Connected through SirinVPN."
    } else if status.waiting_for_user {
        "Connection paused. Use `sirinvpn resume SERVER` to retry or `sirinvpn disconnect` to release the traffic block."
    } else {
        "Connection is still pending. The helper will follow the configured recovery policy. Use `sirinvpn status` to check it."
    };
    print_value(&status, json, message)
}

pub(super) fn connect_managed_with_mtu(
    profile: &ServerProfile,
    secret: &SecretIdentity,
    policy: ConnectionPolicy,
    transport: TransportKind,
    plan: &[TransportSelection],
    routing: &TunnelRoutingPolicy,
    manual_mtu: Option<u16>,
) -> Result<LocalTunnelStatus> {
    let mut request = build_tunnel_request(profile, secret, false, transport, &[], routing)?;
    request.schema_version =
        if routing.mode == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications {
            11
        } else {
            10
        };
    request.policy = Some(policy);
    let mtu_policy = manual_mtu.map_or(sirinvpn_protocol::MtuPolicy::Automatic, |value| {
        sirinvpn_protocol::MtuPolicy::Manual { value }
    });
    mtu_policy
        .validate(profile.ipv6_tunnel_enabled)
        .map_err(anyhow::Error::msg)?;
    request.mtu_policy = Some(mtu_policy);
    let mut ordered = vec![TransportEngine.select(profile, transport)?];
    ordered.extend(plan.iter().filter(|s| s.kind != transport).cloned());
    if let Some(value) = manual_mtu {
        request.mtu = value;
        for candidate in &mut ordered {
            candidate.mtu = value;
        }
    }
    request.reconnect_candidates = sirinvpn_tunnel_model::policy_transport_candidates(&ordered);
    let payload = Zeroizing::new(serde_json::to_vec(&request)?);
    let status = invoke_helper("connect", Some(payload.as_slice()))?;
    if status.policy != Some(policy) || status.server_id != Some(profile.id) {
        bail!("the helper did not acknowledge the requested independent policy");
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_line_controls_are_independent_and_legacy_shortcut_is_unambiguous() {
        for (flag, expected) in [
            ("--kill-switch", (true, false, false)),
            ("--automatic-reconnect", (false, true, false)),
            ("--connect-on-startup", (false, false, true)),
        ] {
            let cli = Cli::try_parse_from(["sirinvpn", "connect", "example", flag]).unwrap();
            let Commands::Connect(args) = cli.command else {
                panic!("wrong command")
            };
            assert_eq!(
                (
                    args.kill_switch,
                    args.automatic_reconnect,
                    args.connect_on_startup
                ),
                expected
            );
            assert!(
                Cli::try_parse_from(["sirinvpn", "connect", "example", "--persistent", flag])
                    .is_err()
            );
        }
        assert!(Cli::try_parse_from(["sirinvpn", "resume", "example"]).is_ok());
    }
}
