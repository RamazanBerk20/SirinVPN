//! Membership.

use super::*;

pub(super) async fn join_server(
    paths: &ClientPaths,
    arguments: JoinServerArguments,
    json: bool,
) -> Result<()> {
    let code = read_invitation_code(arguments.code_stdin)?;
    let mut invitation = DecodedInvitation::decode(&code)?;
    if paths
        .profile_store()
        .load()?
        .iter()
        .any(|profile| profile.id == invitation.server_id())
    {
        bail!("this device already has a profile for the invited server");
    }
    let local = invoke_helper("status", None)?;
    if local.state != ConnectionState::Disconnected {
        bail!("disconnect the current SirinVPN tunnel before joining another server");
    }

    let secrets = paths.secret_store();
    let mut pending = sirinvpn_core::PendingEnrollment::open(
        paths,
        &secrets,
        invitation.server_id(),
        &format!(
            "invitation-{}",
            invitation.enrollment_binding().invitation_id
        ),
        invitation.device_name(),
    )?;

    let outcome = async {
        let profile = if let Some(profile) = pending.completed_profile() {
            profile
        } else {
            invitation.refresh_endpoint().await?;
            let bootstrap_profile = invitation.bootstrap_profile();
            test_endpoint_automatically(
                &bootstrap_profile,
                invitation.bootstrap_secret(),
                NetworkProfile::Automatic,
                None,
                TunnelRoutingPolicy::default(),
            )
            .await?;
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
        pending.commit_profile(paths, profile.clone(), false)?;
        disconnect_candidate(profile.id)?;
        let (status, _) = test_endpoint_automatically(
            &profile,
            &pending.identity.secret,
            NetworkProfile::Automatic,
            None,
            TunnelRoutingPolicy::default(),
        )
        .await?;
        Ok::<_, anyhow::Error>((profile, status))
    }
    .await;

    let (profile, status) = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = disconnect_candidate(invitation.server_id());
            return Err(error);
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&profile)?);
    } else {
        println!(
            "Joined {} as {} on {}. Tunnel: {:?}.",
            profile.name,
            invitation.member_name(),
            invitation.device_name(),
            status.state
        );
    }
    Ok(())
}

pub(super) async fn show_membership(paths: &ClientPaths, selector: &str, json: bool) -> Result<()> {
    let (profile, secret) = connected_identity(paths, selector)?;
    let snapshot = ManagementClient::new(&profile, &secret)?
        .membership()
        .await?;
    print_membership(&snapshot, json)
}

pub(super) async fn cancel_invitation(
    paths: &ClientPaths,
    selector: InvitationSelector,
    json: bool,
) -> Result<()> {
    let invitation_id = selector
        .invitation_id
        .parse::<InvitationId>()
        .context("invitation identifier is invalid")?;
    let (profile, secret) = connected_identity(paths, &selector.server)?;
    ManagementClient::new(&profile, &secret)?
        .cancel_invitation(invitation_id)
        .await?;
    print_value(&(), json, "Invitation cancelled immediately.")
}

pub(super) async fn rename_device(
    paths: &ClientPaths,
    arguments: RenameDeviceArguments,
    json: bool,
) -> Result<()> {
    let device_id = arguments
        .device_id
        .parse::<DeviceId>()
        .context("device identifier is invalid")?;
    let (profile, secret) = connected_identity(paths, &arguments.server)?;
    let snapshot = ManagementClient::new(&profile, &secret)?
        .rename_device(device_id, arguments.name)
        .await?;
    print_membership(&snapshot, json)
}

pub(super) async fn revoke_device(
    paths: &ClientPaths,
    selector: DeviceSelector,
    json: bool,
) -> Result<()> {
    let device_id = selector
        .device_id
        .parse::<DeviceId>()
        .context("device identifier is invalid")?;
    let (profile, secret) = connected_identity(paths, &selector.server)?;
    let snapshot = ManagementClient::new(&profile, &secret)?
        .revoke_device(device_id)
        .await?;
    print_membership(&snapshot, json)
}

pub(super) async fn set_peer_communication(
    paths: &ClientPaths,
    arguments: PeerCommunicationArguments,
    json: bool,
) -> Result<()> {
    let device_id = arguments
        .device_id
        .parse::<DeviceId>()
        .context("device identifier is invalid")?;
    let (profile, secret) = connected_identity(paths, &arguments.server)?;
    let client = ManagementClient::new(&profile, &secret)?;
    if !client.configuration().await?.peer_isolation_enabled {
        bail!("the server must be upgraded before changing peer communication");
    }
    let snapshot = client
        .update_device_peer_communication(
            device_id,
            matches!(arguments.mode, PeerCommunicationMode::Peers),
        )
        .await?;
    print_membership(&snapshot, json)
}

pub(super) async fn add_port_forward(
    paths: &ClientPaths,
    arguments: AddPortForwardArguments,
    json: bool,
) -> Result<()> {
    if !arguments.confirm_public_exposure {
        bail!(
            "pass --confirm-public-exposure after accepting that this port will be reachable from the public internet"
        );
    }
    let device_id = arguments
        .device_id
        .parse::<DeviceId>()
        .context("device identifier is invalid")?;
    let (profile, secret) = connected_identity(paths, &arguments.server)?;
    let client = ManagementClient::new(&profile, &secret)?;
    if !client.configuration().await?.port_forwarding_enabled {
        bail!("repair the SirinVPN server before managing port forwards");
    }
    let snapshot = client
        .create_port_forward(&PortForwardCreateRequest {
            protocol: arguments.protocol.into(),
            public_port: arguments.public_port,
            device_id,
            device_port: arguments.device_port,
        })
        .await?;
    print_membership(&snapshot, json)
}

pub(super) async fn remove_port_forward(
    paths: &ClientPaths,
    arguments: RemovePortForwardArguments,
    json: bool,
) -> Result<()> {
    let (profile, secret) = connected_identity(paths, &arguments.server)?;
    let client = ManagementClient::new(&profile, &secret)?;
    if !client.configuration().await?.port_forwarding_enabled {
        bail!("repair the SirinVPN server before managing port forwards");
    }
    let snapshot = client
        .remove_port_forward(arguments.protocol.into(), arguments.public_port)
        .await?;
    print_membership(&snapshot, json)
}

pub(super) async fn set_member_access(
    paths: &ClientPaths,
    arguments: MemberAccessArguments,
    json: bool,
) -> Result<()> {
    let member_id = arguments
        .member_id
        .parse::<MemberId>()
        .context("member identifier is invalid")?;
    let (mut profile, secret) = connected_identity(paths, &arguments.server)?;
    let client = ManagementClient::new(&profile, &secret)?;
    let status = client.status().await?;
    if let Some(role) = status.caller_role {
        profile.role = role;
        profile.administrator = status.caller_administrator;
        paths.profile_store().upsert(profile.clone())?;
    }
    if status.caller_role != Some(ServerRole::Owner) {
        bail!("only an owner device can change member access");
    }
    if !client.configuration().await?.advanced_invitations_enabled {
        bail!("the server must be upgraded before changing member access");
    }
    let snapshot = client
        .update_member_access(member_id, matches!(arguments.level, AccessLevel::Admin))
        .await?;
    print_membership(&snapshot, json)
}

pub(super) async fn transfer_ownership(
    paths: &ClientPaths,
    arguments: TransferOwnershipArguments,
    json: bool,
) -> Result<()> {
    if !arguments.confirm_transfer {
        bail!(
            "pass --confirm-transfer after verifying the destination device identity and accepting that this device will become an Admin"
        );
    }
    let destination_device_id = arguments
        .destination_device_id
        .parse::<DeviceId>()
        .context("destination device identifier is invalid")?;
    let (mut profile, secret) = connected_identity(paths, &arguments.server)?;
    let client = ManagementClient::new(&profile, &secret)?;
    let status = client.status().await?;
    if status.caller_role != Some(ServerRole::Owner) {
        bail!("only an owner device can transfer ownership");
    }
    if !client.configuration().await?.ownership_transfer_enabled {
        bail!("the server must be upgraded before transferring ownership");
    }
    let snapshot = client.transfer_ownership(destination_device_id).await?;
    profile.role = ServerRole::Member;
    profile.administrator = true;
    paths.profile_store().upsert(profile).context(
        "ownership was transferred on the VPS, but this device's local access level could not be saved; reconnect and run status to retry",
    )?;
    print_membership(&snapshot, json)
}

pub(super) async fn rotate_keys(
    paths: &ClientPaths,
    arguments: RotateKeysArguments,
    json: bool,
) -> Result<()> {
    if !arguments.confirm_key_rotation {
        bail!(
            "pass --confirm-key-rotation after accepting that the current device will briefly reconnect while both of its private keys are replaced"
        );
    }
    let profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    let pending = has_pending_key_rotation(paths, profile.id)?;
    let local = invoke_helper("status", None)?;
    if local.server_id.is_some() && local.server_id != Some(profile.id) {
        bail!("disconnect the other SirinVPN server before rotating this device's keys");
    }
    if !pending
        && (local.server_id != Some(profile.id) || local.state == ConnectionState::Disconnected)
    {
        bail!("connect to this server before rotating the current device's keys");
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
            allow_lan: local.allow_lan,
            selected_applications: local.routing_mode
                == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications,
            selected_routes: (local.routing_mode
                == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedRoutes)
                .then(|| local.included_routes.clone().unwrap_or_default()),
        });
    let result = rotate_current_device_keys_with_policy(
        paths,
        profile.id,
        persistent_protection,
        transport,
        transport_fallback_enabled,
        policy,
        || {
            let current = invoke_helper("status", None).map_err(|e| e.to_string())?;
            if current.server_id.is_some() && current.server_id != Some(profile.id) {
                return Err("Another server became active; it was preserved.".into());
            }
            if current.server_id.is_none() {
                return Ok(());
            }
            if current.policy.is_some() || current.kill_switch_enabled {
                let input = serde_json::to_vec(&profile.id).map_err(|e| e.to_string())?;
                invoke_helper("pause-for-key-rotation", Some(&input))
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            } else {
                invoke_helper("disconnect", None)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
        },
        |profile, secret, persistent, transport, fallback_enabled, policy| {
            let reconnect_plan = if fallback_enabled {
                TransportEngine.plan(profile, TransportPreference::Automatic)
            } else {
                Ok(Vec::new())
            }
            .map_err(|error| error.to_string())?;
            let status = if let Some(policy) = policy {
                let routing = if policy.selected_applications {
                    TunnelRoutingPolicy::selected_applications(policy.allow_lan)
                } else {
                    match &policy.selected_routes {
                        Some(routes) => {
                            TunnelRoutingPolicy::selected_routes(routes.clone(), policy.allow_lan)
                                .map_err(|e| e.to_string())?
                        }
                        None => TunnelRoutingPolicy::full_tunnel(policy.allow_lan),
                    }
                };
                connect_managed_with_mtu(
                    profile,
                    secret,
                    ConnectionPolicy {
                        kill_switch: policy.kill_switch,
                        automatic_reconnect: policy.automatic_reconnect,
                        connect_on_startup: policy.connect_on_startup,
                    },
                    transport,
                    &reconnect_plan,
                    &routing,
                    policy.mtu_policy.and_then(|mtu| match mtu {
                        sirinvpn_protocol::MtuPolicy::Manual { value } => Some(value),
                        _ => None,
                    }),
                )
            } else {
                connect_profile_with_transport_plan(
                    profile,
                    secret,
                    persistent,
                    transport,
                    &reconnect_plan,
                )
            }
            .map_err(|error| error.to_string())?;
            if status.server_id != Some(profile.id) || status.state == ConnectionState::Disconnected
            {
                return Err(
                    "the privileged helper did not activate the requested tunnel".to_owned(),
                );
            }
            Ok(())
        },
    )
    .await?;
    print_value(
        &result,
        json,
        "Rotated this device's WireGuard and management keys. The old local identity was removed.",
    )
}
