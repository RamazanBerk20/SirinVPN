use crate::jni_bridge::Runtime;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sirinvpn_core::{DecodedInvitation, ManagementClient, PendingEnrollment, SecretStore};
use sirinvpn_protocol::*;
use sirinvpn_tunnel_model::{ConnectionPreferenceStore, ConnectionPreferences};

#[path = "commands/maintenance.rs"]
mod maintenance;
#[path = "commands/membership.rs"]
mod membership;
#[path = "commands/recovery.rs"]
mod recovery;
#[path = "commands/releases.rs"]
mod releases;

pub fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .context("Missing or invalid field")
}
pub fn profile(runtime: &Runtime, id: &str) -> Result<ServerProfile> {
    let id: ServerId = id.parse()?;
    runtime
        .paths
        .profile_store()
        .load()?
        .into_iter()
        .find(|p| p.id == id)
        .context("Profile not found")
}
pub fn preferences(runtime: &Runtime) -> ConnectionPreferenceStore {
    ConnectionPreferenceStore::new(
        runtime
            .paths
            .configuration_directory
            .join("connection-preferences"),
    )
}
pub fn confirmed(input: &Value) -> Result<()> {
    ensure!(
        input["confirmed"] == true,
        "Explicit confirmation is required"
    );
    Ok(())
}
fn encode(value: impl serde::Serialize) -> Result<Value> {
    Ok(serde_json::to_value(value)?)
}

pub async fn dispatch(
    runtime: &Runtime,
    command: &str,
    args: Value,
    generation: i64,
) -> Result<Value> {
    let mut args = args;
    if command == "trust_ssh_host" {
        args["input"]["fingerprint"] = args["fingerprint"].clone();
    }
    let input = args.get("input").unwrap_or(&args);
    if matches!(
        command,
        "get_release_update_status"
            | "check_release_update"
            | "install_release_update"
            | "discard_release_update"
            | "rollback_release_update"
            | "prepare_vps_baseline"
            | "install_vps_baseline"
            | "discard_vps_baseline"
            | "manage_vps_release"
    ) {
        return releases::dispatch(runtime, command, input).await;
    }
    if matches!(
        command,
        "create_recovery_key"
            | "preview_recovery_key"
            | "recover_owner_access"
            | "export_recovery_package"
            | "import_recovery_package"
    ) {
        return recovery::dispatch(runtime, command, input, generation).await;
    }
    match command {
        "android_measure_quality" => return crate::quality::measure(runtime, generation).await,
        "get_wifi_policy" | "set_wifi_policy" | "trust_current_wifi" | "forget_trusted_wifi" => {
            let store = runtime.paths.network_policy_store();
            store.initialize_wifi_settings()?;
            let native = runtime.platform.wifi()?;
            let network = native["identifier"].as_str().and_then(|id| {
                sirinvpn_core::NetworkContext::android(
                    id.to_owned(),
                    native["wifi"] == true,
                    native["trustable"] == true,
                )
            });
            match command {
                "set_wifi_policy" => {
                    let policy: sirinvpn_core::WifiAutomationPolicy =
                        serde_json::from_value(args["policy"].clone())?;
                    if let Some(id) = policy.server_id {
                        profile(runtime, &id.to_string())?;
                    }
                    store.set_wifi_automation(policy)?;
                    return Ok(Value::Null);
                }
                "trust_current_wifi" => {
                    let snapshot = store.wifi_snapshot(network.as_ref())?;
                    ensure!(
                        snapshot.current_network_token.as_deref()
                            == Some(text(&args, "expectedNetworkToken")?),
                        "Wi-Fi network changed. Review it again"
                    );
                    store.trust_wifi(
                        network.as_ref().context("Wi-Fi identity unavailable")?,
                        text(&args, "label")?.to_owned(),
                    )?;
                    return Ok(Value::Null);
                }
                "forget_trusted_wifi" => {
                    store.forget_trusted_wifi(text(&args, "id")?)?;
                    return Ok(Value::Null);
                }
                _ => {}
            }
            let snapshot = store.wifi_snapshot(network.as_ref())?;
            let mut value = encode(&snapshot)?;
            value["automation_status"] = json!(if !snapshot.policy.enabled {
                "disabled"
            } else {
                "waiting_for_wifi"
            });
            if let (Some(token), Some(name)) =
                (snapshot.current_network_token, native["name"].as_str())
            {
                value["network_names"] = json!({token:name});
            }
            value["permission_required"] = native["permission_required"].clone();
            value["location_enabled"] = native["location_enabled"].clone();
            return Ok(value);
        }
        "client_platform" => return Ok(json!("android")),
        "android_set_quick_profile" => {
            profile(runtime, text(&args, "serverId")?)?;
            return Ok(Value::Null);
        }
        "list_servers" => return encode(runtime.paths.profile_store().load()?),
        "update_server_presentation" => {
            runtime.paths.profile_store().update_presentation(
                text(&args, "serverId")?.parse()?,
                args["name"].as_str().map(str::to_owned),
                args["favorite"].as_bool(),
            )?;
            return Ok(Value::Null);
        }
        "get_connection_preferences" => {
            return encode(
                preferences(runtime)
                    .get(profile(runtime, text(&args, "serverId")?)?.id)
                    .map_err(anyhow::Error::msg)?,
            );
        }
        "set_connection_preferences" => {
            let profile = profile(runtime, text(&args, "serverId")?)?;
            let prefs: ConnectionPreferences = serde_json::from_value(args["preferences"].clone())?;
            return encode(
                preferences(runtime)
                    .set(profile.id, prefs)
                    .map_err(anyhow::Error::msg)?,
            );
        }
        "current_network_profile" => return Ok(json!("automatic")),
        "local_component_update_status" => {
            return Ok(json!({"install_available":false,"update_required":false}));
        }
        "key_rotation_pending" => {
            return encode(sirinvpn_core::has_pending_key_rotation(
                &runtime.paths,
                text(&args, "serverId")?.parse()?,
            )?);
        }
        "rotate_device_keys" => {
            confirmed(input)?;
            let p = profile(runtime, text(input, "server_id")?)?;
            if !sirinvpn_core::has_pending_key_rotation(&runtime.paths, p.id)? {
                runtime.platform.require_active(&p.id.to_string())?;
            }
            let checkpoint = format!("rotation-preferences-{}", p.id);
            let prefs: ConnectionPreferences =
                if let Some(bytes) = runtime.platform.blob(&checkpoint)? {
                    serde_json::from_slice(&bytes)?
                } else {
                    let prefs = runtime
                        .platform
                        .connection_preferences(&p.id.to_string())?
                        .map(serde_json::from_value)
                        .transpose()?
                        .unwrap_or(preferences(runtime).get(p.id).map_err(anyhow::Error::msg)?);
                    runtime
                        .platform
                        .put_blob(&checkpoint, &serde_json::to_vec(&prefs)?)?;
                    prefs
                };
            let policy = sirinvpn_core::RotationConnectionPolicy {
                mtu_policy: Some(
                    prefs
                        .manual_mtu
                        .map(|value| MtuPolicy::Manual { value })
                        .unwrap_or(MtuPolicy::Automatic),
                ),
                kill_switch: prefs.policy.kill_switch,
                automatic_reconnect: prefs.policy.automatic_reconnect,
                connect_on_startup: prefs.policy.connect_on_startup,
                selected_routes: (prefs.routing.mode
                    == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedRoutes)
                    .then(|| prefs.routing.included_routes.clone()),
                selected_applications: prefs.routing.mode
                    == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications,
                allow_lan: prefs.routing.allow_lan,
            };
            let result = sirinvpn_core::rotate_current_device_keys_with_policy(
                &runtime.paths,
                p.id,
                false,
                TransportKind::DirectUdp,
                prefs.transport == TransportPreference::Automatic,
                Some(policy),
                || {
                    runtime
                        .platform
                        .deactivate(generation)
                        .map_err(|_| "Could not pause tunnel".to_owned())
                },
                |profile, secret, _, _, _, _| {
                    tokio::task::block_in_place(|| {
                        runtime.executor.block_on(async {
                            runtime.platform.prepare_connection(
                                &profile.id.to_string(),
                                &prefs,
                                generation,
                            )?;
                            crate::tunnel::connect(runtime, profile, secret, &prefs, generation)
                                .await
                        })
                    })
                    .map_err(|_| {
                        "Could not verify the rotated identity; resume key rotation".to_owned()
                    })
                },
            )
            .await?;
            runtime.platform.delete_blob(&checkpoint)?;
            return encode(result);
        }
        "connect_saved"
        | "connect_server"
        | "connect_server_with_policy"
        | "resume_server"
        | "reconnect_server" => {
            let profile = profile(runtime, text(&args, "serverId")?)?;
            ensure!(
                !sirinvpn_core::has_pending_key_rotation(&runtime.paths, profile.id)?,
                "Complete key rotation first"
            );
            let mut prefs = if let Some(value) = args.get("preferences") {
                serde_json::from_value::<ConnectionPreferences>(value.clone())?
                    .validated()
                    .map_err(anyhow::Error::msg)?
            } else {
                preferences(runtime)
                    .get(profile.id)
                    .map_err(anyhow::Error::msg)?
            };
            if args.get("preferences").is_none() {
                if let Some(value) = args.get("transport") {
                    prefs.transport = serde_json::from_value(value.clone())?;
                }
                if let Some(value) = args.get("networkProfile") {
                    prefs.network_profile = serde_json::from_value(value.clone())?;
                }
                if let Some(value) = args.get("routing") {
                    prefs.routing = serde_json::from_value(value.clone())?;
                }
                prefs = prefs.validated().map_err(anyhow::Error::msg)?;
            }
            let secret = runtime
                .paths
                .secret_store()
                .get(&profile.identity_reference)?;
            runtime
                .platform
                .prepare_connection(&profile.id.to_string(), &prefs, generation)?;
            crate::tunnel::connect(runtime, &profile, &secret, &prefs, generation).await?;
            return Ok(Value::Null);
        }
        "preview_invitation" => {
            let invitation = DecodedInvitation::decode(text(&args, "code")?)?;
            let binding = invitation.enrollment_binding();
            return Ok(
                json!({"server_name":invitation.server_name(),"host":binding.endpoint.host,
                "server_identity_fingerprint":sirinvpn_core::management_certificate_fingerprint(&binding.pinned_server_certificate_pem)?,
                "expires_at_unix":invitation.expires_at_unix(),"recipient_names":invitation.recipient_names(),
                "creates_member":invitation.creates_member(),"member_name":invitation.member_name(),
                "device_name":invitation.device_name(),"access_level":if invitation.administrator() {"admin"} else {"member"}}),
            );
        }
        "join_server" => return join(runtime, input, generation).await,
        "remove_server" => {
            let p = profile(runtime, text(&args, "serverId")?)?;
            runtime.platform.require_inactive(&p.id.to_string())?;
            ensure!(
                !sirinvpn_core::has_pending_key_rotation(&runtime.paths, p.id)?,
                "Complete key rotation first"
            );
            runtime.paths.secret_store().delete(&p.identity_reference)?;
            runtime.paths.profile_store().remove(p.id)?;
            preferences(runtime)
                .forget(p.id)
                .map_err(anyhow::Error::msg)?;
            runtime.paths.network_policy_store().forget_server(p.id)?;
            return Ok(Value::Null);
        }
        _ => {}
    }
    if maintenance::accepts(command) {
        return maintenance::dispatch(runtime, command, input, generation).await;
    }
    let id = args
        .get("serverId")
        .or_else(|| input.get("server_id"))
        .and_then(Value::as_str)
        .context("Missing server ID")?;
    let p = profile(runtime, id)?;
    if matches!(command, "apply_endpoint_update" | "publish_endpoint_update") {
        let connect = |p: ServerProfile, s: sirinvpn_core::SecretIdentity| async move {
            let result = async {
                let prefs = runtime
                    .platform
                    .connection_preferences(&p.id.to_string())?
                    .map(serde_json::from_value)
                    .transpose()?
                    .unwrap_or(preferences(runtime).get(p.id).map_err(anyhow::Error::msg)?);
                runtime
                    .platform
                    .prepare_connection(&p.id.to_string(), &prefs, generation)?;
                crate::tunnel::connect(runtime, &p, &s, &prefs, generation).await
            }
            .await;
            result.map_err(|_: anyhow::Error| "Could not verify the candidate tunnel".to_owned())
        };
        let disconnect = || {
            runtime
                .platform
                .deactivate(generation)
                .map_err(|_| "Could not stop candidate tunnel".to_owned())
        };
        let result = if command == "apply_endpoint_update" {
            sirinvpn_core::apply_endpoint_transition(
                &runtime.paths,
                p.id,
                text(input, "code")?,
                connect,
                disconnect,
            )
            .await?
        } else {
            sirinvpn_core::publish_endpoint_transition(
                &runtime.paths,
                p.id,
                text(input, "code")?,
                connect,
                disconnect,
            )
            .await?
        };
        return encode(result);
    }
    runtime.platform.require_active(id)?;
    let secret = runtime.paths.secret_store().get(&p.identity_reference)?;
    let client = ManagementClient::new(&p, &secret)?;
    match command {
        "server_status" => {
            let status = client.status().await?;
            if let Some(role) = status.caller_role {
                let mut updated = p.clone();
                updated.role = role;
                updated.administrator = status.caller_administrator;
                if let Some(device) = status.caller_device_id {
                    client.refresh_membership_ids(&mut updated, device).await?;
                }
                if updated != p {
                    runtime.paths.profile_store().upsert(updated)?;
                }
            }
            encode(status)
        }
        "server_configuration" => encode(client.configuration().await?),
        "membership" => encode(client.membership().await?),
        "run_diagnostics" => encode(client.diagnostics().await?),
        "recovery_settings" => encode(client.recovery_settings().await?),
        "update_recovery_policy" => encode(
            client
                .update_recovery_policy(&RecoveryPolicy {
                    administrator_member_ids: serde_json::from_value(
                        args["administratorMemberIds"].clone(),
                    )?,
                })
                .await?,
        ),
        "revoke_recovery_key" => encode(
            client
                .revoke_recovery_key(text(&args, "recoveryId")?.parse()?)
                .await?,
        ),
        "create_endpoint_update" => {
            let code = sirinvpn_core::create_endpoint_transition(&runtime.paths, p.id).await?;
            Ok(
                json!({"server_id":p.id,"generation":code.generation(),"previous_endpoint":code.previous_endpoint(),"endpoint":code.endpoint(),"code":code.expose()}),
            )
        }
        "available_endpoint_update" => {
            if let Some(response) = client.endpoint_transition().await? {
                let code = sirinvpn_core::EndpointTransitionCode::from_response(response)?;
                if code.generation() <= p.endpoint_generation {
                    return Ok(Value::Null);
                }
                Ok(
                    json!({"server_id":p.id,"generation":code.generation(),"previous_endpoint":code.previous_endpoint(),"endpoint":code.endpoint(),"code":code.expose()}),
                )
            } else {
                Ok(Value::Null)
            }
        }
        _ => membership::dispatch(runtime, &client, &p, command, &args).await,
    }
}

async fn join(runtime: &Runtime, input: &Value, generation: i64) -> Result<Value> {
    runtime.platform.require_idle()?;
    let mut invitation = DecodedInvitation::decode(text(input, "code")?)?;
    invitation.set_recipient_names(input["member_name"].as_str(), input["device_name"].as_str())?;
    ensure!(
        !runtime
            .paths
            .profile_store()
            .load()?
            .iter()
            .any(|p| p.id == invitation.server_id()),
        "Profile already exists"
    );
    let secrets = runtime.paths.secret_store();
    let mut pending = PendingEnrollment::open(
        &runtime.paths,
        &secrets,
        invitation.server_id(),
        &format!(
            "invitation-{}",
            invitation.enrollment_binding().invitation_id
        ),
        invitation.device_name(),
    )?;
    pending.bind_invitation_names(invitation.enrollment_binding().names)?;
    let outcome = async {
        let profile = if let Some(profile) = pending.completed_profile() {
            profile
        } else {
            invitation.refresh_endpoint().await?;
            let bootstrap = invitation.bootstrap_profile();
            crate::tunnel::connect(
                runtime,
                &bootstrap,
                invitation.bootstrap_secret(),
                &ConnectionPreferences::default(),
                generation,
            )
            .await?;
            let client = ManagementClient::new(&bootstrap, invitation.bootstrap_secret())?;
            let result = client
                .enroll(&invitation.enrollment_request(&pending.identity.public))
                .await?;
            invitation.permanent_profile(
                &result,
                &pending.identity.public,
                pending.identity_reference.clone(),
            )?
        };
        runtime.platform.current(generation)?;
        pending.commit_profile(&runtime.paths, profile.clone(), false)?;
        runtime.platform.deactivate(generation)?;
        crate::tunnel::connect(
            runtime,
            &profile,
            &pending.identity.secret,
            &ConnectionPreferences::default(),
            generation,
        )
        .await?;
        encode(profile)
    }
    .await;
    if outcome.is_err() {
        let _ = runtime.platform.deactivate(generation);
    }
    outcome
}
