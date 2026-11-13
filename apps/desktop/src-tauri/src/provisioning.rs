//! Provisioning.

use super::*;
use sirinvpn_installer::{InstallerError, OwnerMaintenance, RemoteTransactionState};

#[tauri::command]
pub(super) fn list_servers(state: State<'_, AppState>) -> Result<Vec<ServerProfile>, String> {
    state.paths.profile_store().load().map_err(safe_error)
}

#[tauri::command]
pub(super) fn update_server_presentation(
    state: State<'_, AppState>,
    server_id: String,
    name: Option<String>,
    favorite: Option<bool>,
) -> Result<(), String> {
    let id = server_id.parse::<ServerId>().map_err(safe_error)?;
    state
        .paths
        .profile_store()
        .update_presentation(id, name, favorite)
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn probe_host_key(input: HostKeyInput) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        Provisioner::host_key_fingerprint(&SshTarget {
            host: input.host,
            port: input.port,
            username: "unused".to_owned(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: None,
        })
        .map_err(safe_error)
    })
    .await
    .map_err(|_| "Checking the server’s SSH key was interrupted. Try again.".to_owned())?
}

#[tauri::command]
pub(super) async fn provision_server(
    state: State<'_, AppState>,
    input: ProvisionInput,
) -> Result<ProvisionResult, CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || provision_blocking(paths, input))
        .await
        .map_err(|_| CommandError::from("Server setup was interrupted."))?
}

pub(super) fn provision_blocking(
    paths: ClientPaths,
    mut input: ProvisionInput,
) -> Result<ProvisionResult, CommandError> {
    let server_id = ServerId::new();
    let identity = new_identity_for_server(&input.name).map_err(safe_error)?;
    let request = install_request(&mut input, server_id, identity.public)?;
    let identity_reference = request.identity_reference.clone();
    let pinned = request.target.clone();
    let requested_dns = (
        request.dns_upstream.clone(),
        request.private_dns_records.clone(),
    );
    let journal = crate::vps_transaction::journal(&paths);
    // Refused before the new key is stored: an unresolved change on this host comes first.
    if journal
        .read_server(&pinned.host)
        .map_err(safe_error)?
        .is_some()
    {
        return Err(command_error(InstallerError::TransactionUnresolved {
            host: pinned.host.clone(),
        }));
    }
    let secrets = paths.secret_store();
    secrets
        .put(&identity_reference, &identity.secret)
        .map_err(safe_error)?;
    let discard = |error: CommandError| {
        if secrets.delete(&identity_reference).is_err() {
            return CommandError::from(
                "Server setup failed, and its new key couldn’t be deleted. Unlock secure storage and retry cleanup.",
            );
        }
        error
    };
    let result = match Provisioner::install_with_journal(request, &journal) {
        Ok(outcome) => ProvisionResult {
            network_preflight: Some(outcome.network_preflight),
            profile: outcome.profile,
            events: outcome.events,
            dns_upstream: outcome.dns_upstream,
            private_dns_records: outcome.private_dns_records,
            resolved_after_lost_reply: false,
        },
        // The install may be live: the Owner key stays until the VPS answers.
        Err(InstallerError::CommitUncertain { .. }) => {
            use crate::vps_transaction::{Settlement, settle};
            match settle(&Provisioner::resolve_transaction(&pinned, &journal)) {
                Settlement::Committed(profile) => ProvisionResult {
                    network_preflight: None,
                    profile: *profile,
                    events: Vec::new(),
                    dns_upstream: requested_dns.0,
                    private_dns_records: requested_dns.1,
                    resolved_after_lost_reply: true,
                },
                Settlement::RolledBack => {
                    return Err(discard(crate::vps_transaction::rolled_back()));
                }
                Settlement::Unknown(reason) => {
                    return Err(crate::vps_transaction::outcome_unknown(
                        &pinned.host,
                        &reason,
                    ));
                }
            }
        }
        Err(error) => return Err(discard(command_error(error))),
    };
    // A new server: nothing else can have written this profile yet.
    paths
        .profile_store()
        .upsert(result.profile.clone())
        .map_err(safe_error)?;
    // The installation authenticated with this explicitly verified pin.
    // A failed trust-store write must not turn a completed install into a failure.
    if crate::ssh_trust::remember_verified(
        &paths,
        &input.host,
        input.ssh_port,
        &input.host_key_sha256,
    )
    .is_err()
    {
        eprintln!("The installed VPS SSH identity could not be remembered.");
    }
    crate::hetzner::forget_installed(&paths.configuration_directory, &input.host);
    Ok(result)
}

/// Builds an install request; `provision_server` and the dry run share it.
pub(super) fn install_request(
    input: &mut ProvisionInput,
    server_id: ServerId,
    identity: sirinvpn_core::PublicIdentity,
) -> Result<InstallRequest, String> {
    validate_dns_upstream(&input.dns_upstream).map_err(|error| error.to_string())?;
    validate_private_dns_records(&input.private_dns_records).map_err(|error| error.to_string())?;
    let target = crate::ssh_login::resolve_target(crate::ssh_login::SshLoginInput {
        host: input.host.clone(),
        ssh_port: input.ssh_port,
        username: input.username.clone(),
        authentication: input.authentication.clone(),
        password: input.password.take(),
        private_key_path: input.private_key_path.take(),
        private_key_passphrase: input.private_key_passphrase.take(),
        sudo_password: input.sudo_password.take(),
        host_key_sha256: input.host_key_sha256.clone(),
    })?;
    Ok(InstallRequest {
        server_id,
        server_name: input.name.clone(),
        target,
        server_binary: crate::vps_transaction::server_payload()?,
        identity,
        identity_reference: server_id.to_string(),
        transport: input.transport.clone(),
        dns_upstream: input.dns_upstream.clone(),
        private_dns_records: input.private_dns_records.clone(),
        nat64_prefix: input
            .nat64_prefix
            .as_deref()
            .map(parse_nat64_prefix)
            .transpose()
            .map_err(|error| error.to_string())?,
        replace_existing_installation: input.replace_existing_installation,
        enable_security_updates: false,
    })
}

pub(super) fn take_ssh_authentication(
    method: &str,
    password: &mut Option<String>,
    private_key_path: &mut Option<String>,
    private_key_passphrase: &mut Option<String>,
) -> Result<SshAuthentication, String> {
    Ok(match method {
        "agent" => SshAuthentication::Agent,
        "password" => SshAuthentication::Password(Zeroizing::new(
            password
                .take()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "Enter the SSH password.".to_owned())?,
        )),
        "private_key" => SshAuthentication::PrivateKey {
            path: private_key_path
                .take()
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| "Enter the path to your SSH private key.".to_owned())?,
            passphrase: private_key_passphrase.take().map(Zeroizing::new),
        },
        _ => return Err("Choose a supported SSH sign-in method.".to_owned()),
    })
}

#[tauri::command]
pub(super) async fn uninstall_server(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    input: UninstallInput,
) -> Result<(), CommandError> {
    let paths = state.paths.clone();
    let server_id = input.server_id.clone();
    tauri::async_runtime::spawn_blocking(move || uninstall_blocking(paths, input))
        .await
        .map_err(|_| CommandError::from("Uninstalling was interrupted."))??;
    Ok(crate::connection_preferences::forget(&app, &server_id)?)
}

pub(super) fn uninstall_blocking(
    paths: ClientPaths,
    mut input: UninstallInput,
) -> Result<(), CommandError> {
    let profile = find_profile(&paths, &input.server_id)?;
    crate::vps_transaction::ensure_owner_maintenance_ready(
        &paths,
        &profile,
        OwnerMaintenance::Uninstall,
    )?;
    // Journaled like install, repair and restore, so an interruption can be resolved.
    let request = uninstall_request(&profile, &mut input)?;
    let pinned = request.target.clone();
    let journal = crate::vps_transaction::journal(&paths);
    match Provisioner::uninstall_with_journal(request, &journal) {
        Ok(()) => {}
        // Removed on the VPS only once it confirms; the keys stay otherwise.
        Err(InstallerError::CommitUncertain { .. }) => {
            use crate::vps_transaction::{Settlement, outcome_unknown, rolled_back, settle};
            let resolved = Provisioner::resolve_transaction(&pinned, &journal);
            // An uninstall commits no profile: a confirmed commit alone means it is gone.
            if !matches!(&resolved, Ok(Some(done)) if done.state == RemoteTransactionState::Committed)
            {
                return Err(match settle(&resolved) {
                    Settlement::RolledBack => rolled_back(),
                    Settlement::Unknown(reason) => outcome_unknown(&pinned.host, &reason),
                    Settlement::Committed(_) => outcome_unknown(&pinned.host, "unexpected state"),
                });
            }
        }
        Err(error) => return Err(command_error(error)),
    }
    paths
        .secret_store()
        .delete(&profile.identity_reference)
        .map_err(|_| {
            CommandError::from("SirinVPN was removed from the VPS, but this device’s key couldn’t be deleted. Use Remove from this device to finish.")
        })?;
    paths.profile_store().remove(profile.id).map_err(|_| {
        CommandError::from("SirinVPN was removed from the VPS, but this device couldn’t delete the saved server. Use Remove from this device to finish.")
    })?;
    let _ = paths.network_policy_store().forget_server(profile.id);
    let _ = crate::vps_backup_schedule::forget(&paths, profile.id);
    Ok(())
}

/// Builds an uninstall request; `uninstall_server` and the dry run share it.
pub(super) fn uninstall_request(
    profile: &ServerProfile,
    input: &mut UninstallInput,
) -> Result<UninstallRequest, String> {
    Ok(UninstallRequest {
        server_id: profile.id,
        target: crate::ssh_login::resolve_target(crate::ssh_login::SshLoginInput {
            host: profile.endpoint.host.clone(),
            ssh_port: input.ssh_port,
            username: input.username.clone(),
            authentication: input.authentication.clone(),
            password: input.password.take(),
            private_key_path: input.private_key_path.take(),
            private_key_passphrase: input.private_key_passphrase.take(),
            sudo_password: input.sudo_password.take(),
            host_key_sha256: input.host_key_sha256.clone(),
        })?,
        owner_certificate_pem: profile.client_management_certificate_pem.clone(),
    })
}

#[tauri::command]
pub(super) async fn repair_server(
    state: State<'_, AppState>,
    input: RepairInput,
) -> Result<RepairResult, CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || repair_blocking(paths, input))
        .await
        .map_err(|_| CommandError::from("The VPS repair was interrupted."))?
}

pub(super) fn repair_blocking(
    paths: ClientPaths,
    mut input: RepairInput,
) -> Result<RepairResult, CommandError> {
    if !input.confirmed {
        return Err("Confirm the VPS repair first.".into());
    }
    let profile = find_profile(&paths, &input.server_id)?;
    crate::vps_transaction::ensure_owner_maintenance_ready(
        &paths,
        &profile,
        OwnerMaintenance::Repair,
    )?;
    let request = repair_request(&paths, &mut input, &profile)?;
    let server_identity_fingerprint =
        sirinvpn_core::management_identity_fingerprint(&profile.pinned_server_certificate_pem)
            .map_err(safe_error)?;
    let pinned = request.target.clone();
    let journal = crate::vps_transaction::journal(&paths);
    match Provisioner::repair_with_journal(request, &journal) {
        Ok(outcome) => {
            save_repair(&paths, profile.id, &outcome)?;
            Ok(RepairResult {
                network_preflight: Some(outcome.network_preflight),
                events: outcome.events,
                artifact_sha256: Some(outcome.artifact_sha256),
                server_identity_fingerprint,
                dns_upstream: Some(outcome.dns_upstream),
                private_dns_records: Some(outcome.private_dns_records),
                resolved_after_lost_reply: false,
            })
        }
        Err(InstallerError::CommitUncertain { .. }) => {
            use crate::vps_transaction::{Settlement, settle};
            match settle(&Provisioner::resolve_transaction(&pinned, &journal)) {
                Settlement::Committed(committed) => {
                    crate::vps_transaction::save_committed(&paths, &committed)?;
                    Ok(RepairResult {
                        network_preflight: None,
                        events: Vec::new(),
                        artifact_sha256: None,
                        server_identity_fingerprint,
                        dns_upstream: None,
                        private_dns_records: None,
                        resolved_after_lost_reply: true,
                    })
                }
                Settlement::RolledBack => Err(crate::vps_transaction::rolled_back()),
                Settlement::Unknown(reason) => Err(crate::vps_transaction::outcome_unknown(
                    &pinned.host,
                    &reason,
                )),
            }
        }
        Err(error) => Err(command_error(error)),
    }
}

/// Repair owns the endpoint and transport fields it reinstalled; the rest of
/// the profile stays as it is saved now.
fn save_repair(
    paths: &ClientPaths,
    id: ServerId,
    outcome: &sirinvpn_installer::RepairOutcome,
) -> Result<(), String> {
    paths
        .profile_store()
        .update(id, |current| {
            let repaired = outcome.updated_profile(current);
            if repaired.endpoint_descriptor() != current.endpoint_descriptor()
                || repaired.endpoint_generation != current.endpoint_generation
            {
                *current = repaired;
            }
            Ok(())
        })
        .map_err(|_| {
            "The VPS was repaired, but this device couldn’t save its new settings. Repair again before connecting."
                .to_owned()
        })
}

/// Builds a repair request; `repair_server` and the dry run share it.
pub(super) fn repair_request(
    paths: &ClientPaths,
    input: &mut RepairInput,
    profile: &ServerProfile,
) -> Result<RepairRequest, String> {
    if let Some(dns_upstream) = &input.dns_upstream {
        validate_dns_upstream(dns_upstream).map_err(|error| error.to_string())?;
    }
    if let Some(private_dns_records) = &input.private_dns_records {
        validate_private_dns_records(private_dns_records).map_err(|error| error.to_string())?;
    }
    let identity = explicit_secret(paths, &profile.identity_reference)?
        .public_identity(&profile.client_management_certificate_pem)
        .map_err(safe_error)?;
    Ok(RepairRequest {
        transport: input.transport.clone(),
        enable_security_updates: input.enable_security_updates,
        profile: profile.clone(),
        target: crate::ssh_login::resolve_target(crate::ssh_login::SshLoginInput {
            host: profile.endpoint.host.clone(),
            ssh_port: input.ssh_port,
            username: input.username.clone(),
            authentication: input.authentication.clone(),
            password: input.password.take(),
            private_key_path: input.private_key_path.take(),
            private_key_passphrase: input.private_key_passphrase.take(),
            sudo_password: input.sudo_password.take(),
            host_key_sha256: input.host_key_sha256.clone(),
        })?,
        server_binary: crate::vps_transaction::server_payload()?,
        identity,
        dns_upstream: input.dns_upstream.clone(),
        private_dns_records: input.private_dns_records.clone(),
        nat64_prefix: input
            .nat64_prefix
            .as_ref()
            .map(|prefix| prefix.as_deref().map(parse_nat64_prefix).transpose())
            .transpose()
            .map_err(|error| error.to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sirinvpn_installer::{AddressExposure, NetworkPreflight, RepairOutcome};

    #[test]
    fn a_repair_keeps_a_concurrent_rename() {
        let stale: ServerProfile = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "id": ServerId::new(), "name": "Home",
            "endpoint": {"host": "203.0.113.1", "wireguard_port": 51820},
            "client_tunnel_address": "10.0.0.2", "server_tunnel_address": "10.0.0.1",
            "server_wireguard_public_key": "key", "pinned_server_certificate_pem": "cert",
            "client_management_certificate_pem": "client-cert", "identity_reference": "identity",
            "role": "owner",
        }))
        .unwrap();
        let (_directory, paths) = crate::vps_transaction::tests::store_with_rename(&stale);
        let outcome = RepairOutcome {
            network_preflight: NetworkPreflight {
                public_endpoint: "203.0.113.1".into(),
                endpoint_addresses: vec![],
                ssh_local_address: None,
                exposure: AddressExposure::Unresolved,
                assigned_addresses: vec![],
                required_ports: vec![],
                issues: vec![],
            },
            endpoint: ServerEndpoint {
                host: "203.0.113.1".into(),
                wireguard_port: 443,
            },
            endpoint_generation: 0,
            alternate_endpoint_hosts: vec![],
            endpoint_discovery_port: None,
            events: vec![],
            artifact_sha256: String::new(),
            ipv6_tunnel_enabled: false,
            obfuscated_udp: None,
            tcp_fallback: None,
            tls_like: None,
            dns_upstream: DnsUpstream::default(),
            private_dns_records: vec![],
            wireguard_port: 443,
        };
        save_repair(&paths, stale.id, &outcome).unwrap();
        let saved = paths.profile_store().load().unwrap().remove(0);
        assert_eq!((saved.name.as_str(), saved.favorite), ("Renamed", true));
        assert_eq!(saved.endpoint.wireguard_port, 443);
    }

    #[test]
    fn a_plan_takes_the_operation_and_the_real_arguments() {
        let login = serde_json::json!({
            "server_id": "x", "username": "root", "ssh_port": 22, "authentication": "agent",
            "password": null, "private_key_path": null, "private_key_passphrase": null,
            "sudo_password": null, "host_key_sha256": "SHA256:x", "confirmed": true,
            "dns_upstream": null, "private_dns_records": null,
        });
        let mut repair = login.clone();
        repair["operation"] = "repair".into();
        let crate::vps_transaction::PlanInput::Repair(input) =
            serde_json::from_value(repair).unwrap()
        else {
            panic!("not a repair")
        };
        // Omitted still keeps the VPS's NAT64 choice.
        assert!(input.nat64_prefix.is_none());
        let mut uninstall = login;
        uninstall["operation"] = "uninstall".into();
        assert!(matches!(
            serde_json::from_value(uninstall).unwrap(),
            crate::vps_transaction::PlanInput::Uninstall(_)
        ));
    }
}
