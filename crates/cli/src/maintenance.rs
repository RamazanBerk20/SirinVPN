//! Maintenance.

use super::*;

fn owner_device_state(
    role: ServerRole,
    connection: &ConnectionState,
    kill_switch_enabled: bool,
    auto_reconnect_enabled: bool,
    pending_key_rotation: bool,
    unresolved_transaction: bool,
) -> OwnerDeviceState {
    OwnerDeviceState {
        role,
        disconnected: *connection == ConnectionState::Disconnected,
        kill_switch_enabled,
        auto_reconnect_enabled,
        pending_key_rotation,
        unresolved_transaction,
    }
}

fn blocker_report(blockers: &[MaintenanceBlocker]) -> String {
    blockers
        .iter()
        .map(|blocker| blocker.message())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every Owner maintenance command asks the same rules before it starts anything.
pub(super) fn ensure_maintenance_ready(
    paths: &ClientPaths,
    profile: &ServerProfile,
    operation: OwnerMaintenance,
) -> Result<()> {
    let status = invoke_helper("status", None)?;
    let state = owner_device_state(
        profile.role,
        &status.state,
        status.kill_switch_enabled,
        status.auto_reconnect_enabled,
        has_pending_key_rotation(paths, profile.id)?,
        transaction_journal(paths).blocks_server(profile)?,
    );
    owner_maintenance_ready(operation, &state)
        .map_err(|blockers| anyhow!(blocker_report(&blockers)))
}

/// After a lost commit reply: ask the VPS and keep or drop the change accordingly.
fn finish_uncertain(
    paths: &ClientPaths,
    target: &SshTarget,
    operation: &str,
    json: bool,
) -> Result<()> {
    match settle_uncertain(paths, target) {
        Settlement::Committed(committed) => {
            let profile = save_committed_profile(paths, &committed, &target.host).with_context(|| {
                format!("the VPS {operation} committed, but its local profile could not be saved; {operation} again before connecting")
            })?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        operation: true,
                        "server_id": profile.id,
                        "confirmed_after_lost_reply": true
                    })
                );
            } else {
                println!(
                    "The VPS confirmed the {operation} of {}, although its reply was lost. This device's profile now matches it.",
                    profile.name
                );
            }
            Ok(())
        }
        Settlement::RolledBack => bail!(
            "The VPS rolled the {operation} back. Nothing changed, and this device's profile is unchanged."
        ),
        Settlement::Unknown(reason) => Err(unresolved_outcome(&reason)),
    }
}

pub(super) fn uninstall_server(
    paths: &ClientPaths,
    arguments: UninstallServerArguments,
    json: bool,
) -> Result<()> {
    if !arguments.plan && !arguments.confirm_uninstall {
        bail!(
            "pass --confirm-uninstall after verifying that all current SirinVPN devices and invitations may be revoked"
        );
    }
    let store = paths.profile_store();
    let profile = resolve_profile(&store, &arguments.server)?;
    if !arguments.plan {
        ensure_maintenance_ready(paths, &profile, OwnerMaintenance::Uninstall)?;
    }
    let authentication = if arguments.ssh_agent {
        SshAuthentication::Agent
    } else if let Some(path) = arguments.ssh_key {
        let passphrase = prompt_secret("SSH key passphrase (leave empty if none): ")?;
        SshAuthentication::PrivateKey {
            path,
            passphrase: (!passphrase.is_empty()).then_some(passphrase),
        }
    } else {
        SshAuthentication::Password(prompt_nonempty_secret("SSH password: ")?)
    };
    let sudo_password = if arguments.username == "root" || arguments.passwordless_sudo {
        None
    } else {
        Some(prompt_nonempty_secret("sudo password: ")?)
    };
    let request = UninstallRequest {
        server_id: profile.id,
        target: SshTarget {
            host: profile.endpoint.host.clone(),
            port: arguments.ssh_port,
            username: arguments.username,
            authentication,
            sudo_password,
            expected_host_key_sha256: Some(arguments.host_key),
        },
        owner_certificate_pem: profile.client_management_certificate_pem.clone(),
    };
    if arguments.plan {
        return print_plan(&Provisioner::plan_uninstall(request)?, json);
    }
    // Journaled like install, repair and restore, so an interruption can be resolved.
    let target = request.target.clone();
    match Provisioner::uninstall_with_journal(request, &transaction_journal(paths)) {
        Ok(()) => {}
        // Removed locally only once the VPS confirms; the keys stay otherwise.
        Err(InstallerError::CommitUncertain { .. }) => {
            let resolved = Provisioner::resolve_transaction(&target, &transaction_journal(paths));
            // An uninstall commits no profile: a confirmed commit alone means it is gone.
            if !matches!(&resolved, Ok(Some(done)) if done.state == RemoteTransactionState::Committed)
            {
                return Err(match settle(resolved) {
                    Settlement::RolledBack => anyhow!(
                        "The VPS rolled the uninstall back. SirinVPN is still installed, and this device kept its profile and key."
                    ),
                    Settlement::Unknown(reason) => unresolved_outcome(&reason),
                    Settlement::Committed(_) => unresolved_outcome("unexpected state"),
                });
            }
        }
        Err(error) => return Err(error.into()),
    }
    paths
        .secret_store()
        .delete(&profile.identity_reference)
        .context(
            "SirinVPN was removed from the VPS, but its local device key could not be deleted; use server remove to retry cleanup",
        )?;
    store.remove(profile.id).context(
        "SirinVPN was removed from the VPS, but its local profile could not be deleted; use server remove to retry cleanup",
    )?;
    let _ = paths.network_policy_store().forget_server(profile.id);
    if json {
        println!("{{\"uninstalled\":true}}");
    } else {
        println!(
            "Uninstalled SirinVPN from {} and removed its local profile.",
            profile.name
        );
    }
    Ok(())
}

pub(super) fn repair_server(
    paths: &ClientPaths,
    arguments: RepairServerArguments,
    json: bool,
) -> Result<()> {
    if !arguments.plan && !arguments.confirm_repair {
        bail!(
            "pass --confirm-repair after confirming the VPN is disconnected and the pinned SSH fingerprint belongs to this VPS"
        );
    }
    let mut profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    if !arguments.plan {
        ensure_maintenance_ready(paths, &profile, OwnerMaintenance::Repair)?;
    }
    let secret = explicit_secret(paths, &profile.identity_reference)?;
    let identity = secret.public_identity(&profile.client_management_certificate_pem)?;
    let authentication = if arguments.ssh_agent {
        SshAuthentication::Agent
    } else if let Some(path) = arguments.ssh_key {
        let passphrase = prompt_secret("SSH key passphrase (leave empty if none): ")?;
        SshAuthentication::PrivateKey {
            path,
            passphrase: (!passphrase.is_empty()).then_some(passphrase),
        }
    } else {
        SshAuthentication::Password(prompt_nonempty_secret("SSH password: ")?)
    };
    let sudo_password = if arguments.username == "root" || arguments.passwordless_sudo {
        None
    } else {
        Some(prompt_nonempty_secret("sudo password: ")?)
    };
    let transport = arguments.transport.requested(Some(&profile))?;
    let request = RepairRequest {
        transport,
        enable_security_updates: arguments.enable_security_updates,
        profile: profile.clone(),
        target: SshTarget {
            host: profile.endpoint.host.clone(),
            port: arguments.ssh_port,
            username: arguments.username,
            authentication,
            sudo_password,
            expected_host_key_sha256: Some(arguments.host_key),
        },
        server_binary: resolve_server_binary(arguments.server_binary)?,
        identity,
        dns_upstream: arguments.dns.requested(),
        private_dns_records: arguments.private_dns.requested(),
        nat64_prefix: if arguments.no_nat64 {
            Some(None)
        } else {
            arguments.nat64_prefix.map(Some)
        },
    };
    if arguments.plan {
        return print_plan(&Provisioner::plan_repair(request)?, json);
    }
    let target = request.target.clone();
    let outcome = match Provisioner::repair_with_journal(request, &transaction_journal(paths)) {
        Ok(outcome) => outcome,
        Err(InstallerError::CommitUncertain { .. }) => {
            return finish_uncertain(paths, &target, "repair", json);
        }
        Err(error) => return Err(error.into()),
    };
    if profile.endpoint != outcome.endpoint
        || profile.endpoint_generation != outcome.endpoint_generation
        || profile.alternate_endpoint_hosts != outcome.alternate_endpoint_hosts
        || profile.endpoint_discovery_port != outcome.endpoint_discovery_port
        || profile.ipv6_tunnel_enabled != outcome.ipv6_tunnel_enabled
        || profile.obfuscated_udp != outcome.obfuscated_udp
        || profile.tcp_fallback != outcome.tcp_fallback
        || profile.tls_like != outcome.tls_like
    {
        // Repair owns only the endpoint capabilities; the rest stays as saved now.
        profile = paths
            .profile_store()
            .update(profile.id, |current| {
                current.endpoint = outcome.endpoint.clone();
                current.endpoint_generation = outcome.endpoint_generation;
                current.alternate_endpoint_hosts = outcome.alternate_endpoint_hosts.clone();
                current.endpoint_discovery_port = outcome.endpoint_discovery_port;
                current.set_endpoint_handoff(sirinvpn_protocol::EndpointHandoff::Current);
                current.ipv6_tunnel_enabled = outcome.ipv6_tunnel_enabled;
                current.obfuscated_udp = outcome.obfuscated_udp.clone();
                current.tcp_fallback = outcome.tcp_fallback.clone();
                current.tls_like = outcome.tls_like.clone();
                Ok(current.clone())
            })
            .context(
                "the VPS was repaired, but its local capabilities could not be saved; repair again before connecting",
            )?;
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&RepairOperationResult {
                repaired: true,
                server_id: profile.id,
                artifact_sha256: outcome.artifact_sha256,
                dns_upstream: outcome.dns_upstream,
                private_dns_records: outcome.private_dns_records,
            })?
        );
    } else {
        for event in outcome.events {
            println!("{:?}: {}", event.phase, event.message);
        }
        println!(
            "Repaired {} with artifact SHA-256 {}. DNS: {}; private records: {}. Server and device identities were preserved.",
            profile.name,
            outcome.artifact_sha256,
            dns_upstream_label(&outcome.dns_upstream),
            outcome.private_dns_records.len(),
        );
    }
    Ok(())
}

pub(super) fn backup_vps(
    paths: &ClientPaths,
    arguments: BackupVpsArguments,
    json: bool,
) -> Result<()> {
    eprintln!(
        "Warning: this encrypted file contains the VPS private keys and complete current authorization state. Anyone with the file and password can clone the server identity."
    );
    if !arguments.confirm_server_backup {
        bail!(
            "pass --confirm-server-backup after choosing a strong unique password, a safe destination, and verifying the pinned SSH fingerprint"
        );
    }
    let profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    ensure_maintenance_ready(paths, &profile, OwnerMaintenance::Backup)?;
    let secret = explicit_secret(paths, &profile.identity_reference)?;
    let identity = secret.public_identity(&profile.client_management_certificate_pem)?;
    let authentication = if arguments.ssh_agent {
        SshAuthentication::Agent
    } else if let Some(path) = arguments.ssh_key {
        let passphrase = prompt_secret("SSH key passphrase (leave empty if none): ")?;
        SshAuthentication::PrivateKey {
            path,
            passphrase: (!passphrase.is_empty()).then_some(passphrase),
        }
    } else {
        SshAuthentication::Password(prompt_nonempty_secret("SSH password: ")?)
    };
    let sudo_password = if arguments.username == "root" || arguments.passwordless_sudo {
        None
    } else {
        Some(prompt_nonempty_secret("sudo password: ")?)
    };
    let password =
        prompt_nonempty_secret("Server backup password (hidden, minimum 12 characters): ")?;
    let confirmation = prompt_nonempty_secret("Repeat server backup password: ")?;
    if password.as_str() != confirmation.as_str() {
        bail!("backup passwords do not match");
    }
    let outcome = Provisioner::export_server_backup(ServerBackupRequest {
        profile: profile.clone(),
        target: SshTarget {
            host: profile.endpoint.host.clone(),
            port: arguments.ssh_port,
            username: arguments.username,
            authentication,
            sudo_password,
            expected_host_key_sha256: Some(arguments.host_key),
        },
        server_binary: resolve_server_binary(arguments.server_binary)?,
        identity,
        destination: arguments.output,
        password,
    })?;
    let _ = paths
        .vps_backup_schedule_store()
        .record_success(profile.id, sirinvpn_core::unix_now());
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        println!(
            "Encrypted VPS backup created for {} with validated server artifact SHA-256 {}. No plaintext backup was written locally or remotely. Use `server restore-vps` for guarded recovery or current-device migration.",
            profile.name, outcome.artifact_sha256
        );
    }
    Ok(())
}

/// Read-only: the desktop and Android apps own the schedule, its saved SSH login and password.
pub(super) fn backup_status(paths: &ClientPaths, json: bool) -> Result<()> {
    let profiles = paths.profile_store().load()?;
    let now = sirinvpn_core::unix_now();
    let statuses: Vec<_> = paths
        .vps_backup_schedule_store()
        .load()?
        .into_iter()
        .filter_map(|schedule| {
            let profile = profiles.iter().find(|p| p.id == schedule.server_id)?;
            Some((profile.name.clone(), schedule.status(now)))
        })
        .collect();
    if json {
        let statuses: Vec<_> = statuses.into_iter().map(|(_, status)| status).collect();
        println!("{}", serde_json::to_string_pretty(&statuses)?);
        return Ok(());
    }
    if statuses.is_empty() {
        println!("No scheduled VPS backups. Turn them on in the SirinVPN app.");
    }
    for (name, status) in statuses {
        let schedule = &status.schedule;
        let last = schedule.last_success.map_or_else(
            || "no backup yet".to_owned(),
            |at| format!("last backup {} days ago", (now - at).max(0) / 86_400),
        );
        println!(
            "{name}: every {} days, keeping {} in {}; {last}.",
            schedule.interval_days, schedule.keep, schedule.folder
        );
        if let Some(failure) = &schedule.last_failure {
            println!("  The last attempt didn't finish: {}", failure.message);
        } else if status.stale {
            println!(
                "  Backups are overdue. They run while the app is open and this device is disconnected."
            );
        }
    }
    Ok(())
}

pub(super) fn restore_vps(
    paths: &ClientPaths,
    arguments: RestoreVpsArguments,
    json: bool,
) -> Result<()> {
    eprintln!(
        "Warning: restoring a server backup reinstates its private identity and saved authorization. Devices revoked after that backup may become authorized again."
    );
    if arguments.replace_existing {
        eprintln!(
            "Warning: --replace-existing destroys the destination VPS's current SirinVPN identity after the rollback guard is armed. Unrelated VPS state is not included."
        );
    }
    if !arguments.plan && !arguments.confirm_server_restore {
        bail!(
            "pass --confirm-server-restore after verifying the backup, destination, SSH fingerprint, authorization rollback risk, and any replacement choice"
        );
    }
    let profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    if !arguments.plan {
        ensure_maintenance_ready(paths, &profile, OwnerMaintenance::Restore)?;
    }
    let backup_password = prompt_nonempty_secret("Server backup password (hidden): ")?;
    let secret = explicit_secret(paths, &profile.identity_reference)?;
    let identity = secret.public_identity(&profile.client_management_certificate_pem)?;
    drop(secret);
    let authentication = if arguments.ssh_agent {
        SshAuthentication::Agent
    } else if let Some(path) = arguments.ssh_key {
        let passphrase = prompt_secret("SSH key passphrase (leave empty if none): ")?;
        SshAuthentication::PrivateKey {
            path,
            passphrase: (!passphrase.is_empty()).then_some(passphrase),
        }
    } else {
        SshAuthentication::Password(prompt_nonempty_secret("SSH password: ")?)
    };
    let sudo_password = if arguments.username == "root" || arguments.passwordless_sudo {
        None
    } else {
        Some(prompt_nonempty_secret("sudo password: ")?)
    };
    let previous_host = profile.endpoint.host.clone();
    let request = ServerRestoreRequest {
        profile,
        target: SshTarget {
            host: arguments.host,
            port: arguments.ssh_port,
            username: arguments.username,
            authentication,
            sudo_password,
            expected_host_key_sha256: Some(arguments.host_key),
        },
        server_binary: resolve_server_binary(arguments.server_binary)?,
        identity,
        source: arguments.input,
        password: backup_password,
        replace_existing_installation: arguments.replace_existing,
    };
    if arguments.plan {
        return print_plan(&Provisioner::plan_restore_server_backup(request)?, json);
    }
    let target = request.target.clone();
    let outcome =
        match Provisioner::restore_server_backup_with_journal(request, &transaction_journal(paths))
        {
            Ok(outcome) => outcome,
            Err(InstallerError::CommitUncertain { .. }) => {
                return finish_uncertain(paths, &target, "restore", json);
            }
            Err(error) => return Err(error.into()),
        };
    paths
        .profile_store()
        .upsert(outcome.profile.clone())
        .context(
            "the VPS restore committed, but the new local endpoint could not be saved; rerun the same restore with explicit destination replacement before connecting",
        )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        for event in &outcome.events {
            println!("{:?}: {}", event.phase, event.message);
        }
        println!(
            "Restored {} on {} with artifact SHA-256 {}. Server, device, and authorization identities were preserved; this device's local endpoint now targets the restored VPS.",
            outcome.profile.name, outcome.profile.endpoint.host, outcome.artifact_sha256,
        );
        if previous_host != outcome.profile.endpoint.host {
            println!(
                "The old VPS was not changed, and other devices still point to its old endpoint. Update those devices before retiring it."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SshTarget {
        SshTarget {
            host: "203.0.113.9".to_owned(),
            port: 22,
            username: "root".to_owned(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:pin".to_owned()),
        }
    }

    #[test]
    fn device_state_feeds_the_shared_rules_and_each_blocker_is_reported() {
        let ready = owner_device_state(
            ServerRole::Owner,
            &ConnectionState::Disconnected,
            false,
            false,
            false,
            false,
        );
        assert!(owner_maintenance_ready(OwnerMaintenance::Repair, &ready).is_ok());
        let busy = owner_device_state(
            ServerRole::Member,
            &ConnectionState::Connected,
            true,
            false,
            true,
            true,
        );
        let blockers = owner_maintenance_ready(OwnerMaintenance::Restore, &busy).unwrap_err();
        let report = blocker_report(&blockers);
        for blocker in &blockers {
            assert!(report.contains(blocker.message()));
        }
        assert_eq!(report.lines().count(), blockers.len());
        assert!(report.contains("resolve the interrupted VPS maintenance transaction first"));
    }

    #[test]
    fn a_backup_only_reads_so_the_kill_switch_does_not_block_it() {
        let state = owner_device_state(
            ServerRole::Owner,
            &ConnectionState::Disconnected,
            true,
            true,
            false,
            false,
        );
        assert!(owner_maintenance_ready(OwnerMaintenance::Backup, &state).is_ok());
        assert!(owner_maintenance_ready(OwnerMaintenance::Uninstall, &state).is_err());
    }

    #[test]
    fn an_uncertain_commit_with_no_journal_keeps_everything_and_asks_for_resolve() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().to_owned());
        let error = finish_uncertain(&paths, &target(), "repair", false).unwrap_err();
        assert!(error.to_string().contains("sirinvpn server resolve"));
        assert!(paths.profile_store().load().unwrap().is_empty());
    }
}
