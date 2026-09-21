//! Maintenance.

use super::*;

pub(super) fn uninstall_server(
    paths: &ClientPaths,
    arguments: UninstallServerArguments,
    json: bool,
) -> Result<()> {
    if !arguments.confirm_uninstall {
        bail!(
            "pass --confirm-uninstall after verifying that all current SirinVPN devices and invitations may be revoked"
        );
    }
    let store = paths.profile_store();
    let profile = resolve_profile(&store, &arguments.server)?;
    if has_pending_key_rotation(paths, profile.id)? {
        bail!("complete or recover this device's pending key rotation before uninstalling its VPS");
    }
    if profile.role != ServerRole::Owner {
        bail!("only the Owner can uninstall SirinVPN from this VPS");
    }
    let status = invoke_helper("status", None)?;
    if status.state != ConnectionState::Disconnected {
        bail!("disconnect SirinVPN before uninstalling it from a VPS");
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
    Provisioner::uninstall(UninstallRequest {
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
    })?;
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
    if !arguments.confirm_repair {
        bail!(
            "pass --confirm-repair after confirming the VPN is disconnected and the pinned SSH fingerprint belongs to this VPS"
        );
    }
    let mut profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    if profile.role != ServerRole::Owner {
        bail!("only the Owner can repair or update SirinVPN on this VPS");
    }
    let status = invoke_helper("status", None)?;
    if status.state != ConnectionState::Disconnected {
        bail!("disconnect SirinVPN before repairing or updating its VPS");
    }
    let secret = paths.secret_store().get(&profile.identity_reference)?;
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
    let outcome = Provisioner::repair(RepairRequest {
        transport,
        profile: profile.clone(),
        target: SshTarget {
            host: profile.endpoint.host.clone(),
            port: arguments.ssh_port,
            username: arguments.username,
            authentication,
            sudo_password,
            expected_host_key_sha256: Some(arguments.host_key),
        },
        server_binary: resolve_server_binary(arguments.server_binary)?.into(),
        identity,
        dns_upstream: arguments.dns.requested(),
        private_dns_records: arguments.private_dns.requested(),
    })?;
    if profile.endpoint != outcome.endpoint
        || profile.endpoint_generation != outcome.endpoint_generation
        || profile.alternate_endpoint_hosts != outcome.alternate_endpoint_hosts
        || profile.endpoint_discovery_port != outcome.endpoint_discovery_port
        || profile.ipv6_tunnel_enabled != outcome.ipv6_tunnel_enabled
        || profile.obfuscated_udp != outcome.obfuscated_udp
        || profile.tcp_fallback != outcome.tcp_fallback
        || profile.tls_like != outcome.tls_like
    {
        profile.endpoint = outcome.endpoint.clone();
        profile.endpoint_generation = outcome.endpoint_generation;
        profile.alternate_endpoint_hosts = outcome.alternate_endpoint_hosts.clone();
        profile.endpoint_discovery_port = outcome.endpoint_discovery_port;
        profile.pending_previous_endpoint = None;
        profile.pending_previous_transports = None;
        profile.ipv6_tunnel_enabled = outcome.ipv6_tunnel_enabled;
        profile.obfuscated_udp = outcome.obfuscated_udp.clone();
        profile.tcp_fallback = outcome.tcp_fallback.clone();
        profile.tls_like = outcome.tls_like.clone();
        paths.profile_store().upsert(profile.clone()).context(
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
    if profile.role != ServerRole::Owner {
        bail!("only the Owner can back up SirinVPN state from this VPS");
    }
    if has_pending_key_rotation(paths, profile.id)? {
        bail!("complete or recover this device's pending key rotation before backing up its VPS");
    }
    let status = invoke_helper("status", None)?;
    if status.state != ConnectionState::Disconnected {
        bail!("disconnect SirinVPN before backing up its VPS over SSH");
    }
    let secret = paths.secret_store().get(&profile.identity_reference)?;
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
        server_binary: resolve_server_binary(arguments.server_binary)?.into(),
        identity,
        destination: arguments.output,
        password,
    })?;
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
    if !arguments.confirm_server_restore {
        bail!(
            "pass --confirm-server-restore after verifying the backup, destination, SSH fingerprint, authorization rollback risk, and any replacement choice"
        );
    }
    let profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    if profile.role != ServerRole::Owner {
        bail!("only the Owner can restore this server identity onto a VPS");
    }
    if has_pending_key_rotation(paths, profile.id)? {
        bail!("complete or recover this device's pending key rotation before restoring its VPS");
    }
    let status = invoke_helper("status", None)?;
    if status.state != ConnectionState::Disconnected {
        bail!("disconnect SirinVPN before restoring a VPS over SSH");
    }
    let backup_password = prompt_nonempty_secret("Server backup password (hidden): ")?;
    let secret = paths.secret_store().get(&profile.identity_reference)?;
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
    let outcome = Provisioner::restore_server_backup(ServerRestoreRequest {
        profile,
        target: SshTarget {
            host: arguments.host,
            port: arguments.ssh_port,
            username: arguments.username,
            authentication,
            sudo_password,
            expected_host_key_sha256: Some(arguments.host_key),
        },
        server_binary: resolve_server_binary(arguments.server_binary)?.into(),
        identity,
        source: arguments.input,
        password: backup_password,
        replace_existing_installation: arguments.replace_existing,
    })?;
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
