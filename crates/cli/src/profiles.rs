//! Profiles.

use super::*;

pub(super) fn connected_identity(
    paths: &ClientPaths,
    selector: &str,
) -> Result<(ServerProfile, SecretIdentity)> {
    let profile = resolve_profile(&paths.profile_store(), selector)?;
    let local = invoke_helper("status", None)?;
    if local.server_id != Some(profile.id) || local.state == ConnectionState::Disconnected {
        bail!("connect to this server before using its private management API");
    }
    let secret = paths.secret_store().get(&profile.identity_reference)?;
    Ok((profile, secret))
}

pub(super) fn print_membership(snapshot: &MembershipSnapshot, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(snapshot)?);
        return Ok(());
    }
    for member in &snapshot.members {
        let access = match member.role {
            ServerRole::Owner => "Owner",
            ServerRole::Member if member.administrator => "Admin",
            ServerRole::Member => "Member",
        };
        println!(
            "{}  {}  {}  {}",
            member.id,
            access,
            member.name,
            if member.suspended {
                "Suspended"
            } else {
                "Active"
            }
        );
        for device in &member.devices {
            println!(
                "  {}  {}  {}  {}  identity {}",
                device.id,
                device.client_tunnel_address,
                device.name,
                if device.peer_communication_enabled {
                    "peer communication"
                } else {
                    "internet only"
                },
                if device.identity_fingerprint.is_empty() {
                    "unavailable"
                } else {
                    &device.identity_fingerprint
                }
            );
        }
    }
    if snapshot.active_invitations.is_empty() {
        println!("No active invitations.");
    } else {
        println!("Active invitations:");
        for invitation in &snapshot.active_invitations {
            println!(
                "  {}  {} / {}  expires {}",
                invitation.id,
                invitation.member_name,
                if invitation.administrator {
                    format!("{} (Admin)", invitation.device_name)
                } else {
                    invitation.device_name.clone()
                },
                invitation.expires_at_unix
            );
        }
    }
    if snapshot.port_forwards.is_empty() {
        println!("No public port forwards.");
    } else {
        println!("Public port forwards:");
        for forward in &snapshot.port_forwards {
            println!(
                "  {}/{} -> {}:{}",
                forward.protocol, forward.public_port, forward.device_id, forward.device_port
            );
        }
    }
    Ok(())
}

pub(super) fn read_invitation_code(from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        let mut value = Zeroizing::new(String::new());
        std::io::stdin()
            .take(32 * 1024 + 1)
            .read_to_string(&mut value)?;
        if value.len() > 32 * 1024 {
            bail!("the invitation code is too large");
        }
        return Ok(value);
    }
    prompt_nonempty_secret("Invitation code (hidden): ")
}

pub(super) fn read_endpoint_update_code(from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        let mut value = Zeroizing::new(String::new());
        std::io::stdin()
            .take(32 * 1024 + 1)
            .read_to_string(&mut value)?;
        if value.len() > 32 * 1024 {
            bail!("the endpoint update code is too large");
        }
        if value.trim().is_empty() {
            bail!("the endpoint update code is empty");
        }
        return Ok(value);
    }
    prompt_nonempty_secret("Signed endpoint update code (hidden): ")
}

pub(super) fn list_servers(store: &ProfileStore, json: bool) -> Result<()> {
    let profiles = store.load()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&profiles)?);
    } else if profiles.is_empty() {
        println!("No local servers. Use `sirinvpn server add` to provision one.");
    } else {
        for profile in profiles {
            println!(
                "{}  {}  {}",
                profile.id,
                profile.name,
                profile.endpoint.socket_label()
            );
        }
    }
    Ok(())
}

pub(super) fn remove_server(paths: &ClientPaths, selector: &str) -> Result<()> {
    let store = paths.profile_store();
    let profile = resolve_profile(&store, selector)?;
    if has_pending_key_rotation(paths, profile.id)? {
        bail!("complete or recover this device's pending key rotation before removing its profile");
    }
    let status = invoke_helper("status", None)
        .context("Local tunnel status could not be verified; retry before removing this profile")?;
    if status.server_id == Some(profile.id) && status.state != ConnectionState::Disconnected {
        bail!("disconnect this server before removing its local profile");
    }
    paths.secret_store().delete(&profile.identity_reference)?;
    paths.network_policy_store().forget_server(profile.id)?;
    store.remove(profile.id)?;
    println!("Removed local profile for {}.", profile.name);
    Ok(())
}

pub(super) fn export_server(
    paths: &ClientPaths,
    arguments: ExportServerArguments,
    json: bool,
) -> Result<()> {
    eprintln!(
        "Warning: this encrypted file contains the complete private identity for this device. Anyone with the file and password can use that identity until it is revoked."
    );
    if !arguments.confirm_sensitive_export {
        bail!(
            "pass --confirm-sensitive-export after choosing a strong unique password and a safe destination"
        );
    }
    let profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    let password = prompt_nonempty_secret("Backup password (hidden, minimum 12 characters): ")?;
    let confirmation = prompt_nonempty_secret("Repeat backup password: ")?;
    if password.as_str() != confirmation.as_str() {
        bail!("backup passwords do not match");
    }
    let exported = paths.export_device_backup(profile.id, &arguments.output, password.as_str())?;
    let result = BackupOperationResult {
        operation: "exported",
        server_id: exported.id,
        name: exported.name,
    };
    print_value(&result, json, "Encrypted device backup created.")
}

pub(super) fn import_server(
    paths: &ClientPaths,
    arguments: ImportServerArguments,
    json: bool,
) -> Result<()> {
    let password = prompt_nonempty_secret("Backup password (hidden): ")?;
    let imported = paths.import_device_backup(&arguments.input, password.as_str())?;
    let result = BackupOperationResult {
        operation: "imported",
        server_id: imported.id,
        name: imported.name,
    };
    print_value(
        &result,
        json,
        "Encrypted device backup restored without changing the VPS.",
    )
}
