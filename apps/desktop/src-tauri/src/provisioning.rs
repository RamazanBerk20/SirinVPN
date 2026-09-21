//! Provisioning.

use super::*;

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
    .map_err(|_| "The SSH identity check was interrupted.".to_owned())?
}

#[tauri::command]
pub(super) async fn provision_server(
    state: State<'_, AppState>,
    input: ProvisionInput,
) -> Result<ProvisionResult, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || provision_blocking(paths, input))
        .await
        .map_err(|_| "The installation worker was interrupted.".to_owned())?
}

pub(super) fn provision_blocking(
    paths: ClientPaths,
    mut input: ProvisionInput,
) -> Result<ProvisionResult, String> {
    validate_dns_upstream(&input.dns_upstream).map_err(|error| error.to_string())?;
    validate_private_dns_records(&input.private_dns_records).map_err(|error| error.to_string())?;
    let server_id = ServerId::new();
    let identity_reference = server_id.to_string();
    let identity = new_identity_for_server(&input.name).map_err(safe_error)?;
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
    let request = InstallRequest {
        server_id,
        server_name: input.name.clone(),
        target,
        server_binary: resolve_binary(
            "SIRINVPN_SERVER_BINARY",
            "/usr/lib/sirinvpn/sirinvpn-server",
            "sirinvpn-server",
        )
        .map_err(safe_error)?
        .into(),
        identity: identity.public,
        identity_reference: identity_reference.clone(),
        transport: input.transport.clone(),
        dns_upstream: input.dns_upstream.clone(),
        private_dns_records: input.private_dns_records.clone(),
        replace_existing_installation: input.replace_existing_installation,
    };
    let secrets = paths.secret_store();
    secrets
        .put(&identity_reference, &identity.secret)
        .map_err(safe_error)?;
    let outcome = match Provisioner::install(request) {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = secrets.delete(&identity_reference);
            return Err(error.to_string());
        }
    };
    paths
        .profile_store()
        .upsert(outcome.profile.clone())
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
    Ok(ProvisionResult {
        network_preflight: outcome.network_preflight,
        profile: outcome.profile,
        events: outcome.events,
        dns_upstream: outcome.dns_upstream,
        private_dns_records: outcome.private_dns_records,
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
                .ok_or_else(|| "Enter the local SSH private key path.".to_owned())?,
            passphrase: private_key_passphrase.take().map(Zeroizing::new),
        },
        _ => return Err("Select a supported SSH authentication method.".to_owned()),
    })
}

#[tauri::command]
pub(super) async fn uninstall_server(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    input: UninstallInput,
) -> Result<(), String> {
    let paths = state.paths.clone();
    let server_id = input.server_id.clone();
    tauri::async_runtime::spawn_blocking(move || uninstall_blocking(paths, input))
        .await
        .map_err(|_| "The uninstall worker was interrupted.".to_owned())??;
    crate::connection_preferences::forget(&app, &server_id)
}

pub(super) fn uninstall_blocking(
    paths: ClientPaths,
    mut input: UninstallInput,
) -> Result<(), String> {
    let id: ServerId = input
        .server_id
        .parse()
        .map_err(|_| "The local server ID is invalid.".to_owned())?;
    let status = invoke_helper("status", None).map_err(safe_error)?;
    if status.state != ConnectionState::Disconnected {
        return Err("Disconnect SirinVPN before uninstalling it from a VPS.".to_owned());
    }
    let profile = paths
        .profile_store()
        .load()
        .map_err(safe_error)?
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| "The local server profile was not found.".to_owned())?;
    if has_pending_key_rotation(&paths, id).map_err(safe_error)? {
        return Err(
            "Complete or resume this device's pending key rotation before uninstalling its VPS."
                .to_owned(),
        );
    }
    if profile.role != ServerRole::Owner {
        return Err("Only the Owner can uninstall SirinVPN from this VPS.".to_owned());
    }
    let request = UninstallRequest {
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
    };
    Provisioner::uninstall(request).map_err(|error| error.to_string())?;
    paths
        .secret_store()
        .delete(&profile.identity_reference)
        .map_err(|_| {
            "SirinVPN was removed from the VPS, but its local device key could not be deleted. Use local removal to retry cleanup."
                .to_owned()
        })?;
    paths.profile_store().remove(id).map_err(|_| {
        "SirinVPN was removed from the VPS, but its local profile could not be deleted. Use local removal to retry cleanup."
            .to_owned()
    })?;
    let _ = paths.network_policy_store().forget_server(id);
    Ok(())
}

#[tauri::command]
pub(super) async fn repair_server(
    state: State<'_, AppState>,
    input: RepairInput,
) -> Result<RepairResult, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || repair_blocking(paths, input))
        .await
        .map_err(|_| "The repair worker was interrupted.".to_owned())?
}

pub(super) fn repair_blocking(
    paths: ClientPaths,
    mut input: RepairInput,
) -> Result<RepairResult, String> {
    if !input.confirmed {
        return Err("Confirm the guarded VPS repair before continuing.".to_owned());
    }
    if let Some(dns_upstream) = &input.dns_upstream {
        validate_dns_upstream(dns_upstream).map_err(|error| error.to_string())?;
    }
    if let Some(private_dns_records) = &input.private_dns_records {
        validate_private_dns_records(private_dns_records).map_err(|error| error.to_string())?;
    }
    let status = invoke_helper("status", None).map_err(safe_error)?;
    if status.state != ConnectionState::Disconnected {
        return Err("Disconnect SirinVPN before repairing or updating its VPS.".to_owned());
    }
    let mut profile = find_profile(&paths, &input.server_id)?;
    if profile.role != ServerRole::Owner {
        return Err("Only the Owner can repair or update SirinVPN on this VPS.".to_owned());
    }
    let secret = paths
        .secret_store()
        .get(&profile.identity_reference)
        .map_err(safe_error)?;
    let identity = secret
        .public_identity(&profile.client_management_certificate_pem)
        .map_err(safe_error)?;
    let server_identity_fingerprint =
        sirinvpn_core::management_identity_fingerprint(&profile.pinned_server_certificate_pem)
            .map_err(safe_error)?;
    let outcome = Provisioner::repair(RepairRequest {
        transport: input.transport.clone(),
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
        server_binary: resolve_binary(
            "SIRINVPN_SERVER_BINARY",
            "/usr/lib/sirinvpn/sirinvpn-server",
            "sirinvpn-server",
        )
        .map_err(safe_error)?
        .into(),
        identity,
        dns_upstream: input.dns_upstream.clone(),
        private_dns_records: input.private_dns_records.clone(),
    })
    .map_err(|error| error.to_string())?;
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
        paths.profile_store().upsert(profile).map_err(|_| {
            "The VPS was repaired, but its local capabilities could not be saved. Repair again before connecting."
                .to_owned()
        })?;
    }
    Ok(RepairResult {
        network_preflight: outcome.network_preflight,
        events: outcome.events,
        artifact_sha256: outcome.artifact_sha256,
        server_identity_fingerprint,
        dns_upstream: outcome.dns_upstream,
        private_dns_records: outcome.private_dns_records,
    })
}
