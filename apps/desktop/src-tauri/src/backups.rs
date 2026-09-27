//! Backups.

use super::*;

#[tauri::command]
pub(super) async fn remove_server(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    server_id: String,
) -> Result<(), String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || remove_server_blocking(&app, &paths, &server_id))
        .await.map_err(|_| "The profile cleanup worker was interrupted.".to_owned())?
}

fn remove_server_blocking(app: &tauri::AppHandle, paths: &ClientPaths, server_id: &str) -> Result<(), String> {
    let _operation = crate::connection_controller::acquire()?;
    let id: ServerId = server_id
        .parse()
        .map_err(|_| "The local server ID is invalid.".to_owned())?;
    if has_pending_key_rotation(paths, id).map_err(safe_error)? {
        return Err(
            "Complete or resume this device's pending key rotation before removing its profile."
                .to_owned(),
        );
    }
    let status = invoke_helper("status", None).map_err(|_| "Local tunnel status could not be verified. Refresh status before removing this profile.".to_owned())?;
    if status.server_id == Some(id) {
        return Err("Disconnect this server before removing its local profile.".to_owned());
    }
    let profiles = paths.profile_store().load().map_err(safe_error)?;
    let profile = profiles
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| "The local server profile was not found.".to_owned())?;
    crate::connection_preferences::forget(app, server_id)?;
    paths
        .secret_store()
        .delete(&profile.identity_reference)
        .map_err(safe_error)?;
    paths.network_policy_store().forget_server(id).map_err(safe_error)?;
    paths.profile_store().remove(id).map_err(safe_error)?;
    Ok(())
}

#[tauri::command]
pub(super) async fn export_server_backup(
    state: State<'_, AppState>,
    input: BackupExportInput,
) -> Result<(), String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || export_backup_blocking(paths, input))
        .await
        .map_err(|_| "The backup worker was interrupted.".to_owned())?
}

pub(super) fn export_backup_blocking(
    paths: ClientPaths,
    input: BackupExportInput,
) -> Result<(), String> {
    if !input.confirmed {
        return Err("Confirm the sensitive identity export before continuing.".to_owned());
    }
    let server_id = input
        .server_id
        .parse::<ServerId>()
        .map_err(|_| "The local server ID is invalid.".to_owned())?;
    if input.path.trim().is_empty() {
        return Err("Choose where to save the encrypted backup.".to_owned());
    }
    paths
        .export_device_backup(server_id, Path::new(&input.path), &input.password)
        .map(|_| ())
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn import_server_backup(
    state: State<'_, AppState>,
    input: BackupImportInput,
) -> Result<ServerProfile, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || import_backup_blocking(paths, input))
        .await
        .map_err(|_| "The backup worker was interrupted.".to_owned())?
}

pub(super) fn import_backup_blocking(
    paths: ClientPaths,
    input: BackupImportInput,
) -> Result<ServerProfile, String> {
    if input.path.trim().is_empty() {
        return Err("Choose an encrypted SirinVPN backup.".to_owned());
    }
    paths
        .import_device_backup(Path::new(&input.path), &input.password)
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn export_vps_backup(
    state: State<'_, AppState>,
    input: VpsBackupInput,
) -> Result<ServerBackupOutcome, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || export_vps_backup_blocking(paths, input))
        .await
        .map_err(|_| "The VPS backup worker was interrupted.".to_owned())?
}

pub(super) fn export_vps_backup_blocking(
    paths: ClientPaths,
    mut input: VpsBackupInput,
) -> Result<ServerBackupOutcome, String> {
    if !input.confirmed {
        return Err("Confirm the sensitive VPS-state export before continuing.".to_owned());
    }
    if input.path.trim().is_empty() {
        return Err("Choose where to save the encrypted VPS backup.".to_owned());
    }
    let status = invoke_helper("status", None).map_err(safe_error)?;
    if status.state != ConnectionState::Disconnected {
        return Err("Disconnect SirinVPN before backing up its VPS over SSH.".to_owned());
    }
    let profile = find_profile(&paths, &input.server_id)?;
    if profile.role != ServerRole::Owner {
        return Err("Only the Owner can back up SirinVPN state from this VPS.".to_owned());
    }
    if has_pending_key_rotation(&paths, profile.id).map_err(safe_error)? {
        return Err(
            "Complete or resume this device's pending key rotation before backing up its VPS."
                .to_owned(),
        );
    }
    let secret = paths
        .secret_store()
        .get(&profile.identity_reference)
        .map_err(safe_error)?;
    let identity = secret
        .public_identity(&profile.client_management_certificate_pem)
        .map_err(safe_error)?;
    let request = ServerBackupRequest {
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
        destination: PathBuf::from(&input.path),
        password: Zeroizing::new(std::mem::take(&mut input.backup_password)),
    };
    Provisioner::export_server_backup(request).map_err(|error| error.to_string())
}

#[tauri::command]
pub(super) async fn restore_vps_backup(
    state: State<'_, AppState>,
    input: VpsRestoreInput,
) -> Result<ServerRestoreOutcome, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || restore_vps_backup_blocking(paths, input))
        .await
        .map_err(|_| "The VPS restore worker was interrupted.".to_owned())?
}

pub(super) fn restore_vps_backup_blocking(
    paths: ClientPaths,
    mut input: VpsRestoreInput,
) -> Result<ServerRestoreOutcome, String> {
    if !input.confirmed {
        return Err("Confirm the VPS restore risks before continuing.".to_owned());
    }
    if input.path.trim().is_empty() || input.host.trim().is_empty() {
        return Err("Choose an encrypted VPS backup and destination host.".to_owned());
    }
    let status = invoke_helper("status", None).map_err(safe_error)?;
    if status.state != ConnectionState::Disconnected {
        return Err("Disconnect SirinVPN before restoring a VPS over SSH.".to_owned());
    }
    let profile = find_profile(&paths, &input.server_id)?;
    if profile.role != ServerRole::Owner {
        return Err("Only the Owner can restore this server identity onto a VPS.".to_owned());
    }
    if has_pending_key_rotation(&paths, profile.id).map_err(safe_error)? {
        return Err(
            "Complete or resume this device's pending key rotation before restoring its VPS."
                .to_owned(),
        );
    }
    let secret = paths
        .secret_store()
        .get(&profile.identity_reference)
        .map_err(safe_error)?;
    let identity = secret
        .public_identity(&profile.client_management_certificate_pem)
        .map_err(safe_error)?;
    drop(secret);
    let outcome = Provisioner::restore_server_backup(ServerRestoreRequest {
        profile,
        target: crate::ssh_login::resolve_target(crate::ssh_login::SshLoginInput {
            host: input.host.trim().to_owned(),
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
        source: PathBuf::from(&input.path),
        password: Zeroizing::new(std::mem::take(&mut input.backup_password)),
        replace_existing_installation: input.replace_existing,
    })
    .map_err(|error| error.to_string())?;
    paths
        .profile_store()
        .upsert(outcome.profile.clone())
        .map_err(|_| {
            "The VPS restore committed, but the new local endpoint could not be saved. Repeat the same restore with explicit destination replacement before connecting."
                .to_owned()
        })?;
    Ok(outcome)
}
