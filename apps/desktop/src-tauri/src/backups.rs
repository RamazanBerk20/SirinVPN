//! Backups.

use super::*;
use crate::picked_files::Purpose;
use sirinvpn_installer::OwnerMaintenance;

#[tauri::command]
pub(super) async fn remove_server(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    server_id: String,
) -> Result<(), String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || remove_server_blocking(&app, &paths, &server_id))
        .await.map_err(|_| "Removing the server from this device was interrupted.".to_owned())?
}

fn remove_server_blocking(app: &tauri::AppHandle, paths: &ClientPaths, server_id: &str) -> Result<(), String> {
    let _operation = crate::connection_controller::acquire()?;
    let id: ServerId = server_id
        .parse()
        .map_err(|_| "The local server ID is invalid.".to_owned())?;
    if has_pending_key_rotation(paths, id).map_err(safe_error)? {
        return Err(
            "Finish this device’s key rotation before removing this server."
                .to_owned(),
        );
    }
    let status = invoke_helper("status", None).map_err(|_| "Couldn’t check the VPN status. Refresh, then try removing the server again.".to_owned())?;
    if status.server_id == Some(id) {
        return Err("Disconnect from this server before removing it.".to_owned());
    }
    let profiles = paths.profile_store().load().map_err(safe_error)?;
    let profile = profiles
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| "This server is no longer saved on this device.".to_owned())?;
    crate::connection_preferences::forget(app, server_id)?;
    paths
        .secret_store()
        .delete(&profile.identity_reference)
        .map_err(safe_error)?;
    paths.network_policy_store().forget_server(id).map_err(safe_error)?;
    paths.profile_store().remove(id).map_err(safe_error)?;
    // A locked store leaves the schedule for the next listing to clean up.
    let _ = crate::vps_backup_schedule::forget(paths, id);
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
        .map_err(|_| "Saving the backup was interrupted.".to_owned())?
}

pub(super) fn export_backup_blocking(
    paths: ClientPaths,
    input: BackupExportInput,
) -> Result<(), String> {
    if !input.confirmed {
        return Err("Confirm the sensitive backup export first.".to_owned());
    }
    let server_id = input
        .server_id
        .parse::<ServerId>()
        .map_err(|_| "The local server ID is invalid.".to_owned())?;
    if input.path.trim().is_empty() {
        return Err("Choose where to save the encrypted backup.".to_owned());
    }
    let destination = crate::picked_files::granted(Purpose::BackupExport, &input.path)?;
    paths
        .export_device_backup(server_id, &destination, &input.password)
        .map_err(safe_error)?;
    crate::picked_files::release(Purpose::BackupExport, &input.path);
    Ok(())
}

#[tauri::command]
pub(super) async fn import_server_backup(
    state: State<'_, AppState>,
    input: BackupImportInput,
) -> Result<ServerProfile, CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || import_backup_blocking(paths, input))
        .await
        .map_err(|_| CommandError::from("Restoring the backup was interrupted."))?
}

pub(super) fn import_backup_blocking(
    paths: ClientPaths,
    input: BackupImportInput,
) -> Result<ServerProfile, CommandError> {
    if input.path.trim().is_empty() {
        return Err("Choose an encrypted SirinVPN backup.".into());
    }
    let source = crate::picked_files::granted(Purpose::BackupImport, &input.path)?;
    paths
        .import_device_backup(&source, &input.password)
        .map_err(command_error)
}

#[tauri::command]
pub(super) async fn export_vps_backup(
    state: State<'_, AppState>,
    input: VpsBackupInput,
) -> Result<ServerBackupOutcome, CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || export_vps_backup_blocking(paths, input))
        .await
        .map_err(|_| CommandError::from("The VPS backup was interrupted."))?
}

pub(super) fn export_vps_backup_blocking(
    paths: ClientPaths,
    mut input: VpsBackupInput,
) -> Result<ServerBackupOutcome, CommandError> {
    if !input.confirmed {
        return Err("Confirm the sensitive VPS backup first.".into());
    }
    if input.path.trim().is_empty() {
        return Err("Choose where to save the encrypted VPS backup.".into());
    }
    let destination = crate::picked_files::granted(Purpose::VpsBackupExport, &input.path)?;
    let login = crate::ssh_login::SshLoginInput {
        host: String::new(),
        ssh_port: input.ssh_port,
        username: input.username.clone(),
        authentication: input.authentication.clone(),
        password: input.password.take(),
        private_key_path: input.private_key_path.take(),
        private_key_passphrase: input.private_key_passphrase.take(),
        sudo_password: input.sudo_password.take(),
        host_key_sha256: input.host_key_sha256.clone(),
    };
    let outcome = export_vps_backup_to(
        &paths,
        &input.server_id,
        true,
        |profile| {
            let mut login = login;
            login.host = profile.endpoint.host.clone();
            crate::ssh_login::resolve_target(login)
        },
        destination,
        Zeroizing::new(std::mem::take(&mut input.backup_password)),
    )?;
    crate::picked_files::release(Purpose::VpsBackupExport, &input.path);
    Ok(outcome)
}

/// Shared by the manual dialog and scheduled backups. Only `interactive` work
/// may show a keyring unlock prompt.
pub(super) fn export_vps_backup_to(
    paths: &ClientPaths,
    server_id: &str,
    interactive: bool,
    target: impl FnOnce(&ServerProfile) -> Result<SshTarget, String>,
    destination: PathBuf,
    password: Zeroizing<String>,
) -> Result<ServerBackupOutcome, CommandError> {
    let profile = find_profile(paths, server_id)?;
    crate::vps_transaction::ensure_owner_maintenance_ready(paths, &profile, OwnerMaintenance::Backup)?;
    let secret = if interactive {
        explicit_secret(paths, &profile.identity_reference)?
    } else {
        paths.secret_store().get(&profile.identity_reference).map_err(safe_error)?
    };
    let identity = secret
        .public_identity(&profile.client_management_certificate_pem)
        .map_err(safe_error)?;
    let request = ServerBackupRequest {
        profile: profile.clone(),
        target: target(&profile)?,
        server_binary: crate::vps_transaction::server_payload()?,
        identity,
        destination,
        password,
    };
    let outcome = Provisioner::export_server_backup(request).map_err(command_error)?;
    let _ = paths
        .vps_backup_schedule_store()
        .record_success(profile.id, sirinvpn_core::unix_now());
    Ok(outcome)
}

#[tauri::command]
pub(super) async fn restore_vps_backup(
    state: State<'_, AppState>,
    input: VpsRestoreInput,
) -> Result<serde_json::Value, CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || restore_vps_backup_blocking(paths, input))
        .await
        .map_err(|_| CommandError::from("The VPS restore was interrupted."))?
}

pub(super) fn restore_vps_backup_blocking(
    paths: ClientPaths,
    mut input: VpsRestoreInput,
) -> Result<serde_json::Value, CommandError> {
    if !input.confirmed {
        return Err("Confirm the restore risks first.".into());
    }
    let profile = find_profile(&paths, &input.server_id)?;
    crate::vps_transaction::ensure_owner_maintenance_ready(&paths, &profile, OwnerMaintenance::Restore)?;
    let request = crate::vps_transaction::restore_request(&paths, &mut input, profile)?;
    crate::vps_transaction::restore_server(&paths, request)
}
