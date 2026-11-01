//! Scheduled encrypted VPS backups. The frontend asks for due runs while the
//! device is disconnected; the backup password stays in the OS credential store.
use super::*;
use sirinvpn_core::{
    VpsBackupScheduleStatus, rotate_vps_backup_folder, unix_now, validate_server_backup_password,
    vps_backup_file_name,
};

const SERVICE: &str = "org.sirinvpn.client.vps-backup";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VpsBackupScheduleInput {
    server_id: String,
    folder: String,
    keep: u8,
    interval_days: u8,
    /// Omitted when changing a schedule whose password is already saved.
    backup_password: Option<String>,
}

impl Drop for VpsBackupScheduleInput {
    fn drop(&mut self) {
        if let Some(value) = &mut self.backup_password {
            value.zeroize();
        }
    }
}

fn password_entry(id: ServerId, prompt: bool) -> Result<keyring::Entry, String> {
    crate::ssh_login::credential(SERVICE, id.to_string(), prompt)
}

fn saved_password(id: ServerId, prompt: bool) -> Result<Zeroizing<String>, String> {
    match password_entry(id, prompt)?.get_secret() {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Zeroizing::new)
            .map_err(|_| "The saved backup password is invalid. Enter it again.".to_owned()),
        Err(keyring::Error::NoEntry) => {
            Err("The backup password is no longer saved. Enter it again.".to_owned())
        }
        Err(_) => Err("Unlock secure storage so the scheduled VPS backup can run.".to_owned()),
    }
}

/// Removing a server also removes its schedule and saved backup password. The
/// password goes first, so a locked store leaves the schedule to retry later.
pub(super) fn forget(paths: &ClientPaths, id: ServerId) -> Result<(), String> {
    forget_with(paths, id, true)
}

fn forget_with(paths: &ClientPaths, id: ServerId, prompt: bool) -> Result<(), String> {
    match password_entry(id, prompt)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(_) => {
            return Err(
                "Couldn’t remove the saved backup password. Unlock secure storage and try again."
                    .into(),
            );
        }
    }
    paths
        .vps_backup_schedule_store()
        .forget(id)
        .map_err(safe_error)
}

fn owner(paths: &ClientPaths, server_id: &str) -> Result<ServerProfile, String> {
    let profile = find_profile(paths, server_id)?;
    if profile.role != ServerRole::Owner {
        return Err("Only the Owner can back up this VPS.".to_owned());
    }
    Ok(profile)
}

fn statuses_blocking(paths: &ClientPaths) -> Result<Vec<VpsBackupScheduleStatus>, String> {
    let profiles = paths.profile_store().load().map_err(safe_error)?;
    let now = unix_now();
    let (current, removed): (Vec<_>, Vec<_>) = paths
        .vps_backup_schedule_store()
        .load()
        .map_err(safe_error)?
        .into_iter()
        .partition(|schedule| profiles.iter().any(|profile| profile.id == schedule.server_id));
    // A server removed by the CLI, or whose cleanup failed, leaves its schedule.
    for schedule in removed {
        let _ = forget_with(paths, schedule.server_id, false);
    }
    Ok(current.into_iter().map(|schedule| schedule.status(now)).collect())
}

fn set_blocking(
    paths: &ClientPaths,
    mut input: VpsBackupScheduleInput,
) -> Result<VpsBackupScheduleStatus, String> {
    let profile = owner(paths, &input.server_id)?;
    let folder = Path::new(&input.folder);
    if !folder.is_absolute() || !folder.is_dir() {
        return Err("Choose an existing folder for the VPS backups.".to_owned());
    }
    match input.backup_password.take().map(Zeroizing::new) {
        Some(password) => {
            validate_server_backup_password(&password).map_err(safe_error)?;
            password_entry(profile.id, true)?
                .set_secret(password.as_bytes())
                .map_err(|_| {
                    "Couldn’t save the backup password. Unlock secure storage and try again."
                        .to_owned()
                })?;
        }
        None => drop(saved_password(profile.id, true)?),
    }
    paths
        .vps_backup_schedule_store()
        .set(
            profile.id,
            std::mem::take(&mut input.folder),
            input.keep,
            input.interval_days,
            unix_now(),
        )
        .map(|schedule| schedule.status(unix_now()))
        .map_err(safe_error)
}

fn run_blocking(
    paths: &ClientPaths,
    server_id: &str,
    interactive: bool,
) -> Result<VpsBackupScheduleStatus, String> {
    let profile = owner(paths, server_id)?;
    let store = paths.vps_backup_schedule_store();
    let schedule = store
        .get(profile.id)
        .map_err(safe_error)?
        .ok_or("Turn on scheduled backups for this VPS first.")?;
    // Not a failure: the run waits until this device is disconnected.
    let status = invoke_helper("status", None).map_err(safe_error)?;
    if status.state != ConnectionState::Disconnected {
        return Err("Scheduled VPS backups run while this device is disconnected.".to_owned());
    }
    let folder = PathBuf::from(&schedule.folder);
    let result = (|| {
        if !folder.is_dir() {
            return Err("The backup folder isn’t available. Connect its drive or choose another folder.".to_owned());
        }
        let password = saved_password(profile.id, interactive)?;
        export_vps_backup_to(
            paths,
            server_id,
            interactive,
            |profile| crate::ssh_login::saved_login_target(&profile.endpoint.host, interactive),
            folder.join(vps_backup_file_name(profile.id, unix_now())),
            password,
        )?;
        rotate_vps_backup_folder(&folder, profile.id, schedule.keep).map_err(|_| {
            "The backup was saved, but older backups couldn’t be removed from the folder."
                .to_owned()
        })
    })();
    if let Err(message) = &result {
        store
            .record_failure(profile.id, unix_now(), message)
            .map_err(safe_error)?;
    }
    store
        .get(profile.id)
        .map_err(safe_error)?
        .map(|schedule| schedule.status(unix_now()))
        .ok_or_else(|| "Turn on scheduled backups for this VPS first.".to_owned())
}

#[tauri::command]
pub(super) async fn vps_backup_schedules(
    state: State<'_, AppState>,
) -> Result<Vec<VpsBackupScheduleStatus>, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || statuses_blocking(&paths))
        .await
        .map_err(|_| "Reading the VPS backup schedule was interrupted.".to_owned())?
}

#[tauri::command]
pub(super) async fn set_vps_backup_schedule(
    state: State<'_, AppState>,
    input: VpsBackupScheduleInput,
) -> Result<VpsBackupScheduleStatus, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || set_blocking(&paths, input))
        .await
        .map_err(|_| "Saving the VPS backup schedule was interrupted.".to_owned())?
}

#[tauri::command]
pub(super) async fn disable_vps_backup_schedule(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<(), String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        forget(&paths, owner(&paths, &server_id)?.id)
    })
    .await
    .map_err(|_| "Turning off scheduled backups was interrupted.".to_owned())?
}

/// `interactive` is true only for an explicit “Back up now”.
#[tauri::command]
pub(super) async fn run_scheduled_vps_backup(
    state: State<'_, AppState>,
    server_id: String,
    interactive: bool,
) -> Result<VpsBackupScheduleStatus, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || run_blocking(&paths, &server_id, interactive))
        .await
        .map_err(|_| "The scheduled VPS backup was interrupted.".to_owned())?
}
