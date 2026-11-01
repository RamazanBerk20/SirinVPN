//! Owner-chosen schedule for encrypted VPS backups. Keeps one current status per
//! server (last success, last failure), never a run history.
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sirinvpn_protocol::ServerId;
use std::{
    fs, io,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const SCHEMA_VERSION: u16 = 1;
const MAX_DOCUMENT_BYTES: u64 = 256 * 1024;
const MAX_FOLDER_BYTES: usize = 4096;
const MAX_FAILURE_BYTES: usize = 512;
const DAY: i64 = 86_400;
const FILE_PREFIX: &str = "sirinvpn-vps-";
const FILE_SUFFIX: &str = ".sirinvpn-server-backup";
/// An automatic attempt that failed waits this long before the next one.
pub const VPS_BACKUP_RETRY_SECONDS: i64 = 3_600;
pub const MAX_VPS_BACKUPS_KEPT: u8 = 30;
pub const MAX_VPS_BACKUP_INTERVAL_DAYS: u8 = 30;

#[derive(Debug, Error)]
pub enum VpsBackupScheduleError {
    #[error("choose a backup folder, keep 1–30 backups and run every 1–30 days")]
    InvalidSettings,
    #[error("the VPS backup schedule file is invalid")]
    InvalidData,
    #[error("the VPS backup schedule file operation failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VpsBackupSchedule {
    pub server_id: ServerId,
    /// A local directory, or an Android document-tree URI.
    pub folder: String,
    pub keep: u8,
    pub interval_days: u8,
    /// UTC seconds when the schedule was turned on; the stale clock starts here.
    pub enabled_at: i64,
    pub last_success: Option<i64>,
    pub last_failure: Option<VpsBackupFailure>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VpsBackupFailure {
    pub at: i64,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VpsBackupScheduleStatus {
    #[serde(flatten)]
    pub schedule: VpsBackupSchedule,
    pub due: bool,
    pub stale: bool,
}

impl VpsBackupSchedule {
    pub fn due(&self, now: i64) -> bool {
        let interval = i64::from(self.interval_days) * DAY;
        self.last_success
            .is_none_or(|at| now >= at.saturating_add(interval))
            && self
                .last_failure
                .as_ref()
                .is_none_or(|failure| now >= failure.at.saturating_add(VPS_BACKUP_RETRY_SECONDS))
    }

    /// One missed interval plus a day of grace. Failures are reported on their own.
    pub fn stale(&self, now: i64) -> bool {
        let since = self.last_success.unwrap_or(self.enabled_at);
        now > since.saturating_add((i64::from(self.interval_days) + 1) * DAY)
    }

    pub fn status(self, now: i64) -> VpsBackupScheduleStatus {
        VpsBackupScheduleStatus {
            due: self.due(now),
            stale: self.stale(now),
            schedule: self,
        }
    }

    fn valid(&self) -> bool {
        valid_settings(&self.folder, self.keep, self.interval_days)
            && self
                .last_failure
                .as_ref()
                .is_none_or(|failure| failure.message.len() <= MAX_FAILURE_BYTES)
    }
}

fn valid_settings(folder: &str, keep: u8, interval_days: u8) -> bool {
    !folder.trim().is_empty()
        && folder.len() <= MAX_FOLDER_BYTES
        && !folder.chars().any(char::is_control)
        && (1..=MAX_VPS_BACKUPS_KEPT).contains(&keep)
        && (1..=MAX_VPS_BACKUP_INTERVAL_DAYS).contains(&interval_days)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u16,
    schedules: Vec<VpsBackupSchedule>,
}

pub struct VpsBackupScheduleStore {
    path: PathBuf,
}

impl VpsBackupScheduleStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load(&self) -> Result<Vec<VpsBackupSchedule>, VpsBackupScheduleError> {
        let file = match sirinvpn_platform::files::open_no_follow(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
            return Err(VpsBackupScheduleError::InvalidData);
        }
        let document: Document =
            serde_json::from_slice(&bytes).map_err(|_| VpsBackupScheduleError::InvalidData)?;
        if document.schema_version != SCHEMA_VERSION
            || !document.schedules.iter().all(VpsBackupSchedule::valid)
        {
            return Err(VpsBackupScheduleError::InvalidData);
        }
        Ok(document.schedules)
    }

    pub fn get(&self, id: ServerId) -> Result<Option<VpsBackupSchedule>, VpsBackupScheduleError> {
        Ok(self.load()?.into_iter().find(|item| item.server_id == id))
    }

    /// Turns the schedule on or changes it, keeping the current backup status.
    pub fn set(
        &self,
        id: ServerId,
        folder: String,
        keep: u8,
        interval_days: u8,
        now: i64,
    ) -> Result<VpsBackupSchedule, VpsBackupScheduleError> {
        if !valid_settings(&folder, keep, interval_days) {
            return Err(VpsBackupScheduleError::InvalidSettings);
        }
        self.mutate(|schedules| {
            if let Some(existing) = schedules.iter_mut().find(|item| item.server_id == id) {
                existing.folder = folder;
                existing.keep = keep;
                existing.interval_days = interval_days;
                return existing.clone();
            }
            let schedule = VpsBackupSchedule {
                server_id: id,
                folder,
                keep,
                interval_days,
                enabled_at: now,
                last_success: None,
                last_failure: None,
            };
            schedules.push(schedule.clone());
            schedule
        })
    }

    pub fn forget(&self, id: ServerId) -> Result<(), VpsBackupScheduleError> {
        if !self.path.exists() {
            return Ok(());
        }
        self.mutate(|schedules| schedules.retain(|item| item.server_id != id))
    }

    /// Any successful VPS backup from this device resets the clock, but only a
    /// server with a schedule keeps a status.
    pub fn record_success(&self, id: ServerId, now: i64) -> Result<(), VpsBackupScheduleError> {
        self.update(id, |schedule| {
            schedule.last_success = Some(now);
            schedule.last_failure = None;
        })
    }

    pub fn record_failure(
        &self,
        id: ServerId,
        now: i64,
        message: &str,
    ) -> Result<(), VpsBackupScheduleError> {
        let mut message = message.trim().to_owned();
        if message.len() > MAX_FAILURE_BYTES {
            let mut end = MAX_FAILURE_BYTES;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        self.update(id, |schedule| {
            schedule.last_failure = Some(VpsBackupFailure { at: now, message });
        })
    }

    fn update(
        &self,
        id: ServerId,
        change: impl FnOnce(&mut VpsBackupSchedule),
    ) -> Result<(), VpsBackupScheduleError> {
        if !self.path.exists() {
            return Ok(());
        }
        self.mutate(|schedules| {
            if let Some(schedule) = schedules.iter_mut().find(|item| item.server_id == id) {
                change(schedule);
            }
        })
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(&mut Vec<VpsBackupSchedule>) -> T,
    ) -> Result<T, VpsBackupScheduleError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent"))?;
        sirinvpn_platform::files::create_private_directory(parent)?;
        let lock = sirinvpn_platform::files::open_private_lock(&self.path.with_extension("lock"))?;
        lock.lock_exclusive()?;
        let mut schedules = self.load()?;
        let result = operation(&mut schedules);
        let bytes = serde_json::to_vec_pretty(&Document {
            schema_version: SCHEMA_VERSION,
            schedules,
        })
        .map_err(|_| VpsBackupScheduleError::InvalidData)?;
        sirinvpn_platform::files::atomic_write(&self.path, &bytes, true)?;
        FileExt::unlock(&lock)?;
        Ok(result)
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

/// `sirinvpn-vps-<server id>-<UTC YYYYMMDDTHHMMSSZ>.sirinvpn-server-backup`; the
/// fixed-width stamp sorts by name.
pub fn vps_backup_file_name(id: ServerId, now: i64) -> String {
    format!("{FILE_PREFIX}{id}-{}{FILE_SUFFIX}", utc_stamp(now))
}

/// This server's scheduled backups beyond the newest `keep`. Other files never match.
pub fn expired_vps_backups<'a>(
    id: ServerId,
    names: impl IntoIterator<Item = &'a str>,
    keep: u8,
) -> Vec<&'a str> {
    let prefix = format!("{FILE_PREFIX}{id}-");
    let mut ours: Vec<&str> = names
        .into_iter()
        .filter(|name| {
            name.strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(FILE_SUFFIX))
                .is_some_and(valid_stamp)
        })
        .collect();
    ours.sort_unstable_by(|a, b| b.cmp(a));
    ours.into_iter().skip(keep.into()).collect()
}

/// Deletes this server's regular-file backups beyond the newest `keep`.
pub fn rotate_vps_backup_folder(folder: &Path, id: ServerId, keep: u8) -> io::Result<usize> {
    let mut names = Vec::new();
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        // DirEntry::file_type does not follow symbolic links.
        if entry.file_type()?.is_file()
            && let Ok(name) = entry.file_name().into_string()
        {
            names.push(name);
        }
    }
    let expired = expired_vps_backups(id, names.iter().map(String::as_str), keep);
    for name in &expired {
        fs::remove_file(folder.join(name))?;
    }
    Ok(expired.len())
}

fn valid_stamp(stamp: &str) -> bool {
    let bytes = stamp.as_bytes();
    bytes.len() == 16
        && bytes[8] == b'T'
        && bytes[15] == b'Z'
        && bytes[..8]
            .iter()
            .chain(&bytes[9..15])
            .all(u8::is_ascii_digit)
}

fn utc_stamp(seconds: i64) -> String {
    // Howard Hinnant's days-to-civil conversion for the proleptic Gregorian calendar.
    let (days, time) = (seconds.div_euclid(DAY), seconds.rem_euclid(DAY));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        time / 3_600,
        time % 3_600 / 60,
        time % 60
    )
}

#[cfg(test)]
mod tests;
