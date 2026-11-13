//! One visible-interface status producer. Native VPN lifetime is independent.
//!
//! Readings are pushed: a native watcher (inotify on the Linux helper's runtime state,
//! the Windows service's long-poll) and our own operations (`changed`) wake the worker.
//! A slow timer remains only for byte counters and for when no watcher is available.
use serde::Serialize;
use sirinvpn_tunnel_model::{LocalTunnelStatus, TunnelPhase};
use std::{
    collections::HashMap,
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tauri::Manager;
use tauri::ipc::Channel;

/// What the stream can vouch for, sent with every event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StreamState {
    /// No reading yet; never sent.
    Starting,
    /// `status` is this reading.
    Live,
    /// The last read failed; `status` repeats the previous good reading.
    Stale,
    /// No reading has succeeded since the stream started; `status` is null.
    Unavailable,
}

impl StreamState {
    /// The only transition: one read attempt, successful or not.
    fn next(self, read: bool) -> Self {
        match (self, read) {
            (_, true) => Self::Live,
            (Self::Live | Self::Stale, false) => Self::Stale,
            (Self::Starting | Self::Unavailable, false) => Self::Unavailable,
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct LocalStatusEvent {
    status: Option<serde_json::Value>,
    stream: StreamState,
    sequence: u64,
    generation: u64,
    phase: String,
    stale: bool,
}
#[derive(Default)]
struct Hub {
    listeners: HashMap<String, Channel<LocalStatusEvent>>,
    worker: Option<tauri::async_runtime::JoinHandle<()>>,
    last: Option<LocalStatusEvent>,
}
static HUB: LazyLock<Mutex<Hub>> = LazyLock::new(|| Mutex::new(Hub::default()));
static CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();
/// Process-wide and seeded from the start time, as on Android, so a restarted worker
/// or a reloaded page never sees a sequence or generation number again.
static SEQUENCE: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(started_ms()));
static GENERATION: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(started_ms()));
/// True while a native watcher reports changes; the fallback timer is then slow.
static WATCHING: AtomicBool = AtomicBool::new(false);

fn started_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis().try_into().unwrap_or(u64::MAX))
}

pub(crate) fn changed() {
    CHANGED.notify_one();
}

pub(crate) fn watching() -> bool {
    WATCHING.load(Ordering::Acquire)
}

/// How long to wait for a reading nobody announced. Counters and handshake age change
/// without a file or service publication; an idle or paused tunnel has neither.
fn fallback_interval(phase: Option<TunnelPhase>, watching: bool) -> Duration {
    let settled = matches!(phase, Some(TunnelPhase::Idle | TunnelPhase::Paused { .. }));
    let starting = matches!(
        phase,
        None | Some(
            TunnelPhase::Connecting { .. }
                | TunnelPhase::Recovering { .. }
                | TunnelPhase::Unhealthy { recovering: true, .. }
        )
    );
    Duration::from_secs(match (watching, settled, starting) {
        (true, true, _) => 10,
        (true, false, _) => 2,
        (false, _, true) => 1,
        (false, _, false) => 2,
    })
}

#[tauri::command]
pub(crate) fn subscribe_local_status(
    app: tauri::AppHandle,
    subscription_id: String,
    on_event: Channel<LocalStatusEvent>,
) -> Result<(), String> {
    let mut hub = HUB.lock().unwrap_or_else(|error| error.into_inner());
    if subscription_id.len() > 128 || hub.listeners.len() >= 8 {
        return Err("Too many local status subscriptions.".into());
    }
    // Revalidate on subscription. A previous window's last reading is not live.
    hub.listeners.insert(subscription_id, on_event);
    if hub.worker.is_none() {
        hub.worker = Some(tauri::async_runtime::spawn(produce(app)));
    }
    changed();
    Ok(())
}

#[tauri::command]
pub(crate) fn unsubscribe_local_status(subscription_id: String) {
    let mut hub = HUB.lock().unwrap_or_else(|error| error.into_inner());
    hub.listeners.remove(&subscription_id);
    if hub.listeners.is_empty() {
        if let Some(worker) = hub.worker.take() {
            worker.abort();
        }
        hub.last = None;
    }
}

/// A reloaded page never unsubscribes, and its stale channels still accept sends.
pub(crate) fn clear() {
    let mut hub = HUB.lock().unwrap_or_else(|error| error.into_inner());
    hub.listeners.clear();
    if let Some(worker) = hub.worker.take() {
        worker.abort();
    }
    hub.last = None;
}

async fn read(app: &tauri::AppHandle) -> Result<LocalTunnelStatus, String> {
    crate::connection::local_status(app.state::<crate::AppState>()).await
}

/// A new session, counter epoch or server is a new generation.
fn identity(status: &serde_json::Value) -> String {
    let field = |name| status.get(name).unwrap_or(&serde_json::Value::Null);
    format!(
        "{}:{}",
        status.get("active_profile_id").unwrap_or(field("server_id")),
        field("counter_epoch")
    )
}

async fn produce(app: tauri::AppHandle) {
    let mut generation = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    let mut identity_key: Option<String> = None;
    let mut stream = StreamState::Starting;
    loop {
        let reading = tokio::time::timeout(Duration::from_secs(2), read(&app))
            .await
            .map_err(|_| ())
            .and_then(|result| result.map_err(|_| ()));
        stream = stream.next(reading.is_ok());
        let sequence = SEQUENCE.fetch_add(1, Ordering::AcqRel) + 1;
        let phase = reading.as_ref().ok().and_then(LocalTunnelStatus::phase);
        {
            let mut hub = HUB.lock().unwrap_or_else(|error| error.into_inner());
            let event = match reading {
                Ok(status) => {
                    let phase = serde_json::to_value(&status.state)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_else(|| "unknown".into());
                    // The serialized status carries `phase: {kind}`; nothing strips it.
                    let status = serde_json::to_value(status).unwrap_or_default();
                    let key = identity(&status);
                    if identity_key.as_ref() != Some(&key) {
                        if identity_key.is_some() {
                            crate::management_session::invalidate();
                            generation = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
                        }
                        identity_key = Some(key);
                    }
                    LocalStatusEvent {
                        phase,
                        status: Some(status),
                        stream,
                        sequence,
                        generation,
                        stale: false,
                    }
                }
                Err(()) => LocalStatusEvent {
                    status: hub.last.as_ref().and_then(|event| event.status.clone()),
                    stream,
                    sequence,
                    generation,
                    phase: "unknown".into(),
                    stale: true,
                },
            };
            hub.listeners
                .retain(|_, channel| channel.send(event.clone()).is_ok());
            hub.last = Some(event);
            if hub.listeners.is_empty() {
                hub.worker = None;
                hub.last = None;
                return;
            }
        }
        tokio::select! {
            _ = CHANGED.notified() => {},
            _ = tokio::time::sleep(fallback_interval(phase, watching())) => {},
        }
    }
}

/// Starts the process-wide native change watcher. It wakes the window stream and
/// the tray; without it both fall back to their timers.
pub(crate) fn watch_native(app: tauri::AppHandle) {
    let notify = move || {
        changed();
        crate::desktop_tray::request_refresh(&app);
    };
    #[cfg(target_os = "linux")]
    std::thread::spawn(move || {
        // shortcut: on failure the timers poll; a restart retries the watch.
        let _ = linux::watch(std::path::Path::new("/run/sirinvpn"), &notify);
        WATCHING.store(false, Ordering::Release);
    });
    #[cfg(windows)]
    std::thread::spawn(move || windows::watch(&notify));
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = notify;
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Ordering, WATCHING};
    use nix::sys::inotify::{AddWatchFlags as F, InitFlags, Inotify};
    use std::{ffi::OsStr, path::Path};

    /// Temporary files and locks change without changing what `status` reports.
    pub(super) fn relevant(name: Option<&OsStr>) -> bool {
        name.and_then(OsStr::to_str).is_some_and(|name| {
            !name.ends_with(".new") && !name.ends_with(".lock") && !name.starts_with('.')
        })
    }

    /// The helper writes `runtime` (0755, files 0644) by atomic rename, so an
    /// unprivileged watch sees every committed state. The directory exists only
    /// while a session does; its parent is watched to catch it being created.
    pub(super) fn watch(runtime: &Path, notify: &dyn Fn()) -> nix::Result<()> {
        let (Some(parent), Some(name)) = (runtime.parent(), runtime.file_name()) else {
            return Err(nix::Error::EINVAL);
        };
        let inotify = Inotify::init(InitFlags::IN_CLOEXEC)?;
        let parent_watch =
            inotify.add_watch(parent, F::IN_CREATE | F::IN_MOVED_TO | F::IN_ONLYDIR)?;
        let flags = F::IN_CLOSE_WRITE
            | F::IN_MOVED_TO
            | F::IN_MOVED_FROM
            | F::IN_CREATE
            | F::IN_DELETE
            | F::IN_ONLYDIR;
        let mut directory = inotify.add_watch(runtime, flags).ok();
        WATCHING.store(true, Ordering::Release);
        loop {
            let mut wake = false;
            for event in inotify.read_events()? {
                if event.wd == parent_watch {
                    if event.name.as_deref() == Some(name) {
                        directory = inotify.add_watch(runtime, flags).ok();
                        wake = true;
                    }
                } else if Some(event.wd) == directory {
                    // IN_IGNORED: the directory itself went away with the session.
                    if event.mask.contains(F::IN_IGNORED) {
                        directory = None;
                        wake = true;
                    } else {
                        wake |= relevant(event.name.as_deref());
                    }
                }
            }
            if wake {
                notify();
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{Ordering, WATCHING};
    use sirinvpn_windows_service::{ServiceError, ipc};
    use std::time::Duration;

    /// Holds one of the two per-user wait slots for the app's lifetime.
    pub(super) fn watch(notify: &dyn Fn()) {
        let mut after = None;
        loop {
            match ipc::wait_for_change_blocking(after, Duration::from_secs(30)) {
                Ok((sequence, _)) => {
                    WATCHING.store(true, Ordering::Release);
                    if after != Some(sequence) {
                        notify();
                    }
                    after = Some(sequence);
                }
                Err(error) => {
                    WATCHING.store(false, Ordering::Release);
                    after = None;
                    // An older service has no long-poll; it may be updated in place.
                    std::thread::sleep(Duration::from_secs(
                        if matches!(error, ServiceError::InvalidRequest) {
                            60
                        } else {
                            10
                        },
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sirinvpn_protocol::ServerId;

    #[test]
    fn stream_states_follow_read_outcomes() {
        use StreamState::*;
        assert_eq!(Starting.next(false), Unavailable);
        assert_eq!(Unavailable.next(false), Unavailable);
        assert_eq!(Unavailable.next(true), Live);
        assert_eq!(Live.next(false), Stale);
        assert_eq!(Stale.next(false), Stale);
        assert_eq!(Stale.next(true), Live);
        assert_eq!(serde_json::to_value(Stale).unwrap(), "stale");
    }

    #[test]
    fn numbers_are_process_wide_and_start_from_the_clock() {
        let before = started_ms();
        assert!(SEQUENCE.fetch_add(1, Ordering::AcqRel) >= before - 60_000);
        assert!(GENERATION.load(Ordering::Acquire) >= before - 60_000);
    }

    #[test]
    fn only_moving_tunnels_are_sampled_quickly() {
        let id = ServerId::new();
        let watched = |phase| fallback_interval(phase, true).as_secs();
        let polled = |phase| fallback_interval(phase, false).as_secs();
        assert_eq!(watched(Some(TunnelPhase::Idle)), 10);
        assert_eq!(watched(Some(TunnelPhase::Paused { server_id: id })), 10);
        assert_eq!(watched(Some(TunnelPhase::Connected { server_id: id })), 2);
        assert_eq!(watched(None), 2);
        assert_eq!(polled(Some(TunnelPhase::Connecting { server_id: id })), 1);
        assert_eq!(polled(None), 1);
        assert_eq!(polled(Some(TunnelPhase::Idle)), 2);
        assert_eq!(polled(Some(TunnelPhase::Connected { server_id: id })), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_state_written_by_rename_wakes_the_watcher() {
        use std::sync::mpsc;
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("sirinvpn");
        let (sender, receiver) = mpsc::channel();
        let watched = runtime.clone();
        std::thread::spawn(move || {
            let notify = move || {
                let _ = sender.send(());
            };
            let _ = linux::watch(&watched, &notify);
        });
        let wait = || receiver.recv_timeout(Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(200));
        // The session creates the directory, then commits its state by rename.
        std::fs::create_dir(&runtime).unwrap();
        wait().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(runtime.join("client-state.new"), b"{}").unwrap();
        std::fs::rename(runtime.join("client-state.new"), runtime.join("client-state.json"))
            .unwrap();
        wait().unwrap();
        while receiver.try_recv().is_ok() {}
        std::fs::remove_dir_all(&runtime).unwrap();
        wait().unwrap();
        assert!(!linux::relevant(Some("operation.lock".as_ref())));
        assert!(!linux::relevant(Some("client-state.new".as_ref())));
        assert!(linux::relevant(Some("client-state.json".as_ref())));
    }
}
