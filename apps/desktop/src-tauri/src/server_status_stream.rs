//! Bridge authenticated VPS readings to a cancellable, per-subscription IPC channel.
use super::*;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::ipc::Channel;

#[derive(Default)]
pub(super) struct StatusSubscriptions(Mutex<HashMap<String, tauri::async_runtime::JoinHandle<()>>>);

impl StatusSubscriptions {
    /// A reloaded page never unsubscribes, and its stale channels still accept sends.
    pub(super) fn abort_all(&self) {
        for (_, task) in self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain()
        {
            task.abort();
        }
    }
}

impl Drop for StatusSubscriptions {
    fn drop(&mut self) {
        for (_, task) in self
            .0
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .drain()
        {
            task.abort();
        }
    }
}

/// The stream's own state, sent with every event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamState {
    Connecting,
    Live,
    Polling,
    /// Waiting `delay` seconds before the next attempt.
    Reconnecting { delay: u64 },
    /// The server was removed from this device or the window went away. Final.
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamEvent {
    Reading { live: bool },
    Failed,
    /// Streaming support is probed again; not an interruption.
    Reprobe,
    Removed,
    Closed,
}

impl Serialize for StreamState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Connecting => "connecting",
            Self::Live => "live",
            Self::Polling => "polling",
            Self::Reconnecting { .. } => "reconnecting",
            Self::Stopped => "stopped",
        })
    }
}

impl StreamState {
    /// The only transition function.
    pub(super) fn next(self, event: StreamEvent) -> Self {
        match (self, event) {
            (Self::Stopped, _) | (_, StreamEvent::Removed | StreamEvent::Closed) => Self::Stopped,
            (_, StreamEvent::Reading { live: true }) => Self::Live,
            (_, StreamEvent::Reading { live: false }) => Self::Polling,
            (Self::Reconnecting { delay }, StreamEvent::Failed) => Self::Reconnecting {
                delay: (delay * 2).min(15),
            },
            (_, StreamEvent::Failed) => Self::Reconnecting { delay: 1 },
            (state, StreamEvent::Reprobe) => state,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum StatusEvent {
    Status {
        status: Box<ServerStatus>,
        mode: &'static str,
        management_latency_ms: Option<u64>,
        stream: StreamState,
    },
    State {
        state: StreamState,
        stream: StreamState,
    },
}

impl StatusEvent {
    fn state(state: StreamState) -> Self {
        Self::State {
            state,
            stream: state,
        }
    }
}

#[tauri::command]
pub(super) fn subscribe_server_status(
    state: State<'_, AppState>,
    subscriptions: State<'_, StatusSubscriptions>,
    server_id: String,
    subscription_id: String,
    on_event: Channel<StatusEvent>,
) -> Result<(), String> {
    let paths = state.paths.clone();
    let mut tasks = subscriptions
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    tasks.retain(|_, task| !task.inner().is_finished());
    if tasks.len() >= 8 || subscription_id.len() > 128 {
        return Err("Too many active status subscriptions.".to_owned());
    }
    let task = tauri::async_runtime::spawn(async move {
        watch_status(paths, server_id, on_event).await;
    });
    if let Some(previous) = tasks.insert(subscription_id, task) {
        previous.abort();
    }
    Ok(())
}

#[tauri::command]
pub(super) fn unsubscribe_server_status(
    subscriptions: State<'_, StatusSubscriptions>,
    subscription_id: String,
) {
    if let Some(task) = subscriptions
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&subscription_id)
    {
        task.abort();
    }
}

async fn watch_status(paths: ClientPaths, server_id: String, channel: Channel<StatusEvent>) {
    let mut state = StreamState::Connecting;
    if channel.send(StatusEvent::state(state)).is_err() {
        return;
    }
    loop {
        let event = read_status(&paths, &server_id, &channel, &mut state)
            .await
            .unwrap_or(StreamEvent::Failed);
        state = state.next(event);
        match state {
            StreamState::Stopped => {
                if event == StreamEvent::Removed {
                    let _ = channel.send(StatusEvent::state(state));
                }
                return;
            }
            StreamState::Reconnecting { delay } => {
                if channel.send(StatusEvent::state(state)).is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            _ => {}
        }
    }
}

fn saved_profile(paths: &ClientPaths, server_id: &str) -> Result<Option<ServerProfile>, String> {
    let Ok(id) = server_id.parse::<ServerId>() else {
        return Ok(None);
    };
    Ok(paths
        .profile_store()
        .load()
        .map_err(safe_error)?
        .into_iter()
        .find(|profile| profile.id == id))
}

async fn read_status(
    paths: &ClientPaths,
    server_id: &str,
    channel: &Channel<StatusEvent>,
    state: &mut StreamState,
) -> Result<StreamEvent, String> {
    // A removed server ends its watch instead of reconnecting forever.
    let Some(mut profile) = saved_profile(paths, server_id)? else {
        return Ok(StreamEvent::Removed);
    };
    let secret = paths
        .secret_store()
        .get(&profile.identity_reference)
        .map_err(safe_error)?;
    match ManagementClient::subscribe_status(&profile, &secret).await {
        Ok(mut stream) => loop {
            // A connection that only sends keep-alive comments is not a live reading.
            let status = tokio::time::timeout(Duration::from_secs(8), stream.next_status())
                .await
                .map_err(|_| "Status stream stalled.".to_owned())?
                .map_err(safe_error)?;
            *state = state.next(StreamEvent::Reading { live: true });
            reconcile_status_authority(paths, &mut profile, &status);
            if channel
                .send(StatusEvent::Status {
                    status: Box::new(status),
                    mode: "live",
                    management_latency_ms: None,
                    stream: *state,
                })
                .is_err()
            {
                return Ok(StreamEvent::Closed);
            }
        },
        Err(ManagementError::StatusStreamingUnsupported) => {
            // Old VPS releases remain usable. Probe streaming again periodically
            // so an in-place server update enables it without restarting the app.
            let client = ManagementClient::new(&profile, &secret).map_err(safe_error)?;
            let probe_at = Instant::now() + Duration::from_secs(30);
            loop {
                let started = Instant::now();
                let status = client.status().await.map_err(safe_error)?;
                let latency = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                *state = state.next(StreamEvent::Reading { live: false });
                reconcile_status_authority(paths, &mut profile, &status);
                if channel
                    .send(StatusEvent::Status {
                        status: Box::new(status),
                        mode: "polling",
                        management_latency_ms: Some(latency),
                        stream: *state,
                    })
                    .is_err()
                {
                    return Ok(StreamEvent::Closed);
                }
                tokio::time::sleep(Duration::from_secs(4)).await;
                if Instant::now() >= probe_at {
                    // Retry immediately without showing a spurious interruption.
                    return Ok(StreamEvent::Reprobe);
                }
            }
        }
        Err(error) => Err(safe_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::{StreamEvent as E, StreamState as S};

    #[test]
    fn failures_back_off_readings_reset_and_removal_is_final() {
        let mut state = S::Connecting;
        let mut delays = vec![];
        for _ in 0..6 {
            state = state.next(E::Failed);
            let S::Reconnecting { delay } = state else {
                panic!("{state:?}")
            };
            delays.push(delay);
        }
        assert_eq!(delays, [1, 2, 4, 8, 15, 15]);
        assert_eq!(state.next(E::Reading { live: false }), S::Polling);
        assert_eq!(S::Polling.next(E::Reprobe), S::Polling);
        assert_eq!(S::Polling.next(E::Failed), S::Reconnecting { delay: 1 });
        assert_eq!(S::Live.next(E::Removed), S::Stopped);
        assert_eq!(state.next(E::Closed), S::Stopped);
        for event in [E::Reading { live: true }, E::Failed, E::Reprobe] {
            assert_eq!(S::Stopped.next(event), S::Stopped);
        }
        assert_eq!(
            serde_json::to_value(S::Reconnecting { delay: 4 }).unwrap(),
            "reconnecting"
        );
    }
}
