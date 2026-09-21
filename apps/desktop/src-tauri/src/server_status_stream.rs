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

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum StatusEvent {
    Status {
        status: Box<ServerStatus>,
        mode: &'static str,
        management_latency_ms: Option<u64>,
    },
    State {
        state: &'static str,
    },
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
    if channel
        .send(StatusEvent::State {
            state: "connecting",
        })
        .is_err()
    {
        return;
    }
    let mut delay = 1;
    loop {
        match read_status(&paths, &server_id, &channel, &mut delay).await {
            Ok(WatchResult::Closed) => return,
            Ok(WatchResult::Reprobe) => continue,
            Err(_) => {}
        }
        if channel
            .send(StatusEvent::State {
                state: "reconnecting",
            })
            .is_err()
        {
            return;
        }
        tokio::time::sleep(Duration::from_secs(delay)).await;
        delay = (delay * 2).min(15);
    }
}

enum WatchResult {
    Closed,
    Reprobe,
}

async fn read_status(
    paths: &ClientPaths,
    server_id: &str,
    channel: &Channel<StatusEvent>,
    delay: &mut u64,
) -> Result<WatchResult, String> {
    let mut profile = find_profile(paths, server_id)?;
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
            *delay = 1;
            reconcile_status_authority(paths, &mut profile, &status);
            if channel
                .send(StatusEvent::Status {
                    status: Box::new(status),
                    mode: "live",
                    management_latency_ms: None,
                })
                .is_err()
            {
                return Ok(WatchResult::Closed);
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
                *delay = 1;
                reconcile_status_authority(paths, &mut profile, &status);
                if channel
                    .send(StatusEvent::Status {
                        status: Box::new(status),
                        mode: "polling",
                        management_latency_ms: Some(latency),
                    })
                    .is_err()
                {
                    return Ok(WatchResult::Closed);
                }
                tokio::time::sleep(Duration::from_secs(4)).await;
                if Instant::now() >= probe_at {
                    // Retry immediately without showing a spurious interruption.
                    return Ok(WatchResult::Reprobe);
                }
            }
        }
        Err(error) => Err(safe_error(error)),
    }
}
