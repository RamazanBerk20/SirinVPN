//! One visible-interface status producer. Native VPN lifetime is independent.
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::Duration,
};
use tauri::Manager;
use tauri::ipc::Channel;

#[derive(Clone, Serialize)]
pub(crate) struct LocalStatusEvent {
    status: Option<serde_json::Value>,
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

pub(crate) fn changed() {
    CHANGED.notify_one();
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

async fn read(app: &tauri::AppHandle) -> Result<serde_json::Value, String> {
    let status = crate::connection::local_status(app.state::<crate::AppState>()).await?;
    serde_json::to_value(status).map_err(|_| "Native status unavailable.".into())
}

async fn produce(app: tauri::AppHandle) {
    let mut sequence = 0u64;
    let mut generation = 0u64;
    let mut identity = String::new();
    loop {
        let reading = tokio::time::timeout(Duration::from_secs(2), read(&app)).await;
        sequence += 1;
        let mut connecting = false;
        {
            let mut hub = HUB.lock().unwrap_or_else(|error| error.into_inner());
            let event = match reading {
                Ok(Ok(status)) => {
                    let key = format!(
                        "{}:{}:{}",
                        status
                            .get("active_profile_id")
                            .or(status.get("server_id"))
                            .unwrap_or(&serde_json::Value::Null),
                        status
                            .get("counter_epoch")
                            .unwrap_or(&serde_json::Value::Null),
                        status
                            .get("publication")
                            .and_then(|value| value.get("generation"))
                            .unwrap_or(&serde_json::Value::Null)
                    );
                    if identity != key {
                        if !identity.is_empty() {
                            crate::management_session::invalidate();
                        }
                        identity = key;
                        generation += 1;
                    }
                    let phase = status
                        .pointer("/publication/phase")
                        .and_then(|value| value.as_str())
                        .or_else(|| status.get("state").and_then(|value| value.as_str()))
                        .unwrap_or("unknown")
                        .to_owned();
                    connecting = phase == "connecting";
                    let stale = status
                        .pointer("/publication/sample_age_ms")
                        .and_then(|value| value.as_u64())
                        .is_some_and(|age| age > 2_500);
                    LocalStatusEvent {
                        status: Some(status),
                        sequence,
                        generation,
                        phase,
                        stale,
                    }
                }
                _ => LocalStatusEvent {
                    status: hub.last.as_ref().and_then(|event| event.status.clone()),
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
            _ = tokio::time::sleep(Duration::from_millis(if connecting { 100 } else { 500 })) => {},
        }
    }
}
