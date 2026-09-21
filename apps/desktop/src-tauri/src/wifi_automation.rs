//! Optional desktop network policy. One attempt per network entry; no event log.
use crate::*;
use serde::Serialize;
use sirinvpn_core::{WifiAutomationPolicy, WifiNetworkStatus, WifiPolicySnapshot};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use tauri::Manager;

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
enum AutomationStatus {
    #[default]
    Disabled,
    WaitingForWifi,
    Trusted,
    Connecting,
    SessionActive,
    WaitingForNetworkChange,
    NeedsAttention,
    #[cfg(target_os = "linux")]
    NeedsAuthorization,
}

#[derive(Default)]
pub struct WifiAutomationRuntime {
    revision: AtomicU64,
    status: Mutex<AutomationStatus>,
}
impl WifiAutomationRuntime {
    fn status(&self, status: AutomationStatus) {
        if let Ok(mut current) = self.status.lock() {
            *current = status;
        }
    }
    fn changed(&self) {
        self.revision.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Serialize)]
pub struct WifiSettingsSnapshot {
    #[serde(flatten)]
    network: WifiPolicySnapshot,
    automation_status: AutomationStatus,
    network_names: std::collections::BTreeMap<String, String>,
}

#[tauri::command]
pub async fn get_wifi_policy(app: tauri::AppHandle) -> Result<WifiSettingsSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let paths = &app.state::<AppState>().paths;
        paths
            .network_policy_store()
            .initialize_wifi_settings()
            .map_err(safe_error)?;
        let network = NetworkContext::discover();
        let runtime = app.state::<WifiAutomationRuntime>();
        let snapshot = paths
            .network_policy_store()
            .wifi_snapshot(network.as_ref())
            .map_err(safe_error)?;
        let network_names = paths
            .network_policy_store()
            .wifi_display_names(&snapshot)
            .map_err(safe_error)?;
        Ok(WifiSettingsSnapshot {
            network: snapshot,
            network_names,
            automation_status: *runtime
                .status
                .lock()
                .map_err(|_| "Wi-Fi automation status is unavailable.")?,
        })
    })
    .await
    .map_err(|_| "Network discovery was interrupted.".to_owned())?
}

#[tauri::command]
pub async fn set_wifi_policy(
    app: tauri::AppHandle,
    policy: WifiAutomationPolicy,
) -> Result<(), String> {
    let paths = app.state::<AppState>().paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Some(id) = policy.server_id {
            find_profile(&paths, &id.to_string())?;
        }
        paths
            .network_policy_store()
            .set_wifi_automation(policy)
            .map_err(safe_error)?;
        app.state::<WifiAutomationRuntime>().changed();
        Ok(())
    })
    .await
    .map_err(|_| "Wi-Fi preferences could not be saved.".to_owned())?
}

#[tauri::command]
pub async fn trust_current_wifi(
    app: tauri::AppHandle,
    expected_network_token: String,
    label: String,
) -> Result<(), String> {
    let paths = app.state::<AppState>().paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let network = NetworkContext::discover().ok_or("A Wi-Fi network is unavailable.")?;
        let store = paths.network_policy_store();
        if store
            .wifi_snapshot(Some(&network))
            .map_err(safe_error)?
            .current_network_token
            .as_deref()
            != Some(&expected_network_token)
        {
            return Err("The network changed. Refresh before marking it trusted.".into());
        }
        store.trust_wifi(&network, label).map_err(safe_error)?;
        app.state::<WifiAutomationRuntime>().changed();
        Ok(())
    })
    .await
    .map_err(|_| "Wi-Fi trust could not be saved.".to_owned())?
}

#[tauri::command]
pub async fn forget_trusted_wifi(app: tauri::AppHandle, id: String) -> Result<(), String> {
    app.state::<AppState>()
        .paths
        .network_policy_store()
        .forget_trusted_wifi(&id)
        .map_err(safe_error)?;
    app.state::<WifiAutomationRuntime>().changed();
    Ok(())
}

#[derive(Default)]
struct NetworkEntry {
    network: Option<NetworkContext>,
    revision: u64,
    attempted: bool,
    failed: bool,
}
impl NetworkEntry {
    fn poll_interval(&self, status: AutomationStatus) -> std::time::Duration {
        std::time::Duration::from_millis(
            if self.network.is_none() && matches!(status, AutomationStatus::WaitingForWifi) {
                250
            } else {
                5000
            },
        )
    }

    fn observe(&mut self, network: Option<NetworkContext>, revision: u64) {
        if self.network != network || self.revision != revision {
            self.network = network;
            self.revision = revision;
            self.attempted = false;
            self.failed = false;
        }
    }
}

pub fn start(app: tauri::AppHandle) {
    app.manage(WifiAutomationRuntime::default());
    tauri::async_runtime::spawn_blocking(move || {
        let mut entry = NetworkEntry::default();
        loop {
            let runtime = app.state::<WifiAutomationRuntime>();
            let status = inspect(&app, &mut entry).unwrap_or_else(|_| {
                entry.failed = true;
                AutomationStatus::NeedsAttention
            });
            runtime.status(status);
            std::thread::sleep(entry.poll_interval(status));
        }
    });
}

fn inspect(app: &tauri::AppHandle, entry: &mut NetworkEntry) -> Result<AutomationStatus, String> {
    let paths = app.state::<AppState>().paths.clone();
    let store = paths.network_policy_store();
    let runtime = app.state::<WifiAutomationRuntime>();
    if !store
        .wifi_snapshot(None)
        .map_err(safe_error)?
        .policy
        .enabled
    {
        entry.observe(None, runtime.revision.load(Ordering::SeqCst));
        return Ok(AutomationStatus::Disabled);
    }
    entry.observe(
        NetworkContext::discover(),
        runtime.revision.load(Ordering::SeqCst),
    );
    let snapshot = store
        .wifi_snapshot(entry.network.as_ref())
        .map_err(safe_error)?;
    match snapshot.current_network {
        WifiNetworkStatus::Unavailable | WifiNetworkStatus::OtherNetwork => {
            return Ok(AutomationStatus::WaitingForWifi);
        }
        WifiNetworkStatus::TrustedWifi => return Ok(AutomationStatus::Trusted),
        WifiNetworkStatus::UntrustedWifi => (),
    }
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.server_id.is_some() || !crate::connection_controller::confirmed_disconnected(&local) {
        // A session or retained guard belongs to the user, including paused sessions.
        entry.attempted = true;
        return Ok(AutomationStatus::SessionActive);
    }
    if entry.attempted {
        return Ok(if entry.failed {
            AutomationStatus::NeedsAttention
        } else {
            AutomationStatus::WaitingForNetworkChange
        });
    }
    #[cfg(target_os = "linux")]
    if crate::helper::prepare_helper_for_connection(false).is_err() {
        return Ok(AutomationStatus::NeedsAuthorization);
    }
    let Ok(_operation) = crate::connection_controller::acquire() else {
        return Ok(AutomationStatus::SessionActive);
    };
    let id = snapshot
        .policy
        .server_id
        .ok_or("Choose a server for Wi-Fi automation.")?;
    let preferences = app
        .state::<connection_preferences::ConnectionPreferenceStore>()
        .get(id)?;
    // Save the entry before attempting: cancellation or missing authorization cannot
    // create repeated prompts, or undo a later explicit disconnect on this network.
    entry.attempted = true;
    runtime.status(AutomationStatus::Connecting);
    let still_current = store
        .wifi_snapshot(NetworkContext::discover().as_ref())
        .map_err(safe_error)?;
    if still_current.policy != snapshot.policy
        || still_current.current_network_token != snapshot.current_network_token
        || still_current.current_network != WifiNetworkStatus::UntrustedWifi
    {
        return Ok(AutomationStatus::WaitingForNetworkChange);
    }
    crate::connection_policy::connect_native(paths, &id.to_string(), preferences, None, false)?;
    Ok(AutomationStatus::SessionActive)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_or_manual_disconnect_stays_suppressed_until_network_or_policy_changes() {
        let mut entry = NetworkEntry::default();
        entry.observe(None, 1);
        entry.attempted = true;
        entry.observe(None, 1);
        assert!(entry.attempted);
        entry.observe(None, 2);
        assert!(!entry.attempted);
        assert_eq!(
            entry
                .poll_interval(AutomationStatus::WaitingForWifi)
                .as_millis(),
            250
        );
        for status in [
            AutomationStatus::Disabled,
            #[cfg(target_os = "linux")]
            AutomationStatus::NeedsAuthorization,
            AutomationStatus::SessionActive,
            AutomationStatus::WaitingForNetworkChange,
            AutomationStatus::Trusted,
        ] {
            assert_eq!(entry.poll_interval(status).as_secs(), 5);
        }
    }
}
