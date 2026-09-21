use serde::{Deserialize, Serialize};
use tauri::{
    Manager,
    plugin::{Builder, PluginHandle, TauriPlugin},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    command: String,
    args: serde_json::Value,
}

struct Bridge(PluginHandle<tauri::Wry>);

#[tauri::command]
async fn android_call(
    app: tauri::AppHandle,
    command: String,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let handle = app.state::<Bridge>().0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        handle
            .run_mobile_plugin("call", Request { command, args })
            .map_err(|_| "The Android service is unavailable. Reopen SirinVPN and retry.".into())
    })
    .await
    .map_err(|_| "The Android request was interrupted.".to_owned())?
}

fn bridge() -> TauriPlugin<tauri::Wry> {
    Builder::new("sirin")
        .setup(|app, api| {
            let handle = api.register_android_plugin("org.sirinvpn.client", "SirinPlugin")?;
            app.manage(Bridge(handle));
            Ok(())
        })
        .build()
}

#[tauri::command]
async fn android_watch(
    app: tauri::AppHandle,
    on_event: tauri::ipc::Channel<serde_json::Value>,
) -> Result<(), String> {
    let handle = app.state::<Bridge>().0.clone();
    handle
        .run_mobile_plugin_async::<serde_json::Value>(
            "registerListener",
            serde_json::json!({"event":"status", "handler":on_event}),
        )
        .await
        .map(|_| ())
        .map_err(|_| "Could not observe Android service state.".into())
}

#[tauri::command]
async fn android_unwatch(app: tauri::AppHandle, channel_id: u32) -> Result<(), String> {
    let handle = app.state::<Bridge>().0.clone();
    handle
        .run_mobile_plugin_async::<serde_json::Value>(
            "removeListener",
            serde_json::json!({"event":"status", "channelId":channel_id}),
        )
        .await
        .map(|_| ())
        .map_err(|_| "Could not remove Android observer.".into())
}

#[tauri::mobile_entry_point]
pub fn run() {
    // This shell has no profile store, networking runtime, tray or VPN shutdown hook.
    if tauri::Builder::default()
        .plugin(bridge())
        .invoke_handler(tauri::generate_handler![
            android_call,
            android_watch,
            android_unwatch
        ])
        .run(tauri::generate_context!())
        .is_err()
    {
        std::process::exit(1);
    }
}
