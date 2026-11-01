//! One-click servers on Hetzner Cloud. The API token comes with each call and
//! is never stored. The new server is installed through `provision_server`.

use crate::AppState;
use serde::Serialize;
use sirinvpn_installer::{ServerBinarySource, hetzner::*};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::State;
use zeroize::Zeroizing;

static CANCEL_WAIT: AtomicBool = AtomicBool::new(false);

#[derive(Serialize)]
pub(crate) struct CreatedServer {
    server: HetznerServer,
    private_key_path: String,
}

fn client(token: &str) -> Result<HetznerClient, String> {
    HetznerClient::new(token).map_err(|error| error.to_string())
}

/// Arm servers only when this app carries an aarch64 server payload.
fn arm_payload() -> bool {
    crate::resolve_binary(
        "SIRINVPN_SERVER_BINARY",
        "/usr/lib/sirinvpn/sirinvpn-server",
        "sirinvpn-server",
    )
    .is_ok_and(|path| ServerBinarySource::Exact(path).supports("aarch64"))
}

#[tauri::command]
pub(crate) async fn hetzner_catalog(api_token: String) -> Result<HetznerCatalog, String> {
    let token = Zeroizing::new(api_token);
    client(&token)?
        .catalog(arm_payload())
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) async fn create_hetzner_server(
    state: State<'_, AppState>,
    api_token: String,
    request: HetznerServerRequest,
) -> Result<CreatedServer, String> {
    let token = Zeroizing::new(api_token);
    let client = client(&token)?;
    let directory = state.paths.configuration_directory.clone();
    let prepared = PreparedServer::generate();
    // Saved first, so the key outlives an interrupted creation.
    let path = save_login_key(&directory, &prepared).map_err(|_| {
        "Couldn’t save the new server’s SSH key. Check permissions on the app’s settings folder."
            .to_owned()
    })?;
    match client.create_server(&prepared, &request, arm_payload()).await {
        Ok(server) => Ok(CreatedServer {
            server,
            private_key_path: path.display().to_string(),
        }),
        Err(error) => {
            if !matches!(error, HetznerError::Uncertain(_)) {
                let _ = forget_login_key(&directory, &prepared.name);
            }
            Err(error.to_string())
        }
    }
}

#[tauri::command]
pub(crate) async fn wait_hetzner_server(
    state: State<'_, AppState>,
    api_token: String,
    server: HetznerServer,
) -> Result<HetznerReady, String> {
    let token = Zeroizing::new(api_token);
    let client = client(&token)?;
    let login = load_login_key(&state.paths.configuration_directory, &server.name)
        .map_err(|_| "The new server’s SSH key is missing from the app’s settings folder.".to_owned())?;
    CANCEL_WAIT.store(false, Ordering::SeqCst);
    let ready = client
        .wait_until_ready(&server, login, &CANCEL_WAIT)
        .await
        .map_err(|error| error.to_string())?;
    // The key was read over a pinned session, so it needs no human review.
    if crate::ssh_trust::remember_verified(
        &state.paths,
        &ready.ipv4.to_string(),
        22,
        &ready.host_key_sha256,
    )
    .is_err()
    {
        eprintln!("The new VPS SSH identity could not be remembered.");
    }
    Ok(ready)
}

#[tauri::command]
pub(crate) fn cancel_hetzner_wait() {
    CANCEL_WAIT.store(true, Ordering::SeqCst);
}

#[tauri::command]
pub(crate) async fn delete_hetzner_server(
    state: State<'_, AppState>,
    api_token: String,
    server: HetznerServer,
) -> Result<(), String> {
    let token = Zeroizing::new(api_token);
    client(&token)?
        .delete_server(server.id)
        .await
        .map_err(|error| error.to_string())?;
    let _ = forget_login_key(&state.paths.configuration_directory, &server.name);
    Ok(())
}
