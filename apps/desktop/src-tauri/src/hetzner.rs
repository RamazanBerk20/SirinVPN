//! One-click servers on Hetzner Cloud. The API token comes with each call and
//! is never stored. The new server is installed through `provision_server`.
//!
//! Each creation is recorded (`HetznerProvision`, next to its login key) from
//! before the create request until SirinVPN is installed or the server is
//! deleted, so an interrupted or uncertain creation is resumed, never repeated.

use crate::AppState;
use serde::Serialize;
use sirinvpn_installer::hetzner::*;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::State;
use zeroize::Zeroizing;

static CANCEL_WAIT: AtomicBool = AtomicBool::new(false);
/// Held from the pending check until the new record is saved.
static CREATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Serialize)]
pub(crate) struct CreatedServer {
    server: HetznerServer,
    private_key_path: String,
}

fn client(token: &str) -> Result<HetznerClient, String> {
    HetznerClient::new(token).map_err(|error| error.to_string())
}

fn key_path(directory: &Path, name: &str) -> String {
    directory.join("ssh-keys").join(name).display().to_string()
}

const RECORD_UNREADABLE: &str =
    "The app couldn’t read its record of the new Hetzner server. Check permissions on the app’s settings folder.";

/// Arm servers only when this app carries an aarch64 server payload.
fn arm_payload() -> bool {
    crate::vps_transaction::server_payload().is_ok_and(|payload| payload.supports("aarch64"))
}

/// SirinVPN now runs on `host`: a creation that ended there is finished. The
/// login key stays; it is the Owner's SSH login for that server.
pub(crate) fn forget_installed(directory: &Path, host: &str) {
    for provision in HetznerProvision::pending(directory).unwrap_or_default() {
        if matches!(&provision.phase, HetznerPhase::Ready { ready, .. } if ready.ipv4.to_string() == host)
        {
            let _ = HetznerProvision::forget(directory, &provision.name);
        }
    }
}

fn pending_message(name: &str) -> String {
    format!("The server {name} was not finished. Resume or delete it before creating another.")
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
) -> Result<CreatedServer, crate::CommandError> {
    let token = Zeroizing::new(api_token);
    let client = client(&token)?;
    let directory = state.paths.configuration_directory.clone();
    let _creating = CREATE.lock().await;
    // Never a second server while an earlier creation is unfinished.
    if let Some(pending) = HetznerProvision::pending(&directory)
        .map_err(|_| RECORD_UNREADABLE.to_owned())?
        .into_iter()
        .next()
    {
        return Err(pending_message(&pending.name).into());
    }
    let prepared = PreparedServer::generate();
    // Saved first, so the key outlives an interrupted creation.
    let path = save_login_key(&directory, &prepared).map_err(|_| {
        "Couldn’t save the new server’s SSH key. Check permissions on the app’s settings folder."
    })?;
    // The record keeps the pre-seeded host key, so an uncertain create stays resumable.
    let mut provision = HetznerProvision::requested(&prepared);
    if provision.save(&directory).is_err() {
        let _ = forget_login_key(&directory, &prepared.name);
        return Err(
            "Couldn’t record the new server. Check permissions on the app’s settings folder."
                .into(),
        );
    }
    match client.create_server(&prepared, &request, arm_payload()).await {
        Ok(server) => {
            // Unsaved, the record stays Requested and resuming finds the server by name.
            let _ = provision.advance(
                &directory,
                HetznerPhase::Created {
                    server_id: server.id,
                },
            );
            Ok(CreatedServer {
                server,
                private_key_path: path.display().to_string(),
            })
        }
        // Coded `hetzner_create_uncertain` with the server's name; the record and key stay.
        Err(error @ HetznerError::Uncertain(_)) => Err(crate::command_error(error)),
        Err(error) => {
            let _ = HetznerProvision::forget(&directory, &prepared.name);
            let _ = forget_login_key(&directory, &prepared.name);
            Err(error.to_string().into())
        }
    }
}

/// After an uncertain create: the server this app recorded as `name`, or `None`
/// once Hetzner confirms it has no such server (the record is then dropped).
#[tauri::command]
pub(crate) async fn find_hetzner_server(
    state: State<'_, AppState>,
    api_token: String,
    name: String,
) -> Result<Option<CreatedServer>, String> {
    let token = Zeroizing::new(api_token);
    let client = client(&token)?;
    let directory = state.paths.configuration_directory.clone();
    let Some(mut provision) =
        HetznerProvision::load(&directory, &name).map_err(|_| RECORD_UNREADABLE.to_owned())?
    else {
        return Ok(None);
    };
    if provision.server_id().is_none() {
        let key = load_login_key(&directory, &provision.name).map_err(|_| {
            "The new server’s SSH key is missing from the app’s settings folder.".to_owned()
        })?;
        // Already cancelled, so `resume` only looks the name up and records the server.
        let lookup_only = AtomicBool::new(true);
        match client
            .resume(&directory, &mut provision, key, &lookup_only)
            .await
        {
            Ok(_) | Err(HetznerError::Cancelled) => {}
            // `resume` dropped the record: Hetzner has no server with this name.
            Err(HetznerError::InvalidChoice(_)) => {
                let _ = forget_login_key(&directory, &provision.name);
                return Ok(None);
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    let id = provision.server_id().ok_or_else(|| RECORD_UNREADABLE.to_owned())?;
    Ok(Some(CreatedServer {
        private_key_path: key_path(&directory, &provision.name),
        server: HetznerServer {
            id,
            name: provision.name,
            host_key_sha256: provision.pre_seeded_host_key_sha256,
        },
    }))
}

#[tauri::command]
pub(crate) async fn wait_hetzner_server(
    state: State<'_, AppState>,
    api_token: String,
    server: HetznerServer,
) -> Result<HetznerReady, String> {
    let token = Zeroizing::new(api_token);
    let client = client(&token)?;
    let directory = state.paths.configuration_directory.clone();
    // The record, not the UI, holds the host key to pin.
    let mut provision = HetznerProvision::load(&directory, &server.name)
        .map_err(|_| RECORD_UNREADABLE.to_owned())?
        .filter(|provision| provision.server_id().is_none_or(|id| id == server.id))
        .ok_or_else(|| "The app has no record of this server. Delete it in the Hetzner Cloud Console.".to_owned())?;
    let login = load_login_key(&directory, &server.name).map_err(|_| {
        "The new server’s SSH key is missing from the app’s settings folder.".to_owned()
    })?;
    CANCEL_WAIT.store(false, Ordering::SeqCst);
    let ready = match client
        .resume(&directory, &mut provision, login, &CANCEL_WAIT)
        .await
    {
        Ok(ready) => ready,
        // Its own text names the replacement key the server may present now.
        Err(error @ HetznerError::HostKeyReplacement(_)) => {
            return Err(format!(
                "{error}. The pre-seeded host key was {}.",
                provision.pre_seeded_host_key_sha256
            ));
        }
        Err(error) => return Err(error.to_string()),
    };
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
    // The record stays until SirinVPN is installed there or the server is deleted.
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
    let directory = &state.paths.configuration_directory;
    if let Ok(Some(provision)) = HetznerProvision::load(directory, &server.name)
        && provision.server_id().is_some_and(|id| id != server.id)
    {
        return Err("This is not the server the app created under that name.".to_owned());
    }
    client(&token)?
        .delete_server(server.id)
        .await
        .map_err(|error| error.to_string())?;
    let _ = HetznerProvision::forget(directory, &server.name);
    let _ = forget_login_key(directory, &server.name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_uncertain_create_names_its_server_as_the_ui_expects() {
        // The UI's fallback reads `hetzner_create_uncertain` and the name from this text.
        let text = HetznerError::Uncertain("sirinvpn-0a1b2c3d".into()).to_string();
        let name = text
            .strip_prefix("Hetzner Cloud may have created server ")
            .and_then(|rest| rest.split_once(';'))
            .map(|(name, _)| name);
        assert_eq!(name, Some("sirinvpn-0a1b2c3d"));
    }

    #[test]
    fn a_pending_creation_blocks_another_and_install_finishes_it() {
        let directory = tempfile::tempdir().unwrap();
        let prepared = PreparedServer::generate();
        let mut provision = HetznerProvision::requested(&prepared);
        provision.save(directory.path()).unwrap();
        let pending = HetznerProvision::pending(directory.path()).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending_message(&pending[0].name).contains(&prepared.name));
        // Another host's install leaves it pending; the server's own install finishes it.
        let ready = HetznerReady {
            ipv4: "203.0.113.5".parse().unwrap(),
            ipv6: None,
            host_key_sha256: "SHA256:x".into(),
        };
        provision
            .advance(directory.path(), HetznerPhase::Ready { server_id: 7, ready })
            .unwrap();
        forget_installed(directory.path(), "203.0.113.6");
        assert_eq!(HetznerProvision::pending(directory.path()).unwrap().len(), 1);
        forget_installed(directory.path(), "203.0.113.5");
        assert!(HetznerProvision::pending(directory.path()).unwrap().is_empty());
    }
}
