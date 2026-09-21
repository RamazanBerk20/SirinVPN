//! Remember explicitly verified SSH identities, scoped to a host and port.
//! Probing never establishes trust. Installer connections still check the pin
//! before authentication, including when the UI skips the human review.

use crate::{AppState, command_types::HostKeyInput};
use serde::{Deserialize, Serialize};
use sirinvpn_core::ClientPaths;
use sirinvpn_installer::{Provisioner, SshAuthentication, SshTarget};
use std::{collections::BTreeMap, io::Read, net::IpAddr, path::Path, sync::Mutex};
use tauri::State;

static STORE_LOCK: Mutex<()> = Mutex::new(());
const MAX_STORE_BYTES: usize = 262_144;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrustStatus {
    Trusted,
    Unknown,
    Changed,
}

#[derive(Serialize)]
pub(crate) struct HostInspection {
    fingerprint: String,
    status: TrustStatus,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u16,
    hosts: BTreeMap<String, String>,
}

pub(crate) fn endpoint(host: &str, port: u16) -> Result<String, String> {
    let host = host.trim().trim_end_matches('.');
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if port == 0
        || host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:".contains(&b))
    {
        return Err("Enter a valid SSH host and port.".into());
    }
    let host = host
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| host.to_ascii_lowercase());
    Ok(format!("[{host}]:{port}"))
}

pub(crate) fn valid_fingerprint(value: &str) -> bool {
    value.strip_prefix("SHA256:").is_some_and(|hash| {
        hash.len() == 43
            && hash
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(&b))
    })
}

fn read(path: &Path) -> Result<Document, String> {
    let file = match sirinvpn_platform::files::open_no_follow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Document {
                schema_version: 1,
                hosts: BTreeMap::new(),
            });
        }
        Err(_) => return Err("Saved SSH identities could not be read.".into()),
    };
    let mut bytes = Vec::new();
    file.take((MAX_STORE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Saved SSH identities could not be read.")?;
    let document: Document = serde_json::from_slice(&bytes)
        .map_err(|_| "Saved SSH identities are invalid; the file has been preserved.")?;
    if bytes.len() > MAX_STORE_BYTES
        || document.schema_version != 1
        || document.hosts.values().any(|fp| !valid_fingerprint(fp))
    {
        return Err(
            "Saved SSH identities are unsupported or invalid; the file has been preserved.".into(),
        );
    }
    Ok(document)
}

fn inspect_at(
    path: &Path,
    host: &str,
    port: u16,
    fingerprint: String,
) -> Result<HostInspection, String> {
    let key = endpoint(host, port)?;
    let _guard = STORE_LOCK
        .lock()
        .map_err(|_| "Saved SSH identities are busy.")?;
    let document = read(path)?;
    let status = match document.hosts.get(&key) {
        Some(saved) if saved == &fingerprint => TrustStatus::Trusted,
        Some(_) => TrustStatus::Changed,
        None => TrustStatus::Unknown,
    };
    Ok(HostInspection {
        fingerprint,
        status,
    })
}

fn remember_at(path: &Path, host: &str, port: u16, fingerprint: &str) -> Result<(), String> {
    let key = endpoint(host, port)?;
    if !valid_fingerprint(fingerprint) {
        return Err("The SSH fingerprint is invalid.".into());
    }
    let _guard = STORE_LOCK
        .lock()
        .map_err(|_| "Saved SSH identities are busy.")?;
    let mut document = read(path)?;
    document.hosts.insert(key, fingerprint.to_owned());
    let bytes =
        serde_json::to_vec_pretty(&document).map_err(|_| "The SSH identity could not be saved.")?;
    if bytes.len() > MAX_STORE_BYTES {
        return Err("The saved SSH identity limit has been reached.".into());
    }
    let write = || -> std::io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("missing parent"))?;
        sirinvpn_platform::files::create_private_directory(parent)?;
        sirinvpn_platform::files::atomic_write(path, &bytes, true)
    };
    write().map_err(|_| "The verified SSH identity could not be saved. Check the app configuration directory permissions.".into())
}

pub(crate) fn remember_verified(
    paths: &ClientPaths,
    host: &str,
    port: u16,
    fingerprint: &str,
) -> Result<(), String> {
    remember_at(
        &paths.configuration_directory.join("ssh-host-keys.json"),
        host,
        port,
        fingerprint,
    )
}

fn probe(host: &str, port: u16) -> Result<String, String> {
    endpoint(host, port)?;
    Provisioner::host_key_fingerprint(&SshTarget {
        host: host.to_owned(),
        port,
        username: "unused".into(),
        authentication: SshAuthentication::Agent,
        sudo_password: None,
        expected_host_key_sha256: None,
    })
    .map_err(crate::safe_error)
}

#[tauri::command]
pub(crate) async fn inspect_ssh_host(
    state: State<'_, AppState>,
    input: HostKeyInput,
) -> Result<HostInspection, String> {
    let path = state
        .paths
        .configuration_directory
        .join("ssh-host-keys.json");
    tauri::async_runtime::spawn_blocking(move || {
        let fingerprint = probe(&input.host, input.port)?;
        inspect_at(&path, &input.host, input.port, fingerprint)
    })
    .await
    .map_err(|_| "The SSH identity check was interrupted.".to_owned())?
}

#[tauri::command]
pub(crate) async fn trust_ssh_host(
    state: State<'_, AppState>,
    input: HostKeyInput,
    fingerprint: String,
) -> Result<(), String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let current = probe(&input.host, input.port)?;
        if current != fingerprint {
            return Err(
                "The SSH key changed during verification. Check the VPS identity again.".into(),
            );
        }
        remember_verified(&paths, &input.host, input.port, &fingerprint)
    })
    .await
    .map_err(|_| "Saving the SSH identity was interrupted.".to_owned())?
}

#[cfg(test)]
mod tests;
