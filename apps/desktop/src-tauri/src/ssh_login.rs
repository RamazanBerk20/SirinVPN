//! SSH credentials stay in the OS credential store and never return to the UI.
use crate::{provisioning::take_ssh_authentication, ssh_trust};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use sirinvpn_installer::{Provisioner, SshTarget};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SERVICE: &str = "org.sirinvpn.client.ssh";
const MAX_LOGIN_BYTES: usize = 32_768;

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct SshLoginInput {
    pub(crate) host: String,
    pub(crate) ssh_port: u16,
    pub(crate) username: String,
    pub(crate) authentication: String,
    pub(crate) password: Option<String>,
    pub(crate) private_key_path: Option<String>,
    pub(crate) private_key_passphrase: Option<String>,
    pub(crate) sudo_password: Option<String>,
    pub(crate) host_key_sha256: String,
}

#[derive(Serialize)]
pub(crate) struct SavedSshLogin {
    username: String,
    ssh_port: u16,
    authentication: String,
    private_key_path: Option<String>,
}

fn account(host: &str) -> Result<String, String> {
    // The default port is part of the stored record, so it can be filled in
    // before inspection. Each host retains its most recently saved login.
    ssh_trust::endpoint(host, 22)
}

fn entry(host: &str) -> Result<Entry, String> {
    Entry::new(SERVICE, &account(host)?)
        .map_err(|_| "The desktop credential store is unavailable.".into())
}

fn read(host: &str) -> Result<Option<SshLoginInput>, String> {
    read_entry(host, &entry(host)?)
}

fn read_entry(host: &str, store: &Entry) -> Result<Option<SshLoginInput>, String> {
    let bytes = match store.get_secret() {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(_) => return Err("Unlock your desktop wallet to use the saved SSH login, or enter a login for this operation.".into()),
    };
    if bytes.len() > MAX_LOGIN_BYTES {
        return Err("The saved SSH login is invalid. Forget it and enter it again.".into());
    }
    let login: SshLoginInput = serde_json::from_slice(&bytes)
        .map_err(|_| "The saved SSH login is invalid. Forget it and enter it again.")?;
    validate(&login)?;
    if account(&login.host)? != account(host)? {
        return Err("The saved SSH login belongs to a different host.".into());
    }
    Ok(Some(login))
}

fn validate(login: &SshLoginInput) -> Result<(), String> {
    ssh_trust::endpoint(&login.host, login.ssh_port)?;
    if login.username.trim().is_empty()
        || login.username.len() > 256
        || !ssh_trust::valid_fingerprint(&login.host_key_sha256)
        || !["agent", "password", "private_key"].contains(&login.authentication.as_str())
        || login.authentication == "password"
            && login.password.as_ref().is_none_or(|p| p.is_empty())
        || login.authentication == "private_key"
            && login
                .private_key_path
                .as_ref()
                .is_none_or(|p| p.trim().is_empty())
    {
        return Err("Enter a valid SSH login and verify the VPS fingerprint.".into());
    }
    Ok(())
}

fn summary(login: &SshLoginInput) -> SavedSshLogin {
    SavedSshLogin {
        username: login.username.clone(),
        ssh_port: login.ssh_port,
        authentication: login.authentication.clone(),
        private_key_path: login.private_key_path.clone(),
    }
}

fn target(mut login: SshLoginInput) -> Result<SshTarget, String> {
    let authentication = take_ssh_authentication(
        &login.authentication,
        &mut login.password,
        &mut login.private_key_path,
        &mut login.private_key_passphrase,
    )?;
    Ok(SshTarget {
        host: login.host.clone(),
        port: login.ssh_port,
        username: login.username.clone(),
        authentication,
        sudo_password: login.sudo_password.take().map(Zeroizing::new),
        expected_host_key_sha256: Some(login.host_key_sha256.clone()),
    })
}

fn saved_target(host: &str, port: u16, fingerprint: &str) -> Result<SshTarget, String> {
    let login = read(host)?.ok_or("The saved SSH login was removed. Enter it again.")?;
    bound_target(login, port, fingerprint)
}

fn bound_target(login: SshLoginInput, port: u16, fingerprint: &str) -> Result<SshTarget, String> {
    if login.ssh_port != port || login.host_key_sha256 != fingerprint {
        return Err("The VPS SSH identity or port changed. Choose Change login and enter credentials for this destination.".into());
    }
    target(login)
}

pub(crate) fn resolve_target(login: SshLoginInput) -> Result<SshTarget, String> {
    if login.authentication == "saved" {
        saved_target(&login.host, login.ssh_port, &login.host_key_sha256)
    } else {
        validate(&login)?;
        target(login)
    }
}

#[tauri::command]
pub(crate) async fn get_ssh_login(host: String) -> Result<Option<SavedSshLogin>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        read(&host).map(|value| value.as_ref().map(summary))
    })
    .await
    .map_err(|_| "Reading the saved SSH login was interrupted.".to_owned())?
}

#[tauri::command]
pub(crate) async fn save_ssh_login(input: SshLoginInput) -> Result<SavedSshLogin, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let store = entry(&input.host)?;
        save_entry(input, &store, |target| {
            Provisioner::verify_ssh_login(target).map_err(|error| error.to_string())
        })
    })
    .await
    .map_err(|_| "Saving the SSH login was interrupted.".to_owned())?
}

fn save_entry(
    input: SshLoginInput,
    store: &Entry,
    verify: impl FnOnce(&SshTarget) -> Result<(), String>,
) -> Result<SavedSshLogin, String> {
    validate(&input)?;
    let bytes = Zeroizing::new(
        serde_json::to_vec(&input).map_err(|_| "The SSH login could not be saved.")?,
    );
    if bytes.len() > MAX_LOGIN_BYTES {
        return Err("The SSH login exceeds the size limit.".into());
    }
    let saved = summary(&input);
    // Authenticate before remembering a password, without running a command.
    verify(&target(input)?)?;
    store.set_secret(&bytes).map_err(|_| "The SSH login worked, but it could not be saved. Unlock your desktop wallet, or turn off Remember login to continue.".to_owned())?;
    Ok(saved)
}

#[cfg(test)]
mod tests;

#[tauri::command]
pub(crate) async fn forget_ssh_login(host: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || match entry(&host)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(
            "The saved SSH login could not be removed. Unlock your desktop wallet and try again."
                .into(),
        ),
    })
    .await
    .map_err(|_| "Removing the SSH login was interrupted.".to_owned())?
}
