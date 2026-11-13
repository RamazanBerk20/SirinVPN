//! One-click VPS creation on Hetzner Cloud.
//!
//! The API token is sent only to api.hetzner.cloud and is never stored. The SSH
//! login key and the SSH host key are generated here; the host key reaches the
//! VPS through cloud-init, so the first SSH connection is already pinned. That
//! connection replaces the host key, because cloud-init user data stays readable
//! on the server for its whole life.

use crate::{InstallerError, Provisioner, SshAuthentication, SshTarget};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use reqwest::{Client, Method, StatusCode, Url, header::HeaderValue};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use thiserror::Error;
use zeroize::Zeroizing;

const API: &str = "https://api.hetzner.cloud/v1/";
pub const IMAGE: &str = "debian-13";
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const LABELS: &str = r#"{"managed-by":"sirinvpn"}"#;

#[derive(Debug, Error)]
pub enum HetznerError {
    #[error("enter a valid Hetzner Cloud API token")]
    InvalidToken,
    #[error("Hetzner Cloud refused the request ({code}): {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error("Hetzner Cloud could not be reached: {0}")]
    Request(String),
    #[error("Hetzner Cloud returned an unexpected response")]
    InvalidResponse,
    #[error("{0}")]
    InvalidChoice(String),
    #[error("the monthly price changed to {0}; review the new price before creating the server")]
    PriceChanged(String),
    #[error(
        "Hetzner Cloud may have created server {0}; check the Hetzner Cloud Console and delete it there if it exists"
    )]
    Uncertain(String),
    #[error("the server did not {0} in time")]
    Timeout(&'static str),
    #[error(
        "the server answered SSH with a host key other than the pre-seeded one; it was not trusted"
    )]
    HostKeyMismatch,
    #[error("the server's SSH host key could not be replaced: {0}")]
    HostKeyReplacement(String),
    #[error("server creation was cancelled")]
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HetznerLocation {
    pub name: String,
    pub description: String,
    pub city: String,
    pub country: String,
}

/// Monthly gross prices as reported by Hetzner, rounded to cents.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HetznerPrice {
    pub location: String,
    pub server_monthly: String,
    /// Hetzner bills the primary IPv4 address separately.
    pub ipv4_monthly: Option<String>,
    pub total_monthly: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HetznerServerType {
    pub name: String,
    pub description: String,
    /// "x86" or "arm".
    pub architecture: String,
    pub cores: f64,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub prices: Vec<HetznerPrice>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HetznerCatalog {
    pub currency: String,
    pub image: String,
    pub locations: Vec<HetznerLocation>,
    pub server_types: Vec<HetznerServerType>,
}

impl HetznerCatalog {
    pub fn price(&self, location: &str, server_type: &str) -> Option<&HetznerPrice> {
        self.server_types
            .iter()
            .find(|candidate| candidate.name == server_type)?
            .prices
            .iter()
            .find(|price| price.location == location)
    }

    /// The default plan: the cheapest x86 type available in this location.
    pub fn cheapest_x86(&self, location: &str) -> Option<&HetznerServerType> {
        self.server_types
            .iter()
            .filter(|candidate| candidate.architecture == "x86")
            .filter_map(|candidate| {
                let price = candidate.prices.iter().find(|p| p.location == location)?;
                Some((money(&price.total_monthly)?, candidate))
            })
            .min_by_key(|(total, _)| *total)
            .map(|(_, candidate)| candidate)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HetznerServerRequest {
    pub location: String,
    pub server_type: String,
    /// The total the Owner confirmed. Creation stops if Hetzner's price differs.
    pub accepted_monthly_price: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HetznerServer {
    pub id: u64,
    pub name: String,
    pub host_key_sha256: String,
}

/// A running server and the host key that replaced the pre-seeded one.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HetznerReady {
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub host_key_sha256: String,
}

/// Keys and the server name, generated before anything is sent to Hetzner so a
/// caller can save the login key first.
pub struct PreparedServer {
    pub name: String,
    login: SigningKey,
    host: SigningKey,
}

impl PreparedServer {
    pub fn generate() -> Self {
        let mut suffix = [0u8; 4];
        OsRng.fill_bytes(&mut suffix);
        Self {
            name: format!("sirinvpn-{}", hex::encode(suffix)),
            login: random_key(),
            host: random_key(),
        }
    }

    /// The root login key in OpenSSH format, unencrypted.
    pub fn login_private_key(&self) -> Zeroizing<String> {
        openssh_private_key(&self.login, &format!("{}-login", self.name))
    }

    pub fn host_key_sha256(&self) -> String {
        fingerprint(&public_key_blob(&self.host))
    }

    pub fn user_data(&self) -> String {
        let host_private = openssh_private_key(&self.host, &format!("{}-host", self.name));
        let indented = host_private
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect::<String>();
        // Only the pre-seeded key exists, and sshd offers only it even if
        // something later generates other host key types.
        format!(
            "#cloud-config\n\
             disable_root: false\n\
             ssh_pwauth: false\n\
             ssh_deletekeys: true\n\
             ssh_authorized_keys:\n  - {}\n\
             ssh_keys:\n  ed25519_private: |\n{indented}  ed25519_public: {}\n\
             write_files:\n  - path: /etc/ssh/sshd_config.d/10-sirinvpn-host-key.conf\n    \
             permissions: \"0644\"\n    content: |\n      HostKey /etc/ssh/ssh_host_ed25519_key\n",
            openssh_public_key(&self.login, &format!("{}-login", self.name)),
            openssh_public_key(&self.host, &format!("{}-host", self.name)),
        )
    }
}

pub fn ssh_target(
    ipv4: Ipv4Addr,
    login_private_key: Zeroizing<String>,
    host_key_sha256: String,
) -> SshTarget {
    SshTarget {
        host: ipv4.to_string(),
        port: 22,
        username: "root".to_owned(),
        authentication: SshAuthentication::PrivateKeyMemory {
            private_key_pem: login_private_key,
            passphrase: None,
        },
        sudo_password: None,
        expected_host_key_sha256: Some(host_key_sha256),
    }
}

mod host_key;
use host_key::presented_host_key;
#[cfg(test)]
use host_key::{PREPARE_HOST_KEY, activate_host_key, public_key_fingerprint};
pub use host_key::{replace_host_key, replace_host_key_with};

mod keys;
use keys::{
    fingerprint, login_key_path, openssh_private_key, openssh_public_key, public_key_blob,
    random_key,
};
pub use keys::{forget_login_key, load_login_key, save_login_key};

const PROVISION_SCHEMA_VERSION: u16 = 1;

/// Where a Hetzner server creation stands. Persisted next to the login key
/// (never the token) after every phase, so an app or CLI that exits while
/// waiting can resume the same server or delete it instead of losing track.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum HetznerPhase {
    /// The login key is saved; the create request may or may not have reached Hetzner.
    Requested,
    /// Hetzner created the server; it answers SSH with the pre-seeded host key.
    Created { server_id: u64 },
    /// The replacement host key is known and may already be active.
    ReplacingHostKey {
        server_id: u64,
        replacement_host_key_sha256: String,
    },
    /// Running with the replacement host key: install SirinVPN, then forget the record.
    Ready { server_id: u64, ready: HetznerReady },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HetznerProvision {
    pub schema_version: u16,
    pub name: String,
    pub pre_seeded_host_key_sha256: String,
    pub phase: HetznerPhase,
}

impl HetznerProvision {
    pub fn requested(prepared: &PreparedServer) -> Self {
        Self {
            schema_version: PROVISION_SCHEMA_VERSION,
            name: prepared.name.clone(),
            pre_seeded_host_key_sha256: prepared.host_key_sha256(),
            phase: HetznerPhase::Requested,
        }
    }

    pub fn server_id(&self) -> Option<u64> {
        match self.phase {
            HetznerPhase::Requested => None,
            HetznerPhase::Created { server_id }
            | HetznerPhase::ReplacingHostKey { server_id, .. }
            | HetznerPhase::Ready { server_id, .. } => Some(server_id),
        }
    }

    fn path(configuration_directory: &Path, name: &str) -> std::io::Result<PathBuf> {
        let key = login_key_path(configuration_directory, name)?;
        Ok(key.with_file_name(format!("{name}.provision.json")))
    }

    /// Records this phase (private file, replaced atomically).
    pub fn save(&self, configuration_directory: &Path) -> std::io::Result<()> {
        let path = Self::path(configuration_directory, &self.name)?;
        sirinvpn_platform::files::create_private_directory(path.parent().expect("ssh-keys"))?;
        let bytes = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        sirinvpn_platform::files::atomic_write(&path, &bytes, true)
    }

    pub fn advance(
        &mut self,
        configuration_directory: &Path,
        phase: HetznerPhase,
    ) -> std::io::Result<()> {
        self.phase = phase;
        self.save(configuration_directory)
    }

    pub fn load(configuration_directory: &Path, name: &str) -> std::io::Result<Option<Self>> {
        let path = Self::path(configuration_directory, name)?;
        let bytes = match sirinvpn_platform::files::read_bounded(&path, 64 * 1024) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let provision: Self = serde_json::from_slice(&bytes)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        if provision.schema_version != PROVISION_SCHEMA_VERSION || provision.name != name {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        Ok(Some(provision))
    }

    /// Every creation not yet installed or deleted, to offer Resume or Delete.
    pub fn pending(configuration_directory: &Path) -> std::io::Result<Vec<Self>> {
        let directory = configuration_directory.join("ssh-keys");
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut pending = Vec::new();
        for entry in entries {
            let file = entry?.file_name();
            if let Some(name) = file
                .to_str()
                .and_then(|file| file.strip_suffix(".provision.json"))
                && let Some(provision) = Self::load(configuration_directory, name)?
            {
                pending.push(provision);
            }
        }
        pending.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(pending)
    }

    /// Drops the record once SirinVPN is installed or the server is deleted.
    pub fn forget(configuration_directory: &Path, name: &str) -> std::io::Result<()> {
        match std::fs::remove_file(Self::path(configuration_directory, name)?) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

mod client;
pub use client::HetznerClient;
#[cfg(test)]
use client::Wait;

mod api;
use api::{
    ApiId, ApiPricing, ApiServerResponse, ApiServerType, ApiSshKey, cents, first_address, money,
    refused,
};

#[cfg(test)]
mod tests;
