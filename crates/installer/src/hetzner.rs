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

const REPLACE_HOST_KEY: &str = "set -eu
key=/etc/ssh/ssh_host_ed25519_key
rm -f \"$key.new\" \"$key.new.pub\"
ssh-keygen -q -t ed25519 -N '' -C '' -f \"$key.new\"
mv -f \"$key.new.pub\" \"$key.pub\"
mv -f \"$key.new\" \"$key\"
/usr/sbin/sshd -t
systemctl reload ssh
cat \"$key.pub\"";

/// Replaces the pre-seeded host key with one generated on the server and
/// returns its fingerprint, read over the session pinned to the old key.
pub fn replace_host_key(target: &SshTarget) -> Result<String, InstallerError> {
    let session = crate::connect_transport(target)
        .map_err(|error| crate::phase_error("connection", error))?;
    crate::verify_host_key(&session, target.expected_host_key_sha256.as_deref())?;
    crate::authenticate(&session, target)?;
    let public = crate::run(&session, REPLACE_HOST_KEY)
        .map_err(|error| crate::phase_error("host key", error))?;
    public
        .strip_prefix("ssh-ed25519 ")
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|key| STANDARD.decode(key).ok())
        .filter(|blob| blob.starts_with(b"\0\0\0\x0bssh-ed25519"))
        .map(|blob| fingerprint(&blob))
        .ok_or_else(|| crate::phase_error("host key", anyhow::anyhow!("unexpected host key")))
}

/// Saves the login key next to the app's settings so the Owner can reach the
/// VPS later, also outside SirinVPN. The file is readable only by this user.
pub fn save_login_key(
    configuration_directory: &Path,
    server: &PreparedServer,
) -> std::io::Result<PathBuf> {
    let directory = configuration_directory.join("ssh-keys");
    sirinvpn_platform::files::create_private_directory(&directory)?;
    let path = directory.join(&server.name);
    sirinvpn_platform::files::atomic_write(&path, server.login_private_key().as_bytes(), false)?;
    Ok(path)
}

fn login_key_path(configuration_directory: &Path, name: &str) -> std::io::Result<PathBuf> {
    // The name comes back from the UI; accept only names `PreparedServer` generates.
    let generated = name
        .strip_prefix("sirinvpn-")
        .is_some_and(|suffix| suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    if !generated {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    Ok(configuration_directory.join("ssh-keys").join(name))
}

pub fn load_login_key(
    configuration_directory: &Path,
    name: &str,
) -> std::io::Result<Zeroizing<String>> {
    std::fs::read_to_string(login_key_path(configuration_directory, name)?).map(Zeroizing::new)
}

/// Removes the saved login key once its server is deleted.
pub fn forget_login_key(configuration_directory: &Path, name: &str) -> std::io::Result<()> {
    match std::fs::remove_file(login_key_path(configuration_directory, name)?) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[derive(Clone, Copy)]
struct Wait {
    running: Duration,
    ssh: Duration,
    poll: Duration,
}

pub struct HetznerClient {
    http: Client,
    base: Url,
    authorization: HeaderValue,
    wait: Wait,
}

impl std::fmt::Debug for HetznerClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HetznerClient([REDACTED])")
    }
}

impl HetznerClient {
    pub fn new(token: &str) -> Result<Self, HetznerError> {
        #[allow(unused_mut)]
        let mut builder = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .user_agent("SirinVPN");
        // rustls-native-certs does not read Android's trust store.
        #[cfg(target_os = "android")]
        for directory in [
            "/apex/com.android.conscrypt/cacerts",
            "/system/etc/security/cacerts",
        ] {
            let roots = std::fs::read_dir(directory)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|entry| std::fs::read(entry.path()).ok())
                .filter_map(|pem| reqwest::Certificate::from_pem(&pem).ok())
                .collect::<Vec<_>>();
            if !roots.is_empty() {
                for root in roots {
                    builder = builder.add_root_certificate(root);
                }
                break;
            }
        }
        let http = builder
            .build()
            .map_err(|error| HetznerError::Request(error.to_string()))?;
        Self::with(
            http,
            Url::parse(API).expect("valid API URL"),
            token,
            Wait {
                running: Duration::from_secs(5 * 60),
                ssh: Duration::from_secs(5 * 60),
                poll: Duration::from_secs(3),
            },
        )
    }

    fn with(http: Client, base: Url, token: &str, wait: Wait) -> Result<Self, HetznerError> {
        let token = token.trim();
        if !(16..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(HetznerError::InvalidToken);
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| HetznerError::InvalidToken)?;
        authorization.set_sensitive(true);
        Ok(Self {
            http,
            base,
            authorization,
            wait,
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T, HetznerError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| HetznerError::InvalidResponse)?;
        let mut request = self
            .http
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone());
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| HetznerError::Request(error.without_url().to_string()))?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| HetznerError::Request(error.without_url().to_string()))?
        {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > MAX_RESPONSE_BYTES {
                return Err(HetznerError::InvalidResponse);
            }
        }
        if !status.is_success() {
            let error: Value = serde_json::from_slice(&bytes).unwrap_or_default();
            let text = |key: &str, fallback: &str| {
                error["error"][key]
                    .as_str()
                    .unwrap_or(fallback)
                    .chars()
                    .filter(|character| !character.is_control())
                    .take(300)
                    .collect::<String>()
            };
            return Err(HetznerError::Api {
                status: status.as_u16(),
                code: text("code", "http_error"),
                message: text("message", status.canonical_reason().unwrap_or("error")),
            });
        }
        if status == StatusCode::NO_CONTENT {
            bytes = b"null".to_vec();
        }
        serde_json::from_slice(&bytes).map_err(|_| HetznerError::InvalidResponse)
    }

    /// Every page of a list endpoint.
    async fn list<T: DeserializeOwned>(
        &self,
        path: &str,
        field: &str,
    ) -> Result<Vec<T>, HetznerError> {
        let mut items = Vec::new();
        for page in 1..=20 {
            let separator = if path.contains('?') { '&' } else { '?' };
            let mut response: Value = self
                .call(
                    Method::GET,
                    &format!("{path}{separator}per_page=50&page={page}"),
                    None,
                )
                .await?;
            let batch: Vec<T> = serde_json::from_value(response[field].take())
                .map_err(|_| HetznerError::InvalidResponse)?;
            items.extend(batch);
            if response["meta"]["pagination"]["next_page"]
                .as_u64()
                .is_none()
            {
                return Ok(items);
            }
        }
        Err(HetznerError::InvalidResponse)
    }

    /// Locations and server types with monthly prices. Arm types are listed only
    /// when the caller has an aarch64 server payload.
    pub async fn catalog(&self, allow_arm: bool) -> Result<HetznerCatalog, HetznerError> {
        let locations: Vec<HetznerLocation> = self.list("locations", "locations").await?;
        let types: Vec<ApiServerType> = self.list("server_types", "server_types").await?;
        let pricing: ApiPricing = self.call(Method::GET, "pricing", None).await?;
        let ipv4 = pricing
            .pricing
            .primary_ips
            .into_iter()
            .find(|price| price.kind == "ipv4")
            .map(|price| price.prices)
            .unwrap_or_default();
        let server_types = types
            .into_iter()
            .filter(|kind| {
                !kind.deprecated.unwrap_or(false)
                    && kind.deprecation.is_none()
                    && (kind.architecture == "x86" || allow_arm && kind.architecture == "arm")
            })
            .filter_map(|kind| {
                let prices = kind
                    .prices
                    .iter()
                    .filter(|price| {
                        kind.locations.is_empty()
                            || kind.locations.iter().any(|location| {
                                location.name == price.location
                                    && location.available.unwrap_or(true)
                                    && location.deprecation.is_none()
                            })
                    })
                    .filter_map(|price| {
                        let server = money(&price.price_monthly.gross)?;
                        let address = ipv4
                            .iter()
                            .find(|address| address.location == price.location)
                            .and_then(|address| money(&address.price_monthly.gross));
                        Some(HetznerPrice {
                            location: price.location.clone(),
                            server_monthly: cents(server),
                            ipv4_monthly: address.map(cents),
                            total_monthly: cents(server.checked_add(address.unwrap_or(0))?),
                        })
                    })
                    .collect::<Vec<_>>();
                (!prices.is_empty()).then_some(HetznerServerType {
                    name: kind.name,
                    description: kind.description,
                    architecture: kind.architecture,
                    cores: kind.cores,
                    memory_gb: kind.memory,
                    disk_gb: kind.disk,
                    prices,
                })
            })
            .collect::<Vec<_>>();
        Ok(HetznerCatalog {
            currency: pricing.pricing.currency,
            image: IMAGE.to_owned(),
            locations: locations
                .into_iter()
                .filter(|location| {
                    server_types.iter().any(|kind| {
                        kind.prices
                            .iter()
                            .any(|price| price.location == location.name)
                    })
                })
                .collect(),
            server_types,
        })
    }

    /// Creates the server with the prepared keys. Returns once Hetzner accepted
    /// it; call [`Self::wait_until_ready`] next.
    pub async fn create_server(
        &self,
        prepared: &PreparedServer,
        request: &HetznerServerRequest,
        allow_arm: bool,
    ) -> Result<HetznerServer, HetznerError> {
        let catalog = self.catalog(allow_arm).await?;
        let architecture = catalog
            .server_types
            .iter()
            .find(|kind| kind.name == request.server_type)
            .map(|kind| kind.architecture.clone())
            .ok_or_else(|| {
                HetznerError::InvalidChoice("this server type is not available".to_owned())
            })?;
        let price = catalog
            .price(&request.location, &request.server_type)
            .ok_or_else(|| {
                HetznerError::InvalidChoice(
                    "this server type is not available in the chosen location".to_owned(),
                )
            })?;
        if price.total_monthly != request.accepted_monthly_price {
            return Err(HetznerError::PriceChanged(format!(
                "{} {}",
                price.total_monthly, catalog.currency
            )));
        }
        let images: Vec<ApiId> = self
            .list(
                &format!("images?type=system&name={IMAGE}&architecture={architecture}"),
                "images",
            )
            .await?;
        let image = images.first().ok_or_else(|| {
            HetznerError::InvalidChoice(format!(
                "Hetzner Cloud offers no Debian 13 image for {architecture} servers"
            ))
        })?;

        let labels: Value = serde_json::from_str(LABELS).expect("valid labels");
        let key = match self
            .call::<ApiSshKey>(
                Method::POST,
                "ssh_keys",
                Some(json!({
                    "name": prepared.name,
                    "public_key": openssh_public_key(&prepared.login, &format!("{}-login", prepared.name)),
                    "labels": labels,
                })),
            )
            .await
        {
            Ok(key) => key.ssh_key.id,
            Err(error) => {
                if !refused(&error) && let Some(id) = self.find("ssh_keys", &prepared.name).await {
                    self.forget_ssh_key(id).await;
                }
                return Err(error);
            }
        };
        let created = self
            .call::<ApiServerResponse>(
                Method::POST,
                "servers",
                Some(json!({
                    "name": prepared.name,
                    "server_type": request.server_type,
                    "location": request.location,
                    "image": image.id.to_string(),
                    "ssh_keys": [key],
                    "user_data": prepared.user_data(),
                    "labels": labels,
                    "start_after_create": true,
                    "public_net": {"enable_ipv4": true, "enable_ipv6": true},
                })),
            )
            .await;
        let server = match created {
            Ok(response) => Ok(response.server.id),
            Err(error) if refused(&error) => Err(error),
            // No answer, a server error or an unreadable answer: the server may
            // exist anyway. Look it up before reporting.
            Err(_) => self
                .find("servers", &prepared.name)
                .await
                .ok_or_else(|| HetznerError::Uncertain(prepared.name.clone())),
        };
        // The login key reaches root through user_data too, so the per-server
        // project key is no longer needed once the server exists (or failed).
        self.forget_ssh_key(key).await;
        Ok(HetznerServer {
            id: server?,
            name: prepared.name.clone(),
            host_key_sha256: prepared.host_key_sha256(),
        })
    }

    /// Waits until the server runs and answers SSH with the pre-seeded host key,
    /// then replaces that key over the pinned session. Pin the returned key.
    pub async fn wait_until_ready(
        &self,
        server: &HetznerServer,
        login_private_key: Zeroizing<String>,
        cancel: &AtomicBool,
    ) -> Result<HetznerReady, HetznerError> {
        let pin = server.host_key_sha256.clone();
        self.wait_with(
            server,
            cancel,
            |ipv4| {
                Provisioner::host_key_fingerprint(&SshTarget {
                    host: ipv4.to_string(),
                    port: 22,
                    username: "unused".to_owned(),
                    authentication: SshAuthentication::Agent,
                    sudo_password: None,
                    expected_host_key_sha256: None,
                })
                .ok()
            },
            move |ipv4| {
                replace_host_key(&ssh_target(ipv4, login_private_key, pin))
                    .map_err(|error| HetznerError::HostKeyReplacement(error.to_string()))
            },
        )
        .await
    }

    async fn wait_with(
        &self,
        server: &HetznerServer,
        cancel: &AtomicBool,
        probe: impl Fn(Ipv4Addr) -> Option<String> + Clone + Send + 'static,
        replace: impl FnOnce(Ipv4Addr) -> Result<String, HetznerError> + Send + 'static,
    ) -> Result<HetznerReady, HetznerError> {
        let deadline = Instant::now() + self.wait.running;
        let (ipv4, ipv6) = loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(HetznerError::Cancelled);
            }
            let current: ApiServerResponse = self
                .call(Method::GET, &format!("servers/{}", server.id), None)
                .await?;
            let network = current.server.public_net;
            if current.server.status == "running"
                && let Some(ipv4) = network.ipv4.and_then(|address| address.ip.parse().ok())
            {
                break (
                    ipv4,
                    network.ipv6.and_then(|address| first_address(&address.ip)),
                );
            }
            if Instant::now() > deadline {
                return Err(HetznerError::Timeout("start"));
            }
            tokio::time::sleep(self.wait.poll).await;
        };
        self.wait_for_key(ipv4, &server.host_key_sha256, None, cancel, &probe)
            .await?;
        let host_key_sha256 = tokio::task::spawn_blocking(move || replace(ipv4))
            .await
            .map_err(|error| HetznerError::HostKeyReplacement(error.to_string()))??;
        // sshd restarts on reload; until then it may still present the old key.
        self.wait_for_key(
            ipv4,
            &host_key_sha256,
            Some(&server.host_key_sha256),
            cancel,
            &probe,
        )
        .await?;
        Ok(HetznerReady {
            ipv4,
            ipv6,
            host_key_sha256,
        })
    }

    async fn wait_for_key(
        &self,
        ipv4: Ipv4Addr,
        expected: &str,
        previous: Option<&str>,
        cancel: &AtomicBool,
        probe: &(impl Fn(Ipv4Addr) -> Option<String> + Clone + Send + 'static),
    ) -> Result<(), HetznerError> {
        let deadline = Instant::now() + self.wait.ssh;
        let mut mismatch = false;
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(HetznerError::Cancelled);
            }
            let probe = probe.clone();
            match tokio::task::spawn_blocking(move || probe(ipv4)).await {
                Ok(Some(fingerprint)) if fingerprint == expected => return Ok(()),
                Ok(Some(fingerprint)) if Some(fingerprint.as_str()) == previous => {}
                // Keep waiting: cloud-init may not have written the key yet.
                Ok(Some(_)) => mismatch = true,
                _ => {}
            }
            if Instant::now() > deadline {
                return Err(if mismatch {
                    HetznerError::HostKeyMismatch
                } else {
                    HetznerError::Timeout("accept SSH connections")
                });
            }
            tokio::time::sleep(self.wait.poll).await;
        }
    }

    /// The ID of the named resource, if it exists.
    async fn find(&self, collection: &str, name: &str) -> Option<u64> {
        self.list::<ApiId>(&format!("{collection}?name={name}"), collection)
            .await
            .ok()?
            .first()
            .map(|item| item.id)
    }

    async fn forget_ssh_key(&self, id: u64) {
        let _ = self
            .call::<serde::de::IgnoredAny>(Method::DELETE, &format!("ssh_keys/{id}"), None)
            .await;
    }

    /// Deletes the server. A server that no longer exists counts as deleted.
    pub async fn delete_server(&self, id: u64) -> Result<(), HetznerError> {
        match self
            .call::<serde::de::IgnoredAny>(Method::DELETE, &format!("servers/{id}"), None)
            .await
        {
            Ok(_) | Err(HetznerError::Api { status: 404, .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Deserialize)]
struct ApiId {
    id: u64,
}

#[derive(Deserialize)]
struct ApiSshKey {
    ssh_key: ApiId,
}

#[derive(Deserialize)]
struct ApiServerResponse {
    server: ApiServer,
}

#[derive(Deserialize)]
struct ApiServer {
    id: u64,
    status: String,
    public_net: ApiPublicNet,
}

#[derive(Deserialize)]
struct ApiPublicNet {
    ipv4: Option<ApiAddress>,
    ipv6: Option<ApiAddress>,
}

#[derive(Deserialize)]
struct ApiAddress {
    ip: String,
}

#[derive(Deserialize)]
struct ApiServerType {
    name: String,
    description: String,
    cores: f64,
    memory: f64,
    disk: f64,
    architecture: String,
    deprecated: Option<bool>,
    deprecation: Option<Value>,
    prices: Vec<ApiPrice>,
    #[serde(default)]
    locations: Vec<ApiTypeLocation>,
}

#[derive(Deserialize)]
struct ApiTypeLocation {
    name: String,
    available: Option<bool>,
    deprecation: Option<Value>,
}

#[derive(Deserialize)]
struct ApiPrice {
    location: String,
    price_monthly: ApiAmount,
}

#[derive(Deserialize)]
struct ApiAmount {
    gross: String,
}

#[derive(Deserialize)]
struct ApiPricing {
    pricing: ApiPricingBody,
}

#[derive(Deserialize)]
struct ApiPricingBody {
    currency: String,
    #[serde(default)]
    primary_ips: Vec<ApiPrimaryIpPrice>,
}

#[derive(Deserialize)]
struct ApiPrimaryIpPrice {
    #[serde(rename = "type")]
    kind: String,
    prices: Vec<ApiPrice>,
}

/// Hetzner answered and refused, so nothing was created.
fn refused(error: &HetznerError) -> bool {
    matches!(error, HetznerError::Api { status, .. } if *status < 500)
}

/// A decimal string in ten-thousandths, the precision cents are rounded from.
fn money(value: &str) -> Option<u64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let fraction = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(4)
        .fold(0, |total, digit| total * 10 + u64::from(digit - b'0'));
    whole
        .parse::<u64>()
        .ok()?
        .checked_mul(10_000)?
        .checked_add(fraction)
}

fn cents(ten_thousandths: u64) -> String {
    let cents = (ten_thousandths + 50) / 100;
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// Hetzner assigns a /64; its first address is the server's.
fn first_address(network: &str) -> Option<Ipv6Addr> {
    let mut segments = network
        .split('/')
        .next()?
        .parse::<Ipv6Addr>()
        .ok()?
        .segments();
    segments[7] = 1;
    Some(Ipv6Addr::from(segments))
}

fn random_key() -> SigningKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    SigningKey::from_bytes(&seed)
}

fn ssh_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn public_key_blob(key: &SigningKey) -> Vec<u8> {
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-ed25519");
    ssh_string(&mut blob, key.verifying_key().as_bytes());
    blob
}

fn openssh_public_key(key: &SigningKey, comment: &str) -> String {
    format!(
        "ssh-ed25519 {} {comment}",
        STANDARD.encode(public_key_blob(key))
    )
}

/// SHA-256 of the public key blob, as the installer pins host keys.
fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// The unencrypted "openssh-key-v1" format that sshd and libssh2 both read.
fn openssh_private_key(key: &SigningKey, comment: &str) -> Zeroizing<String> {
    let public = key.verifying_key();
    // The check value only detects a wrong passphrase; a fixed one keeps the output stable.
    let check = &Sha256::digest(public.as_bytes())[..4];
    let mut private = Zeroizing::new(Vec::new());
    private.extend_from_slice(check);
    private.extend_from_slice(check);
    ssh_string(&mut private, b"ssh-ed25519");
    ssh_string(&mut private, public.as_bytes());
    let mut pair = Zeroizing::new(key.to_bytes().to_vec());
    pair.extend_from_slice(public.as_bytes());
    ssh_string(&mut private, &pair);
    ssh_string(&mut private, comment.as_bytes());
    for padding in 1..=(8 - private.len() % 8) % 8 {
        private.push(padding as u8);
    }
    let mut body = Zeroizing::new(b"openssh-key-v1\0".to_vec());
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"");
    body.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut body, &public_key_blob(key));
    ssh_string(&mut body, &private);
    let encoded = Zeroizing::new(STANDARD.encode(&*body));
    let mut pem = Zeroizing::new(String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    for line in encoded.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    pem
}

#[cfg(test)]
mod tests;
