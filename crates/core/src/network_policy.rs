use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(any(not(windows), test))]
use sirinvpn_protocol::INTERFACE_NAME;
use sirinvpn_protocol::{NetworkProfile, ServerId, TransportKind};
use std::{
    fmt, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(any(not(windows), test))]
use std::{
    fs,
    process::{Command, Stdio},
};
use thiserror::Error;
use zeroize::Zeroizing;

const NETWORK_POLICY_SCHEMA_VERSION: u16 = 2;
mod wifi;
pub use wifi::{TrustedWifiNetwork, WifiAutomationPolicy, WifiNetworkStatus, WifiPolicySnapshot};
const NETWORK_SALT_LENGTH: usize = 32;
const NETWORK_CACHE_TTL_DAYS: u64 = 7;
const SECONDS_PER_DAY: u64 = 86_400;
const MAX_DOCUMENT_BYTES: u64 = 16 * 1024;

#[derive(Debug, Error)]
pub enum NetworkPolicyError {
    #[error("network profile store operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("network profile store contains invalid data")]
    InvalidData,
    #[error("network profile store was written by a newer SirinVPN version")]
    UnsupportedSchema,
}

#[derive(Clone, Eq, PartialEq)]
pub struct NetworkContext {
    stable_identifier: Zeroizing<String>,
    wifi: bool,
    trustable: bool,
}

impl fmt::Debug for NetworkContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkContext")
            .field("stable_identifier", &"[REDACTED]")
            .finish()
    }
}

impl NetworkContext {
    #[cfg(target_os = "android")]
    pub fn android(identifier: String, wifi: bool, trustable: bool) -> Option<Self> {
        let mut context = Self::from_stable_identifier(format!("android-wifi:v1:{identifier}"))?;
        context.wifi = wifi;
        context.trustable = wifi && trustable;
        Some(context)
    }
    #[cfg(windows)]
    pub fn discover() -> Option<Self> {
        let current = sirinvpn_platform::windows::network_context::discover()?;
        Some(Self {
            stable_identifier: current.identifier,
            wifi: current.wifi,
            trustable: current.trustable,
        })
    }

    #[cfg(not(windows))]
    pub fn discover() -> Option<Self> {
        let routes = fs::read_to_string("/proc/net/route").ok()?;
        let route = parse_default_route(&routes)?;
        let uuid = network_manager_connection_uuid(&route.interface);
        let trustable = uuid.is_some();
        let wifi = Path::new("/sys/class/net")
            .join(&route.interface)
            .join("wireless")
            .exists();
        let identifier = uuid
            .map(|uuid| format!("networkmanager:v1:{uuid}"))
            .unwrap_or_else(|| {
                format!("default-route:v1:{}:{:08x}", route.interface, route.gateway)
            });
        let mut context = Self::from_stable_identifier(identifier)?;
        context.wifi = wifi;
        context.trustable = wifi && trustable;
        Some(context)
    }

    pub fn is_wifi(&self) -> bool {
        self.wifi
    }
    pub fn can_trust(&self) -> bool {
        self.wifi && self.trustable
    }

    fn from_stable_identifier(identifier: impl Into<String>) -> Option<Self> {
        let identifier = identifier.into();
        if identifier.is_empty() || identifier.len() > 512 || identifier.contains('\0') {
            return None;
        }
        Some(Self {
            stable_identifier: Zeroizing::new(identifier),
            wifi: false,
            trustable: false,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(any(not(windows), test))]
struct DefaultRoute {
    interface: String,
    gateway: u32,
    metric: u32,
}

#[cfg(any(not(windows), test))]
fn parse_default_route(contents: &str) -> Option<DefaultRoute> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 8
                || fields[1] != "00000000"
                || fields[7] != "00000000"
                || fields[0] == INTERFACE_NAME
                || fields[0] == "lo"
                || !valid_interface(fields[0])
            {
                return None;
            }
            let flags = u16::from_str_radix(fields[3], 16).ok()?;
            if flags & 1 == 0 {
                return None;
            }
            Some(DefaultRoute {
                interface: fields[0].to_owned(),
                gateway: u32::from_str_radix(fields[2], 16).ok()?,
                metric: fields[6].parse().ok()?,
            })
        })
        .min_by_key(|route| route.metric)
}

#[cfg(any(not(windows), test))]
fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(not(windows))]
fn network_manager_connection_uuid(interface: &str) -> Option<String> {
    let output = Command::new("nmcli")
        .args([
            "--wait",
            "2",
            "--terse",
            "--get-values",
            "GENERAL.CON-UUID",
            "device",
            "show",
            interface,
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 256 {
        return None;
    }
    let uuid = String::from_utf8(output.stdout).ok()?;
    let uuid = uuid.lines().next()?.trim();
    valid_uuid(uuid).then(|| uuid.to_ascii_lowercase())
}

#[cfg(any(not(windows), test))]
fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyDocument {
    schema_version: u16,
    salt_hex: String,
    network_profile: NetworkProfile,
    #[serde(default, skip_serializing_if = "wifi::is_default_policy")]
    wifi_automation: WifiAutomationPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    trusted_wifi: Vec<TrustedWifiNetwork>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_success: Option<CachedTransport>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedTransport {
    network_fingerprint_sha256: String,
    server_id: ServerId,
    transport: TransportKind,
    valid_through_utc_day: u64,
}

#[derive(Deserialize)]
struct SchemaProbe {
    schema_version: u16,
}

#[derive(Clone, Debug)]
pub struct NetworkPolicyStore {
    path: PathBuf,
}

impl NetworkPolicyStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn network_profile(&self) -> Result<NetworkProfile, NetworkPolicyError> {
        Ok(self
            .load_document()?
            .map_or_else(NetworkProfile::default, |document| document.network_profile))
    }

    pub fn set_network_profile(
        &self,
        network_profile: NetworkProfile,
    ) -> Result<(), NetworkPolicyError> {
        self.mutate(move |document| {
            document.network_profile = network_profile;
            Ok(())
        })
    }

    pub fn cached_transport(
        &self,
        server_id: ServerId,
        network: &NetworkContext,
    ) -> Result<Option<TransportKind>, NetworkPolicyError> {
        self.cached_transport_at(server_id, network, current_utc_day())
    }

    pub fn record_success(
        &self,
        server_id: ServerId,
        network: &NetworkContext,
        transport: TransportKind,
    ) -> Result<(), NetworkPolicyError> {
        self.record_success_at(server_id, network, transport, current_utc_day())
    }

    pub fn forget_server(&self, server_id: ServerId) -> Result<(), NetworkPolicyError> {
        if !self.path.exists() {
            return Ok(());
        }
        self.mutate(move |document| {
            if document.wifi_automation.server_id == Some(server_id) {
                document.wifi_automation = WifiAutomationPolicy::default();
            }
            if document
                .current_success
                .as_ref()
                .is_some_and(|cached| cached.server_id == server_id)
            {
                document.current_success = None;
            }
            Ok(())
        })
    }

    fn cached_transport_at(
        &self,
        server_id: ServerId,
        network: &NetworkContext,
        today: u64,
    ) -> Result<Option<TransportKind>, NetworkPolicyError> {
        let Some(document) = self.load_document()? else {
            return Ok(None);
        };
        let fingerprint = fingerprint_network(&decode_salt(&document.salt_hex)?, network);
        Ok(document.current_success.and_then(|cached| {
            (cached.server_id == server_id
                && cached.network_fingerprint_sha256 == fingerprint
                && cached.valid_through_utc_day >= today
                && cached.valid_through_utc_day <= today.saturating_add(NETWORK_CACHE_TTL_DAYS))
            .then_some(cached.transport)
        }))
    }

    fn record_success_at(
        &self,
        server_id: ServerId,
        network: &NetworkContext,
        transport: TransportKind,
        today: u64,
    ) -> Result<(), NetworkPolicyError> {
        self.mutate(|document| {
            let fingerprint = fingerprint_network(&decode_salt(&document.salt_hex)?, network);
            let valid_through_utc_day = document
                .current_success
                .as_ref()
                .filter(|cached| {
                    cached.server_id == server_id
                        && cached.network_fingerprint_sha256 == fingerprint
                        && cached.valid_through_utc_day >= today
                        && cached.valid_through_utc_day
                            <= today.saturating_add(NETWORK_CACHE_TTL_DAYS)
                })
                .map_or_else(
                    || today.saturating_add(NETWORK_CACHE_TTL_DAYS),
                    |cached| cached.valid_through_utc_day,
                );
            document.current_success = Some(CachedTransport {
                network_fingerprint_sha256: fingerprint,
                server_id,
                transport,
                valid_through_utc_day,
            });
            Ok(())
        })
    }

    fn mutate(
        &self,
        operation: impl FnOnce(&mut NetworkPolicyDocument) -> Result<(), NetworkPolicyError>,
    ) -> Result<(), NetworkPolicyError> {
        let parent = self.path.parent().ok_or_else(|| {
            NetworkPolicyError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing parent",
            ))
        })?;
        sirinvpn_platform::files::create_private_directory(parent)?;

        let lock_path = self.path.with_extension("lock");
        let lock = sirinvpn_platform::files::open_private_lock(&lock_path)?;
        lock.lock_exclusive()?;

        let mut document = self
            .load_document()?
            .unwrap_or_else(new_network_policy_document);
        operation(&mut document)?;
        document.schema_version = if document.wifi_automation == WifiAutomationPolicy::default()
            && document.trusted_wifi.is_empty()
        {
            1
        } else {
            NETWORK_POLICY_SCHEMA_VERSION
        };
        validate_document(&document)?;
        self.write_locked(parent, &document)?;
        FileExt::unlock(&lock)?;
        Ok(())
    }

    fn load_document(&self) -> Result<Option<NetworkPolicyDocument>, NetworkPolicyError> {
        let file = match sirinvpn_platform::files::open_no_follow(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if metadata.len() > MAX_DOCUMENT_BYTES {
            return Err(NetworkPolicyError::InvalidData);
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
            return Err(NetworkPolicyError::InvalidData);
        }
        let probe: SchemaProbe =
            serde_json::from_slice(&bytes).map_err(|_| NetworkPolicyError::InvalidData)?;
        if !(1..=NETWORK_POLICY_SCHEMA_VERSION).contains(&probe.schema_version) {
            return Err(NetworkPolicyError::UnsupportedSchema);
        }
        let document: NetworkPolicyDocument =
            serde_json::from_slice(&bytes).map_err(|_| NetworkPolicyError::InvalidData)?;
        validate_document(&document)?;
        Ok(Some(document))
    }

    fn write_locked(
        &self,
        _parent: &Path,
        document: &NetworkPolicyDocument,
    ) -> Result<(), NetworkPolicyError> {
        let bytes =
            serde_json::to_vec_pretty(document).map_err(|_| NetworkPolicyError::InvalidData)?;
        sirinvpn_platform::files::atomic_write(&self.path, &bytes, true)?;
        Ok(())
    }
}

fn new_network_policy_document() -> NetworkPolicyDocument {
    let mut salt = [0_u8; NETWORK_SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    NetworkPolicyDocument {
        schema_version: 1,
        wifi_automation: WifiAutomationPolicy::default(),
        trusted_wifi: Vec::new(),
        salt_hex: hex::encode(salt),
        network_profile: NetworkProfile::default(),
        current_success: None,
    }
}

fn validate_document(document: &NetworkPolicyDocument) -> Result<(), NetworkPolicyError> {
    if !(1..=NETWORK_POLICY_SCHEMA_VERSION).contains(&document.schema_version) {
        return Err(NetworkPolicyError::UnsupportedSchema);
    }
    wifi::validate(document)?;
    decode_salt(&document.salt_hex)?;
    if let Some(cached) = &document.current_success {
        let fingerprint = hex::decode(&cached.network_fingerprint_sha256)
            .map_err(|_| NetworkPolicyError::InvalidData)?;
        if fingerprint.len() != 32
            || fingerprint.iter().all(|byte| *byte == 0)
            || cached.valid_through_utc_day == 0
        {
            return Err(NetworkPolicyError::InvalidData);
        }
    }
    Ok(())
}

fn decode_salt(value: &str) -> Result<[u8; NETWORK_SALT_LENGTH], NetworkPolicyError> {
    let decoded = hex::decode(value).map_err(|_| NetworkPolicyError::InvalidData)?;
    let salt: [u8; NETWORK_SALT_LENGTH] = decoded
        .try_into()
        .map_err(|_| NetworkPolicyError::InvalidData)?;
    if salt.iter().all(|byte| *byte == 0) {
        return Err(NetworkPolicyError::InvalidData);
    }
    Ok(salt)
}

fn fingerprint_network(salt: &[u8; NETWORK_SALT_LENGTH], network: &NetworkContext) -> String {
    let mut digest = Sha256::new();
    digest.update(b"SirinVPN local network cache v1\0");
    digest.update(salt);
    digest.update((network.stable_identifier.len() as u64).to_be_bytes());
    digest.update(network.stable_identifier.as_bytes());
    hex::encode(digest.finalize())
}

fn current_utc_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / SECONDS_PER_DAY
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn default_route_parser_chooses_the_lowest_metric_physical_route() {
        let routes = concat!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n",
            "sirinvpn0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n",
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t500\t00000000\n",
            "wlan0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\n",
        );
        assert_eq!(
            parse_default_route(routes),
            Some(DefaultRoute {
                interface: "wlan0".to_owned(),
                gateway: 0x0100000A,
                metric: 100,
            })
        );
        assert!(parse_default_route("malformed").is_none());
    }

    #[test]
    fn profile_and_success_cache_are_private_atomic_local_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-policy.json");
        let store = NetworkPolicyStore::new(path.clone());
        assert_eq!(store.network_profile().unwrap(), NetworkProfile::Automatic);
        assert!(!path.exists());

        store
            .set_network_profile(NetworkProfile::Restricted)
            .unwrap();
        let network = NetworkContext::from_stable_identifier(
            "networkmanager:v1:12345678-1234-1234-1234-123456789abc",
        )
        .unwrap();
        let server_id = ServerId::new();
        store
            .record_success_at(server_id, &network, TransportKind::TcpFallback, 20_000)
            .unwrap();

        assert_eq!(store.network_profile().unwrap(), NetworkProfile::Restricted);
        assert_eq!(
            store
                .cached_transport_at(server_id, &network, 20_001)
                .unwrap(),
            Some(TransportKind::TcpFallback)
        );
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("12345678-1234-1234-1234-123456789abc"));
        assert!(!contents.contains("networkmanager"));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(directory.path().join("network-policy.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn cache_expires_and_overwrites_instead_of_building_network_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-policy.json");
        let store = NetworkPolicyStore::new(path.clone());
        let first = NetworkContext::from_stable_identifier("default-route:v1:wlan0:first").unwrap();
        let second =
            NetworkContext::from_stable_identifier("default-route:v1:wlan0:second").unwrap();
        let server_id = ServerId::new();

        store
            .record_success_at(server_id, &first, TransportKind::ObfuscatedUdp, 1_000)
            .unwrap();
        assert_eq!(
            store.cached_transport_at(server_id, &first, 1_007).unwrap(),
            Some(TransportKind::ObfuscatedUdp)
        );
        assert_eq!(
            store.cached_transport_at(server_id, &first, 1_008).unwrap(),
            None
        );

        store
            .record_success_at(server_id, &second, TransportKind::TcpFallback, 1_008)
            .unwrap();
        assert_eq!(
            store.cached_transport_at(server_id, &first, 1_008).unwrap(),
            None
        );
        assert_eq!(
            store
                .cached_transport_at(server_id, &second, 1_008)
                .unwrap(),
            Some(TransportKind::TcpFallback)
        );
        let document: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert!(document["current_success"].is_object());
        assert!(document.get("history").is_none());
        let encoded = document.to_string();
        assert!(!encoded.contains("wlan0"));
        assert!(!encoded.contains("first"));
        assert!(!encoded.contains("second"));
    }

    #[test]
    fn cache_is_server_bound_and_can_be_forgotten() {
        let directory = tempfile::tempdir().unwrap();
        let store = NetworkPolicyStore::new(directory.path().join("network-policy.json"));
        let network = NetworkContext::from_stable_identifier("route").unwrap();
        let first_server = ServerId::new();
        let second_server = ServerId::new();
        store
            .record_success_at(first_server, &network, TransportKind::DirectUdp, 2_000)
            .unwrap();
        assert_eq!(
            store
                .cached_transport_at(second_server, &network, 2_000)
                .unwrap(),
            None
        );
        store.forget_server(first_server).unwrap();
        assert_eq!(
            store
                .cached_transport_at(first_server, &network, 2_000)
                .unwrap(),
            None
        );
    }

    #[test]
    fn future_schema_is_preserved_for_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-policy.json");
        let original = br#"{"schema_version":3,"future":"preserve me"}"#;
        fs::write(&path, original).unwrap();
        let store = NetworkPolicyStore::new(path.clone());

        assert!(matches!(
            store.network_profile(),
            Err(NetworkPolicyError::UnsupportedSchema)
        ));
        assert!(matches!(
            store.set_network_profile(NetworkProfile::Extreme),
            Err(NetworkPolicyError::UnsupportedSchema)
        ));
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn corrupt_document_is_preserved_and_never_used() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-policy.json");
        let original = br#"{\"schema_version\":1,\"network_profile\":\"extreme\",\"broken\":true}"#;
        fs::write(&path, original).unwrap();
        let store = NetworkPolicyStore::new(path.clone());
        let network = NetworkContext::from_stable_identifier("route").unwrap();

        assert!(matches!(
            store.network_profile(),
            Err(NetworkPolicyError::InvalidData)
        ));
        assert!(matches!(
            store.cached_transport(ServerId::new(), &network),
            Err(NetworkPolicyError::InvalidData)
        ));
        assert!(matches!(
            store.set_network_profile(NetworkProfile::Normal),
            Err(NetworkPolicyError::InvalidData)
        ));
        assert_eq!(fs::read(path).unwrap(), original);
    }
}
