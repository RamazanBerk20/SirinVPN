use crate::{
    encrypted_backup::{self, EncryptedBackupError},
    endpoint_transition, management_identity_fingerprint,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sirinvpn_protocol::{
    DEFAULT_MANAGEMENT_PORT, DnsUpstream, EndpointTransitionResponse, INTERFACE_NAME,
    ObfuscatedUdpEndpoint, PrivateDnsRecord, SERVER_TUNNEL_ADDRESS, ServerId, TUNNEL_CIDR,
    TcpFallbackEndpoint, TlsLikeEndpoint, validate_server_dns_configuration, validate_server_name,
};
use std::{io, net::IpAddr, path::Path};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const SERVER_BACKUP_FORMAT: &str = "sirinvpn-server-backup";
const MAX_SERVER_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
const MAX_SERVER_BACKUP_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SERVER_STATE_FILE_BYTES: usize = 64 * 1024;
const MAX_SERVER_AUTHORIZATION_BYTES: usize = 1024 * 1024;
#[cfg(test)]
const SERVER_BACKUP_SNAPSHOT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Error)]
pub enum ServerBackupError {
    #[error("the backup password must contain at least 12 characters")]
    WeakPassword,
    #[error("the backup password is invalid")]
    InvalidPassword,
    #[error("the backup destination already exists")]
    DestinationExists,
    #[error("the server backup snapshot is invalid")]
    InvalidSnapshot,
    #[error("the encrypted server backup is too large")]
    FileTooLarge,
    #[error("the server backup format is invalid")]
    InvalidFormat,
    #[error("the server backup format version is not supported")]
    IncompatibleVersion,
    #[error("the backup password is incorrect or the file was modified")]
    AuthenticationFailed,
    #[error("the server backup file operation failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerBackupMetadata {
    pub endpoint_discovery_port: Option<u16>,
    pub server_id: ServerId,
    pub server_name: String,
    pub server_tunnel_address: IpAddr,
    pub wireguard_port: u16,
    pub server_wireguard_public_key: String,
    pub management_certificate_pem: String,
    pub dns_upstream: DnsUpstream,
    pub private_dns_records: Vec<PrivateDnsRecord>,
    pub ipv6_tunnel_enabled: bool,
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    pub tls_like: Option<TlsLikeEndpoint>,
    pub endpoint_generation: u64,
}

pub struct DecryptedServerBackup {
    metadata: ServerBackupMetadata,
    snapshot: Zeroizing<Vec<u8>>,
}

impl DecryptedServerBackup {
    pub fn metadata(&self) -> &ServerBackupMetadata {
        &self.metadata
    }

    pub fn snapshot(&self) -> &[u8] {
        self.snapshot.as_slice()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerBackupSnapshot {
    schema_version: u16,
    server_id: ServerId,
    configuration_json: String,
    wireguard_private_key: String,
    transport_private_key: Option<String>,
    management_certificate_pem: String,
    management_private_key_pem: String,
    authorization_json: Option<String>,
    authorization_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    https_private_key_pem: Option<String>,
}

impl Drop for ServerBackupSnapshot {
    fn drop(&mut self) {
        if let Some(key) = &mut self.https_private_key_pem {
            key.zeroize();
        }
        self.configuration_json.zeroize();
        self.wireguard_private_key.zeroize();
        if let Some(value) = &mut self.transport_private_key {
            value.zeroize();
        }
        self.management_certificate_pem.zeroize();
        self.management_private_key_pem.zeroize();
        if let Some(value) = &mut self.authorization_json {
            value.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupServerConfiguration {
    #[serde(default)]
    public_endpoint: Option<sirinvpn_protocol::ServerEndpoint>,
    #[serde(default)]
    alternate_endpoint_hosts: Vec<String>,
    #[serde(default)]
    endpoint_discovery_port: Option<u16>,
    schema_version: u16,
    server_name: String,
    interface_name: String,
    tunnel_cidr: String,
    server_tunnel_address: IpAddr,
    wireguard_port: u16,
    management_port: u16,
    wireguard_public_key: String,
    owner_certificate_pem: String,
    #[serde(default)]
    dns_upstream: DnsUpstream,
    #[serde(default)]
    private_dns_records: Vec<PrivateDnsRecord>,
    #[serde(default)]
    ipv6_tunnel_enabled: bool,
    #[serde(default)]
    obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    #[serde(default)]
    tcp_fallback: Option<TcpFallbackEndpoint>,
    #[serde(default)]
    tls_like: Option<TlsLikeEndpoint>,
    #[serde(default)]
    https_certificate_pem: Option<String>,
}

#[derive(Deserialize)]
struct BackupAuthorizationState {
    #[serde(default)]
    endpoint_transition_source: bool,
    schema_version: u16,
    server_id: ServerId,
    #[serde(default)]
    endpoint_transition: Option<EndpointTransitionResponse>,
}

pub fn validate_server_backup_password(password: &str) -> Result<(), ServerBackupError> {
    encrypted_backup::validate_export_password(password).map_err(map_encrypted_backup_error)
}

pub fn write_encrypted_server_backup(
    destination: &Path,
    snapshot: &[u8],
    password: &str,
) -> Result<(), ServerBackupError> {
    validate_server_backup_password(password)?;
    if snapshot.is_empty() || snapshot.len() > MAX_SERVER_SNAPSHOT_BYTES {
        return Err(ServerBackupError::InvalidSnapshot);
    }
    let encrypted = encrypted_backup::encrypt(SERVER_BACKUP_FORMAT, snapshot, password)
        .map_err(map_encrypted_backup_error)?;
    if encrypted.len() > MAX_SERVER_BACKUP_FILE_BYTES {
        return Err(ServerBackupError::FileTooLarge);
    }
    encrypted_backup::write_file(destination, &encrypted, ".sirinvpn-server-backup-")
        .map_err(map_encrypted_backup_error)
}

pub fn read_encrypted_server_backup(
    source: &Path,
    password: &str,
) -> Result<DecryptedServerBackup, ServerBackupError> {
    encrypted_backup::validate_import_password(password).map_err(map_encrypted_backup_error)?;
    let encrypted = encrypted_backup::read_file(source, MAX_SERVER_BACKUP_FILE_BYTES)
        .map_err(map_encrypted_backup_error)?;
    let snapshot = encrypted_backup::decrypt(SERVER_BACKUP_FORMAT, &encrypted, password)
        .map_err(map_encrypted_backup_error)?;
    if snapshot.is_empty() || snapshot.len() > MAX_SERVER_SNAPSHOT_BYTES {
        return Err(ServerBackupError::InvalidSnapshot);
    }
    let decoded: ServerBackupSnapshot = serde_json::from_slice(snapshot.as_slice())
        .map_err(|_| ServerBackupError::InvalidSnapshot)?;
    let metadata = validate_snapshot(&decoded)?;
    Ok(DecryptedServerBackup { metadata, snapshot })
}

fn validate_snapshot(
    snapshot: &ServerBackupSnapshot,
) -> Result<ServerBackupMetadata, ServerBackupError> {
    if !matches!(snapshot.schema_version, 1 | 2)
        || (snapshot.schema_version == 2) != snapshot.https_private_key_pem.is_some()
    {
        return Err(ServerBackupError::IncompatibleVersion);
    }
    if snapshot.configuration_json.is_empty()
        || snapshot.configuration_json.len() > MAX_SERVER_STATE_FILE_BYTES
        || snapshot.wireguard_private_key.is_empty()
        || snapshot.wireguard_private_key.len() > MAX_SERVER_STATE_FILE_BYTES
        || snapshot.management_certificate_pem.is_empty()
        || snapshot.management_certificate_pem.len() > MAX_SERVER_STATE_FILE_BYTES
        || snapshot.management_private_key_pem.is_empty()
        || snapshot.management_private_key_pem.len() > MAX_SERVER_STATE_FILE_BYTES
        || snapshot
            .transport_private_key
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_SERVER_STATE_FILE_BYTES)
        || snapshot
            .authorization_json
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_SERVER_AUTHORIZATION_BYTES)
        || (snapshot.authorization_required && snapshot.authorization_json.is_none())
    {
        return Err(ServerBackupError::InvalidSnapshot);
    }

    let configuration: BackupServerConfiguration =
        serde_json::from_str(&snapshot.configuration_json)
            .map_err(|_| ServerBackupError::InvalidSnapshot)?;
    if configuration.schema_version > 8 {
        return Err(ServerBackupError::IncompatibleVersion);
    }
    let https = configuration
        .tls_like
        .as_ref()
        .and_then(|endpoint| endpoint.https.as_ref());
    if (configuration.schema_version < 7 && https.is_some())
        || (configuration.schema_version == 7 && https.is_none())
        || https.is_some_and(|https| !https.is_valid())
        || configuration.https_certificate_pem.is_some() != snapshot.https_private_key_pem.is_some()
        || configuration
            .https_certificate_pem
            .as_ref()
            .is_some_and(|pem| pem.is_empty() || pem.len() > 65_536)
        || snapshot
            .https_private_key_pem
            .as_ref()
            .is_some_and(|pem| pem.is_empty() || pem.len() > 65_536)
    {
        return Err(ServerBackupError::InvalidSnapshot);
    }
    validate_server_name(&configuration.server_name)
        .map_err(|_| ServerBackupError::InvalidSnapshot)?;
    if (configuration.schema_version == 8) != configuration.public_endpoint.is_some()
        || (configuration.public_endpoint.is_none()
            && (!configuration.alternate_endpoint_hosts.is_empty()
                || configuration.endpoint_discovery_port.is_some()))
    {
        return Err(ServerBackupError::InvalidSnapshot);
    }
    if let Some(endpoint) = &configuration.public_endpoint {
        if endpoint.wireguard_port != configuration.wireguard_port {
            return Err(ServerBackupError::InvalidSnapshot);
        }
        crate::endpoint_transition::validate_descriptor(&sirinvpn_protocol::EndpointDescriptor {
            endpoint: endpoint.clone(),
            alternate_endpoint_hosts: configuration.alternate_endpoint_hosts.clone(),
            endpoint_discovery_port: configuration.endpoint_discovery_port,
            ipv6_tunnel_enabled: configuration.ipv6_tunnel_enabled,
            obfuscated_udp: configuration.obfuscated_udp.clone(),
            tcp_fallback: configuration.tcp_fallback.clone(),
            tls_like: configuration.tls_like.clone(),
        })
        .map_err(|_| ServerBackupError::InvalidSnapshot)?;
    }
    validate_server_dns_configuration(
        configuration.schema_version,
        &configuration.dns_upstream,
        &configuration.private_dns_records,
    )
    .map_err(|_| ServerBackupError::InvalidSnapshot)?;
    if configuration.interface_name != INTERFACE_NAME
        || configuration.tunnel_cidr != TUNNEL_CIDR
        || configuration.server_tunnel_address
            != SERVER_TUNNEL_ADDRESS
                .parse::<IpAddr>()
                .map_err(|_| ServerBackupError::InvalidSnapshot)?
        || configuration.wireguard_port == 0
        || configuration.management_port != DEFAULT_MANAGEMENT_PORT
        || !valid_wireguard_public_key(&configuration.wireguard_public_key)
        || management_identity_fingerprint(&configuration.owner_certificate_pem).is_err()
        || management_identity_fingerprint(&snapshot.management_certificate_pem).is_err()
    {
        return Err(ServerBackupError::InvalidSnapshot);
    }
    validate_transport_configuration(
        configuration.wireguard_port,
        configuration.obfuscated_udp.as_ref(),
        configuration.tcp_fallback.as_ref(),
        configuration.tls_like.as_ref(),
        snapshot.transport_private_key.is_some(),
    )?;
    let endpoint_generation = match &snapshot.authorization_json {
        Some(encoded) => {
            let authorization: BackupAuthorizationState =
                serde_json::from_str(encoded).map_err(|_| ServerBackupError::InvalidSnapshot)?;
            if !matches!(authorization.schema_version, 1..=5)
                || authorization.server_id != snapshot.server_id
            {
                return Err(ServerBackupError::InvalidSnapshot);
            }
            match authorization.endpoint_transition {
                Some(transition) => {
                    let descriptor = if authorization.endpoint_transition_source {
                        match &transition.claims.previous_transports {
                            Some(previous) => previous.clone(),
                            None if transition.claims.schema_version == 1 => {
                                let mut previous = transition.claims.endpoint_descriptor();
                                previous.endpoint = transition.claims.previous_endpoint.clone();
                                previous
                            }
                            None => return Err(ServerBackupError::InvalidSnapshot),
                        }
                    } else {
                        transition.claims.endpoint_descriptor()
                    };
                    endpoint_transition::validate_response(&transition)
                        .map_err(|_| ServerBackupError::InvalidSnapshot)?;
                    if transition.claims.server_id != snapshot.server_id
                        || transition.claims.server_name != configuration.server_name
                        || transition.claims.server_tunnel_address
                            != configuration.server_tunnel_address
                        || transition.claims.management_port != configuration.management_port
                        || transition.claims.server_wireguard_public_key
                            != configuration.wireguard_public_key
                        || transition.claims.pinned_server_certificate_pem
                            != snapshot.management_certificate_pem
                        || descriptor.endpoint.wireguard_port != configuration.wireguard_port
                        || descriptor.ipv6_tunnel_enabled != configuration.ipv6_tunnel_enabled
                        || descriptor.obfuscated_udp != configuration.obfuscated_udp
                        || descriptor.tcp_fallback != configuration.tcp_fallback
                        || descriptor.tls_like != configuration.tls_like
                        || descriptor.alternate_endpoint_hosts
                            != configuration.alternate_endpoint_hosts
                        || descriptor.endpoint_discovery_port
                            != configuration.endpoint_discovery_port
                    {
                        return Err(ServerBackupError::InvalidSnapshot);
                    }
                    transition.claims.generation
                }
                None => 0,
            }
        }
        None => 0,
    };

    Ok(ServerBackupMetadata {
        endpoint_discovery_port: configuration.endpoint_discovery_port,
        server_id: snapshot.server_id,
        server_name: configuration.server_name,
        server_tunnel_address: configuration.server_tunnel_address,
        wireguard_port: configuration.wireguard_port,
        server_wireguard_public_key: configuration.wireguard_public_key,
        management_certificate_pem: snapshot.management_certificate_pem.clone(),
        dns_upstream: configuration.dns_upstream,
        private_dns_records: configuration.private_dns_records,
        ipv6_tunnel_enabled: configuration.ipv6_tunnel_enabled,
        obfuscated_udp: configuration.obfuscated_udp,
        tcp_fallback: configuration.tcp_fallback,
        tls_like: configuration.tls_like,
        endpoint_generation,
    })
}

fn validate_transport_configuration(
    wireguard_port: u16,
    obfuscated_udp: Option<&ObfuscatedUdpEndpoint>,
    tcp_fallback: Option<&TcpFallbackEndpoint>,
    tls_like: Option<&TlsLikeEndpoint>,
    has_transport_private_key: bool,
) -> Result<(), ServerBackupError> {
    if obfuscated_udp.is_some_and(|endpoint| {
        endpoint.port == 0
            || endpoint.port == wireguard_port
            || !valid_wireguard_public_key(&endpoint.server_public_key)
    }) || tcp_fallback.is_some_and(|endpoint| {
        endpoint.port == 0
            || endpoint.port == wireguard_port
            || !valid_wireguard_public_key(&endpoint.server_public_key)
    }) || tls_like.is_some_and(|endpoint| {
        endpoint.port == 0
            || endpoint.port == wireguard_port
            || !valid_wireguard_public_key(&endpoint.server_public_key)
            || !valid_base64_sha256(&endpoint.certificate_sha256)
            || tcp_fallback.is_none_or(|tcp| tcp.port != endpoint.port)
    }) || obfuscated_udp
        .zip(tcp_fallback)
        .is_some_and(|(udp, tcp)| udp.server_public_key != tcp.server_public_key)
        || tls_like.is_some_and(|tls| {
            obfuscated_udp.is_some_and(|udp| udp.server_public_key != tls.server_public_key)
                || tcp_fallback.is_some_and(|tcp| tcp.server_public_key != tls.server_public_key)
        })
        || (obfuscated_udp.is_some() || tcp_fallback.is_some() || tls_like.is_some())
            != has_transport_private_key
    {
        return Err(ServerBackupError::InvalidSnapshot);
    }
    Ok(())
}

fn valid_base64_sha256(value: &str) -> bool {
    STANDARD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 32 && STANDARD.encode(&decoded) == value)
}

fn valid_wireguard_public_key(value: &str) -> bool {
    STANDARD.decode(value).is_ok_and(|decoded| {
        decoded.len() == 32
            && decoded.iter().any(|byte| *byte != 0)
            && STANDARD.encode(decoded.as_slice()) == value
    })
}

fn map_encrypted_backup_error(error: EncryptedBackupError) -> ServerBackupError {
    match error {
        EncryptedBackupError::WeakPassword => ServerBackupError::WeakPassword,
        EncryptedBackupError::InvalidPassword => ServerBackupError::InvalidPassword,
        EncryptedBackupError::DestinationExists => ServerBackupError::DestinationExists,
        EncryptedBackupError::FileTooLarge => ServerBackupError::FileTooLarge,
        EncryptedBackupError::InvalidFormat => ServerBackupError::InvalidFormat,
        EncryptedBackupError::IncompatibleVersion => ServerBackupError::IncompatibleVersion,
        EncryptedBackupError::AuthenticationFailed => ServerBackupError::AuthenticationFailed,
        EncryptedBackupError::Io(error) => ServerBackupError::Io(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalIdentity;
    use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey};
    use serde_json::json;
    use sirinvpn_protocol::{DEFAULT_OBFUSCATED_UDP_PORT, DEFAULT_TCP_FALLBACK_PORT};
    use sirinvpn_protocol::{EndpointTransitionClaims, EndpointTransitionResponse, ServerEndpoint};
    use std::fs;

    #[test]
    fn encrypted_server_backup_is_private_bounded_and_domain_separated() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("server.sirinvpn-server-backup");
        let snapshot = br#"{"schema_version":1,"secret":"private-server-material"}"#;
        let password = "correct horse battery staple";

        write_encrypted_server_backup(&destination, snapshot, password).unwrap();
        let bytes = fs::read(&destination).unwrap();
        sirinvpn_platform::files::validate_private_file(&fs::File::open(&destination).unwrap())
            .unwrap();
        assert!(
            !bytes
                .windows(23)
                .any(|window| window == b"private-server-material")
        );
        let plaintext = encrypted_backup::decrypt(SERVER_BACKUP_FORMAT, &bytes, password).unwrap();
        assert_eq!(plaintext.as_slice(), snapshot);
        assert!(matches!(
            encrypted_backup::decrypt("sirinvpn-device-backup", &bytes, password),
            Err(EncryptedBackupError::InvalidFormat)
        ));
        assert!(matches!(
            write_encrypted_server_backup(&destination, snapshot, password),
            Err(ServerBackupError::DestinationExists)
        ));
        assert!(matches!(
            write_encrypted_server_backup(&directory.path().join("weak"), snapshot, "too short"),
            Err(ServerBackupError::WeakPassword)
        ));
        assert!(matches!(
            write_encrypted_server_backup(
                &directory.path().join("oversized"),
                &vec![0; MAX_SERVER_SNAPSHOT_BYTES + 1],
                password
            ),
            Err(ServerBackupError::InvalidSnapshot)
        ));
    }

    #[test]
    fn encrypted_server_backup_restore_metadata_is_strict_and_authenticated() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("server.sirinvpn-server-backup");
        let password = "correct horse battery staple";
        let server = LocalIdentity::generate("Backup server").unwrap();
        let owner = LocalIdentity::generate("Backup owner").unwrap();
        let server_id = ServerId::new();
        let transport_key = STANDARD.encode([7_u8; 32]);
        let configuration = json!({
            "schema_version": 1,
            "server_name": "Recovered VPS",
            "interface_name": INTERFACE_NAME,
            "tunnel_cidr": TUNNEL_CIDR,
            "server_tunnel_address": SERVER_TUNNEL_ADDRESS,
            "wireguard_port": 51_820,
            "management_port": DEFAULT_MANAGEMENT_PORT,
            "wireguard_public_key": server.public.wireguard_public_key,
            "owner_certificate_pem": owner.public.management_certificate_pem,
            "obfuscated_udp": {
                "port": DEFAULT_OBFUSCATED_UDP_PORT,
                "server_public_key": transport_key,
            },
            "tcp_fallback": {
                "port": DEFAULT_TCP_FALLBACK_PORT,
                "server_public_key": transport_key,
            },
            "tls_like": {
                "port": DEFAULT_TCP_FALLBACK_PORT,
                "server_public_key": transport_key,
                "certificate_sha256": STANDARD.encode([8_u8; 32]),
            },
        });
        let transition_claims = EndpointTransitionClaims {
            endpoint_discovery_port: None,
            alternate_endpoint_hosts: Vec::new(),
            previous_transports: None,
            schema_version: 1,
            server_id,
            generation: 7,
            server_name: "Recovered VPS".to_owned(),
            previous_endpoint: ServerEndpoint {
                host: "203.0.113.10".to_owned(),
                wireguard_port: 51_820,
            },
            endpoint: ServerEndpoint {
                host: "203.0.113.20".to_owned(),
                wireguard_port: 51_820,
            },
            server_tunnel_address: SERVER_TUNNEL_ADDRESS.parse().unwrap(),
            management_port: DEFAULT_MANAGEMENT_PORT,
            server_wireguard_public_key: server.public.wireguard_public_key.clone(),
            pinned_server_certificate_pem: server.public.management_certificate_pem.clone(),
            authorization_fingerprint: hex::encode([42_u8; 32]),
            ipv6_tunnel_enabled: false,
            obfuscated_udp: Some(ObfuscatedUdpEndpoint {
                port: DEFAULT_OBFUSCATED_UDP_PORT,
                server_public_key: transport_key.clone(),
            }),
            tcp_fallback: Some(TcpFallbackEndpoint {
                port: DEFAULT_TCP_FALLBACK_PORT,
                server_public_key: transport_key.clone(),
            }),
            tls_like: Some(TlsLikeEndpoint {
                port: DEFAULT_TCP_FALLBACK_PORT,
                server_public_key: transport_key.clone(),
                certificate_sha256: STANDARD.encode([8_u8; 32]),
                https: None,
            }),
        };
        let signing_key =
            SigningKey::from_pkcs8_pem(&server.secret.management_private_key_pem).unwrap();
        let transition = EndpointTransitionResponse {
            signature: STANDARD.encode(
                signing_key
                    .sign(&serde_json::to_vec(&transition_claims).unwrap())
                    .to_bytes(),
            ),
            claims: transition_claims,
        };
        let snapshot = serde_json::to_vec(&json!({
            "schema_version": SERVER_BACKUP_SNAPSHOT_SCHEMA_VERSION,
            "server_id": server_id,
            "configuration_json": serde_json::to_string_pretty(&configuration).unwrap(),
            "wireguard_private_key": server.secret.wireguard_private_key,
            "transport_private_key": STANDARD.encode([9_u8; 32]),
            "management_certificate_pem": server.public.management_certificate_pem,
            "management_private_key_pem": server.secret.management_private_key_pem,
            "authorization_json": serde_json::to_string(&json!({
                "schema_version": 1,
                "server_id": server_id,
                "endpoint_transition": transition,
            })).unwrap(),
            "authorization_required": true,
        }))
        .unwrap();

        write_encrypted_server_backup(&destination, &snapshot, password).unwrap();
        let restored = read_encrypted_server_backup(&destination, password).unwrap();
        assert_eq!(restored.snapshot(), snapshot);
        assert_eq!(restored.metadata().server_id, server_id);
        assert_eq!(restored.metadata().server_name, "Recovered VPS");
        assert_eq!(restored.metadata().wireguard_port, 51_820);
        assert!(restored.metadata().obfuscated_udp.is_some());
        assert!(restored.metadata().tcp_fallback.is_some());
        assert!(restored.metadata().tls_like.is_some());
        assert_eq!(restored.metadata().endpoint_generation, 7);
        assert!(matches!(
            read_encrypted_server_backup(&destination, "wrong password"),
            Err(ServerBackupError::AuthenticationFailed)
        ));

        let future = json!({
            "schema_version": SERVER_BACKUP_SNAPSHOT_SCHEMA_VERSION + 2,
            "server_id": server_id,
            "configuration_json": serde_json::to_string(&configuration).unwrap(),
            "wireguard_private_key": "secret",
            "transport_private_key": STANDARD.encode([9_u8; 32]),
            "management_certificate_pem": server.public.management_certificate_pem,
            "management_private_key_pem": "secret",
            "authorization_json": "{}",
            "authorization_required": true,
        });
        let future_path = directory.path().join("future.sirinvpn-server-backup");
        write_encrypted_server_backup(
            &future_path,
            &serde_json::to_vec(&future).unwrap(),
            password,
        )
        .unwrap();
        assert!(matches!(
            read_encrypted_server_backup(&future_path, password),
            Err(ServerBackupError::IncompatibleVersion)
        ));
    }
}
