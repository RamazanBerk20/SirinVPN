#![forbid(unsafe_code)]

mod https_identity;
pub use https_identity::HttpsCertificatePaths;
use https_identity::*;
mod initialization;
use initialization::*;
pub use initialization::{
    ServerCapabilities, initialize, initialize_with_capabilities,
    initialize_with_transport_capabilities,
};
mod configuration;
use configuration::*;
pub use configuration::{load_configuration, validate_state};
mod backup;
use backup::*;
pub use backup::{export_backup_state, restore_backup_state};
mod api;
use api::*;
mod endpoint_observation;
mod endpoint_transition;
use endpoint_transition::*;
mod membership;
use membership::*;
mod member_lifecycle;
use member_lifecycle::*;
mod forwarding_api;
mod recovery;
use forwarding_api::*;
mod enrollment;
use enrollment::*;
mod access;
mod authorization_transaction;
use access::*;
mod measurement;
mod metrics;
mod service_metrics;
mod status_stream;
pub use metrics::collect_status;
use metrics::*;
mod diagnostics;
pub use diagnostics::collect_diagnostics;
mod runtime;
pub use runtime::serve;
use runtime::*;
mod network_policy;
pub mod release_update;
pub use network_policy::install_network_guard;
use network_policy::*;

mod authorization;
mod dns_diagnostics;
mod doh_proxy;

pub use doh_proxy::{DOH_PROXY_PORT, serve_doh_proxy};

use anyhow::{Context, Result, anyhow, bail};
use authorization::{
    AuthorizationDocument, DeviceRecord, ENROLLMENT_HANDOFF_SECONDS, EnrollmentReceipt,
    InvitationRecord, MemberRecord, certificate_fingerprint, load_authorization, sign_claims,
    sign_endpoint_transition, validate_display_name, validate_wireguard_public_key,
    verify_endpoint_transition_signature, verify_endpoint_transition_signature_with_key,
    write_authorization,
};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ConnectionBuilder,
    service::TowerToHyperService,
};
use rand::rngs::OsRng;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ED25519,
};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sirinvpn_protocol::{
    API_VERSION, ApiEnvelope, ApiErrorBody, ConnectionState, CurrentConfiguration,
    DEFAULT_MANAGEMENT_PORT, DEFAULT_WIREGUARD_PORT, DeviceId,
    DevicePeerCommunicationUpdateRequest, DiagnosticReport, DnsUpstream, EndpointTransitionClaims,
    EndpointTransitionCreateRequest, EndpointTransitionResponse, EnrollmentRequest,
    EnrollmentResult, ErrorCode, INTERFACE_NAME, InvitationClaims, InvitationCreateRequest,
    InvitationCreateResponse, InvitationId, KeyRotationCommitResponse, KeyRotationId,
    KeyRotationPrepareRequest, KeyRotationPrepareResponse, MAX_PORT_FORWARDS,
    MIN_PORT_FORWARD_PUBLIC_PORT, MemberAccessUpdateRequest, MemberDevicesRevokeRequest, MemberId,
    MemberSuspensionUpdateRequest, MembershipSnapshot, ObfuscatedUdpEndpoint,
    OwnershipTransferRequest, PortForward, PortForwardCreateRequest, PortForwardProtocol,
    PrivateDnsRecord, RenameDeviceRequest, SERVER_TUNNEL_ADDRESS, ServerEndpoint, ServerId,
    ServerRole, ServerStatus, TUNNEL_CIDR, TcpFallbackEndpoint, TlsLikeEndpoint, TransportKind,
    ipv6_tunnel_address, server_dns_configuration_schema_version, validate_dns_upstream,
    validate_host, validate_private_dns_records, validate_server_dns_configuration,
    validate_server_name,
};
use sirinvpn_transport::{
    ActiveTransportRegistry, AuthorizedPeers, ServerRelayConfig, TcpServerRelayConfig, decode_key,
    run_server_relay, run_tcp_server_relay, run_tcp_server_relay_with_https,
    run_tcp_server_relay_with_tls,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncWriteExt, net::TcpListener, process::Command, sync::RwLock};
use tokio_rustls::TlsAcceptor;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const SERVER_BACKUP_STATE_SCHEMA_VERSION: u16 = 1;
const MAX_BACKUP_STATE_FILE_BYTES: u64 = 64 * 1024;
const MAX_BACKUP_AUTHORIZATION_BYTES: u64 = 1024 * 1024;
pub const MAX_SERVER_BACKUP_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
const TLS_LIKE_CERTIFICATE_KEY_CONTEXT: &[u8] = b"SirinVPN TLS-like certificate key v1";
const TLS_LIKE_SERVER_NAME: &str = "www.example.com";
const OPERATIONAL_CONFIGURATION_SCHEMA_VERSION: u16 = 1;
const MAX_OPERATIONAL_CONFIGURATION_BYTES: u64 = 4 * 1024;
const PORT_FORWARD_MARK: u32 = 0x5356_504e;

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug)]
pub struct ServerPaths {
    pub state_directory: PathBuf,
    pub configuration: PathBuf,
    pub wireguard_private_key: PathBuf,
    pub transport_private_key: PathBuf,
    pub https_private_key: PathBuf,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub authorization: PathBuf,
    pub authorization_required: PathBuf,
    pub operational_configuration: PathBuf,
}

impl ServerPaths {
    pub fn under(directory: impl Into<PathBuf>) -> Self {
        let state_directory = directory.into();
        Self {
            configuration: state_directory.join("server.json"),
            wireguard_private_key: state_directory.join("wireguard.key"),
            transport_private_key: state_directory.join("transport.key"),
            https_private_key: state_directory.join("https.key"),
            tls_certificate: state_directory.join("management.crt"),
            tls_private_key: state_directory.join("management.key"),
            authorization: state_directory
                .join("authorization")
                .join("authorization.json"),
            authorization_required: state_directory.join("authorization-required"),
            operational_configuration: state_directory.join("operational.json"),
            state_directory,
        }
    }

    pub fn system() -> Self {
        Self::under("/etc/sirinvpn")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfiguration {
    pub schema_version: u16,
    pub server_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_endpoint: Option<ServerEndpoint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternate_endpoint_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_discovery_port: Option<u16>,
    pub interface_name: String,
    pub tunnel_cidr: String,
    pub server_tunnel_address: IpAddr,
    pub wireguard_port: u16,
    pub management_port: u16,
    pub wireguard_public_key: String,
    pub owner_certificate_pem: String,
    #[serde(default, skip_serializing_if = "DnsUpstream::is_recursive")]
    pub dns_upstream: DnsUpstream,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_dns_records: Vec<PrivateDnsRecord>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ipv6_tunnel_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_like: Option<TlsLikeEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_certificate_pem: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationalConfiguration {
    schema_version: u16,
    external_interface: String,
    ssh_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_transition: Option<EndpointTransitionResponse>,
    pub wireguard_public_key: String,
    pub management_certificate_pem: String,
    pub server_tunnel_address: IpAddr,
    pub wireguard_port: u16,
    pub management_port: u16,
    #[serde(default, skip_serializing_if = "DnsUpstream::is_recursive")]
    pub dns_upstream: DnsUpstream,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_dns_records: Vec<PrivateDnsRecord>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ipv6_tunnel_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_like: Option<TlsLikeEndpoint>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerBackupState {
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

impl Drop for ServerBackupState {
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

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn default_wireguard_port() -> u16 {
    DEFAULT_WIREGUARD_PORT
}

#[cfg(test)]
mod tests;
