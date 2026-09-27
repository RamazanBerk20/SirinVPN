#![forbid(unsafe_code)]

mod android_routing;
mod dns;
pub use android_routing::{
    AndroidApplicationMode, AndroidApplicationRouting, valid_android_package,
};
mod endpoints;
pub use endpoints::{
    EndpointDescriptor, EndpointIdentity, MAX_ALTERNATE_ENDPOINT_HOSTS,
    valid_alternate_endpoint_hosts,
};
mod split_dns;
use dns::*;
pub use dns::{
    DnsOverHttpsEndpoint, DnsOverTlsEndpoint, DnsUpstream, PrivateDnsRecord,
    server_dns_configuration_schema_version, validate_dns_over_https_endpoint,
    validate_dns_over_tls_endpoint, validate_dns_upstream, validate_host,
    validate_private_dns_record, validate_private_dns_records, validate_server_name,
};
pub use split_dns::{DnsSplitZone, SplitDnsUpstream, validate_split_dns};
mod management;
mod member_policy;
mod mtu;
mod quality;
pub use mtu::{
    MAX_TUNNEL_MTU, MIN_IPV4_TUNNEL_MTU, MIN_IPV6_TUNNEL_MTU, MtuPolicy, MtuProbeOutcome, MtuStatus,
};
pub use quality::{MeasurementLease, MeasurementLeaseRequest, TransportSwitchReason};
pub use quality::{QualitySelection, TransportQualitySample, TransportQualityStatus};
mod recovery;
pub use member_policy::{MemberPolicy, WeeklyAccessWindow};
pub use recovery::{
    RecoveryKeyClaims, RecoveryKeyCreateRequest, RecoveryKeyResponse, RecoveryKeySummary,
    RecoveryPolicy, RecoveryRedeemRequest, RecoverySettings,
};

pub use management::{
    ActiveInvitationSummary, ApiEnvelope, ApiErrorBody, CurrentConfiguration,
    DevicePeerCommunicationUpdateRequest, DeviceSummary, DiagnosticCheck, DiagnosticLevel,
    DiagnosticReport, EndpointTransitionClaims, EndpointTransitionCreateRequest,
    EndpointTransitionResponse, EnrollmentNames, EnrollmentRequest, EnrollmentResult,
    InvitationClaims, InvitationCreateRequest, InvitationCreateResponse, KeyRotationCommitResponse,
    KeyRotationPrepareRequest, KeyRotationPrepareResponse, MemberAccessUpdateRequest,
    MemberDevicesRevokeRequest, MemberSummary, MemberSuspensionUpdateRequest, MembershipSnapshot,
    OwnershipTransferRequest, PortForward, PortForwardCreateRequest, PortForwardProtocol,
    RenameDeviceRequest,
};

use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;
use uuid::Uuid;

pub const API_VERSION: &str = "v1";
pub const DEFAULT_WIREGUARD_PORT: u16 = 51_820;
pub const DEFAULT_OBFUSCATED_UDP_PORT: u16 = 443;
pub const DEFAULT_TCP_FALLBACK_PORT: u16 = 443;
pub const DEFAULT_TLS_LIKE_PORT: u16 = 443;
pub const DEFAULT_MANAGEMENT_PORT: u16 = 8_443;
pub const DOH_PROXY_PORT: u16 = 5_053;
pub const MAX_DNS_OVER_TLS_ENDPOINTS: usize = 2;
pub const MAX_DNS_OVER_HTTPS_ENDPOINTS: usize = 2;
pub const MAX_PRIVATE_DNS_RECORDS: usize = 64;
pub const MAX_PORT_FORWARDS: usize = 32;
pub const MIN_PORT_FORWARD_PUBLIC_PORT: u16 = 1_024;
pub const SERVER_TUNNEL_ADDRESS: &str = "10.77.0.1";
pub const FIRST_CLIENT_TUNNEL_ADDRESS: &str = "10.77.0.2";
pub const TUNNEL_CIDR: &str = "10.77.0.0/24";
pub const INTERFACE_NAME: &str = "sirinvpn0";

pub fn ipv6_tunnel_prefix(server_id: ServerId) -> Ipv6Addr {
    let identifier = server_id.0.as_bytes();
    Ipv6Addr::from([
        0xfd,
        identifier[0],
        identifier[1],
        identifier[2],
        identifier[3],
        identifier[4],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ])
}

pub fn ipv6_tunnel_cidr(server_id: ServerId) -> String {
    format!("{}/64", ipv6_tunnel_prefix(server_id))
}

pub fn ipv6_tunnel_address(server_id: ServerId, ipv4_address: Ipv4Addr) -> Option<Ipv6Addr> {
    let ipv4_octets = ipv4_address.octets();
    if ipv4_octets[..3] != [10, 77, 0] || ipv4_octets[3] == 0 {
        return None;
    }
    let mut octets = ipv6_tunnel_prefix(server_id).octets();
    octets[15] = ipv4_octets[3];
    Some(Ipv6Addr::from(octets))
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerId(pub Uuid);

impl ServerId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ServerId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ServerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::str::FromStr for ServerId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

macro_rules! uuid_identifier {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

uuid_identifier!(MemberId);
uuid_identifier!(DeviceId);
uuid_identifier!(InvitationId);
uuid_identifier!(RecoveryId);
uuid_identifier!(KeyRotationId);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerEndpoint {
    pub host: String,
    pub wireguard_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObfuscatedUdpEndpoint {
    pub port: u16,
    pub server_public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TcpFallbackEndpoint {
    pub port: u16,
    pub server_public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TlsLikeEndpoint {
    pub port: u16,
    pub server_public_key: String,
    pub certificate_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https: Option<HttpsTransport>,
}

/// HTTPS appearance is public endpoint metadata, authenticated with the server pins.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsTransport {
    pub server_name: String,
    pub path: String,
}

impl HttpsTransport {
    pub fn is_valid(&self) -> bool {
        validate_host(&self.server_name).is_ok()
            && self.server_name.trim() == self.server_name
            && self.server_name.parse::<std::net::IpAddr>().is_err()
            && self.server_name.contains('.')
            && self.server_name == self.server_name.to_ascii_lowercase()
            && (2..=128).contains(&self.path.len())
            && self.path.starts_with('/')
            && self
                .path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/-_.".contains(&byte))
            && !self.path.contains("..")
            && !self.path.contains("//")
    }
}

impl ServerEndpoint {
    pub fn socket_label(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.wireguard_port)
        } else {
            format!("{}:{}", self.host, self.wireguard_port)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerRole {
    Owner,
    Member,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerProfile {
    pub schema_version: u16,
    pub id: ServerId,
    pub name: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub favorite: bool,
    pub endpoint: ServerEndpoint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternate_endpoint_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_discovery_port: Option<u16>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub endpoint_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_previous_endpoint: Option<ServerEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_previous_transports: Option<EndpointDescriptor>,
    pub client_tunnel_address: IpAddr,
    pub server_tunnel_address: IpAddr,
    pub server_wireguard_public_key: String,
    pub pinned_server_certificate_pem: String,
    pub client_management_certificate_pem: String,
    pub identity_reference: String,
    pub role: ServerRole,
    #[serde(default, skip_serializing_if = "is_false")]
    pub administrator: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_id: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ipv6_tunnel_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_like: Option<TlsLikeEndpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Degraded,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    #[default]
    DirectUdp,
    ObfuscatedUdp,
    TlsLike,
    TcpFallback,
}

impl TransportKind {
    pub fn is_direct_udp(&self) -> bool {
        *self == Self::DirectUdp
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportPreference {
    #[default]
    Automatic,
    DirectUdp,
    ObfuscatedUdp,
    TlsLike,
    TcpFallback,
}

impl TransportPreference {
    pub fn concrete_kind(self) -> Option<TransportKind> {
        match self {
            Self::Automatic => None,
            Self::DirectUdp => Some(TransportKind::DirectUdp),
            Self::ObfuscatedUdp => Some(TransportKind::ObfuscatedUdp),
            Self::TlsLike => Some(TransportKind::TlsLike),
            Self::TcpFallback => Some(TransportKind::TcpFallback),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProfile {
    #[default]
    Automatic,
    Normal,
    Restricted,
    Extreme,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_recovery: Option<AuthorizationRecovery>,
    pub api_version: String,
    pub server_name: String,
    pub connection_state: ConnectionState,
    pub interface_up: bool,
    pub dns_healthy: bool,
    #[serde(default, skip_serializing_if = "is_recursive_dns_upstream")]
    pub dns_upstream: DnsUpstream,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_dns_records: Vec<PrivateDnsRecord>,
    pub transport: TransportKind,
    pub peer_count: u32,
    /// Distinguishes an old server from a failed current activity reading.
    #[serde(default, skip_serializing_if = "is_false")]
    pub peer_activity_supported: bool,
    /// Authorized peers with a handshake within three minutes; not a presence guarantee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recently_active_peer_count: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub uptime_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_usage_basis_points: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_used_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_bytes_per_second: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_bytes_per_second: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_used_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_role: Option<ServerRole>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub caller_administrator: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub caller_identity_fingerprint: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationHealth {
    #[default]
    Healthy,
    Applying,
    RecoveryPending,
    RecoveryFailed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRecovery {
    pub health: AuthorizationHealth,
    pub generation: u64,
    pub containment_verified: bool,
    pub committed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AuthenticationFailed,
    AuthorizationFailed,
    ConflictDetected,
    DnsUnavailable,
    HostKeyUnknown,
    HostKeyMismatch,
    IncompatibleServer,
    InstallationFailed,
    InvalidInput,
    InvitationExpired,
    NetworkUnavailable,
    PermissionDenied,
    ProtocolMismatch,
    RateLimited,
    SecretStoreUnavailable,
    SshUnavailable,
    TunnelFailed,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("server name must contain 1 to 64 visible characters")]
    InvalidServerName,
    #[error("host must contain 1 to 253 characters and no whitespace")]
    InvalidHost,
    #[error("port must be non-zero")]
    InvalidPort,
    #[error("WireGuard public key is not valid base64-encoded 32-byte material")]
    InvalidWireGuardPublicKey,
    #[error("DNS-over-TLS endpoints must use IP#authentication-name")]
    InvalidDnsOverTlsEndpoint,
    #[error("DNS-over-TLS authentication names must be valid DNS names")]
    InvalidDnsAuthenticationName,
    #[error("DNS-over-TLS endpoint addresses must be usable unicast addresses")]
    InvalidDnsUpstreamAddress,
    #[error("DNS-over-TLS requires one or two unique endpoints")]
    InvalidDnsUpstreamEndpoints,
    #[error("DNS-over-HTTPS endpoints must use IP#authentication-name/path")]
    InvalidDnsOverHttpsEndpoint,
    #[error("DNS-over-HTTPS paths must be canonical absolute URL paths")]
    InvalidDnsOverHttpsPath,
    #[error("DNS-over-HTTPS requires one or two unique endpoints")]
    InvalidDnsOverHttpsEndpoints,
    #[error("private DNS records must use a canonical DNS-name=IP-address value")]
    InvalidPrivateDnsRecord,
    #[error("private DNS record names must be canonical multi-label DNS names")]
    InvalidPrivateDnsName,
    #[error("private DNS record addresses must be usable unicast addresses")]
    InvalidPrivateDnsAddress,
    #[error("private DNS allows at most 64 unique records")]
    InvalidPrivateDnsRecords,
    #[error("the server DNS schema does not match its configured policy")]
    InvalidDnsConfigurationSchema,
    #[error(
        "split DNS requires up to 16 unique domain suffixes, each with private-address resolvers or authenticated TLS resolvers"
    )]
    InvalidSplitDns,
}

pub fn validate_server_dns_configuration(
    schema_version: u16,
    upstream: &DnsUpstream,
    private_records: &[PrivateDnsRecord],
) -> Result<(), ValidationError> {
    validate_dns_upstream(upstream)?;
    validate_private_dns_records(private_records)?;
    let valid_pair = matches!(
        (schema_version, upstream, private_records.is_empty()),
        (1, DnsUpstream::Recursive, true)
            | (2, DnsUpstream::DnsOverTls { .. }, true)
            | (
                3,
                DnsUpstream::Recursive | DnsUpstream::DnsOverTls { .. },
                false
            )
            | (4, DnsUpstream::DnsOverHttps { .. }, true)
            | (5, DnsUpstream::DnsOverHttps { .. }, false)
            | (6, DnsUpstream::Split { .. }, _)
            | (7 | 8, _, _)
    );
    if !valid_pair {
        return Err(ValidationError::InvalidDnsConfigurationSchema);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
