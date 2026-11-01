//! Management.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Pass,
    Warning,
    Fail,
    /// Produced only by local leak checks; VPS reports never use it.
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub code: String,
    pub label: String,
    pub level: DiagnosticLevel,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub api_version: String,
    pub checks: Vec<DiagnosticCheck>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CurrentConfiguration {
    #[serde(default)]
    pub isolated_measurement_enabled: bool,
    pub api_version: String,
    pub interface_name: String,
    pub tunnel_cidr: String,
    pub dns_address: IpAddr,
    #[serde(default, skip_serializing_if = "is_recursive_dns_upstream")]
    pub dns_upstream: DnsUpstream,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_dns_records: Vec<PrivateDnsRecord>,
    pub wireguard_port: u16,
    pub management_port: u16,
    pub ipv6_tunnel_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_like: Option<TlsLikeEndpoint>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub advanced_invitations_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ownership_transfer_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub key_rotation_enabled: bool,
    /// Enrollment and key rotation accept a device-generated WireGuard preshared key.
    #[serde(default, skip_serializing_if = "is_false")]
    pub preshared_keys_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub endpoint_transitions_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub peer_isolation_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub port_forwarding_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub member_lifecycle_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub member_policies_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub reusable_invitations_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub recipient_names_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub recovery_keys_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub dns_blocklist_management_enabled: bool,
    /// Managers can add devices that join only through a standard WireGuard configuration.
    #[serde(default, skip_serializing_if = "is_false")]
    pub wireguard_devices_enabled: bool,
    /// The VPS redirects the leak-test addresses and answers the leak-test DNS zone.
    #[serde(default, skip_serializing_if = "is_false")]
    pub leak_test_enabled: bool,
    /// The Owner can assign LAN ranges that one of their devices forwards.
    #[serde(default, skip_serializing_if = "is_false")]
    pub subnet_routes_enabled: bool,
    /// Devices can be allowed to reach each other pair by pair.
    #[serde(default, skip_serializing_if = "is_false")]
    pub device_pairs_enabled: bool,
}

/// The source address of the one request that asked; the VPS keeps nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeakTestObservation {
    pub source_address: IpAddr,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EndpointTransitionCreateRequest {
    pub server_id: ServerId,
    pub generation: u64,
    pub previous_endpoint: ServerEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_transports: Option<crate::EndpointDescriptor>,
    pub endpoint: ServerEndpoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EndpointTransitionClaims {
    pub schema_version: u16,
    pub server_id: ServerId,
    pub generation: u64,
    pub server_name: String,
    pub previous_endpoint: ServerEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_transports: Option<crate::EndpointDescriptor>,
    pub endpoint: ServerEndpoint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternate_endpoint_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_discovery_port: Option<u16>,
    pub server_tunnel_address: IpAddr,
    pub management_port: u16,
    pub server_wireguard_public_key: String,
    pub pinned_server_certificate_pem: String,
    pub authorization_fingerprint: String,
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
pub struct EndpointTransitionResponse {
    pub claims: EndpointTransitionClaims,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvitationCreateRequest {
    pub server_id: ServerId,
    pub endpoint: ServerEndpoint,
    pub member_name: String,
    pub device_name: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub recipient_names: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_member_id: Option<MemberId>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub administrator: bool,
    #[serde(default = "one_use", skip_serializing_if = "is_one_use")]
    pub max_uses: u16,
    #[serde(default, skip_serializing_if = "MemberPolicy::is_default")]
    pub member_policy: MemberPolicy,
    pub expires_in_seconds: u32,
    pub token_hash: String,
    pub bootstrap_wireguard_public_key: String,
    pub bootstrap_management_certificate_pem: String,
}

/// The issuing device generated the key pair; only the public key and preshared key leave it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardDeviceCreateRequest {
    pub server_id: ServerId,
    pub endpoint: ServerEndpoint,
    pub member_name: String,
    pub device_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_member_id: Option<MemberId>,
    #[serde(default, skip_serializing_if = "MemberPolicy::is_default")]
    pub member_policy: MemberPolicy,
    pub wireguard_public_key: String,
    pub preshared_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvitationClaims {
    pub schema_version: u16,
    pub invitation_id: InvitationId,
    pub server_id: ServerId,
    pub server_name: String,
    pub endpoint: ServerEndpoint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternate_endpoint_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_discovery_port: Option<u16>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub endpoint_generation: u64,
    pub server_tunnel_address: IpAddr,
    pub management_port: u16,
    pub server_wireguard_public_key: String,
    pub pinned_server_certificate_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_like: Option<TlsLikeEndpoint>,
    pub member_id: MemberId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_member_id: Option<MemberId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_role: Option<ServerRole>,
    pub device_id: DeviceId,
    pub member_name: String,
    pub device_name: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub recipient_names: bool,
    pub role: ServerRole,
    #[serde(default, skip_serializing_if = "is_false")]
    pub administrator: bool,
    #[serde(default = "one_use", skip_serializing_if = "is_one_use")]
    pub max_uses: u16,
    #[serde(default, skip_serializing_if = "MemberPolicy::is_default")]
    pub member_policy: MemberPolicy,
    pub client_tunnel_address: IpAddr,
    pub bootstrap_tunnel_address: IpAddr,
    pub expires_at_unix: u64,
    pub token_hash: String,
    pub bootstrap_wireguard_public_key: String,
    pub bootstrap_management_certificate_pem: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvitationCreateResponse {
    pub claims: InvitationClaims,
    pub signature: String,
}

/// Display labels only; authority and stable member/device IDs always come from the grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentNames {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_name: Option<String>,
    pub device_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<EnrollmentNames>,
    pub claims: InvitationClaims,
    pub signature: String,
    pub token: String,
    pub device_wireguard_public_key: String,
    pub device_management_certificate_pem: String,
    /// Older servers ignore this field; `EnrollmentResult::preshared_key` confirms storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_preshared_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<EnrollmentNames>,
    pub server_id: ServerId,
    pub member_id: MemberId,
    pub device_id: DeviceId,
    pub role: ServerRole,
    #[serde(default, skip_serializing_if = "is_false")]
    pub administrator: bool,
    pub server_name: String,
    pub endpoint: ServerEndpoint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternate_endpoint_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_discovery_port: Option<u16>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub endpoint_generation: u64,
    pub client_tunnel_address: IpAddr,
    pub server_tunnel_address: IpAddr,
    pub server_wireguard_public_key: String,
    pub pinned_server_certificate_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_like: Option<TlsLikeEndpoint>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ipv6_tunnel_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub preshared_key: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub id: DeviceId,
    pub member_id: MemberId,
    pub name: String,
    pub client_tunnel_address: IpAddr,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity_fingerprint: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub peer_communication_enabled: bool,
    /// Current kernel handshake recency, never persisted in authorization state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_handshake: Option<bool>,
    /// Joins through a standard WireGuard configuration: Direct UDP only, no management access.
    #[serde(default, skip_serializing_if = "is_false")]
    pub wireguard_only: bool,
    /// Owner-assigned LAN ranges this device forwards for peers that may reach it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subnet_routes: Vec<String>,
    /// Ranges the VPS cannot route right now because another of its interfaces routes them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inactive_subnet_routes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemberSummary {
    pub id: MemberId,
    pub name: String,
    pub role: ServerRole,
    #[serde(default, skip_serializing_if = "is_false")]
    pub administrator: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub suspended: bool,
    #[serde(default, skip_serializing_if = "MemberPolicy::is_default")]
    pub policy: MemberPolicy,
    pub devices: Vec<DeviceSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberSuspensionUpdateRequest {
    pub suspended: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberDevicesRevokeRequest {
    pub confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActiveInvitationSummary {
    #[serde(default, skip_serializing_if = "is_false")]
    pub recipient_names: bool,
    pub id: InvitationId,
    pub member_name: String,
    pub device_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_member_id: Option<MemberId>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub administrator: bool,
    pub expires_at_unix: u64,
    #[serde(default = "one_use")]
    pub uses_remaining: u16,
    #[serde(default = "one_use")]
    pub max_uses: u16,
    #[serde(default, skip_serializing_if = "MemberPolicy::is_default")]
    pub member_policy: MemberPolicy,
}

fn one_use() -> u16 {
    1
}
fn is_one_use(value: &u16) -> bool {
    *value == 1
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortForwardProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for PortForwardProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortForward {
    pub protocol: PortForwardProtocol,
    pub public_port: u16,
    pub device_id: DeviceId,
    pub device_port: u16,
}

/// Lets two devices reach each other whatever their mutual-access switches say.
/// It is also the `PUT /v1/device-pairs` body, which replaces any pair of the same devices.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePair {
    /// The device that may always start connections.
    pub device_id: DeviceId,
    pub peer_device_id: DeviceId,
    /// The peer only answers connections the device started.
    #[serde(default, skip_serializing_if = "is_false")]
    pub one_way: bool,
}

impl DevicePair {
    /// Whether `source` may start connections to `destination`.
    pub fn permits(&self, source: DeviceId, destination: DeviceId) -> bool {
        (self.device_id == source && self.peer_device_id == destination)
            || (!self.one_way && self.device_id == destination && self.peer_device_id == source)
    }

    pub fn joins(&self, device: DeviceId, peer: DeviceId) -> bool {
        (self.device_id, self.peer_device_id) == (device, peer)
            || (self.device_id, self.peer_device_id) == (peer, device)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipSnapshot {
    pub members: Vec<MemberSummary>,
    pub active_invitations: Vec<ActiveInvitationSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<PortForward>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_pairs: Vec<DevicePair>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RenameDeviceRequest {
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DevicePeerCommunicationUpdateRequest {
    pub enabled: bool,
}

/// Replaces the device's whole route list; an empty list removes every route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSubnetRoutesUpdateRequest {
    pub routes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortForwardCreateRequest {
    pub protocol: PortForwardProtocol,
    pub public_port: u16,
    pub device_id: DeviceId,
    pub device_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemberAccessUpdateRequest {
    pub administrator: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnershipTransferRequest {
    pub destination_device_id: DeviceId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyRotationPrepareRequest {
    pub rotation_id: KeyRotationId,
    pub server_id: ServerId,
    pub new_wireguard_public_key: String,
    pub new_management_certificate_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_wireguard_preshared_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyRotationPrepareResponse {
    pub rotation_id: KeyRotationId,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyRotationCommitResponse {
    pub server_id: ServerId,
    pub device_id: DeviceId,
    pub identity_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub api_version: String,
    pub request_id: Uuid,
    pub payload: T,
}

impl<T> ApiEnvelope<T> {
    pub fn new(payload: T) -> Self {
        Self {
            api_version: API_VERSION.to_owned(),
            request_id: Uuid::new_v4(),
            payload,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub api_version: String,
    pub code: ErrorCode,
    pub message: String,
}
