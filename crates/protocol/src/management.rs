//! Management.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Pass,
    Warning,
    Fail,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipSnapshot {
    pub members: Vec<MemberSummary>,
    pub active_invitations: Vec<ActiveInvitationSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<PortForward>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RenameDeviceRequest {
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DevicePeerCommunicationUpdateRequest {
    pub enabled: bool,
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
