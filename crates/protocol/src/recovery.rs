//! Offline recovery authorization; no developer or hosted recovery authority.
use super::*;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryPolicy {
    /// Explicitly selected current administrators may issue an Owner recovery key.
    pub administrator_member_ids: Vec<MemberId>,
}

impl RecoveryPolicy {
    pub fn is_default(&self) -> bool {
        self.administrator_member_ids.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyCreateRequest {
    pub recovery_id: RecoveryId,
    pub server_id: ServerId,
    pub endpoint: ServerEndpoint,
    pub endpoint_generation: u64,
    pub recovery_wireguard_public_key: String,
    pub recovery_management_certificate_pem: String,
    pub replace_recovery_id: Option<RecoveryId>,
    pub confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyClaims {
    pub schema_version: u16,
    pub recovery_id: RecoveryId,
    pub server_id: ServerId,
    pub owner_member_id: MemberId,
    pub issuer_member_id: MemberId,
    pub server_name: String,
    pub endpoint: ServerEndpoint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternate_endpoint_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_discovery_port: Option<u16>,
    pub endpoint_generation: u64,
    pub server_tunnel_address: IpAddr,
    pub management_port: u16,
    pub server_wireguard_public_key: String,
    pub pinned_server_certificate_pem: String,
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    pub tls_like: Option<TlsLikeEndpoint>,
    pub recovery_tunnel_address: IpAddr,
    pub recovery_wireguard_public_key: String,
    pub recovery_management_certificate_pem: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyResponse {
    pub claims: RecoveryKeyClaims,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRedeemRequest {
    pub recovery_id: RecoveryId,
    pub device_name: String,
    pub device_wireguard_public_key: String,
    pub device_management_certificate_pem: String,
    pub confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryKeySummary {
    pub recovery_id: RecoveryId,
    pub identity_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoverySettings {
    pub policy: RecoveryPolicy,
    pub key: Option<RecoveryKeySummary>,
    pub enrollment_finishing: bool,
    pub can_issue_key: bool,
}
