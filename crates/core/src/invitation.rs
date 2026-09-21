use crate::{LocalIdentity, PublicIdentity, SecretIdentity, identity};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey, pkcs8::DecodePrivateKey};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sirinvpn_protocol::{
    DeviceId, EnrollmentRequest, EnrollmentResult, InvitationCreateRequest,
    InvitationCreateResponse, InvitationId, MemberId, ObfuscatedUdpEndpoint, SERVER_TUNNEL_ADDRESS,
    ServerEndpoint, ServerId, ServerProfile, ServerRole, TcpFallbackEndpoint, TlsLikeEndpoint,
    validate_host, validate_server_name,
};
use std::{
    io::{Read, Write},
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const CODE_PREFIX: &str = "sirin1.";
const QR_CODE_PREFIX: &str = "sirq1.";
const CODE_SCHEMA_VERSION: u16 = 1;
const MAX_CODE_LENGTH: usize = 32 * 1024;
const MAX_PAYLOAD_LENGTH: usize = 24 * 1024;

#[derive(Debug, Error)]
pub enum InvitationError {
    #[error("the invitation code is invalid")]
    InvalidCode,
    #[error("the invitation has expired")]
    Expired,
    #[error("the invitation signature is invalid")]
    InvalidSignature,
    #[error("the invitation response does not match the local request")]
    BindingMismatch,
    #[error("the permanent enrollment result does not match the invitation")]
    EnrollmentMismatch,
    #[error("the invitation could not be encoded")]
    EncodingFailed,
}

pub struct InvitationDraft {
    request: InvitationCreateRequest,
    bootstrap_secret: SecretIdentity,
    token: Zeroizing<String>,
    expected_server: ExpectedServer,
    expected_target: InvitationTarget,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InvitationTarget {
    pub member_id: Option<MemberId>,
    pub role: Option<ServerRole>,
    pub administrator: bool,
}

#[derive(Clone)]
struct ExpectedServer {
    alternate_endpoint_hosts: Vec<String>,
    endpoint_discovery_port: Option<u16>,
    endpoint_generation: u64,
    tunnel_address: IpAddr,
    wireguard_public_key: String,
    certificate_pem: String,
    obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    tcp_fallback: Option<TcpFallbackEndpoint>,
    tls_like: Option<TlsLikeEndpoint>,
}

pub struct SecretInvitationCode {
    value: Zeroizing<String>,
    qr_value: Zeroizing<String>,
    invitation_id: InvitationId,
    expires_at_unix: u64,
}

impl std::fmt::Debug for SecretInvitationCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretInvitationCode")
            .field("value", &"[REDACTED]")
            .field("invitation_id", &self.invitation_id)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl SecretInvitationCode {
    pub fn expose(&self) -> &str {
        self.value.as_str()
    }

    pub fn qr_payload(&self) -> &str {
        self.qr_value.as_str()
    }

    pub fn invitation_id(&self) -> InvitationId {
        self.invitation_id
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

pub struct DecodedInvitation {
    names: Option<sirinvpn_protocol::EnrollmentNames>,
    endpoint_override: Option<sirinvpn_protocol::EndpointIdentity>,
    response: InvitationCreateResponse,
    token: Zeroizing<String>,
    bootstrap_secret: SecretIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationEnrollmentBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<sirinvpn_protocol::EnrollmentNames>,
    pub invitation_id: InvitationId,
    pub server_id: ServerId,
    pub server_name: String,
    pub endpoint: ServerEndpoint,
    pub endpoint_generation: u64,
    pub client_tunnel_address: IpAddr,
    pub server_tunnel_address: IpAddr,
    pub server_wireguard_public_key: String,
    pub pinned_server_certificate_pem: String,
    pub member_id: MemberId,
    pub device_id: DeviceId,
    pub role: ServerRole,
    pub administrator: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reusable: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub creates_member: bool,
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_like: Option<TlsLikeEndpoint>,
}

impl std::fmt::Debug for DecodedInvitation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecodedInvitation")
            .field("invitation_id", &self.response.claims.invitation_id)
            .field("server_id", &self.response.claims.server_id)
            .field("token", &"[REDACTED]")
            .field("bootstrap_secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct EncodedInvitation {
    schema_version: u16,
    response: InvitationCreateResponse,
    token: String,
    bootstrap_secret: SecretIdentity,
}

impl Drop for EncodedInvitation {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl InvitationDraft {
    pub fn new(
        profile: &ServerProfile,
        member_name: &str,
        device_name: &str,
        expires_in_seconds: u32,
    ) -> Result<Self, InvitationError> {
        Self::new_for_target(
            profile,
            member_name,
            device_name,
            expires_in_seconds,
            InvitationTarget::default(),
        )
    }

    pub fn new_for_target(
        profile: &ServerProfile,
        member_name: &str,
        device_name: &str,
        expires_in_seconds: u32,
        target: InvitationTarget,
    ) -> Result<Self, InvitationError> {
        validate_server_name(member_name).map_err(|_| InvitationError::InvalidCode)?;
        validate_server_name(device_name).map_err(|_| InvitationError::InvalidCode)?;
        validate_host(&profile.endpoint.host).map_err(|_| InvitationError::InvalidCode)?;
        if !(60..=7 * 24 * 60 * 60).contains(&expires_in_seconds)
            || target.member_id.is_some() != target.role.is_some()
            || (target.role == Some(ServerRole::Owner) && target.administrator)
        {
            return Err(InvitationError::InvalidCode);
        }

        let bootstrap = LocalIdentity::generate("SirinVPN invitation bootstrap")
            .map_err(|_| InvitationError::EncodingFailed)?;
        let mut token_bytes = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(token_bytes.as_mut());
        let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(token_bytes.as_ref()));
        let token_hash = hex_sha256(token.as_bytes());
        let request = InvitationCreateRequest {
            recipient_names: false,
            server_id: profile.id,
            endpoint: profile.endpoint.clone(),
            member_name: member_name.trim().to_owned(),
            device_name: device_name.trim().to_owned(),
            target_member_id: target.member_id,
            administrator: target.administrator,
            max_uses: 1,
            member_policy: sirinvpn_protocol::MemberPolicy::default(),
            expires_in_seconds,
            token_hash,
            bootstrap_wireguard_public_key: bootstrap.public.wireguard_public_key,
            bootstrap_management_certificate_pem: bootstrap.public.management_certificate_pem,
        };
        Ok(Self {
            request,
            bootstrap_secret: bootstrap.secret,
            token,
            expected_server: ExpectedServer {
                alternate_endpoint_hosts: profile.alternate_endpoint_hosts.clone(),
                endpoint_discovery_port: profile.endpoint_discovery_port,
                endpoint_generation: profile.endpoint_generation,
                tunnel_address: profile.server_tunnel_address,
                wireguard_public_key: profile.server_wireguard_public_key.clone(),
                certificate_pem: profile.pinned_server_certificate_pem.clone(),
                obfuscated_udp: profile.obfuscated_udp.clone(),
                tcp_fallback: profile.tcp_fallback.clone(),
                tls_like: profile.tls_like.clone(),
            },
            expected_target: target,
        })
    }

    pub fn request(&self) -> &InvitationCreateRequest {
        &self.request
    }

    pub fn with_recipient_names(mut self, enabled: bool) -> Self {
        self.request.recipient_names = enabled;
        self
    }

    pub fn with_policy(
        mut self,
        max_uses: u16,
        member_policy: sirinvpn_protocol::MemberPolicy,
    ) -> Result<Self, InvitationError> {
        if !(1..=100).contains(&max_uses)
            || member_policy.validate().is_err()
            || (self.request.target_member_id.is_some() && !member_policy.is_default())
            || (self.expected_target.role == Some(ServerRole::Owner) && max_uses > 1)
        {
            return Err(InvitationError::InvalidCode);
        }
        self.request.max_uses = max_uses;
        self.request.member_policy = member_policy;
        Ok(self)
    }

    pub fn finish(
        self,
        response: InvitationCreateResponse,
    ) -> Result<SecretInvitationCode, InvitationError> {
        let claims = &response.claims;
        if claims.recipient_names != self.request.recipient_names
            || claims.max_uses != self.request.max_uses
            || claims.member_policy != self.request.member_policy
            || claims.server_id != self.request.server_id
            || claims.endpoint != self.request.endpoint
            || claims.member_name != self.request.member_name
            || claims.device_name != self.request.device_name
            || claims.target_member_id != self.request.target_member_id
            || claims.target_role != self.expected_target.role
            || claims.administrator != self.request.administrator
            || claims.token_hash != self.request.token_hash
            || claims.bootstrap_wireguard_public_key != self.request.bootstrap_wireguard_public_key
            || claims.bootstrap_management_certificate_pem
                != self.request.bootstrap_management_certificate_pem
            || claims.endpoint_generation != self.expected_server.endpoint_generation
            || claims.server_tunnel_address != self.expected_server.tunnel_address
            || claims.server_wireguard_public_key != self.expected_server.wireguard_public_key
            || claims.pinned_server_certificate_pem != self.expected_server.certificate_pem
            || claims.obfuscated_udp != self.expected_server.obfuscated_udp
            || claims.tcp_fallback != self.expected_server.tcp_fallback
            || claims.tls_like != self.expected_server.tls_like
            || claims.alternate_endpoint_hosts != self.expected_server.alternate_endpoint_hosts
            || claims.endpoint_discovery_port != self.expected_server.endpoint_discovery_port
            || claims.role != ServerRole::Member
            || claims.expires_at_unix <= unix_time()
        {
            return Err(InvitationError::BindingMismatch);
        }
        validate_invitation_response(&response)?;

        let invitation_id = claims.invitation_id;
        let expires_at_unix = claims.expires_at_unix;
        let payload = EncodedInvitation {
            schema_version: CODE_SCHEMA_VERSION,
            response,
            token: self.token.to_string(),
            bootstrap_secret: self.bootstrap_secret.clone(),
        };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&payload).map_err(|_| InvitationError::EncodingFailed)?,
        );
        let value = Zeroizing::new(format!("{CODE_PREFIX}{}", URL_SAFE_NO_PAD.encode(&bytes)));
        let qr_value = encode_qr_payload(&bytes)?;
        Ok(SecretInvitationCode {
            value,
            qr_value,
            invitation_id,
            expires_at_unix,
        })
    }
}

impl DecodedInvitation {
    pub async fn refresh_endpoint(&mut self) -> Result<(), crate::EndpointTransitionError> {
        let profile = self.bootstrap_profile();
        if let Some(response) = crate::discover_endpoint_checkpoint(
            &profile.endpoint_identity(),
            &self.bootstrap_secret.wireguard_private_key,
            None,
        )
        .await?
        {
            self.endpoint_override = Some(crate::verify_endpoint_checkpoint(
                &profile.endpoint_identity(),
                &response,
            )?);
        }
        Ok(())
    }
    pub fn decode(code: &str) -> Result<Self, InvitationError> {
        let code = code.trim();
        if code.len() > MAX_CODE_LENGTH {
            return Err(InvitationError::InvalidCode);
        }
        let bytes = decode_payload(code)?;
        let payload: EncodedInvitation =
            serde_json::from_slice(&bytes).map_err(|_| InvitationError::InvalidCode)?;
        if payload.schema_version != CODE_SCHEMA_VERSION {
            return Err(InvitationError::InvalidCode);
        }
        validate_invitation_response(&payload.response)?;
        if payload.response.claims.expires_at_unix <= unix_time() {
            return Err(InvitationError::Expired);
        }
        if hex_sha256(payload.token.as_bytes()) != payload.response.claims.token_hash {
            return Err(InvitationError::InvalidCode);
        }
        verify_bootstrap_identity(
            &payload.bootstrap_secret,
            &payload.response.claims.bootstrap_wireguard_public_key,
            &payload.response.claims.bootstrap_management_certificate_pem,
        )?;
        Ok(Self {
            names: None,
            response: payload.response.clone(),
            endpoint_override: None,
            token: Zeroizing::new(payload.token.clone()),
            bootstrap_secret: payload.bootstrap_secret.clone(),
        })
    }

    pub fn invitation_id(&self) -> InvitationId {
        self.response.claims.invitation_id
    }

    pub fn server_id(&self) -> sirinvpn_protocol::ServerId {
        self.response.claims.server_id
    }

    pub fn device_id(&self) -> sirinvpn_protocol::DeviceId {
        self.response.claims.device_id
    }

    pub fn server_name(&self) -> &str {
        &self.response.claims.server_name
    }

    pub fn member_name(&self) -> &str {
        &self.response.claims.member_name
    }

    pub fn device_name(&self) -> &str {
        &self.response.claims.device_name
    }

    pub fn administrator(&self) -> bool {
        self.response.claims.administrator
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.response.claims.expires_at_unix
    }

    pub fn recipient_names(&self) -> bool {
        self.response.claims.recipient_names
    }

    pub fn creates_member(&self) -> bool {
        self.response.claims.target_member_id.is_none()
    }

    pub fn set_recipient_names(
        &mut self,
        member_name: Option<&str>,
        device_name: Option<&str>,
    ) -> Result<(), InvitationError> {
        if !self.recipient_names() {
            if member_name.is_some() || device_name.is_some() {
                return Err(InvitationError::BindingMismatch);
            }
            return Ok(());
        }
        if self.creates_member() != member_name.is_some() {
            return Err(InvitationError::BindingMismatch);
        }
        let device_name = device_name.ok_or(InvitationError::InvalidCode)?;
        validate_server_name(device_name).map_err(|_| InvitationError::InvalidCode)?;
        if let Some(name) = member_name {
            validate_server_name(name).map_err(|_| InvitationError::InvalidCode)?;
        }
        self.names = Some(sirinvpn_protocol::EnrollmentNames {
            member_name: member_name.map(|name| name.trim().to_owned()),
            device_name: device_name.trim().to_owned(),
        });
        Ok(())
    }

    pub fn enrollment_binding(&self) -> InvitationEnrollmentBinding {
        let claims = &self.response.claims;
        InvitationEnrollmentBinding {
            names: self.names.clone(),
            invitation_id: claims.invitation_id,
            server_id: claims.server_id,
            server_name: claims.server_name.clone(),
            endpoint: claims.endpoint.clone(),
            endpoint_generation: claims.endpoint_generation,
            client_tunnel_address: claims.client_tunnel_address,
            server_tunnel_address: claims.server_tunnel_address,
            server_wireguard_public_key: claims.server_wireguard_public_key.clone(),
            pinned_server_certificate_pem: claims.pinned_server_certificate_pem.clone(),
            member_id: claims.target_member_id.unwrap_or(claims.member_id),
            device_id: claims.device_id,
            role: claims.target_role.unwrap_or(claims.role),
            administrator: claims.administrator,
            reusable: claims.max_uses > 1,
            creates_member: claims.max_uses > 1 && claims.target_member_id.is_none(),
            obfuscated_udp: claims.obfuscated_udp.clone(),
            tcp_fallback: claims.tcp_fallback.clone(),
            tls_like: claims.tls_like.clone(),
        }
    }

    pub fn bootstrap_secret(&self) -> &SecretIdentity {
        &self.bootstrap_secret
    }

    pub fn bootstrap_profile(&self) -> ServerProfile {
        let claims = &self.response.claims;
        let mut profile = ServerProfile {
            favorite: false,
            schema_version: 1,
            id: claims.server_id,
            name: format!("{} enrollment", claims.server_name),
            endpoint: claims.endpoint.clone(),
            endpoint_generation: claims.endpoint_generation,
            pending_previous_endpoint: None,
            pending_previous_transports: None,
            endpoint_discovery_port: claims.endpoint_discovery_port,
            alternate_endpoint_hosts: claims.alternate_endpoint_hosts.clone(),
            client_tunnel_address: claims.bootstrap_tunnel_address,
            server_tunnel_address: claims.server_tunnel_address,
            server_wireguard_public_key: claims.server_wireguard_public_key.clone(),
            pinned_server_certificate_pem: claims.pinned_server_certificate_pem.clone(),
            client_management_certificate_pem: claims.bootstrap_management_certificate_pem.clone(),
            identity_reference: format!("bootstrap-{}", claims.invitation_id),
            role: ServerRole::Member,
            administrator: false,
            member_id: Some(claims.member_id),
            device_id: Some(claims.device_id),
            ipv6_tunnel_enabled: false,
            obfuscated_udp: claims.obfuscated_udp.clone(),
            tcp_fallback: claims.tcp_fallback.clone(),
            tls_like: claims.tls_like.clone(),
        };
        if let Some(current) = &self.endpoint_override {
            profile.set_endpoint_descriptor(&current.descriptor);
            profile.endpoint_generation = current.generation;
            profile.ipv6_tunnel_enabled = false;
        }
        profile
    }

    pub fn enrollment_request(&self, permanent: &PublicIdentity) -> EnrollmentRequest {
        EnrollmentRequest {
            names: self.names.clone(),
            claims: self.response.claims.clone(),
            signature: self.response.signature.clone(),
            token: self.token.to_string(),
            device_wireguard_public_key: permanent.wireguard_public_key.clone(),
            device_management_certificate_pem: permanent.management_certificate_pem.clone(),
        }
    }

    pub fn permanent_profile(
        &self,
        result: &EnrollmentResult,
        permanent: &PublicIdentity,
        identity_reference: String,
    ) -> Result<ServerProfile, InvitationError> {
        let claims = &self.response.claims;
        let expected_member_id = claims.target_member_id.unwrap_or(claims.member_id);
        let expected_role = claims.target_role.unwrap_or(claims.role);
        if result.names != self.names
            || (claims.recipient_names && self.names.is_none())
            || result.server_id != claims.server_id
            || ((claims.max_uses == 1 || claims.target_member_id.is_some())
                && result.member_id != expected_member_id)
            || (claims.max_uses == 1 && result.device_id != claims.device_id)
            || result.role != expected_role
            || result.administrator != claims.administrator
            || result.server_name != claims.server_name
            || result.endpoint != claims.endpoint
            || result.endpoint_generation != claims.endpoint_generation
            || (claims.max_uses == 1
                && result.client_tunnel_address != claims.client_tunnel_address)
            || !is_member_address(result.client_tunnel_address)
            || result.server_tunnel_address != claims.server_tunnel_address
            || result.server_wireguard_public_key != claims.server_wireguard_public_key
            || result.pinned_server_certificate_pem != claims.pinned_server_certificate_pem
            || result.obfuscated_udp != claims.obfuscated_udp
            || result.tcp_fallback != claims.tcp_fallback
            || result.tls_like != claims.tls_like
            || result.alternate_endpoint_hosts != claims.alternate_endpoint_hosts
            || result.endpoint_discovery_port != claims.endpoint_discovery_port
        {
            return Err(InvitationError::EnrollmentMismatch);
        }
        verify_public_identity(permanent)?;
        let mut profile = ServerProfile {
            favorite: false,
            schema_version: 1,
            id: result.server_id,
            name: result.server_name.clone(),
            endpoint: result.endpoint.clone(),
            endpoint_generation: result.endpoint_generation,
            pending_previous_endpoint: None,
            pending_previous_transports: None,
            endpoint_discovery_port: result.endpoint_discovery_port,
            alternate_endpoint_hosts: result.alternate_endpoint_hosts.clone(),
            client_tunnel_address: result.client_tunnel_address,
            server_tunnel_address: result.server_tunnel_address,
            server_wireguard_public_key: result.server_wireguard_public_key.clone(),
            pinned_server_certificate_pem: result.pinned_server_certificate_pem.clone(),
            client_management_certificate_pem: permanent.management_certificate_pem.clone(),
            identity_reference,
            role: result.role,
            administrator: result.administrator,
            member_id: Some(result.member_id),
            device_id: Some(result.device_id),
            ipv6_tunnel_enabled: result.ipv6_tunnel_enabled,
            obfuscated_udp: result.obfuscated_udp.clone(),
            tcp_fallback: result.tcp_fallback.clone(),
            tls_like: result.tls_like.clone(),
        };
        if let Some(current) = &self.endpoint_override {
            profile.set_endpoint_descriptor(&current.descriptor);
            profile.endpoint_generation = current.generation;
        }
        Ok(profile)
    }
}

fn encode_qr_payload(bytes: &[u8]) -> Result<Zeroizing<String>, InvitationError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(bytes)
        .map_err(|_| InvitationError::EncodingFailed)?;
    let compressed = Zeroizing::new(
        encoder
            .finish()
            .map_err(|_| InvitationError::EncodingFailed)?,
    );
    Ok(Zeroizing::new(format!(
        "{QR_CODE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(&compressed)
    )))
}

fn decode_payload(code: &str) -> Result<Zeroizing<Vec<u8>>, InvitationError> {
    if let Some(encoded) = code.strip_prefix(CODE_PREFIX) {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| InvitationError::InvalidCode)?,
        );
        if bytes.len() > MAX_PAYLOAD_LENGTH {
            return Err(InvitationError::InvalidCode);
        }
        return Ok(bytes);
    }
    let encoded = code
        .strip_prefix(QR_CODE_PREFIX)
        .ok_or(InvitationError::InvalidCode)?;
    let compressed = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| InvitationError::InvalidCode)?,
    );
    let mut decoder =
        DeflateDecoder::new(compressed.as_slice()).take(MAX_PAYLOAD_LENGTH as u64 + 1);
    let mut bytes = Zeroizing::new(Vec::new());
    decoder
        .read_to_end(&mut bytes)
        .map_err(|_| InvitationError::InvalidCode)?;
    if bytes.len() > MAX_PAYLOAD_LENGTH {
        return Err(InvitationError::InvalidCode);
    }
    Ok(bytes)
}

fn validate_invitation_response(
    response: &InvitationCreateResponse,
) -> Result<(), InvitationError> {
    let claims = &response.claims;
    validate_server_name(&claims.server_name).map_err(|_| InvitationError::InvalidCode)?;
    validate_server_name(&claims.member_name).map_err(|_| InvitationError::InvalidCode)?;
    validate_server_name(&claims.device_name).map_err(|_| InvitationError::InvalidCode)?;
    validate_host(&claims.endpoint.host).map_err(|_| InvitationError::InvalidCode)?;
    let target_is_valid = match (claims.target_member_id, claims.target_role) {
        (None, None) => true,
        (Some(target_member_id), Some(target_role)) => {
            target_member_id != claims.member_id
                && !(target_role == ServerRole::Owner && claims.administrator)
        }
        _ => false,
    };
    if claims.schema_version != claims.required_schema_version()
        || !sirinvpn_protocol::valid_alternate_endpoint_hosts(
            &claims.endpoint.host,
            &claims.alternate_endpoint_hosts,
        )
        || claims
            .endpoint_discovery_port
            .is_some_and(|port| port == 0 || claims.tls_like.is_none())
        || !(1..=100).contains(&claims.max_uses)
        || claims.member_policy.validate().is_err()
        || (claims.target_role == Some(ServerRole::Owner)
            && (claims.max_uses > 1 || !claims.member_policy.is_default()))
        || claims.endpoint.wireguard_port == 0
        || claims.management_port == 0
        || claims.server_tunnel_address
            != SERVER_TUNNEL_ADDRESS
                .parse::<IpAddr>()
                .map_err(|_| InvitationError::InvalidCode)?
        || claims.role != ServerRole::Member
        || !target_is_valid
        || !is_member_address(claims.client_tunnel_address)
        || !is_bootstrap_address(claims.bootstrap_tunnel_address)
        || claims.client_tunnel_address == claims.bootstrap_tunnel_address
        || hex::decode(&claims.token_hash)
            .map(|bytes| bytes.len() != 32)
            .unwrap_or(true)
        || claims.token_hash.len() != 64
        || !valid_transport_capabilities(claims)
    {
        return Err(InvitationError::InvalidCode);
    }
    validate_wireguard_public_key(&claims.server_wireguard_public_key)?;
    validate_wireguard_public_key(&claims.bootstrap_wireguard_public_key)?;
    extract_ed25519_public_key(&claims.bootstrap_management_certificate_pem)?;
    let server_public_key = extract_ed25519_public_key(&claims.pinned_server_certificate_pem)?;
    let signature_bytes = STANDARD
        .decode(&response.signature)
        .map_err(|_| InvitationError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| InvitationError::InvalidSignature)?;
    let canonical = serde_json::to_vec(claims).map_err(|_| InvitationError::InvalidCode)?;
    server_public_key
        .verify(&canonical, &signature)
        .map_err(|_| InvitationError::InvalidSignature)
}

fn valid_transport_capabilities(claims: &sirinvpn_protocol::InvitationClaims) -> bool {
    valid_transport_endpoints(
        claims.endpoint.wireguard_port,
        claims.obfuscated_udp.as_ref(),
        claims.tcp_fallback.as_ref(),
        claims.tls_like.as_ref(),
    )
}

pub(crate) fn valid_transport_endpoints(
    direct_port: u16,
    obfuscated_udp: Option<&ObfuscatedUdpEndpoint>,
    tcp_fallback: Option<&TcpFallbackEndpoint>,
    tls_like: Option<&TlsLikeEndpoint>,
) -> bool {
    let valid_key = |value: &str| {
        STANDARD.decode(value).is_ok_and(|decoded| {
            decoded.len() == 32
                && decoded.iter().any(|byte| *byte != 0)
                && STANDARD.encode(&decoded) == value
        })
    };
    let obfuscated_valid = obfuscated_udp.is_none_or(|endpoint| {
        endpoint.port != 0 && endpoint.port != direct_port && valid_key(&endpoint.server_public_key)
    });
    let tcp_valid = tcp_fallback.is_none_or(|endpoint| {
        endpoint.port != 0 && endpoint.port != direct_port && valid_key(&endpoint.server_public_key)
    });
    let tls_valid = tls_like.is_none_or(|endpoint| {
        endpoint.https.as_ref().is_none_or(|https| https.is_valid())
            && endpoint.port != 0
            && endpoint.port != direct_port
            && valid_key(&endpoint.server_public_key)
            && STANDARD
                .decode(&endpoint.certificate_sha256)
                .is_ok_and(|decoded| {
                    decoded.len() == 32 && STANDARD.encode(&decoded) == endpoint.certificate_sha256
                })
            && tcp_fallback.is_some_and(|tcp| tcp.port == endpoint.port)
    });
    let mut keys = obfuscated_udp
        .map(|endpoint| endpoint.server_public_key.as_str())
        .into_iter()
        .chain(tcp_fallback.map(|endpoint| endpoint.server_public_key.as_str()))
        .chain(tls_like.map(|endpoint| endpoint.server_public_key.as_str()));
    let first = keys.next();
    let shared_key = first.is_none_or(|first| keys.all(|key| key == first));
    obfuscated_valid && tcp_valid && tls_valid && shared_key
}

fn verify_bootstrap_identity(
    secret: &SecretIdentity,
    expected_wireguard_public_key: &str,
    certificate_pem: &str,
) -> Result<(), InvitationError> {
    let private_bytes = STANDARD
        .decode(&secret.wireguard_private_key)
        .map_err(|_| InvitationError::InvalidCode)?;
    let private: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| InvitationError::InvalidCode)?;
    let private = StaticSecret::from(private);
    let public = PublicKey::from(&private);
    if STANDARD.encode(public.as_bytes()) != expected_wireguard_public_key {
        return Err(InvitationError::InvalidCode);
    }
    let signing_key = SigningKey::from_pkcs8_pem(&secret.management_private_key_pem)
        .map_err(|_| InvitationError::InvalidCode)?;
    if signing_key.verifying_key() != extract_ed25519_public_key(certificate_pem)? {
        return Err(InvitationError::InvalidCode);
    }
    Ok(())
}

fn verify_public_identity(identity: &PublicIdentity) -> Result<(), InvitationError> {
    validate_wireguard_public_key(&identity.wireguard_public_key)?;
    extract_ed25519_public_key(&identity.management_certificate_pem)?;
    Ok(())
}

fn extract_ed25519_public_key(certificate_pem: &str) -> Result<VerifyingKey, InvitationError> {
    identity::extract_ed25519_public_key(certificate_pem).map_err(|_| InvitationError::InvalidCode)
}

fn validate_wireguard_public_key(public_key: &str) -> Result<(), InvitationError> {
    let decoded = STANDARD
        .decode(public_key)
        .map_err(|_| InvitationError::InvalidCode)?;
    if decoded.len() != 32 {
        return Err(InvitationError::InvalidCode);
    }
    Ok(())
}

fn is_member_address(address: IpAddr) -> bool {
    matches!(address, IpAddr::V4(address) if address.octets()[..3] == [10, 77, 0] && (3..=223).contains(&address.octets()[3]))
}

fn is_bootstrap_address(address: IpAddr) -> bool {
    matches!(address, IpAddr::V4(address) if address.octets()[..3] == [10, 77, 0] && (224..=254).contains(&address.octets()[3]))
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests;
