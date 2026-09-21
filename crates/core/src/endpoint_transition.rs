use crate::{
    ClientPaths, KeyRotationError, ManagementClient, ManagementError, ProfileStoreError,
    SecretIdentity, SecretStore, SecretStoreError, has_pending_key_rotation, identity,
    management_certificate_fingerprint,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Verifier};
use serde::Serialize;
use sirinvpn_protocol::{
    DEFAULT_MANAGEMENT_PORT, EndpointTransitionCreateRequest, EndpointTransitionResponse,
    SERVER_TUNNEL_ADDRESS, ServerEndpoint, ServerId, ServerProfile, ServerRole, validate_host,
    validate_server_name,
};
use std::future::Future;
use std::net::IpAddr;
use thiserror::Error;

const CODE_PREFIX: &str = "sirm1.";
const MAX_CODE_LENGTH: usize = 32 * 1024;
const MAX_PAYLOAD_LENGTH: usize = 24 * 1024;

#[derive(Debug, Error)]
pub enum EndpointTransitionError {
    #[error("local server profile operation failed: {0}")]
    Profile(#[from] ProfileStoreError),
    #[error("local device secret operation failed: {0}")]
    Secret(#[from] SecretStoreError),
    #[error("private management operation failed: {0}")]
    Management(#[from] ManagementError),
    #[error("the endpoint update code is invalid")]
    InvalidCode,
    #[error("the endpoint update signature is invalid")]
    InvalidSignature,
    #[error("the endpoint update does not match this local server profile")]
    BindingMismatch,
    #[error("the endpoint update is stale or has already been applied")]
    StaleTransition,
    #[error("only the Owner can publish an endpoint update")]
    OwnerRequired,
    #[error("this server profile has no pending VPS migration to publish")]
    NoPendingMigration,
    #[error("complete or recover the pending device key rotation before changing endpoints")]
    KeyRotationPending,
    #[error("device key rotation state could not be checked: {0}")]
    KeyRotation(#[from] KeyRotationError),
    #[error("the server does not support signed endpoint updates; repair/update it first")]
    UnsupportedServer,
    #[error("the candidate endpoint could not be activated: {0}")]
    Tunnel(String),
    #[error("the candidate endpoint failed authenticated verification")]
    CandidateVerificationFailed,
    #[error("candidate cleanup failed; recover local networking before retrying: {0}")]
    CleanupRequired(String),
    #[error("the endpoint update could not be encoded")]
    EncodingFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EndpointTransitionResult {
    pub server_id: ServerId,
    pub previous_endpoint: ServerEndpoint,
    pub endpoint: ServerEndpoint,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointTransitionCode {
    value: String,
    response: EndpointTransitionResponse,
}

impl EndpointTransitionCode {
    pub fn expose(&self) -> &str {
        &self.value
    }

    pub fn generation(&self) -> u64 {
        self.response.claims.generation
    }

    pub fn previous_endpoint(&self) -> &ServerEndpoint {
        &self.response.claims.previous_endpoint
    }

    pub fn endpoint(&self) -> &ServerEndpoint {
        &self.response.claims.endpoint
    }

    pub fn response(&self) -> &EndpointTransitionResponse {
        &self.response
    }

    pub fn from_response(
        response: EndpointTransitionResponse,
    ) -> Result<Self, EndpointTransitionError> {
        validate_response(&response)?;
        let bytes =
            serde_json::to_vec(&response).map_err(|_| EndpointTransitionError::EncodingFailed)?;
        if bytes.len() > MAX_PAYLOAD_LENGTH {
            return Err(EndpointTransitionError::EncodingFailed);
        }
        Ok(Self {
            value: format!("{CODE_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)),
            response,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedEndpointTransition {
    response: EndpointTransitionResponse,
}

impl DecodedEndpointTransition {
    pub fn from_response(
        response: EndpointTransitionResponse,
    ) -> Result<Self, EndpointTransitionError> {
        validate_response(&response)?;
        Ok(Self { response })
    }

    pub fn decode(code: &str) -> Result<Self, EndpointTransitionError> {
        let code = code.trim();
        if code.len() > MAX_CODE_LENGTH {
            return Err(EndpointTransitionError::InvalidCode);
        }
        let encoded = code
            .strip_prefix(CODE_PREFIX)
            .ok_or(EndpointTransitionError::InvalidCode)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| EndpointTransitionError::InvalidCode)?;
        if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_LENGTH {
            return Err(EndpointTransitionError::InvalidCode);
        }
        let response: EndpointTransitionResponse =
            serde_json::from_slice(&bytes).map_err(|_| EndpointTransitionError::InvalidCode)?;
        validate_response(&response)?;
        Ok(Self { response })
    }

    pub fn response(&self) -> &EndpointTransitionResponse {
        &self.response
    }

    pub fn candidate_profile(
        &self,
        profile: &ServerProfile,
    ) -> Result<ServerProfile, EndpointTransitionError> {
        let claims = &self.response.claims;
        if claims.server_id != profile.id
            || (claims.schema_version == 1 && claims.previous_endpoint != profile.endpoint)
            || claims.server_tunnel_address != profile.server_tunnel_address
            || claims.server_wireguard_public_key != profile.server_wireguard_public_key
            || claims.pinned_server_certificate_pem != profile.pinned_server_certificate_pem
        {
            return Err(EndpointTransitionError::BindingMismatch);
        }
        if claims.generation <= profile.endpoint_generation
            || (claims.schema_version == 1
                && profile
                    .endpoint_generation
                    .checked_add(1)
                    .is_none_or(|expected| claims.generation != expected))
        {
            return Err(EndpointTransitionError::StaleTransition);
        }

        let mut candidate = profile.clone();
        candidate.set_endpoint_descriptor(&claims.endpoint_descriptor());
        candidate.endpoint_generation = claims.generation;
        candidate.pending_previous_endpoint = None;
        candidate.pending_previous_transports = None;
        Ok(candidate)
    }

    pub fn previous_profile_for_owner(
        &self,
        profile: &ServerProfile,
    ) -> Result<ServerProfile, EndpointTransitionError> {
        let claims = &self.response.claims;
        if profile.role != ServerRole::Owner
            || claims.server_id != profile.id
            || claims.endpoint != profile.endpoint
            || claims.generation != profile.endpoint_generation
            || claims.server_tunnel_address != profile.server_tunnel_address
            || claims.server_wireguard_public_key != profile.server_wireguard_public_key
            || claims.pinned_server_certificate_pem != profile.pinned_server_certificate_pem
        {
            return Err(EndpointTransitionError::BindingMismatch);
        }
        let mut previous = profile.clone();
        if let Some(descriptor) = &claims.previous_transports {
            previous.set_endpoint_descriptor(descriptor);
        }
        previous.endpoint = claims.previous_endpoint.clone();
        previous.endpoint_generation = claims.generation.saturating_sub(1);
        previous.pending_previous_endpoint = None;
        previous.pending_previous_transports = None;
        Ok(previous)
    }

    /// Retain an Owner's signed checkpoint after its new VPS confirms the migration.
    pub fn owner_profile(
        &self,
        profile: &ServerProfile,
    ) -> Result<ServerProfile, EndpointTransitionError> {
        if profile.role != ServerRole::Owner {
            return Err(EndpointTransitionError::OwnerRequired);
        }
        validate_owner_response(profile, &self.response)?;
        let mut next = profile.clone();
        next.set_endpoint_descriptor(&self.response.claims.endpoint_descriptor());
        next.endpoint_generation = self.response.claims.generation;
        next.pending_previous_endpoint = None;
        next.pending_previous_transports = None;
        Ok(next)
    }
}

pub async fn create_endpoint_transition(
    paths: &ClientPaths,
    server_id: ServerId,
) -> Result<EndpointTransitionCode, EndpointTransitionError> {
    if has_pending_key_rotation(paths, server_id)? {
        return Err(EndpointTransitionError::KeyRotationPending);
    }
    let profiles = paths.profile_store();
    let mut profile = profiles
        .load()?
        .into_iter()
        .find(|profile| profile.id == server_id)
        .ok_or(ProfileStoreError::NotFound)?;
    if profile.role != ServerRole::Owner {
        return Err(EndpointTransitionError::OwnerRequired);
    }
    let secret = paths.secret_store().get(&profile.identity_reference)?;
    let client = ManagementClient::new(&profile, &secret)?;
    if !client.configuration().await?.endpoint_transitions_enabled {
        return Err(EndpointTransitionError::UnsupportedServer);
    }

    let response = if let Some(previous_endpoint) = profile.pending_previous_endpoint.clone() {
        let generation = profile
            .endpoint_generation
            .checked_add(1)
            .ok_or(EndpointTransitionError::InvalidCode)?;
        let request = EndpointTransitionCreateRequest {
            server_id,
            generation,
            previous_endpoint,
            previous_transports: profile.pending_previous_transports.clone(),
            endpoint: profile.endpoint.clone(),
        };
        client.create_endpoint_transition(&request).await?
    } else {
        client
            .endpoint_transition()
            .await?
            .ok_or(EndpointTransitionError::NoPendingMigration)?
    };

    validate_owner_response(&profile, &response)?;
    let code = EndpointTransitionCode::from_response(response)?;
    profile.endpoint_generation = code.generation();
    profile.pending_previous_endpoint = None;
    profile.pending_previous_transports = None;
    profiles.upsert(profile)?;
    Ok(code)
}

pub async fn apply_endpoint_transition<Connect, ConnectFuture, Disconnect>(
    paths: &ClientPaths,
    server_id: ServerId,
    code: &str,
    mut connect: Connect,
    mut disconnect: Disconnect,
) -> Result<EndpointTransitionResult, EndpointTransitionError>
where
    Connect: FnMut(ServerProfile, SecretIdentity) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<(), String>>,
    Disconnect: FnMut() -> Result<(), String>,
{
    if has_pending_key_rotation(paths, server_id)? {
        return Err(EndpointTransitionError::KeyRotationPending);
    }
    let profiles = paths.profile_store();
    let profile = profiles
        .load()?
        .into_iter()
        .find(|profile| profile.id == server_id)
        .ok_or(ProfileStoreError::NotFound)?;
    let decoded = DecodedEndpointTransition::decode(code)?;
    let mut candidate = decoded.candidate_profile(&profile)?;
    let secret = paths.secret_store().get(&profile.identity_reference)?;

    if let Err(error) = connect(candidate.clone(), secret.clone()).await {
        cleanup_after_failure(&mut disconnect)?;
        return Err(EndpointTransitionError::Tunnel(error));
    }
    let verification = async {
        let client = ManagementClient::new(&candidate, &secret)?;
        if !client.configuration().await?.endpoint_transitions_enabled {
            return Err(EndpointTransitionError::UnsupportedServer);
        }
        let status = client.status().await?;
        let expected_fingerprint =
            management_certificate_fingerprint(&profile.client_management_certificate_pem)
                .map_err(|_| EndpointTransitionError::CandidateVerificationFailed)?;
        if !status.interface_up
            || status.caller_role.is_none()
            || status.caller_device_id.is_none()
            || status.caller_identity_fingerprint != expected_fingerprint
            || profile
                .device_id
                .is_some_and(|device_id| Some(device_id) != status.caller_device_id)
        {
            return Err(EndpointTransitionError::CandidateVerificationFailed);
        }
        let published = client
            .endpoint_transition()
            .await?
            .ok_or(EndpointTransitionError::CandidateVerificationFailed)?;
        if published != *decoded.response() {
            return Err(EndpointTransitionError::CandidateVerificationFailed);
        }
        candidate.role = status
            .caller_role
            .ok_or(EndpointTransitionError::CandidateVerificationFailed)?;
        candidate.administrator = status.caller_administrator;
        client
            .refresh_membership_ids(
                &mut candidate,
                status
                    .caller_device_id
                    .ok_or(EndpointTransitionError::CandidateVerificationFailed)?,
            )
            .await?;
        Ok::<(), EndpointTransitionError>(())
    }
    .await;

    if let Err(error) = verification {
        cleanup_after_failure(&mut disconnect)?;
        return Err(error);
    }
    if let Err(error) = profiles.upsert(candidate.clone()) {
        cleanup_after_failure(&mut disconnect)?;
        return Err(error.into());
    }
    Ok(EndpointTransitionResult {
        server_id,
        previous_endpoint: profile.endpoint,
        endpoint: candidate.endpoint,
        generation: candidate.endpoint_generation,
    })
}

pub async fn publish_endpoint_transition<Connect, ConnectFuture, Disconnect>(
    paths: &ClientPaths,
    server_id: ServerId,
    code: &str,
    mut connect: Connect,
    mut disconnect: Disconnect,
) -> Result<EndpointTransitionResult, EndpointTransitionError>
where
    Connect: FnMut(ServerProfile, SecretIdentity) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<(), String>>,
    Disconnect: FnMut() -> Result<(), String>,
{
    if has_pending_key_rotation(paths, server_id)? {
        return Err(EndpointTransitionError::KeyRotationPending);
    }
    let profile = paths
        .profile_store()
        .load()?
        .into_iter()
        .find(|profile| profile.id == server_id)
        .ok_or(ProfileStoreError::NotFound)?;
    let decoded = DecodedEndpointTransition::decode(code)?;
    let previous = decoded.previous_profile_for_owner(&profile)?;
    let secret = paths.secret_store().get(&profile.identity_reference)?;

    if let Err(error) = connect(previous.clone(), secret.clone()).await {
        cleanup_after_failure(&mut disconnect)?;
        return Err(EndpointTransitionError::Tunnel(error));
    }
    let publish_result = async {
        let client = ManagementClient::new(&previous, &secret)?;
        if !client.configuration().await?.endpoint_transitions_enabled {
            return Err(EndpointTransitionError::UnsupportedServer);
        }
        let status = client.status().await?;
        let expected_fingerprint =
            management_certificate_fingerprint(&profile.client_management_certificate_pem)
                .map_err(|_| EndpointTransitionError::CandidateVerificationFailed)?;
        if !status.interface_up
            || status.caller_role != Some(ServerRole::Owner)
            || status.caller_identity_fingerprint != expected_fingerprint
            || profile
                .device_id
                .is_some_and(|device_id| Some(device_id) != status.caller_device_id)
        {
            return Err(EndpointTransitionError::CandidateVerificationFailed);
        }
        let published = client
            .publish_endpoint_transition(decoded.response())
            .await?;
        if published != *decoded.response()
            || client.endpoint_transition().await? != Some(published)
        {
            return Err(EndpointTransitionError::CandidateVerificationFailed);
        }
        Ok::<(), EndpointTransitionError>(())
    }
    .await;
    let cleanup = disconnect();
    if let Err(error) = cleanup {
        return Err(EndpointTransitionError::CleanupRequired(error));
    }
    publish_result?;
    Ok(EndpointTransitionResult {
        server_id,
        previous_endpoint: decoded.response.claims.previous_endpoint.clone(),
        endpoint: decoded.response.claims.endpoint.clone(),
        generation: decoded.response.claims.generation,
    })
}

fn cleanup_after_failure(
    disconnect: &mut impl FnMut() -> Result<(), String>,
) -> Result<(), EndpointTransitionError> {
    disconnect().map_err(EndpointTransitionError::CleanupRequired)
}

fn validate_owner_response(
    profile: &ServerProfile,
    response: &EndpointTransitionResponse,
) -> Result<(), EndpointTransitionError> {
    validate_response(response)?;
    let claims = &response.claims;
    let generation_or_predecessor_mismatch = match &profile.pending_previous_endpoint {
        Some(previous) => {
            previous != &claims.previous_endpoint
                || profile
                    .endpoint_generation
                    .checked_add(1)
                    .is_none_or(|expected| claims.generation != expected)
        }
        None => claims.generation < profile.endpoint_generation,
    };
    if claims.server_id != profile.id
        || claims.endpoint != profile.endpoint
        || claims.server_tunnel_address != profile.server_tunnel_address
        || claims.server_wireguard_public_key != profile.server_wireguard_public_key
        || claims.pinned_server_certificate_pem != profile.pinned_server_certificate_pem
        || generation_or_predecessor_mismatch
    {
        return Err(EndpointTransitionError::BindingMismatch);
    }
    Ok(())
}

pub(crate) fn validate_response(
    response: &EndpointTransitionResponse,
) -> Result<(), EndpointTransitionError> {
    let claims = &response.claims;
    validate_server_name(&claims.server_name).map_err(|_| EndpointTransitionError::InvalidCode)?;
    validate_endpoint(&claims.previous_endpoint)?;
    validate_endpoint(&claims.endpoint)?;
    let expected_tunnel = SERVER_TUNNEL_ADDRESS
        .parse::<IpAddr>()
        .map_err(|_| EndpointTransitionError::InvalidCode)?;
    if !matches!(claims.schema_version, 1 | 2)
        || claims.generation == 0
        || (claims.schema_version == 1
            && (claims.previous_endpoint == claims.endpoint
                || claims.previous_transports.is_some()
                || !claims.alternate_endpoint_hosts.is_empty()
                || claims.endpoint_discovery_port.is_some()))
        || (claims.schema_version == 2 && claims.previous_transports.is_none())
        || claims.server_tunnel_address != expected_tunnel
        || claims.management_port != DEFAULT_MANAGEMENT_PORT
        || !valid_public_key(&claims.server_wireguard_public_key)
        || !valid_sha256_fingerprint(&claims.authorization_fingerprint)
        || claims.obfuscated_udp.as_ref().is_some_and(|endpoint| {
            endpoint.port == 0
                || endpoint.port == claims.endpoint.wireguard_port
                || !valid_public_key(&endpoint.server_public_key)
        })
        || claims.tcp_fallback.as_ref().is_some_and(|endpoint| {
            endpoint.port == 0
                || endpoint.port == claims.endpoint.wireguard_port
                || !valid_public_key(&endpoint.server_public_key)
        })
        || claims.tls_like.as_ref().is_some_and(|endpoint| {
            endpoint
                .https
                .as_ref()
                .is_some_and(|https| !https.is_valid())
                || endpoint.port == 0
                || endpoint.port == claims.endpoint.wireguard_port
                || !valid_public_key(&endpoint.server_public_key)
                || !valid_base64_sha256(&endpoint.certificate_sha256)
        })
        || claims.tls_like.as_ref().is_some_and(|tls| {
            claims
                .tcp_fallback
                .as_ref()
                .is_none_or(|tcp| tcp.port != tls.port)
        })
        || claims
            .obfuscated_udp
            .as_ref()
            .zip(claims.tcp_fallback.as_ref())
            .is_some_and(|(udp, tcp)| udp.server_public_key != tcp.server_public_key)
        || claims.tls_like.as_ref().is_some_and(|tls| {
            claims
                .obfuscated_udp
                .as_ref()
                .is_some_and(|udp| udp.server_public_key != tls.server_public_key)
                || claims
                    .tcp_fallback
                    .as_ref()
                    .is_some_and(|tcp| tcp.server_public_key != tls.server_public_key)
        })
    {
        return Err(EndpointTransitionError::InvalidCode);
    }
    validate_descriptor(&claims.endpoint_descriptor())?;
    if let Some(previous) = &claims.previous_transports {
        validate_descriptor(previous)?;
        if previous.endpoint != claims.previous_endpoint {
            return Err(EndpointTransitionError::InvalidCode);
        }
    }

    let verifying_key = identity::extract_ed25519_public_key(&claims.pinned_server_certificate_pem)
        .map_err(|_| EndpointTransitionError::InvalidCode)?;
    let signature = STANDARD
        .decode(&response.signature)
        .map_err(|_| EndpointTransitionError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| EndpointTransitionError::InvalidSignature)?;
    let canonical = serde_json::to_vec(claims).map_err(|_| EndpointTransitionError::InvalidCode)?;
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| EndpointTransitionError::InvalidSignature)
}

pub(crate) fn validate_descriptor(
    descriptor: &sirinvpn_protocol::EndpointDescriptor,
) -> Result<(), EndpointTransitionError> {
    validate_endpoint(&descriptor.endpoint)?;
    if !sirinvpn_protocol::valid_alternate_endpoint_hosts(
        &descriptor.endpoint.host,
        &descriptor.alternate_endpoint_hosts,
    ) || descriptor.endpoint_discovery_port.is_some_and(|port| {
        port == 0 || port == descriptor.endpoint.wireguard_port || descriptor.tls_like.is_none()
    }) || !crate::invitation::valid_transport_endpoints(
        descriptor.endpoint.wireguard_port,
        descriptor.obfuscated_udp.as_ref(),
        descriptor.tcp_fallback.as_ref(),
        descriptor.tls_like.as_ref(),
    ) {
        return Err(EndpointTransitionError::InvalidCode);
    }
    Ok(())
}

fn validate_endpoint(endpoint: &ServerEndpoint) -> Result<(), EndpointTransitionError> {
    validate_host(&endpoint.host).map_err(|_| EndpointTransitionError::InvalidCode)?;
    if endpoint.wireguard_port == 0 {
        return Err(EndpointTransitionError::InvalidCode);
    }
    Ok(())
}

fn valid_public_key(value: &str) -> bool {
    STANDARD.decode(value).is_ok_and(|decoded| {
        decoded.len() == 32
            && decoded.iter().any(|byte| *byte != 0)
            && STANDARD.encode(decoded.as_slice()) == value
    })
}

fn valid_sha256_fingerprint(value: &str) -> bool {
    hex::decode(value)
        .is_ok_and(|decoded| decoded.len() == 32 && hex::encode(decoded.as_slice()) == value)
}

fn valid_base64_sha256(value: &str) -> bool {
    STANDARD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 32 && STANDARD.encode(&decoded) == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalIdentity;
    use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey};
    use sirinvpn_protocol::{
        DeviceId, EndpointTransitionClaims, ServerRole, TcpFallbackEndpoint, TlsLikeEndpoint,
    };

    fn fixture() -> (ServerProfile, EndpointTransitionResponse) {
        let (profile, response, _) = signing_fixture();
        (profile, response)
    }

    fn signing_fixture() -> (ServerProfile, EndpointTransitionResponse, SigningKey) {
        let server = LocalIdentity::generate("Endpoint transition server").unwrap();
        let device = LocalIdentity::generate("Endpoint transition device").unwrap();
        let server_id = ServerId::new();
        let previous_endpoint = ServerEndpoint {
            host: "203.0.113.10".to_owned(),
            wireguard_port: 51_820,
        };
        let endpoint = ServerEndpoint {
            host: "203.0.113.20".to_owned(),
            wireguard_port: 51_820,
        };
        let claims = EndpointTransitionClaims {
            endpoint_discovery_port: None,
            alternate_endpoint_hosts: Vec::new(),
            previous_transports: None,
            schema_version: 1,
            server_id,
            generation: 1,
            server_name: "Migrated VPS".to_owned(),
            previous_endpoint: previous_endpoint.clone(),
            endpoint,
            server_tunnel_address: SERVER_TUNNEL_ADDRESS.parse().unwrap(),
            management_port: DEFAULT_MANAGEMENT_PORT,
            server_wireguard_public_key: server.public.wireguard_public_key.clone(),
            pinned_server_certificate_pem: server.public.management_certificate_pem.clone(),
            authorization_fingerprint: hex::encode([42_u8; 32]),
            ipv6_tunnel_enabled: false,
            obfuscated_udp: None,
            tcp_fallback: Some(TcpFallbackEndpoint {
                port: 443,
                server_public_key: STANDARD.encode([17_u8; 32]),
            }),
            tls_like: Some(TlsLikeEndpoint {
                port: 443,
                server_public_key: STANDARD.encode([17_u8; 32]),
                certificate_sha256: STANDARD.encode([18_u8; 32]),
                https: None,
            }),
        };
        let signing_key =
            SigningKey::from_pkcs8_pem(&server.secret.management_private_key_pem).unwrap();
        let signature = STANDARD.encode(
            signing_key
                .sign(&serde_json::to_vec(&claims).unwrap())
                .to_bytes(),
        );
        let profile = ServerProfile {
            favorite: false,
            schema_version: 1,
            id: server_id,
            name: "Migrated VPS".to_owned(),
            endpoint: previous_endpoint,
            endpoint_generation: 0,
            pending_previous_endpoint: None,
            pending_previous_transports: None,
            endpoint_discovery_port: None,
            alternate_endpoint_hosts: Vec::new(),
            client_tunnel_address: "10.77.0.2".parse().unwrap(),
            server_tunnel_address: SERVER_TUNNEL_ADDRESS.parse().unwrap(),
            server_wireguard_public_key: server.public.wireguard_public_key,
            pinned_server_certificate_pem: server.public.management_certificate_pem,
            client_management_certificate_pem: device.public.management_certificate_pem,
            identity_reference: "endpoint-device".to_owned(),
            role: ServerRole::Owner,
            administrator: false,
            member_id: None,
            device_id: Some(DeviceId::new()),
            ipv6_tunnel_enabled: false,
            obfuscated_udp: None,
            tcp_fallback: None,
            tls_like: None,
        };
        (
            profile,
            EndpointTransitionResponse { claims, signature },
            signing_key,
        )
    }

    #[test]
    fn signed_code_round_trip_updates_only_public_endpoint_state() {
        let (profile, response) = fixture();
        let code = EndpointTransitionCode::from_response(response.clone()).unwrap();
        assert!(code.expose().starts_with(CODE_PREFIX));
        assert!(!code.expose().contains("PRIVATE KEY"));

        let decoded = DecodedEndpointTransition::decode(code.expose()).unwrap();
        assert_eq!(decoded.response(), &response);
        let candidate = decoded.candidate_profile(&profile).unwrap();
        assert_eq!(candidate.endpoint, response.claims.endpoint);
        assert_eq!(candidate.endpoint_generation, 1);
        assert_eq!(candidate.identity_reference, profile.identity_reference);
        assert_eq!(
            candidate.client_management_certificate_pem,
            profile.client_management_certificate_pem
        );
        assert_eq!(
            candidate.server_wireguard_public_key,
            profile.server_wireguard_public_key
        );
        assert_eq!(candidate.tls_like, response.claims.tls_like);
    }

    #[test]
    fn owner_checkpoint_requires_the_restored_endpoint_and_retains_device_identity() {
        let (profile, response) = fixture();
        let decoded = DecodedEndpointTransition::from_response(response.clone()).unwrap();
        assert!(decoded.owner_profile(&profile).is_err());
        let mut restored = profile.clone();
        restored.endpoint = response.claims.endpoint.clone();
        restored.pending_previous_endpoint = Some(profile.endpoint.clone());
        let updated = decoded.owner_profile(&restored).unwrap();
        assert_eq!(updated.endpoint_generation, 1);
        assert!(updated.pending_previous_endpoint.is_none());
        assert_eq!(updated.identity_reference, profile.identity_reference);
        assert_eq!(
            updated.client_management_certificate_pem,
            profile.client_management_certificate_pem
        );
        assert_eq!(
            updated.endpoint_descriptor(),
            response.claims.endpoint_descriptor()
        );
        restored.role = ServerRole::Member;
        assert!(decoded.owner_profile(&restored).is_err());
        restored.role = ServerRole::Owner;
        restored.pending_previous_endpoint.as_mut().unwrap().host = "foreign.example.com".into();
        assert!(decoded.owner_profile(&restored).is_err());
    }

    #[test]
    fn tampering_wrong_binding_and_replay_are_rejected_before_profile_mutation() {
        let (_profile, mut response) = fixture();
        response.claims.endpoint.host = "203.0.113.99".to_owned();
        assert!(matches!(
            EndpointTransitionCode::from_response(response),
            Err(EndpointTransitionError::InvalidSignature)
        ));

        let (profile, response) = fixture();
        let code = EndpointTransitionCode::from_response(response).unwrap();
        let decoded = DecodedEndpointTransition::decode(code.expose()).unwrap();
        let mut wrong = profile.clone();
        wrong.endpoint.host = "203.0.113.11".to_owned();
        assert!(matches!(
            decoded.candidate_profile(&wrong),
            Err(EndpointTransitionError::BindingMismatch)
        ));

        let mut replayed = profile;
        replayed.endpoint_generation = 1;
        assert!(matches!(
            decoded.candidate_profile(&replayed),
            Err(EndpointTransitionError::StaleTransition)
        ));

        let (profile, mut skipped_response) = fixture();
        skipped_response.claims.generation = 2;
        let decoded = DecodedEndpointTransition {
            response: skipped_response,
        };
        assert!(matches!(
            decoded.candidate_profile(&profile),
            Err(EndpointTransitionError::StaleTransition)
        ));
    }

    #[test]
    fn owner_publication_uses_the_exact_previous_endpoint_without_changing_identity() {
        let (old_profile, response) = fixture();
        let mut current_profile = old_profile.clone();
        current_profile.endpoint = response.claims.endpoint.clone();
        current_profile.endpoint_generation = response.claims.generation;
        let code = EndpointTransitionCode::from_response(response).unwrap();
        let decoded = DecodedEndpointTransition::decode(code.expose()).unwrap();
        let previous = decoded
            .previous_profile_for_owner(&current_profile)
            .unwrap();
        assert_eq!(previous.endpoint, old_profile.endpoint);
        assert_eq!(previous.endpoint_generation, 0);
        assert_eq!(
            previous.identity_reference,
            current_profile.identity_reference
        );
        assert_eq!(
            previous.client_management_certificate_pem,
            current_profile.client_management_certificate_pem
        );
    }
    #[test]
    fn checkpoints_catch_up_across_generations_and_rotate_only_public_capabilities() {
        let (mut profile, mut response, key) = signing_fixture();
        profile.name = "My saved name".into();
        profile.favorite = true;
        profile.endpoint_generation = 2;
        response.claims.schema_version = 2;
        response.claims.generation = 19;
        response.claims.previous_transports = Some(profile.endpoint_descriptor());
        // A certificate/port update is valid even when the primary name stays put.
        response.claims.endpoint = profile.endpoint.clone();
        response.claims.endpoint_discovery_port = Some(443);
        response.claims.alternate_endpoint_hosts =
            vec!["2001:db8::2".into(), "fallback.example.com".into()];
        response.claims.tcp_fallback.as_mut().unwrap().port = 8444;
        let tls = response.claims.tls_like.as_mut().unwrap();
        tls.port = 8444;
        tls.certificate_sha256 = STANDARD.encode([77_u8; 32]);
        response.signature = STANDARD.encode(
            key.sign(&serde_json::to_vec(&response.claims).unwrap())
                .to_bytes(),
        );
        let next =
            crate::verify_endpoint_checkpoint(&profile.endpoint_identity(), &response).unwrap();
        assert_eq!(next.generation, 19);
        assert_eq!(next.descriptor.endpoint, profile.endpoint);
        let directory = tempfile::tempdir().unwrap();
        let store = crate::ProfileStore::new(directory.path().join("profiles.json"));
        store.upsert(profile.clone()).unwrap();
        let saved = store.apply_endpoint_checkpoint(response.clone()).unwrap();
        assert_eq!(saved.name, profile.name);
        assert!(saved.favorite);
        assert_eq!(saved.identity_reference, profile.identity_reference);
        assert_eq!(
            saved.client_management_certificate_pem,
            profile.client_management_certificate_pem
        );
        assert_eq!(saved.endpoint_descriptor(), next.descriptor);
        assert!(store.apply_endpoint_checkpoint(response.clone()).is_err());
        response.claims.alternate_endpoint_hosts[0] = "2001:db8::3".into();
        assert!(matches!(
            DecodedEndpointTransition::from_response(response),
            Err(EndpointTransitionError::InvalidSignature)
        ));
        assert_eq!(store.load().unwrap(), vec![saved]);
    }

    #[test]
    fn checkpoints_cannot_replace_immutable_server_identity() {
        let (profile, mut response, key) = signing_fixture();
        response.claims.schema_version = 2;
        response.claims.generation = 21;
        response.claims.previous_transports = Some(profile.endpoint_descriptor());
        for wrong_field in 0..2 {
            let mut wrong = response.clone();
            if wrong_field == 0 {
                wrong.claims.server_id = ServerId::new();
            } else {
                wrong.claims.server_wireguard_public_key = STANDARD.encode([66_u8; 32]);
            }
            wrong.signature = STANDARD.encode(
                key.sign(&serde_json::to_vec(&wrong.claims).unwrap())
                    .to_bytes(),
            );
            assert!(matches!(
                crate::verify_endpoint_checkpoint(&profile.endpoint_identity(), &wrong),
                Err(EndpointTransitionError::BindingMismatch)
            ));
        }
    }
}
