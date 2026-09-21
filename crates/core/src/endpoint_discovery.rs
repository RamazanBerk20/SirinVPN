use crate::{DecodedEndpointTransition, EndpointTransitionError, endpoint_transition};
use sirinvpn_protocol::{EndpointIdentity, EndpointTransitionResponse};
use sirinvpn_transport::{EndpointDiscoveryConfig, decode_key, fetch_endpoint_checkpoint};
use std::time::Duration;
use zeroize::Zeroizing;

/// Short-lived connection candidates for enrollment and explicit endpoint tests.
/// Resolved addresses change only outer routing; every candidate retains the
/// enrolled WireGuard and management identity. Nothing is written to the profile.
pub async fn endpoint_connection_candidates(
    profile: &sirinvpn_protocol::ServerProfile,
) -> Vec<sirinvpn_protocol::ServerProfile> {
    let hosts = std::iter::once(&profile.endpoint.host)
        .chain(&profile.alternate_endpoint_hosts)
        .cloned()
        .collect::<Vec<_>>();
    let mut tasks = tokio::task::JoinSet::new();
    for (index, host) in hosts.iter().cloned().enumerate() {
        tasks.spawn(async move {
            let addresses = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::lookup_host((host.as_str(), 1)),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .map(|addresses| addresses.map(|address| address.ip()).collect::<Vec<_>>())
            .unwrap_or_default();
            let v4 = addresses.iter().find(|ip| ip.is_ipv4()).copied();
            let v6 = addresses.iter().find(|ip| ip.is_ipv6()).copied();
            (index, [v4, v6].into_iter().flatten().collect::<Vec<_>>())
        });
    }
    let mut addresses = vec![Vec::new(); hosts.len()];
    while let Some(Ok((index, found))) = tasks.join_next().await {
        addresses[index] = found;
    }
    let mut candidates = Vec::new();
    for (host, addresses) in hosts.iter().zip(addresses) {
        let alternatives = if addresses.is_empty() {
            vec![host.clone()]
        } else {
            addresses
                .into_iter()
                .map(|address| address.to_string())
                .collect()
        };
        for address in alternatives {
            if candidates
                .iter()
                .any(|candidate: &sirinvpn_protocol::ServerProfile| {
                    candidate.endpoint.host == address
                })
            {
                continue;
            }
            let mut candidate = profile.clone();
            candidate.endpoint.host = address.clone();
            candidate.alternate_endpoint_hosts = hosts
                .iter()
                .filter(|host| **host != address)
                .take(3)
                .cloned()
                .collect();
            candidates.push(candidate);
        }
    }
    candidates
}

pub fn validate_endpoint_identity(known: &EndpointIdentity) -> Result<(), EndpointTransitionError> {
    endpoint_transition::validate_descriptor(&known.descriptor)?;
    if known.server_id.0.is_nil()
        || known.pinned_server_certificate_pem.len() > 16 * 1024
        || crate::identity::extract_ed25519_public_key(&known.pinned_server_certificate_pem)
            .is_err()
        || decode_key(&known.server_wireguard_public_key).is_err()
    {
        return Err(EndpointTransitionError::InvalidCode);
    }
    Ok(())
}

pub async fn discover_endpoint_checkpoint_at(
    known: &EndpointIdentity,
    client_wireguard_private_key: &str,
    address: std::net::IpAddr,
    socket_mark: Option<u32>,
) -> Result<Option<EndpointTransitionResponse>, EndpointTransitionError> {
    validate_endpoint_identity(known)?;
    let Some(tls) = known.descriptor.tls_like.as_ref() else {
        return Ok(None);
    };
    let config = EndpointDiscoveryConfig {
        server_address: std::net::SocketAddr::new(
            address,
            known.descriptor.endpoint_discovery_port.unwrap_or(tls.port),
        ),
        server_name: tls
            .https
            .as_ref()
            .map_or("www.example.com", |https| &https.server_name)
            .to_owned(),
        client_private_key: Zeroizing::new(
            decode_key(client_wireguard_private_key)
                .map_err(|_| EndpointTransitionError::InvalidCode)?,
        ),
        server_public_key: decode_key(&tls.server_public_key)
            .map_err(|_| EndpointTransitionError::InvalidCode)?,
        socket_mark,
    };
    let bytes = match fetch_endpoint_checkpoint(config).await {
        Ok(Some(bytes)) => bytes,
        _ => return Ok(None),
    };
    let response: EndpointTransitionResponse =
        serde_json::from_slice(&bytes).map_err(|_| EndpointTransitionError::InvalidCode)?;
    match verify_endpoint_checkpoint(known, &response) {
        Ok(_) => Ok(Some(response)),
        Err(EndpointTransitionError::StaleTransition)
            if current_checkpoint_matches(known, &response) =>
        {
            Ok(Some(response))
        }
        Err(EndpointTransitionError::StaleTransition) => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn current_checkpoint_matches(
    known: &EndpointIdentity,
    response: &EndpointTransitionResponse,
) -> bool {
    DecodedEndpointTransition::from_response(response.clone()).is_ok()
        && response.claims.server_id == known.server_id
        && response.claims.generation == known.generation
        && response.claims.server_wireguard_public_key == known.server_wireguard_public_key
        && response.claims.pinned_server_certificate_pem == known.pinned_server_certificate_pem
        && response.claims.endpoint_descriptor() == known.descriptor
}

pub async fn offer_endpoint_checkpoint_at(
    known: &EndpointIdentity,
    response: &EndpointTransitionResponse,
    client_wireguard_private_key: &str,
    source: std::net::IpAddr,
    socket_mark: Option<u32>,
) -> Result<bool, EndpointTransitionError> {
    if verify_endpoint_checkpoint(known, response).is_err()
        && !current_checkpoint_matches(known, response)
    {
        return Err(EndpointTransitionError::BindingMismatch);
    }
    let Some(previous) = &response.claims.previous_transports else {
        return Ok(false);
    };
    let Some(tls) = &previous.tls_like else {
        return Ok(false);
    };
    let config = EndpointDiscoveryConfig {
        server_address: std::net::SocketAddr::new(
            source,
            previous.endpoint_discovery_port.unwrap_or(tls.port),
        ),
        server_name: tls
            .https
            .as_ref()
            .map_or("www.example.com", |https| https.server_name.as_str())
            .to_owned(),
        client_private_key: Zeroizing::new(
            decode_key(client_wireguard_private_key)
                .map_err(|_| EndpointTransitionError::InvalidCode)?,
        ),
        server_public_key: decode_key(&tls.server_public_key)
            .map_err(|_| EndpointTransitionError::InvalidCode)?,
        socket_mark,
    };
    let encoded = serde_json::to_vec(response).map_err(|_| EndpointTransitionError::InvalidCode)?;
    Ok(
        sirinvpn_transport::offer_endpoint_checkpoint(config, &encoded)
            .await
            .unwrap_or(false),
    )
}

pub fn verify_endpoint_checkpoint(
    known: &EndpointIdentity,
    response: &EndpointTransitionResponse,
) -> Result<EndpointIdentity, EndpointTransitionError> {
    // Validate and authenticate the complete descriptor before inspecting its data.
    DecodedEndpointTransition::from_response(response.clone())?;
    let claims = &response.claims;
    if claims.server_id != known.server_id
        || claims.server_wireguard_public_key != known.server_wireguard_public_key
        || claims.pinned_server_certificate_pem != known.pinned_server_certificate_pem
        || (claims.schema_version == 1 && claims.previous_endpoint != known.descriptor.endpoint)
    {
        return Err(EndpointTransitionError::BindingMismatch);
    }
    if claims.generation <= known.generation
        || (claims.schema_version == 1
            && known.generation.checked_add(1) != Some(claims.generation))
    {
        return Err(EndpointTransitionError::StaleTransition);
    }
    let mut updated = known.clone();
    updated.descriptor = claims.endpoint_descriptor();
    updated.generation = claims.generation;
    Ok(updated)
}

/// Best-effort discovery is allowed only while explicitly connecting or under an
/// active automatic reconnect policy. Callers enforce that lifecycle boundary.
/// DNS and network attempts have a single eight-second deadline and are bounded
/// to the primary address and at most three explicitly configured alternatives.
pub async fn discover_endpoint_checkpoint(
    known: &EndpointIdentity,
    client_wireguard_private_key: &str,
    socket_mark: Option<u32>,
) -> Result<Option<EndpointTransitionResponse>, EndpointTransitionError> {
    validate_endpoint_identity(known)?;
    let transport_key = known
        .descriptor
        .tls_like
        .as_ref()
        .map(|tls| &tls.server_public_key)
        .or_else(|| {
            known
                .descriptor
                .tcp_fallback
                .as_ref()
                .map(|tcp| &tcp.server_public_key)
        });
    let Some(transport_key) = transport_key else {
        return Ok(None);
    };
    let server_public_key =
        decode_key(transport_key).map_err(|_| EndpointTransitionError::InvalidCode)?;
    let private = Zeroizing::new(
        decode_key(client_wireguard_private_key)
            .map_err(|_| EndpointTransitionError::InvalidCode)?,
    );
    let Some(port) = known
        .descriptor
        .endpoint_discovery_port
        .or_else(|| known.descriptor.tls_like.as_ref().map(|tls| tls.port))
        .or_else(|| known.descriptor.tcp_fallback.as_ref().map(|tcp| tcp.port))
    else {
        return Ok(None);
    };
    let server_name = known
        .descriptor
        .tls_like
        .as_ref()
        .and_then(|tls| tls.https.as_ref())
        .map_or("www.example.com", |https| https.server_name.as_str())
        .to_owned();
    let discovery = async {
        let mut attempts = tokio::task::JoinSet::new();
        for host in std::iter::once(&known.descriptor.endpoint.host)
            .chain(&known.descriptor.alternate_endpoint_hosts)
        {
            let host = host.clone();
            let server_name = server_name.clone();
            let private = private.clone();
            let known = known.clone();
            attempts.spawn(async move {
                let addresses = tokio::net::lookup_host((host.as_str(), port)).await.ok()?;
                // Multiple A/AAAA records are alternative paths to the same pin.
                let mut connections = tokio::task::JoinSet::new();
                for address in addresses.take(4) {
                    let config = EndpointDiscoveryConfig {
                        server_address: address,
                        server_name: server_name.clone(),
                        client_private_key: private.clone(),
                        server_public_key,
                        socket_mark,
                    };
                    connections.spawn(fetch_endpoint_checkpoint(config));
                }
                while let Some(result) = connections.join_next().await {
                    if let Ok(Ok(Some(bytes))) = result
                        && let Ok(response) =
                            serde_json::from_slice::<EndpointTransitionResponse>(&bytes)
                        && verify_endpoint_checkpoint(&known, &response).is_ok()
                    {
                        return Some(response);
                    }
                }
                None
            });
        }
        while let Some(result) = attempts.join_next().await {
            if let Ok(Some(response)) = result
                && verify_endpoint_checkpoint(known, &response).is_ok()
            {
                return Some(response);
            }
        }
        None
    };
    Ok(tokio::time::timeout(Duration::from_secs(8), discovery)
        .await
        .unwrap_or(None))
}
