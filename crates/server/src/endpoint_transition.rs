//! Endpoint transition.

use super::*;

pub(super) async fn endpoint_transition_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> Result<Json<ApiEnvelope<Option<EndpointTransitionResponse>>>, ApiError> {
    authorize_device(&state, &caller, false).await?;
    let authorization = require_authorization(&state)?;
    let current = authorization.read().await;
    authorize_current(&current, &caller, false)?;
    let transition = current.endpoint_transition.clone();
    Ok(Json(ApiEnvelope::new(transition)))
}

pub(super) async fn create_endpoint_transition_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(request): Json<EndpointTransitionCreateRequest>,
) -> Result<Json<ApiEnvelope<EndpointTransitionResponse>>, ApiError> {
    validate_transition_request(&state, &request)?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &caller, false)?;
    if !caller.is_owner() {
        return Err(ApiError::forbidden());
    }
    ensure_active_endpoint_authority(&current)?;
    if current.server_id != request.server_id {
        return Err(ApiError::conflict(
            "the endpoint update belongs to a different server profile",
        ));
    }
    let now = unix_time();
    let mut next = current.clone();
    next.prune_expired(now);
    ensure_transition_quiescent(&next)?;
    let claims = endpoint_transition_claims(&state, &request, &next)?;
    let signature = sign_endpoint_transition(&state.paths.tls_private_key, &claims)
        .map_err(|_| ApiError::internal())?;
    let response = EndpointTransitionResponse { claims, signature };
    next.accept_endpoint_transition(response.clone())
        .map_err(|error| ApiError::conflict(error.to_string()))?;
    if next != *current {
        commit_authorization(&state, &mut current, next).await?;
    }
    Ok(Json(ApiEnvelope::new(response)))
}

pub(super) async fn publish_endpoint_transition_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(response): Json<EndpointTransitionResponse>,
) -> Result<Json<ApiEnvelope<EndpointTransitionResponse>>, ApiError> {
    verify_endpoint_transition_signature(&state.paths.tls_private_key, &response)
        .map_err(|_| ApiError::invalid("the endpoint update signature is invalid"))?;
    validate_transition_claims_for_server(&state, &response.claims)?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &caller, false)?;
    if !caller.is_owner() {
        return Err(ApiError::forbidden());
    }
    if response.claims.server_id != current.server_id {
        return Err(ApiError::conflict(
            "the endpoint update belongs to a different server identity",
        ));
    }
    if !current.endpoint_transition_source
        && current.endpoint_transition.as_ref() == Some(&response)
    {
        // This is the active destination, possibly reached through an alias of
        // its predecessor. Publishing its own checkpoint must not freeze it.
        return Ok(Json(ApiEnvelope::new(response)));
    }
    if !current.endpoint_transition_source && response.claims.schema_version == 2 {
        let expected = current
            .endpoint_transition
            .as_ref()
            .map(|head| head.claims.endpoint_descriptor())
            .unwrap_or_else(|| {
                configuration_endpoint_descriptor(
                    &state.configuration,
                    state.configuration.public_endpoint.as_ref().map_or(
                        response.claims.previous_endpoint.host.as_str(),
                        |endpoint| endpoint.host.as_str(),
                    ),
                )
            });
        if response.claims.previous_transports.as_ref() != Some(&expected) {
            return Err(ApiError::conflict(
                "the signed predecessor does not match this handoff source",
            ));
        }
    }
    let authorization_fingerprint = current
        .endpoint_authorization_fingerprint()
        .map_err(|_| ApiError::internal())?;
    if response.claims.authorization_fingerprint != authorization_fingerprint {
        return Err(ApiError::conflict(
            "the old and restored VPS authorization state differs; reconcile access before publishing this endpoint update",
        ));
    }
    if current.endpoint_transition_source && current.endpoint_transition.as_ref() != Some(&response)
    {
        return Err(ApiError::conflict(
            "this handoff source is already bound to its current signed endpoint update",
        ));
    }
    let mut next = current.clone();
    next.prune_expired(unix_time());
    ensure_transition_quiescent(&next)?;
    next.accept_endpoint_transition(response.clone())
        .map_err(|error| ApiError::conflict(error.to_string()))?;
    next.endpoint_observed_address = None;
    next.endpoint_transition_source = true;
    if next != *current {
        commit_authorization(&state, &mut current, next).await?;
    }
    Ok(Json(ApiEnvelope::new(response)))
}

pub(super) fn validate_transition_request(
    state: &AppState,
    request: &EndpointTransitionCreateRequest,
) -> Result<(), ApiError> {
    validate_endpoint(&request.previous_endpoint)?;
    validate_endpoint(&request.endpoint)?;
    if request.generation == 0
        || request.endpoint.wireguard_port != state.configuration.wireguard_port
    {
        return Err(ApiError::invalid(
            "the endpoint update contains an invalid generation or endpoint",
        ));
    }
    if let Some(previous) = &request.previous_transports {
        authorization::validate_endpoint_descriptor(previous)
            .map_err(|_| ApiError::invalid("previous transport descriptor is invalid"))?;
        if previous.endpoint != request.previous_endpoint {
            return Err(ApiError::invalid(
                "previous transport endpoint does not match",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_endpoint(endpoint: &ServerEndpoint) -> Result<(), ApiError> {
    validate_host(&endpoint.host).map_err(|error| ApiError::invalid(error.to_string()))?;
    if endpoint.wireguard_port == 0 {
        return Err(ApiError::invalid("endpoint ports must be non-zero"));
    }
    Ok(())
}

pub(super) fn ensure_transition_quiescent(
    authorization: &AuthorizationDocument,
) -> Result<(), ApiError> {
    if !authorization.invitations.is_empty()
        || !authorization.enrollment_receipts.is_empty()
        || !authorization.key_rotations.is_empty()
        || authorization.recovery_receipt.is_some()
    {
        return Err(ApiError::conflict(
            "cancel active invitations and finish enrollment handoffs and key rotations before publishing an endpoint update",
        ));
    }
    Ok(())
}

pub(super) fn ensure_active_endpoint_authority(
    authorization: &AuthorizationDocument,
) -> Result<(), ApiError> {
    if authorization.endpoint_transition_source {
        return Err(ApiError::conflict(
            "this VPS is a read-only endpoint handoff source; manage access on the restored VPS",
        ));
    }
    Ok(())
}

pub(super) fn endpoint_transition_claims(
    state: &AppState,
    request: &EndpointTransitionCreateRequest,
    authorization: &AuthorizationDocument,
) -> Result<EndpointTransitionClaims, ApiError> {
    Ok(EndpointTransitionClaims {
        schema_version: 2,
        server_id: request.server_id,
        generation: request.generation,
        server_name: state.configuration.server_name.clone(),
        previous_endpoint: request.previous_endpoint.clone(),
        previous_transports: Some(
            request
                .previous_transports
                .clone()
                .or_else(|| {
                    authorization
                        .endpoint_transition
                        .as_ref()
                        .map(|head| head.claims.endpoint_descriptor())
                })
                .unwrap_or_else(|| sirinvpn_protocol::EndpointDescriptor {
                    endpoint: request.previous_endpoint.clone(),
                    endpoint_discovery_port: state.configuration.endpoint_discovery_port,
                    alternate_endpoint_hosts: Vec::new(),
                    ipv6_tunnel_enabled: state.configuration.ipv6_tunnel_enabled,
                    obfuscated_udp: state.configuration.obfuscated_udp.clone(),
                    tcp_fallback: state.configuration.tcp_fallback.clone(),
                    tls_like: state.configuration.tls_like.clone(),
                }),
        ),
        endpoint: request.endpoint.clone(),
        alternate_endpoint_hosts: state.configuration.alternate_endpoint_hosts.clone(),
        endpoint_discovery_port: state.configuration.endpoint_discovery_port,
        server_tunnel_address: state.configuration.server_tunnel_address,
        management_port: state.configuration.management_port,
        server_wireguard_public_key: state.configuration.wireguard_public_key.clone(),
        pinned_server_certificate_pem: fs::read_to_string(&state.paths.tls_certificate)
            .map_err(|_| ApiError::internal())?,
        authorization_fingerprint: authorization
            .endpoint_authorization_fingerprint()
            .map_err(|_| ApiError::internal())?,
        ipv6_tunnel_enabled: state.configuration.ipv6_tunnel_enabled,
        obfuscated_udp: state.configuration.obfuscated_udp.clone(),
        tcp_fallback: state.configuration.tcp_fallback.clone(),
        tls_like: state.configuration.tls_like.clone(),
    })
}

pub(super) fn configuration_endpoint_descriptor(
    configuration: &ServerConfiguration,
    host: &str,
) -> sirinvpn_protocol::EndpointDescriptor {
    sirinvpn_protocol::EndpointDescriptor {
        endpoint: ServerEndpoint {
            host: host.to_owned(),
            wireguard_port: configuration.wireguard_port,
        },
        alternate_endpoint_hosts: configuration.alternate_endpoint_hosts.clone(),
        endpoint_discovery_port: configuration.endpoint_discovery_port,
        ipv6_tunnel_enabled: configuration.ipv6_tunnel_enabled,
        obfuscated_udp: configuration.obfuscated_udp.clone(),
        tcp_fallback: configuration.tcp_fallback.clone(),
        tls_like: configuration.tls_like.clone(),
    }
}

/// Root initialization and repair publish the new contact information in the
/// existing authorization transaction. Retrying after interruption is idempotent.
pub(super) fn synchronize_configuration_endpoint(
    paths: &ServerPaths,
    configuration: &ServerConfiguration,
    previous: Option<sirinvpn_protocol::EndpointDescriptor>,
) -> Result<Option<EndpointTransitionResponse>> {
    let Some(endpoint) = &configuration.public_endpoint else {
        return Ok(None);
    };
    let mut authorization = load_authorization(&paths.authorization)?;
    let descriptor = configuration_endpoint_descriptor(configuration, &endpoint.host);
    authorization::validate_endpoint_descriptor(&descriptor)?;
    if authorization.endpoint_transition_source
        || authorization
            .endpoint_transition
            .as_ref()
            .is_some_and(|head| head.claims.endpoint_descriptor() == descriptor)
    {
        return Ok(authorization.endpoint_transition);
    }
    authorization.prune_expired(unix_time());
    ensure_transition_quiescent(&authorization).map_err(|error| anyhow!(error.message))?;
    let previous = authorization
        .endpoint_transition
        .as_ref()
        .map(|head| head.claims.endpoint_descriptor())
        .or(previous)
        .unwrap_or_else(|| descriptor.clone());
    let generation = authorization
        .endpoint_generation()
        .checked_add(1)
        .context("endpoint generation exhausted")?;
    let claims = checkpoint_claims(
        paths,
        configuration,
        &authorization,
        previous,
        descriptor,
        generation,
    )?;
    let signature = sign_endpoint_transition(&paths.tls_private_key, &claims)?;
    let response = EndpointTransitionResponse { claims, signature };
    authorization.accept_endpoint_transition(response.clone())?;
    write_authorization(&paths.authorization, &authorization)?;
    Ok(Some(response))
}

pub(super) fn checkpoint_claims(
    paths: &ServerPaths,
    configuration: &ServerConfiguration,
    authorization: &AuthorizationDocument,
    previous: sirinvpn_protocol::EndpointDescriptor,
    descriptor: sirinvpn_protocol::EndpointDescriptor,
    generation: u64,
) -> Result<EndpointTransitionClaims> {
    Ok(EndpointTransitionClaims {
        schema_version: 2,
        server_id: authorization.server_id,
        generation,
        server_name: configuration.server_name.clone(),
        previous_endpoint: previous.endpoint.clone(),
        previous_transports: Some(previous),
        endpoint: descriptor.endpoint,
        alternate_endpoint_hosts: descriptor.alternate_endpoint_hosts,
        endpoint_discovery_port: descriptor.endpoint_discovery_port,
        server_tunnel_address: configuration.server_tunnel_address,
        management_port: configuration.management_port,
        server_wireguard_public_key: configuration.wireguard_public_key.clone(),
        pinned_server_certificate_pem: fs::read_to_string(&paths.tls_certificate)?,
        authorization_fingerprint: authorization.endpoint_authorization_fingerprint()?,
        ipv6_tunnel_enabled: descriptor.ipv6_tunnel_enabled,
        obfuscated_udp: descriptor.obfuscated_udp,
        tcp_fallback: descriptor.tcp_fallback,
        tls_like: descriptor.tls_like,
    })
}

pub(super) fn validate_transition_claims_for_server(
    state: &AppState,
    claims: &EndpointTransitionClaims,
) -> Result<(), ApiError> {
    let request = EndpointTransitionCreateRequest {
        server_id: claims.server_id,
        generation: claims.generation,
        previous_endpoint: claims.previous_endpoint.clone(),
        previous_transports: claims.previous_transports.clone(),
        endpoint: claims.endpoint.clone(),
    };
    // The handoff source can have different ports/certificates than the target.
    // Only immutable server identity is shared; its own current endpoint must
    // match the signed predecessor when that information is available.
    validate_endpoint(&request.previous_endpoint)?;
    validate_endpoint(&request.endpoint)?;
    let certificate =
        fs::read_to_string(&state.paths.tls_certificate).map_err(|_| ApiError::internal())?;
    if !matches!(claims.schema_version, 1 | 2)
        || claims.server_name != state.configuration.server_name
        || claims.server_tunnel_address != state.configuration.server_tunnel_address
        || claims.management_port != state.configuration.management_port
        || claims.server_wireguard_public_key != state.configuration.wireguard_public_key
        || claims.pinned_server_certificate_pem != certificate
    {
        return Err(ApiError::conflict(
            "the endpoint update does not match this server identity and capabilities",
        ));
    }
    Ok(())
}

/// The transport has authenticated this WireGuard key with Noise IK. Reuse the
/// private API's exact Owner, signature, predecessor, quiescence and state checks.
pub(super) async fn publish_from_transport(
    state: &AppState,
    request: sirinvpn_transport::EndpointPublicationRequest,
) {
    let result = async {
        let authorization = require_authorization(state)?;
        let certificate_fingerprint = {
            let current = authorization.read().await;
            let public_key = STANDARD.encode(request.device_public_key);
            current
                .devices
                .iter()
                .find(|device| {
                    device.wireguard_public_key == public_key
                        && current
                            .access_for_device(device)
                            .is_some_and(|access| access.role == ServerRole::Owner)
                })
                .map(|device| device.certificate_fingerprint.clone())
                .ok_or_else(ApiError::forbidden)?
        };
        let response: EndpointTransitionResponse = serde_json::from_slice(&request.checkpoint)
            .map_err(|_| ApiError::invalid("invalid endpoint checkpoint"))?;
        publish_endpoint_transition_handler(
            State(state.clone()),
            Extension(CallerIdentity {
                certificate_fingerprint,
            }),
            Json(response),
        )
        .await
        .map(|_| ())
    }
    .await;
    let _ = request.result.send(result.is_ok());
}
