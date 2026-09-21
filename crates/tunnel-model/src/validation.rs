use super::*;

pub fn normalize_included_routes(
    included_routes: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, String> {
    let included_routes = included_routes.into_iter().collect::<Vec<_>>();
    if included_routes.is_empty() || included_routes.len() > MAX_INCLUDED_ROUTES {
        return Err(format!(
            "selected routing requires between 1 and {MAX_INCLUDED_ROUTES} CIDRs"
        ));
    }
    let mut normalized = BTreeSet::new();
    for route in included_routes {
        let route = route.trim();
        if !route.contains('/') {
            return Err(format!("route {route:?} must include a prefix length"));
        }
        let network = route
            .parse::<IpNet>()
            .map_err(|_| format!("route {route:?} is not a valid IPv4 or IPv6 CIDR"))?
            .trunc();
        if network.prefix_len() == 0 {
            return Err("default routes must use Full tunnel mode".to_owned());
        }
        normalized.insert(network.to_string());
    }
    Ok(normalized.into_iter().collect())
}

pub fn validate_routing(request: &TunnelConnectRequest) -> Result<(), HelperError> {
    if request.routing.is_legacy_default() {
        if request.schema_version == 6 {
            return Err(HelperError::InvalidConfiguration(
                "schema 6 requires an explicit routing policy".to_owned(),
            ));
        }
        return Ok(());
    }
    if !matches!(request.schema_version, 6..=11) {
        return Err(HelperError::InvalidConfiguration(
            "custom routing requires schema 6 or newer".to_owned(),
        ));
    }
    match request.routing.mode {
        TunnelRoutingMode::SelectedApplications => {
            if request.schema_version < 11
                || request.policy.is_none()
                || !request.routing.included_routes.is_empty()
            {
                return Err(HelperError::InvalidConfiguration(
                    "application routing requires schema 11, independent policy, and no CIDR list"
                        .into(),
                ));
            }
        }
        TunnelRoutingMode::FullTunnel if !request.routing.included_routes.is_empty() => {
            return Err(HelperError::InvalidConfiguration(
                "Full tunnel mode must not include selected routes".to_owned(),
            ));
        }
        TunnelRoutingMode::FullTunnel => {}
        TunnelRoutingMode::SelectedRoutes => {
            let normalized = normalize_included_routes(request.routing.included_routes.clone())
                .map_err(HelperError::InvalidConfiguration)?;
            if normalized != request.routing.included_routes {
                return Err(HelperError::InvalidConfiguration(
                    "selected routes must be canonical, sorted, and unique".to_owned(),
                ));
            }
            if request.client_ipv6_address.is_none()
                && normalized.iter().any(|route| {
                    route
                        .parse::<IpNet>()
                        .is_ok_and(|route| matches!(route, IpNet::V6(_)))
                })
            {
                return Err(HelperError::InvalidConfiguration(
                    "IPv6 routes require an IPv6-capable VPS profile".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

pub fn validate_request(request: &TunnelConnectRequest) -> Result<(), HelperError> {
    if !matches!(request.schema_version, 1..=11)
        || (request.schema_version == 1 && request.client_ipv6_address.is_some())
        || (request.schema_version <= 5
            && request.transport == TransportKind::ObfuscatedUdp
            && request.schema_version != 3)
        || (request.schema_version <= 5
            && request.transport == TransportKind::TcpFallback
            && request.schema_version != 4)
        || (request.schema_version <= 5
            && request.transport == TransportKind::TlsLike
            && request.schema_version != 5)
        || (request.transport == TransportKind::TlsLike && request.persistent_protection)
    {
        return Err(HelperError::InvalidConfiguration(
            "unsupported schema version".to_owned(),
        ));
    }
    if (request.schema_version >= 7) != request.policy.is_some()
        || (request.policy.is_some() && request.persistent_protection)
    {
        return Err(HelperError::InvalidConfiguration(
            "independent policy requires schema 7 without the legacy bundle".into(),
        ));
    }
    if (request.schema_version < 9 && request.requires_https_support())
        || request
            .https
            .as_ref()
            .is_some_and(|https| !https.is_valid() || request.transport != TransportKind::TlsLike)
    {
        return Err(HelperError::InvalidConfiguration(
            "HTTPS transport requires schema 9 and valid TLS endpoint metadata".into(),
        ));
    }
    validate_routing(request)?;
    validate_endpoint_state(request)?;
    if request.schema_version < 10 && request.endpoint_host.parse::<Ipv6Addr>().is_ok() {
        return Err(HelperError::InvalidConfiguration(
            "IPv6 outer endpoints require schema 10".into(),
        ));
    }
    if (request.schema_version >= 8) != request.mtu_policy.is_some() {
        return Err(HelperError::InvalidConfiguration(
            "MTU policy requires schema 8".into(),
        ));
    }
    if let Some(policy) = request.mtu_policy {
        policy
            .validate(request.client_ipv6_address.is_some())
            .map_err(|message| HelperError::InvalidConfiguration(message.into()))?;
        if let sirinvpn_protocol::MtuPolicy::Manual { value } = policy
            && request.mtu != value
        {
            return Err(HelperError::InvalidConfiguration(
                "manual MTU must match the requested transport MTU".into(),
            ));
        }
    }
    validate_host(&request.endpoint_host)
        .map_err(|error| HelperError::InvalidConfiguration(error.to_string()))?;
    let minimum = if request.schema_version < 8 || request.client_ipv6_address.is_some() {
        1280
    } else {
        576
    };
    if request.endpoint_port == 0 || !(minimum..=1_420).contains(&request.mtu) {
        return Err(HelperError::InvalidConfiguration(
            "port or MTU is outside the supported range".to_owned(),
        ));
    }
    for key in [&request.private_key, &request.server_public_key] {
        let decoded =
            zeroize::Zeroizing::new(STANDARD.decode(key).map_err(|_| {
                HelperError::InvalidConfiguration("invalid WireGuard key".to_owned())
            })?);
        if decoded.len() != 32 {
            return Err(HelperError::InvalidConfiguration(
                "invalid WireGuard key length".to_owned(),
            ));
        }
    }
    match request.transport {
        TransportKind::DirectUdp
            if request.server_transport_public_key.is_some()
                || request.server_certificate_sha256.is_some() =>
        {
            return Err(HelperError::InvalidConfiguration(
                "Direct UDP must not include outer transport identity".to_owned(),
            ));
        }
        TransportKind::DirectUdp => {}
        TransportKind::ObfuscatedUdp | TransportKind::TcpFallback => {
            if request.server_certificate_sha256.is_some() {
                return Err(HelperError::InvalidConfiguration(
                    "this authenticated transport must not include a TLS certificate fingerprint"
                        .to_owned(),
                ));
            }
            let key = request
                .server_transport_public_key
                .as_deref()
                .ok_or_else(|| {
                    HelperError::InvalidConfiguration(
                        "authenticated transports require the pinned server transport key"
                            .to_owned(),
                    )
                })?;
            let decoded = STANDARD.decode(key).map_err(|_| {
                HelperError::InvalidConfiguration("invalid server transport key".to_owned())
            })?;
            if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
                return Err(HelperError::InvalidConfiguration(
                    "invalid server transport key length".to_owned(),
                ));
            }
        }
        TransportKind::TlsLike => {
            let key = request
                .server_transport_public_key
                .as_deref()
                .ok_or_else(|| {
                    HelperError::InvalidConfiguration(
                        "TLS-like transport requires the pinned server transport key".to_owned(),
                    )
                })?;
            let decoded = STANDARD.decode(key).map_err(|_| {
                HelperError::InvalidConfiguration("invalid server transport key".to_owned())
            })?;
            if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
                return Err(HelperError::InvalidConfiguration(
                    "invalid server transport key length".to_owned(),
                ));
            }
            let fingerprint = request
                .server_certificate_sha256
                .as_deref()
                .ok_or_else(|| {
                    HelperError::InvalidConfiguration(
                        "TLS-like transport requires a pinned certificate fingerprint".to_owned(),
                    )
                })?;
            let decoded = STANDARD.decode(fingerprint).map_err(|_| {
                HelperError::InvalidConfiguration(
                    "invalid TLS-like certificate fingerprint".to_owned(),
                )
            })?;
            if decoded.len() != 32 || STANDARD.encode(&decoded) != fingerprint {
                return Err(HelperError::InvalidConfiguration(
                    "invalid TLS-like certificate fingerprint".to_owned(),
                ));
            }
        }
    }
    if request.client_ipv6_address.is_some()
        && ipv6_tunnel_address(request.server_id, request.client_address)
            != request.client_ipv6_address
    {
        return Err(HelperError::InvalidConfiguration(
            "IPv6 tunnel address does not match the server identity and IPv4 host".to_owned(),
        ));
    }
    validate_reconnect_candidates(request)?;
    Ok(())
}

pub fn validate_endpoint_state(request: &TunnelConnectRequest) -> Result<(), HelperError> {
    let invalid = || {
        HelperError::InvalidConfiguration(
            "signed endpoint metadata is inconsistent with this tunnel request".into(),
        )
    };
    if (request.schema_version >= 10) != request.endpoint_identity.is_some()
        || (request.endpoint_identity.is_none()
            && (request.endpoint_checkpoint.is_some()
                || request.endpoint_publication_enabled
                || !request.endpoint_dns_servers.is_empty()))
    {
        return Err(invalid());
    }
    let Some(known) = &request.endpoint_identity else {
        return Ok(());
    };
    sirinvpn_core::validate_endpoint_identity(known).map_err(|_| invalid())?;
    if known.server_id != request.server_id
        || known.server_wireguard_public_key != request.server_public_key
        || !hosts(known).any(|host| host == request.endpoint_host)
        || request.endpoint_dns_servers.len() > 4
        || request.endpoint_dns_servers.iter().any(|address| {
            address.port() != 53
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
                || address.ip().is_loopback()
                || address.ip() == IpAddr::V4(request.dns_address)
        })
    {
        return Err(invalid());
    }
    let selected = TransportEngine
        .select_descriptor(&known.descriptor, request.transport)
        .map_err(|_| invalid())?;
    if selected.network_endpoint.wireguard_port != request.endpoint_port
        || selected.server_transport_public_key != request.server_transport_public_key
        || selected.server_certificate_sha256 != request.server_certificate_sha256
        || selected.https != request.https
    {
        return Err(invalid());
    }
    if let Some(head) = &request.endpoint_checkpoint {
        sirinvpn_core::DecodedEndpointTransition::from_response(head.clone())
            .map_err(|_| invalid())?;
        if head.claims.server_id != known.server_id
            || head.claims.generation != known.generation
            || head.claims.server_wireguard_public_key != known.server_wireguard_public_key
            || head.claims.pinned_server_certificate_pem != known.pinned_server_certificate_pem
            || head.claims.endpoint_descriptor() != known.descriptor
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub fn hosts(known: &EndpointIdentity) -> impl Iterator<Item = &str> {
    std::iter::once(known.descriptor.endpoint.host.as_str()).chain(
        known
            .descriptor
            .alternate_endpoint_hosts
            .iter()
            .map(String::as_str),
    )
}

pub fn validate_reconnect_candidates(request: &TunnelConnectRequest) -> Result<(), HelperError> {
    if request.reconnect_candidates.is_empty() {
        return Ok(());
    }
    let maximum = if request.policy.is_some() { 4 } else { 3 };
    if (!request.persistent_protection && request.policy.is_none())
        || !(2..=maximum).contains(&request.reconnect_candidates.len())
    {
        return Err(HelperError::InvalidConfiguration(
            "automatic reconnect requires two or three persistent transport candidates".to_owned(),
        ));
    }
    let first = &request.reconnect_candidates[0];
    if first.transport != request.transport
        || first.endpoint_port != request.endpoint_port
        || first.server_transport_public_key != request.server_transport_public_key
        || first.server_certificate_sha256 != request.server_certificate_sha256
        || first.https != request.https
        || first.mtu != request.mtu
    {
        return Err(HelperError::InvalidConfiguration(
            "the first reconnect candidate must match the active transport".to_owned(),
        ));
    }
    for (index, candidate) in request.reconnect_candidates.iter().enumerate() {
        if candidate.transport == TransportKind::TlsLike && request.policy.is_none() {
            return Err(HelperError::InvalidConfiguration(
                "TLS-like transport is not yet available for persistent reconnect".to_owned(),
            ));
        }
        if request.reconnect_candidates[..index]
            .iter()
            .any(|previous| previous.transport == candidate.transport)
        {
            return Err(HelperError::InvalidConfiguration(
                "reconnect transport candidates must be unique".to_owned(),
            ));
        }
        let mut candidate_request = request_for_reconnect_candidate(request, candidate);
        candidate_request.reconnect_candidates.clear();
        validate_request(&candidate_request)?;
    }
    Ok(())
}

pub fn request_for_reconnect_candidate(
    base: &TunnelConnectRequest,
    candidate: &ReconnectCandidate,
) -> TunnelConnectRequest {
    let mut request = base.clone();
    request.https = candidate.https.clone();
    request.schema_version = if request.routing.mode == TunnelRoutingMode::SelectedApplications {
        11
    } else if request.endpoint_identity.is_some() {
        10
    } else if request.requires_https_support() {
        9
    } else if request.mtu_policy.is_some() {
        8
    } else if request.policy.is_some() {
        7
    } else if request.routing.is_legacy_default() {
        match candidate.transport {
            TransportKind::DirectUdp => 2,
            TransportKind::ObfuscatedUdp => 3,
            TransportKind::TcpFallback => 4,
            TransportKind::TlsLike => 5,
        }
    } else {
        6
    };
    request.endpoint_port = candidate.endpoint_port;
    request.transport = candidate.transport;
    request.server_transport_public_key = candidate.server_transport_public_key.clone();
    request.server_certificate_sha256 = candidate.server_certificate_sha256.clone();
    request.mtu = candidate.mtu;
    request
}
