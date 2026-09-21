//! Reconnect.

use super::*;
pub(super) use sirinvpn_tunnel_model::request_for_reconnect_candidate;

pub(super) fn persistent_request_for_rollback(
    request: &TunnelConnectRequest,
) -> (
    TunnelConnectRequest,
    Option<PersistentObfuscatedUdp>,
    Option<PersistentTcpFallback>,
    Option<TunnelRoutingPolicy>,
) {
    let extended_routing = (!request.routing.is_legacy_default()).then(|| request.routing.clone());
    let mut compatible = request.clone();
    if extended_routing.is_some() {
        compatible.schema_version = match request.transport {
            TransportKind::DirectUdp => 2,
            TransportKind::ObfuscatedUdp => 3,
            TransportKind::TcpFallback => 4,
            TransportKind::TlsLike => {
                unreachable!("persistent TLS-like requests are rejected during validation")
            }
        };
        compatible.routing = TunnelRoutingPolicy::default();
    }
    if request.transport == TransportKind::DirectUdp {
        return (compatible, None, None, extended_routing);
    }
    let mut fallback = compatible;
    let server_transport_public_key = fallback
        .server_transport_public_key
        .take()
        .expect("validated Obfuscated UDP request has a server transport key");
    fallback.schema_version = 2;
    fallback.transport = TransportKind::DirectUdp;
    fallback.server_certificate_sha256 = None;
    fallback.https = None;
    match request.transport {
        TransportKind::ObfuscatedUdp => (
            fallback,
            Some(PersistentObfuscatedUdp {
                server_transport_public_key,
            }),
            None,
            extended_routing,
        ),
        TransportKind::TcpFallback => (
            fallback,
            None,
            Some(PersistentTcpFallback {
                server_transport_public_key,
            }),
            extended_routing,
        ),
        TransportKind::DirectUdp => unreachable!(),
        TransportKind::TlsLike => {
            unreachable!("persistent TLS-like requests are rejected during validation")
        }
    }
}

pub(super) fn current_persistent_request(
    persistent: &PersistentConnection,
    runtime: Option<&RuntimeState>,
) -> TunnelConnectRequest {
    let Some(transport) = runtime
        .filter(|state| state.server_id == persistent.request.server_id)
        .map(|state| state.transport)
    else {
        return persistent.request.clone();
    };
    persistent
        .request
        .reconnect_candidates
        .iter()
        .find(|candidate| candidate.transport == transport)
        .map_or_else(
            || persistent.request.clone(),
            |candidate| request_for_reconnect_candidate(&persistent.request, candidate),
        )
}

pub(super) fn next_persistent_request(
    persistent: &PersistentConnection,
    current: TransportKind,
) -> TunnelConnectRequest {
    let candidates = &persistent.request.reconnect_candidates;
    if candidates.is_empty() {
        return persistent.request.clone();
    }
    let next_index = candidates
        .iter()
        .position(|candidate| candidate.transport == current)
        .map_or(0, |index| (index + 1) % candidates.len());
    request_for_reconnect_candidate(&persistent.request, &candidates[next_index])
}

pub(super) fn route_output_contains_table(output: &[u8], table: &str) -> bool {
    let mut tokens = output
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|token| !token.is_empty());
    while let Some(token) = tokens.next() {
        if token == b"table" && tokens.next().is_some_and(|value| value == table.as_bytes()) {
            return true;
        }
    }
    false
}

pub(super) fn output_contains_token(output: &[u8], expected: &str) -> bool {
    output
        .split(|byte| byte.is_ascii_whitespace())
        .any(|token| token == expected.as_bytes())
}

pub(super) fn line_contains_pair(line: &[u8], first: &[u8], second: &[u8]) -> bool {
    line.split(|byte| byte.is_ascii_whitespace())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair[0] == first && pair[1] == second)
}

pub(super) fn rule_output_contains_destination_table(
    output: &[u8],
    destination: &str,
    table: &str,
) -> bool {
    let displayed_destinations = displayed_destination_tokens(destination);
    output.split(|byte| *byte == b'\n').any(|line| {
        displayed_destinations
            .iter()
            .any(|candidate| output_contains_token(line, candidate))
            && line_contains_pair(line, b"lookup", table.as_bytes())
    })
}

pub(super) fn route_output_contains_owned_destination(
    output: &[u8],
    destination: &str,
    table: &str,
) -> bool {
    let displayed_destinations = displayed_destination_tokens(destination);
    output.split(|byte| *byte == b'\n').any(|line| {
        displayed_destinations
            .iter()
            .any(|candidate| output_contains_token(line, candidate))
            && line_contains_pair(line, b"dev", INTERFACE_NAME.as_bytes())
            && line_contains_pair(line, b"table", table.as_bytes())
    })
}

pub(super) fn displayed_destination_tokens(destination: &str) -> Vec<String> {
    let mut displayed_destinations = vec![destination.to_owned()];
    if let Ok(network) = destination.parse::<IpNet>() {
        let host_prefix = match network {
            IpNet::V4(_) => 32,
            IpNet::V6(_) => 128,
        };
        if network.prefix_len() == host_prefix {
            displayed_destinations.push(network.addr().to_string());
        }
    }
    displayed_destinations
}

pub(super) fn default_route_fingerprint(output: &str) -> Option<u64> {
    let routes = output
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|tokens| {
            tokens.first() == Some(&"default")
                && !tokens
                    .windows(2)
                    .any(|pair| pair[0] == "dev" && pair[1] == INTERFACE_NAME)
        })
        .filter_map(|tokens| {
            let metric = tokens
                .windows(2)
                .find(|pair| pair[0] == "metric")
                .map(|pair| pair[1].parse::<u64>())
                .transpose()
                .ok()?
                .unwrap_or(0);
            // NetworkManager can add 20000 to a route's metric after its
            // connectivity probe is blocked by the VPN. DHCP lease countdowns
            // and route provenance also do not change the underlying path.
            let mut path = Vec::new();
            let mut tokens = tokens.into_iter();
            while let Some(token) = tokens.next() {
                if matches!(token, "metric" | "proto" | "protocol" | "expires") {
                    tokens.next();
                } else {
                    path.push(token);
                }
            }
            Some((metric, path.join(" ")))
        })
        .collect::<Vec<_>>();
    // A metric change matters if it selects a different gateway/device. Ignore
    // changes to standby routes, while retaining all equally preferred paths.
    let preferred_metric = routes.iter().map(|(metric, _)| *metric).min()?;
    let mut routes = routes
        .into_iter()
        .filter_map(|(metric, path)| (metric == preferred_metric).then_some(path))
        .collect::<Vec<_>>();
    routes.sort_unstable();
    routes.dedup();
    let mut hasher = DefaultHasher::new();
    routes.hash(&mut hasher);
    Some(hasher.finish())
}

pub(super) fn latest_handshake(output: &[u8]) -> Option<u64> {
    output
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|token| !token.is_empty())
        .skip(1)
        .step_by(2)
        .filter_map(|token| std::str::from_utf8(token).ok()?.parse().ok())
        .max()
}

pub(super) fn handshake_timestamp_is_recent(timestamp: u64, now: u64) -> bool {
    timestamp > 0 && (timestamp >= now || now.saturating_sub(timestamp) <= HANDSHAKE_STALE_SECONDS)
}

pub(super) fn established_handshake_is_healthy(
    latest_handshake_unix: Option<u64>,
    now: u64,
    route_transition: Option<RouteTransition>,
) -> bool {
    latest_handshake_unix.is_some_and(|timestamp| {
        handshake_timestamp_is_recent(timestamp, now)
            && route_transition.is_none_or(|transition| timestamp > transition.prior_handshake_unix)
    })
}

pub(super) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn resolve_endpoint(host: &str, port: u16) -> Result<IpAddr, HelperError> {
    (host, port)
        .to_socket_addrs()
        .map_err(|_| HelperError::InvalidConfiguration("endpoint did not resolve".to_owned()))?
        .map(|address| address.ip())
        .find(|address| !address.is_unspecified() && !address.is_multicast())
        .ok_or_else(|| {
            HelperError::InvalidConfiguration(
                "the server endpoint did not resolve to a usable address".to_owned(),
            )
        })
}
