#![forbid(unsafe_code)]

mod relay;
mod socket_policy;
mod tcp;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sirinvpn_protocol::{
    NetworkProfile, ObfuscatedUdpEndpoint, ServerEndpoint, ServerProfile, TcpFallbackEndpoint,
    TlsLikeEndpoint, TransportKind, TransportPreference, validate_host,
};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use thiserror::Error;
use zeroize::Zeroizing;

pub use relay::{
    ActiveTransportRegistry, AuthorizedPeers, ClientRelayConfig, EndpointPublicationRequest,
    RelayError, ServerRelayConfig, run_client_relay, run_client_relay_with_remote_socket_setup,
    run_client_relay_with_socket_protector, run_server_relay,
};
pub use tcp::{
    EndpointDiscoveryConfig, TcpClientRelayConfig, TcpServerRelayConfig, TlsLikeClientRelayConfig,
    fetch_endpoint_checkpoint, fetch_endpoint_checkpoint_with_socket_protector,
    offer_endpoint_checkpoint, offer_endpoint_checkpoint_with_socket_protector,
    run_endpoint_discovery_server, run_tcp_client_relay,
    run_tcp_client_relay_with_remote_socket_setup, run_tcp_client_relay_with_socket_protector,
    run_tcp_server_relay, run_tcp_server_relay_with_https, run_tcp_server_relay_with_tls,
    run_tls_like_client_relay, run_tls_like_client_relay_with_remote_socket_setup,
    run_tls_like_client_relay_with_socket_protector,
};

pub const CLIENT_RELAY_PORT: u16 = 51_821;
pub const TCP_CLIENT_RELAY_PORT: u16 = 51_822;
pub const TLS_LIKE_CLIENT_RELAY_PORT: u16 = 51_823;
pub const TUNNEL_SOCKET_MARK: u32 = 51_820;
pub const DIRECT_MTU: u16 = 1_420;
pub const OBFUSCATED_UDP_MTU: u16 = 1_320;
pub const TCP_FALLBACK_MTU: u16 = 1_280;
pub const TLS_LIKE_MTU: u16 = 1_280;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportSelection {
    pub kind: TransportKind,
    pub network_endpoint: ServerEndpoint,
    pub wireguard_endpoint: ServerEndpoint,
    pub mtu: u16,
    pub server_transport_public_key: Option<String>,
    pub server_certificate_sha256: Option<String>,
    pub https: Option<sirinvpn_protocol::HttpsTransport>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TransportEngine;

impl TransportEngine {
    pub fn validate_descriptor(
        &self,
        descriptor: &sirinvpn_protocol::EndpointDescriptor,
    ) -> Result<(), TransportError> {
        validate_endpoint(&descriptor.endpoint)?;
        if descriptor.endpoint_discovery_port.is_some_and(|port| {
            port == 0 || port == descriptor.endpoint.wireguard_port || descriptor.tls_like.is_none()
        }) {
            return Err(TransportError::InvalidEndpoint);
        }
        if !sirinvpn_protocol::valid_alternate_endpoint_hosts(
            &descriptor.endpoint.host,
            &descriptor.alternate_endpoint_hosts,
        ) {
            return Err(TransportError::InvalidEndpoint);
        }
        if let Some(udp) = &descriptor.obfuscated_udp {
            validate_obfuscated_endpoint(udp)?;
            if udp.port == descriptor.endpoint.wireguard_port {
                return Err(TransportError::InvalidEndpoint);
            }
        }
        if let Some(tcp) = &descriptor.tcp_fallback {
            validate_tcp_endpoint(tcp)?;
            if tcp.port == descriptor.endpoint.wireguard_port {
                return Err(TransportError::InvalidEndpoint);
            }
        }
        if let Some(tls) = &descriptor.tls_like {
            validate_tls_like_endpoint(tls)?;
            if tls.port == descriptor.endpoint.wireguard_port
                || descriptor
                    .tcp_fallback
                    .as_ref()
                    .is_none_or(|tcp| tcp.port != tls.port)
            {
                return Err(TransportError::InvalidEndpoint);
            }
        }
        let mut keys = descriptor
            .obfuscated_udp
            .as_ref()
            .map(|e| &e.server_public_key)
            .into_iter()
            .chain(
                descriptor
                    .tcp_fallback
                    .as_ref()
                    .map(|e| &e.server_public_key),
            )
            .chain(descriptor.tls_like.as_ref().map(|e| &e.server_public_key));
        if let Some(first) = keys.next()
            && keys.any(|key| key != first)
        {
            return Err(TransportError::InvalidKey);
        }
        Ok(())
    }

    pub fn plan(
        &self,
        profile: &ServerProfile,
        preference: TransportPreference,
    ) -> Result<Vec<TransportSelection>, TransportError> {
        if let Some(kind) = preference.concrete_kind() {
            return Ok(vec![self.select(profile, kind)?]);
        }

        self.automatic_plan(profile, NetworkProfile::Automatic, None)
    }

    pub fn automatic_plan(
        &self,
        profile: &ServerProfile,
        network_profile: NetworkProfile,
        cached_transport: Option<TransportKind>,
    ) -> Result<Vec<TransportSelection>, TransportError> {
        let baseline = match network_profile {
            NetworkProfile::Automatic | NetworkProfile::Normal => [
                TransportKind::DirectUdp,
                TransportKind::ObfuscatedUdp,
                TransportKind::TlsLike,
                TransportKind::TcpFallback,
            ],
            NetworkProfile::Restricted => [
                TransportKind::ObfuscatedUdp,
                TransportKind::TlsLike,
                TransportKind::TcpFallback,
                TransportKind::DirectUdp,
            ],
            NetworkProfile::Extreme => [
                TransportKind::TlsLike,
                TransportKind::TcpFallback,
                TransportKind::ObfuscatedUdp,
                TransportKind::DirectUdp,
            ],
        };
        let mut kinds = Vec::with_capacity(4);
        if network_profile == NetworkProfile::Automatic
            && let Some(kind) = cached_transport
            && transport_available(profile, kind)
        {
            kinds.push(kind);
        }
        for kind in baseline {
            if transport_available(profile, kind) && !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        kinds
            .into_iter()
            .map(|kind| self.select(profile, kind))
            .collect()
    }

    pub fn select(
        &self,
        profile: &ServerProfile,
        requested: TransportKind,
    ) -> Result<TransportSelection, TransportError> {
        self.select_descriptor(&profile.endpoint_descriptor(), requested)
    }

    pub fn select_descriptor(
        &self,
        profile: &sirinvpn_protocol::EndpointDescriptor,
        requested: TransportKind,
    ) -> Result<TransportSelection, TransportError> {
        validate_endpoint(&profile.endpoint)?;
        match requested {
            TransportKind::DirectUdp => Ok(TransportSelection {
                kind: requested,
                network_endpoint: profile.endpoint.clone(),
                wireguard_endpoint: profile.endpoint.clone(),
                mtu: DIRECT_MTU,
                server_transport_public_key: None,
                https: None,
                server_certificate_sha256: None,
            }),
            TransportKind::ObfuscatedUdp => {
                let obfuscated = profile
                    .obfuscated_udp
                    .as_ref()
                    .ok_or(TransportError::Unavailable)?;
                validate_obfuscated_endpoint(obfuscated)?;
                Ok(TransportSelection {
                    kind: requested,
                    network_endpoint: ServerEndpoint {
                        host: profile.endpoint.host.clone(),
                        wireguard_port: obfuscated.port,
                    },
                    wireguard_endpoint: ServerEndpoint {
                        host: Ipv4Addr::LOCALHOST.to_string(),
                        wireguard_port: CLIENT_RELAY_PORT,
                    },
                    mtu: OBFUSCATED_UDP_MTU,
                    server_transport_public_key: Some(obfuscated.server_public_key.clone()),
                    https: None,
                    server_certificate_sha256: None,
                })
            }
            TransportKind::TlsLike => {
                let tls = profile
                    .tls_like
                    .as_ref()
                    .ok_or(TransportError::Unavailable)?;
                validate_tls_like_endpoint(tls)?;
                if tls.port == profile.endpoint.wireguard_port {
                    return Err(TransportError::InvalidEndpoint);
                }
                Ok(TransportSelection {
                    kind: requested,
                    network_endpoint: ServerEndpoint {
                        host: profile.endpoint.host.clone(),
                        wireguard_port: tls.port,
                    },
                    wireguard_endpoint: ServerEndpoint {
                        host: Ipv4Addr::LOCALHOST.to_string(),
                        wireguard_port: TLS_LIKE_CLIENT_RELAY_PORT,
                    },
                    mtu: TLS_LIKE_MTU,
                    server_transport_public_key: Some(tls.server_public_key.clone()),
                    https: tls.https.clone(),
                    server_certificate_sha256: Some(tls.certificate_sha256.clone()),
                })
            }
            TransportKind::TcpFallback => {
                let tcp = profile
                    .tcp_fallback
                    .as_ref()
                    .ok_or(TransportError::Unavailable)?;
                validate_tcp_endpoint(tcp)?;
                if tcp.port == profile.endpoint.wireguard_port {
                    return Err(TransportError::InvalidEndpoint);
                }
                Ok(TransportSelection {
                    kind: requested,
                    network_endpoint: ServerEndpoint {
                        host: profile.endpoint.host.clone(),
                        wireguard_port: tcp.port,
                    },
                    wireguard_endpoint: ServerEndpoint {
                        host: Ipv4Addr::LOCALHOST.to_string(),
                        wireguard_port: TCP_CLIENT_RELAY_PORT,
                    },
                    mtu: TCP_FALLBACK_MTU,
                    server_transport_public_key: Some(tcp.server_public_key.clone()),
                    https: None,
                    server_certificate_sha256: None,
                })
            }
        }
    }
}

fn transport_available(profile: &ServerProfile, kind: TransportKind) -> bool {
    match kind {
        TransportKind::DirectUdp => true,
        TransportKind::ObfuscatedUdp => profile.obfuscated_udp.is_some(),
        TransportKind::TlsLike => profile.tls_like.is_some(),
        TransportKind::TcpFallback => profile.tcp_fallback.is_some(),
    }
}

pub async fn establish_automatic<T, CleanupError, Attempt, AttemptFuture, Cleanup, CleanupFuture>(
    selections: Vec<TransportSelection>,
    mut attempt: Attempt,
    mut cleanup: Cleanup,
) -> Result<EstablishedTransport<T>, AutomaticConnectError>
where
    Attempt: FnMut(TransportSelection) -> AttemptFuture,
    AttemptFuture: Future<Output = AutomaticAttempt<T>>,
    Cleanup: FnMut(TransportKind) -> CleanupFuture,
    CleanupFuture: Future<Output = Result<(), CleanupError>>,
{
    for selection in selections {
        let kind = selection.kind;
        match attempt(selection.clone()).await {
            AutomaticAttempt::Connected(value) => {
                return Ok(EstablishedTransport { selection, value });
            }
            AutomaticAttempt::Unavailable => {
                cleanup(kind)
                    .await
                    .map_err(|_| AutomaticConnectError::CleanupFailed)?;
            }
            AutomaticAttempt::Abort(reason) => {
                cleanup(kind)
                    .await
                    .map_err(|_| AutomaticConnectError::CleanupFailed)?;
                return Err(AutomaticConnectError::Aborted(reason));
            }
        }
    }
    Err(AutomaticConnectError::Unavailable)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomaticAttempt<T> {
    Connected(T),
    Unavailable,
    Abort(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EstablishedTransport<T> {
    pub selection: TransportSelection,
    pub value: T,
}

pub fn client_relay_config(
    server_address: SocketAddr,
    client_private_key: &str,
    server_public_key: &str,
) -> Result<ClientRelayConfig, TransportError> {
    client_relay_config_with_mark(
        server_address,
        client_private_key,
        server_public_key,
        Some(TUNNEL_SOCKET_MARK),
    )
}

pub fn client_relay_config_unmarked(
    server_address: SocketAddr,
    client_private_key: &str,
    server_public_key: &str,
) -> Result<ClientRelayConfig, TransportError> {
    client_relay_config_with_mark(server_address, client_private_key, server_public_key, None)
}

fn client_relay_config_with_mark(
    server_address: SocketAddr,
    client_private_key: &str,
    server_public_key: &str,
    socket_mark: Option<u32>,
) -> Result<ClientRelayConfig, TransportError> {
    let client_private_key = decode_key(client_private_key)?;
    let server_public_key = decode_key(server_public_key)?;
    Ok(ClientRelayConfig {
        local_listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), CLIENT_RELAY_PORT),
        server_address,
        socket_mark,
        client_private_key: STANDARD.encode(client_private_key),
        server_public_key: STANDARD.encode(server_public_key),
    })
}

pub fn tcp_client_relay_config(
    server_address: SocketAddr,
    client_private_key: &str,
    server_public_key: &str,
) -> Result<TcpClientRelayConfig, TransportError> {
    tcp_client_relay_config_with_mark(
        server_address,
        client_private_key,
        server_public_key,
        Some(TUNNEL_SOCKET_MARK),
    )
}

pub fn tcp_client_relay_config_unmarked(
    server_address: SocketAddr,
    client_private_key: &str,
    server_public_key: &str,
) -> Result<TcpClientRelayConfig, TransportError> {
    tcp_client_relay_config_with_mark(server_address, client_private_key, server_public_key, None)
}

pub fn tls_like_client_relay_config(
    server_address: SocketAddr,
    client_private_key: &str,
    server_public_key: &str,
    server_certificate_sha256: &str,
) -> Result<TlsLikeClientRelayConfig, TransportError> {
    tls_like_client_relay_config_with_mark(
        server_address,
        client_private_key,
        server_public_key,
        server_certificate_sha256,
        Some(TUNNEL_SOCKET_MARK),
    )
}

pub fn tls_like_client_relay_config_unmarked(
    server_address: SocketAddr,
    client_private_key: &str,
    server_public_key: &str,
    server_certificate_sha256: &str,
) -> Result<TlsLikeClientRelayConfig, TransportError> {
    tls_like_client_relay_config_with_mark(
        server_address,
        client_private_key,
        server_public_key,
        server_certificate_sha256,
        None,
    )
}

fn tls_like_client_relay_config_with_mark(
    server_address: SocketAddr,
    client_private_key: &str,
    server_public_key: &str,
    server_certificate_sha256: &str,
    socket_mark: Option<u32>,
) -> Result<TlsLikeClientRelayConfig, TransportError> {
    let client_private_key = decode_key(client_private_key)?;
    let server_public_key = decode_key(server_public_key)?;
    let certificate_sha256 = decode_fingerprint(server_certificate_sha256)?;
    Ok(TlsLikeClientRelayConfig {
        local_listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), TLS_LIKE_CLIENT_RELAY_PORT),
        server_address,
        socket_mark,
        client_private_key: STANDARD.encode(client_private_key),
        server_public_key: STANDARD.encode(server_public_key),
        server_certificate_sha256: STANDARD.encode(certificate_sha256),
        https: None,
    })
}

fn tcp_client_relay_config_with_mark(
    server_address: SocketAddr,
    client_private_key: &str,
    server_public_key: &str,
    socket_mark: Option<u32>,
) -> Result<TcpClientRelayConfig, TransportError> {
    let client_private_key = decode_key(client_private_key)?;
    let server_public_key = decode_key(server_public_key)?;
    Ok(TcpClientRelayConfig {
        local_listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), TCP_CLIENT_RELAY_PORT),
        server_address,
        socket_mark,
        client_private_key: STANDARD.encode(client_private_key),
        server_public_key: STANDARD.encode(server_public_key),
    })
}

pub fn decode_key(value: &str) -> Result<[u8; 32], TransportError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| TransportError::InvalidKey)?,
    );
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::InvalidKey)?;
    if key.iter().all(|byte| *byte == 0) || STANDARD.encode(key) != value {
        return Err(TransportError::InvalidKey);
    }
    Ok(key)
}

fn validate_endpoint(endpoint: &ServerEndpoint) -> Result<(), TransportError> {
    validate_host(&endpoint.host).map_err(|_| TransportError::InvalidEndpoint)?;
    if endpoint.wireguard_port == 0 {
        return Err(TransportError::InvalidEndpoint);
    }
    Ok(())
}

fn validate_obfuscated_endpoint(endpoint: &ObfuscatedUdpEndpoint) -> Result<(), TransportError> {
    if endpoint.port == 0 {
        return Err(TransportError::InvalidEndpoint);
    }
    decode_key(&endpoint.server_public_key)?;
    Ok(())
}

fn validate_tcp_endpoint(endpoint: &TcpFallbackEndpoint) -> Result<(), TransportError> {
    if endpoint.port == 0 {
        return Err(TransportError::InvalidEndpoint);
    }
    decode_key(&endpoint.server_public_key)?;
    Ok(())
}

fn validate_tls_like_endpoint(endpoint: &TlsLikeEndpoint) -> Result<(), TransportError> {
    if endpoint.port == 0
        || endpoint
            .https
            .as_ref()
            .is_some_and(|https| !https.is_valid())
    {
        return Err(TransportError::InvalidEndpoint);
    }
    decode_key(&endpoint.server_public_key)?;
    decode_fingerprint(&endpoint.certificate_sha256)?;
    Ok(())
}

fn decode_fingerprint(value: &str) -> Result<[u8; 32], TransportError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| TransportError::InvalidCertificateFingerprint)?;
    let fingerprint: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::InvalidCertificateFingerprint)?;
    if STANDARD.encode(fingerprint) != value {
        return Err(TransportError::InvalidCertificateFingerprint);
    }
    Ok(fingerprint)
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("the transport endpoint is invalid")]
    InvalidEndpoint,
    #[error("the transport key is invalid")]
    InvalidKey,
    #[error("the TLS certificate fingerprint is invalid")]
    InvalidCertificateFingerprint,
    #[error("the requested transport is not installed on this server")]
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AutomaticConnectError {
    #[error("no available transport could reach this VPS; local networking was restored")]
    Unavailable,
    #[error(
        "automatic transport selection stopped because local networking could not be restored; use Disconnect before retrying"
    )]
    CleanupFailed,
    #[error("automatic transport selection stopped safely: {0}")]
    Aborted(String),
}

#[cfg(test)]
mod tests;
