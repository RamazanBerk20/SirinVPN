use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::{Rng, RngCore, rngs::OsRng};
use rustls::{
    CertificateError, ClientConfig,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sirinvpn_protocol::TransportKind;
use snow::{Builder, HandshakeState, StatelessTransportState, params::NoiseParams};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, oneshot},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::{Zeroize, Zeroizing};

use crate::relay::{
    ActiveTransportRegistry, AuthorizedPeers, CarrierPhase, CarrierSession, HandshakeReplayCache,
    LocalPeer, ProbeLimiter, RelayError, client_handshake_payload, client_handshake_payload_bound,
    handshake_is_bound,
};

mod client;
mod discovery;
#[cfg(fuzzing)]
pub(crate) mod fuzzing;
mod publication;
pub use client::{
    run_tcp_client_relay, run_tcp_client_relay_pinned,
    run_tcp_client_relay_with_remote_socket_setup, run_tcp_client_relay_with_socket_protector,
    run_tls_like_client_relay, run_tls_like_client_relay_pinned,
    run_tls_like_client_relay_with_remote_socket_setup,
    run_tls_like_client_relay_with_socket_protector,
};
pub use discovery::{
    EndpointDiscoveryConfig, fetch_endpoint_checkpoint,
    fetch_endpoint_checkpoint_with_socket_protector,
};
pub use publication::{offer_endpoint_checkpoint, offer_endpoint_checkpoint_with_socket_protector};
mod https;
mod quic;
mod tls;
pub use quic::{
    run_quic_client_relay, run_quic_client_relay_pinned,
    run_quic_client_relay_with_remote_socket_setup, run_quic_client_relay_with_socket_protector,
    run_quic_server_relay,
};
use tls::tls_client_configuration;

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const TCP_NOISE_PROLOGUE: &[u8] = b"SirinVPN authenticated TCP fallback v1";
const TLS_LIKE_NOISE_PROLOGUE: &[u8] = b"SirinVPN authenticated TLS-like transport v1";
const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const HANDSHAKE_MIN_LENGTH: usize = 144;
const HANDSHAKE_MAX_LENGTH: usize = 512;
const MAX_FRAME_LENGTH: usize = 2_048;
const MAX_INNER_PACKET_LENGTH: usize = 1_472;
const MAX_PADDING_LENGTH: usize = 64;
const AEAD_TAG_LENGTH: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_SERVER_CONNECTIONS: usize = 1_024;
const MAX_CONNECTIONS_PER_CLIENT: usize = 4;

/// Without an HTTPS name, connect like any client that reaches a bare address: no SNI,
/// and the address as the HTTP host. A fixed decoy name would be one rule to block.
fn tls_destination(
    name: Option<&str>,
    address: SocketAddr,
) -> Result<(ServerName<'static>, String), RelayError> {
    match name {
        Some(name) => Ok((
            ServerName::try_from(name.to_owned()).map_err(|_| RelayError::InvalidConfiguration)?,
            name.to_owned(),
        )),
        None => Ok((
            ServerName::IpAddress(address.ip().into()),
            match address.ip() {
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
                ip => ip.to_string(),
            },
        )),
    }
}

type TlsLikeClientMaterial = (Zeroizing<[u8; 32]>, [u8; 32], [u8; 32]);

#[derive(Clone, Copy)]
enum TcpOuterProtocol {
    Raw,
    TlsLike,
}

impl TcpOuterProtocol {
    fn transport(self) -> TransportKind {
        match self {
            Self::Raw => TransportKind::TcpFallback,
            Self::TlsLike => TransportKind::TlsLike,
        }
    }

    fn noise_prologue(self) -> &'static [u8] {
        match self {
            Self::Raw => TCP_NOISE_PROLOGUE,
            Self::TlsLike => TLS_LIKE_NOISE_PROLOGUE,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TcpClientRelayConfig {
    pub local_listen: SocketAddr,
    pub server_address: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_mark: Option<u32>,
    pub client_private_key: String,
    pub server_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TlsLikeClientRelayConfig {
    pub local_listen: SocketAddr,
    pub server_address: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_mark: Option<u32>,
    pub client_private_key: String,
    pub server_public_key: String,
    pub server_certificate_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https: Option<sirinvpn_protocol::HttpsTransport>,
}

impl std::fmt::Debug for TlsLikeClientRelayConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsLikeClientRelayConfig")
            .field("local_listen", &self.local_listen)
            .field("server_address", &self.server_address)
            .field("socket_mark", &self.socket_mark)
            .field("client_private_key", &"[REDACTED]")
            .field("server_public_key", &self.server_public_key)
            .field("server_certificate_sha256", &self.server_certificate_sha256)
            .field("https", &self.https)
            .finish()
    }
}

impl Drop for TlsLikeClientRelayConfig {
    fn drop(&mut self) {
        self.client_private_key.zeroize();
    }
}

impl TlsLikeClientRelayConfig {
    pub fn with_https(
        mut self,
        https: Option<sirinvpn_protocol::HttpsTransport>,
    ) -> Result<Self, RelayError> {
        if https.as_ref().is_some_and(|value| !value.is_valid()) {
            return Err(RelayError::InvalidConfiguration);
        }
        self.https = https;
        Ok(self)
    }

    fn decoded_material(&self) -> Result<TlsLikeClientMaterial, RelayError> {
        Ok((
            Zeroizing::new(decode_key(&self.client_private_key)?),
            decode_key(&self.server_public_key)?,
            decode_fingerprint(&self.server_certificate_sha256)?,
        ))
    }
}

impl std::fmt::Debug for TcpClientRelayConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpClientRelayConfig")
            .field("local_listen", &self.local_listen)
            .field("server_address", &self.server_address)
            .field("socket_mark", &self.socket_mark)
            .field("client_private_key", &"[REDACTED]")
            .field("server_public_key", &self.server_public_key)
            .finish()
    }
}

impl Drop for TcpClientRelayConfig {
    fn drop(&mut self) {
        self.client_private_key.zeroize();
    }
}

impl TcpClientRelayConfig {
    fn decoded_keys(&self) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), RelayError> {
        Ok((
            Zeroizing::new(decode_key(&self.client_private_key)?),
            decode_key(&self.server_public_key)?,
        ))
    }
}

#[derive(Clone)]
pub struct TcpServerRelayConfig {
    pub listen: SocketAddr,
    pub wireguard_backend: SocketAddr,
    pub server_private_key: Zeroizing<[u8; 32]>,
}

mod registry;
use registry::{ClientConnectionPermit, ClientConnectionRegistry, Eviction};

async fn relay_client_stream<S, F>(
    local_socket: UdpSocket,
    local_peer: LocalPeer,
    mut stream: S,
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    prologue: &[u8],
    ready: F,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(),
{
    let noise =
        establish_client_session(&mut stream, client_private, server_public, prologue).await?;
    relay_client_session(local_socket, local_peer, stream, noise, ready).await
}

async fn relay_client_session<S, F>(
    local_socket: UdpSocket,
    local_peer: LocalPeer,
    stream: S,
    noise: StatelessTransportState,
    ready: F,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(),
{
    ready();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let local_peer = Mutex::new(local_peer);
    let carrier = Mutex::new(CarrierSession::established());

    let outbound = async {
        // Nonces count records actually sent, so a dropped datagram never skips one.
        let mut outbound_nonce = 0_u64;
        let mut local_buffer = [0_u8; MAX_INNER_PACKET_LENGTH];
        loop {
            let (length, peer) = match local_socket.recv_from(&mut local_buffer).await {
                Ok(received) => received,
                // Windows reports an earlier ICMP port-unreachable on the next receive.
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(error) => return Err(error.into()),
            };
            if !lock(&local_peer).admit(peer) {
                continue;
            }
            // An empty or oversized datagram is dropped, as the UDP relay does, instead
            // of ending the carrier.
            let Ok(record) = encode_record(&noise, outbound_nonce, &local_buffer[..length]) else {
                continue;
            };
            outbound_nonce = outbound_nonce
                .checked_add(1)
                .ok_or(RelayError::NonceExhausted)?;
            write_frame(&mut writer, &record).await?;
            lock(&carrier).sent();
        }
        #[allow(unreachable_code)]
        Ok::<(), RelayError>(())
    };

    let inbound = async {
        let mut inbound_nonce = 0_u64;
        loop {
            let frame = read_frame(&mut reader, MAX_FRAME_LENGTH).await?;
            let inner =
                decrypt_record(&noise, inbound_nonce, &frame).ok_or(RelayError::HandshakeFailed)?;
            inbound_nonce = inbound_nonce
                .checked_add(1)
                .ok_or(RelayError::NonceExhausted)?;
            lock(&carrier).received();
            let target = lock(&local_peer).target();
            if let Some(peer) = target {
                local_socket.send_to(&inner, peer).await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), RelayError>(())
    };

    // A half-open stream can last until kernel retransmissions give up, minutes later.
    // Ending it lets the service restart the carrier, as the UDP relay re-handshakes.
    let liveness = async {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if lock(&carrier).phase() == CarrierPhase::Stale {
                return Err::<(), _>(RelayError::HandshakeFailed);
            }
        }
    };

    tokio::try_join!(outbound, inbound, liveness)?;
    Ok(())
}

mod server;
use server::{TlsServerMode, handle_server_connection, relay_server_session};
pub use server::{
    run_endpoint_discovery_server, run_tcp_server_relay, run_tcp_server_relay_with_https,
    run_tcp_server_relay_with_tls,
};

mod framing;
use framing::{
    accept_bound_handshake_message, accept_handshake_message, accept_server_handshake,
    decrypt_record, encode_record, establish_client_session, read_frame, write_frame,
};

async fn connect_marked_protected(
    server_address: SocketAddr,
    socket_mark: Option<u32>,
    protect: impl FnOnce(&Socket) -> Result<(), RelayError>,
) -> Result<TcpStream, RelayError> {
    let domain = if server_address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    crate::socket_policy::set_mark(&socket, socket_mark)?;
    socket.set_nonblocking(true)?;
    protect(&socket)?;
    if let Err(error) = socket.connect(&server_address.into())
        && error.kind() != io::ErrorKind::WouldBlock
        && error.raw_os_error() != Some(115)
    {
        return Err(error.into());
    }
    let standard: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(standard)?;
    timeout(CONNECT_TIMEOUT, stream.writable())
        .await
        .map_err(|_| RelayError::HandshakeFailed)??;
    if let Some(error) = stream.take_error()? {
        return Err(error.into());
    }
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn initiator_handshake(
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    prologue: &[u8],
) -> Result<HandshakeState, RelayError> {
    let parameters: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| RelayError::InvalidConfiguration)?;
    Ok(Builder::new(parameters)
        .prologue(prologue)?
        .local_private_key(local_private)?
        .remote_public_key(remote_public)?
        .build_initiator()?)
}

fn responder_handshake(
    local_private: &[u8; 32],
    prologue: &[u8],
) -> Result<HandshakeState, RelayError> {
    let parameters: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| RelayError::InvalidConfiguration)?;
    Ok(Builder::new(parameters)
        .prologue(prologue)?
        .local_private_key(local_private)?
        .build_responder()?)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn decode_key(value: &str) -> Result<[u8; 32], RelayError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| RelayError::InvalidConfiguration)?,
    );
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| RelayError::InvalidConfiguration)?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(RelayError::InvalidConfiguration);
    }
    Ok(key)
}

fn decode_fingerprint(value: &str) -> Result<[u8; 32], RelayError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| RelayError::InvalidConfiguration)?;
    let fingerprint: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| RelayError::InvalidConfiguration)?;
    if STANDARD.encode(fingerprint) != value {
        return Err(RelayError::InvalidConfiguration);
    }
    Ok(fingerprint)
}

fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests;
