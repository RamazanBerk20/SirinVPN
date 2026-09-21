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
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::{Zeroize, Zeroizing};

use crate::relay::{ActiveTransportRegistry, AuthorizedPeers, RelayError};

mod client;
mod discovery;
mod publication;
pub use client::{
    run_tcp_client_relay, run_tcp_client_relay_with_remote_socket_setup,
    run_tcp_client_relay_with_socket_protector, run_tls_like_client_relay,
    run_tls_like_client_relay_with_remote_socket_setup,
    run_tls_like_client_relay_with_socket_protector,
};
pub use discovery::{
    EndpointDiscoveryConfig, fetch_endpoint_checkpoint,
    fetch_endpoint_checkpoint_with_socket_protector,
};
pub use publication::{offer_endpoint_checkpoint, offer_endpoint_checkpoint_with_socket_protector};
mod https;
mod tls;
use tls::tls_client_configuration;

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const TCP_NOISE_PROLOGUE: &[u8] = b"SirinVPN authenticated TCP fallback v1";
const TLS_LIKE_NOISE_PROLOGUE: &[u8] = b"SirinVPN authenticated TLS-like transport v1";
const TLS_LIKE_SERVER_NAME: &str = "www.example.com";
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

#[derive(Default)]
struct HandshakeReplayCache {
    entries: VecDeque<(Instant, [u8; 32])>,
    digests: HashSet<[u8; 32]>,
}

impl HandshakeReplayCache {
    fn insert_once(&mut self, message: &[u8]) -> bool {
        self.prune();
        let digest: [u8; 32] = Sha256::digest(message).into();
        if self.digests.contains(&digest) {
            return false;
        }
        while self.entries.len() >= 4_096 {
            if let Some((_, removed)) = self.entries.pop_front() {
                self.digests.remove(&removed);
            }
        }
        self.entries.push_back((Instant::now(), digest));
        self.digests.insert(digest);
        true
    }

    fn prune(&mut self) {
        while self
            .entries
            .front()
            .is_some_and(|(seen, _)| seen.elapsed() > Duration::from_secs(180))
        {
            if let Some((_, digest)) = self.entries.pop_front() {
                self.digests.remove(&digest);
            }
        }
    }
}

#[derive(Default)]
struct ProbeLimiter {
    peers: HashMap<IpAddr, ProbeWindow>,
}

struct ProbeWindow {
    started: Instant,
    attempts: u8,
}

impl ProbeLimiter {
    fn allow(&mut self, address: IpAddr) -> bool {
        if self.peers.len() >= 1_024 {
            self.peers
                .retain(|_, window| window.started.elapsed() < Duration::from_secs(60));
            if self.peers.len() >= 1_024 && !self.peers.contains_key(&address) {
                return false;
            }
        }
        let window = self.peers.entry(address).or_insert(ProbeWindow {
            started: Instant::now(),
            attempts: 0,
        });
        if window.started.elapsed() >= Duration::from_secs(10) {
            window.started = Instant::now();
            window.attempts = 0;
        }
        if window.attempts >= 12 {
            return false;
        }
        window.attempts += 1;
        true
    }
}

#[derive(Clone, Default)]
struct ClientConnectionRegistry(Arc<Mutex<HashMap<[u8; 32], usize>>>);

impl ClientConnectionRegistry {
    fn acquire(&self, peer: [u8; 32]) -> Option<ClientConnectionPermit> {
        let mut connections = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = connections.entry(peer).or_default();
        if *count >= MAX_CONNECTIONS_PER_CLIENT {
            return None;
        }
        *count += 1;
        Some(ClientConnectionPermit {
            registry: self.clone(),
            peer,
        })
    }
}

struct ClientConnectionPermit {
    registry: ClientConnectionRegistry,
    peer: [u8; 32],
}

impl Drop for ClientConnectionPermit {
    fn drop(&mut self) {
        let mut connections = self
            .registry
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = connections.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                connections.remove(&self.peer);
            }
        }
    }
}

async fn relay_client_stream<S, F>(
    local_socket: UdpSocket,
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
    relay_client_session(local_socket, stream, noise, ready).await
}

async fn relay_client_session<S, F>(
    local_socket: UdpSocket,
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
    let mut initial_buffer = [0_u8; MAX_INNER_PACKET_LENGTH];
    let (initial_length, initial_peer) = loop {
        let (length, peer) = local_socket.recv_from(&mut initial_buffer).await?;
        if peer.ip().is_loopback() {
            break (length, peer);
        }
    };
    let initial_record = encode_record(&noise, 0, &initial_buffer[..initial_length])?;
    write_frame(&mut writer, &initial_record).await?;

    let local_peer = Arc::new(Mutex::new(initial_peer));
    let outbound_peer = local_peer.clone();
    let outbound = async {
        let mut outbound_nonce = 1_u64;
        let mut local_buffer = [0_u8; MAX_INNER_PACKET_LENGTH];
        loop {
            let (length, peer) = local_socket.recv_from(&mut local_buffer).await?;
            if !peer.ip().is_loopback() {
                continue;
            }
            *outbound_peer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = peer;
            let record = encode_record(&noise, outbound_nonce, &local_buffer[..length])?;
            outbound_nonce = outbound_nonce
                .checked_add(1)
                .ok_or(RelayError::NonceExhausted)?;
            write_frame(&mut writer, &record).await?;
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
            let peer = *local_peer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            local_socket.send_to(&inner, peer).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), RelayError>(())
    };

    tokio::try_join!(outbound, inbound)?;
    Ok(())
}

pub async fn run_tcp_server_relay(
    config: TcpServerRelayConfig,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
) -> Result<(), RelayError> {
    run_tcp_server_relay_inner(config, None, authorized, activity).await
}

pub async fn run_tcp_server_relay_with_tls(
    config: TcpServerRelayConfig,
    tls_acceptor: TlsAcceptor,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
) -> Result<(), RelayError> {
    run_tcp_server_relay_inner(
        config,
        Some(TlsServerMode {
            acceptor: tls_acceptor,
            https: None,
            discovery_only: false,
        }),
        authorized,
        activity,
    )
    .await
}

#[derive(Clone)]
struct TlsServerMode {
    acceptor: TlsAcceptor,
    https: Option<sirinvpn_protocol::HttpsTransport>,
    discovery_only: bool,
}

pub async fn run_tcp_server_relay_with_https(
    config: TcpServerRelayConfig,
    tls_acceptor: TlsAcceptor,
    https: sirinvpn_protocol::HttpsTransport,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
) -> Result<(), RelayError> {
    if !https.is_valid() {
        return Err(RelayError::InvalidConfiguration);
    }
    run_tcp_server_relay_inner(
        config,
        Some(TlsServerMode {
            acceptor: tls_acceptor,
            https: Some(https),
            discovery_only: false,
        }),
        authorized,
        activity,
    )
    .await
}

pub async fn run_endpoint_discovery_server(
    config: TcpServerRelayConfig,
    tls_acceptor: TlsAcceptor,
    authorized: AuthorizedPeers,
) -> Result<(), RelayError> {
    run_tcp_server_relay_inner(
        config,
        Some(TlsServerMode {
            acceptor: tls_acceptor,
            https: None,
            discovery_only: true,
        }),
        authorized,
        ActiveTransportRegistry::default(),
    )
    .await
}

async fn run_tcp_server_relay_inner(
    config: TcpServerRelayConfig,
    tls_acceptor: Option<TlsServerMode>,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
) -> Result<(), RelayError> {
    if config.listen.ip().is_loopback() || !config.wireguard_backend.ip().is_loopback() {
        return Err(RelayError::InvalidConfiguration);
    }
    let listener = if config.listen.is_ipv6() {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(false)?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&config.listen.into())?;
        socket.listen(128)?;
        TcpListener::from_std(socket.into())?
    } else {
        TcpListener::bind(config.listen).await?
    };
    let replay_cache = Arc::new(Mutex::new(HandshakeReplayCache::default()));
    let probe_limiter = Arc::new(Mutex::new(ProbeLimiter::default()));
    let global_connections = Arc::new(Semaphore::new(MAX_SERVER_CONNECTIONS));
    let client_connections = ClientConnectionRegistry::default();
    let mut activity_cleanup = tokio::time::interval(Duration::from_secs(30));
    activity_cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = activity_cleanup.tick() => {
                activity.prune(CONNECTION_IDLE_TIMEOUT);
                continue;
            }
        };
        let (stream, source) = accepted;
        if !probe_limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allow(source.ip())
        {
            continue;
        }
        let Ok(global_permit) = global_connections.clone().try_acquire_owned() else {
            continue;
        };
        let connection_config = config.clone();
        let connection_authorized = authorized.clone();
        let connection_activity = activity.clone();
        let connection_replay = replay_cache.clone();
        let connection_clients = client_connections.clone();
        let connection_tls = tls_acceptor.clone();
        tokio::spawn(async move {
            let _global_permit = global_permit;
            let _ = handle_outer_connection(
                stream,
                connection_config,
                connection_tls,
                connection_authorized,
                connection_activity,
                connection_replay,
                connection_clients,
            )
            .await;
        });
    }
}

async fn handle_outer_connection(
    stream: TcpStream,
    config: TcpServerRelayConfig,
    tls_acceptor: Option<TlsServerMode>,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
    replay_cache: Arc<Mutex<HandshakeReplayCache>>,
    client_connections: ClientConnectionRegistry,
) -> Result<(), RelayError> {
    stream.set_nodelay(true)?;
    if let Some(tls_acceptor) = tls_acceptor {
        let mut first = [0_u8; 1];
        let length = timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first))
            .await
            .map_err(|_| RelayError::HandshakeFailed)??;
        if length == 1 && first[0] == TLS_HANDSHAKE_RECORD {
            let tls_stream = timeout(HANDSHAKE_TIMEOUT, tls_acceptor.acceptor.accept(stream))
                .await
                .map_err(|_| RelayError::HandshakeFailed)?
                .map_err(|_| RelayError::HandshakeFailed)?;
            return https::server(
                tls_stream,
                tls_acceptor,
                config,
                authorized,
                activity,
                replay_cache,
                client_connections,
            )
            .await;
        }
        if tls_acceptor.discovery_only {
            return Err(RelayError::HandshakeFailed);
        }
    }
    handle_server_connection(
        stream,
        config,
        authorized,
        activity,
        replay_cache,
        client_connections,
        TcpOuterProtocol::Raw,
    )
    .await
}

async fn handle_server_connection<S>(
    mut stream: S,
    config: TcpServerRelayConfig,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
    replay_cache: Arc<Mutex<HandshakeReplayCache>>,
    client_connections: ClientConnectionRegistry,
    outer_protocol: TcpOuterProtocol,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some((noise, client_static, response)) = timeout(
        HANDSHAKE_TIMEOUT,
        accept_server_handshake(
            &mut stream,
            &config,
            &authorized,
            &replay_cache,
            outer_protocol.noise_prologue(),
        ),
    )
    .await
    .map_err(|_| RelayError::HandshakeFailed)??
    else {
        return Ok(());
    };
    let Some(_client_permit) = client_connections.acquire(client_static) else {
        return Ok(());
    };
    write_frame(&mut stream, &response).await?;
    relay_server_session(
        stream,
        config,
        authorized,
        activity,
        noise,
        client_static,
        outer_protocol,
    )
    .await
}

async fn relay_server_session<S>(
    stream: S,
    config: TcpServerRelayConfig,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
    noise: StatelessTransportState,
    client_static: [u8; 32],
    outer_protocol: TcpOuterProtocol,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let connection_activity = activity.connection(client_static, outer_protocol.transport());

    let backend = UdpSocket::bind("127.0.0.1:0").await?;
    backend.connect(config.wireguard_backend).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let last_activity = Arc::new(Mutex::new(Instant::now()));

    let inbound_activity = last_activity.clone();
    let client_to_backend = async {
        let mut inbound_nonce = 0_u64;
        loop {
            let frame = read_frame(&mut reader, MAX_FRAME_LENGTH).await?;
            let inner =
                decrypt_record(&noise, inbound_nonce, &frame).ok_or(RelayError::HandshakeFailed)?;
            inbound_nonce = inbound_nonce
                .checked_add(1)
                .ok_or(RelayError::NonceExhausted)?;
            *inbound_activity
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
            connection_activity.record();
            backend.send(&inner).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), RelayError>(())
    };

    let outbound_activity = last_activity.clone();
    let backend_to_client = async {
        let mut backend_buffer = [0_u8; MAX_INNER_PACKET_LENGTH];
        let mut outbound_nonce = 0_u64;
        loop {
            let length = backend.recv(&mut backend_buffer).await?;
            *outbound_activity
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
            let record = encode_record(&noise, outbound_nonce, &backend_buffer[..length])?;
            outbound_nonce = outbound_nonce
                .checked_add(1)
                .ok_or(RelayError::NonceExhausted)?;
            write_frame(&mut writer, &record).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), RelayError>(())
    };

    let relay = async {
        tokio::try_join!(client_to_backend, backend_to_client)?;
        Ok::<(), RelayError>(())
    };
    let maintenance = async {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let idle = last_activity
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .elapsed();
            if !authorized.contains(&client_static) || idle > CONNECTION_IDLE_TIMEOUT {
                return Ok::<(), RelayError>(());
            }
        }
    };

    tokio::select! {
        result = relay => result,
        result = maintenance => result,
    }
}

async fn establish_client_session<S>(
    stream: &mut S,
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    prologue: &[u8],
) -> Result<StatelessTransportState, RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(HANDSHAKE_TIMEOUT, async {
        let mut handshake = initiator_handshake(client_private, server_public, prologue)?;
        let padding = random_bytes(OsRng.gen_range(48..=144));
        let mut request = [0_u8; HANDSHAKE_MAX_LENGTH];
        let request_length = handshake.write_message(&padding, &mut request)?;
        write_frame(stream, &request[..request_length]).await?;
        let response = read_frame(stream, HANDSHAKE_MAX_LENGTH).await?;
        let mut payload = [0_u8; HANDSHAKE_MAX_LENGTH];
        handshake.read_message(&response, &mut payload)?;
        Ok(handshake.into_stateless_transport_mode()?)
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)?
}

async fn accept_server_handshake<S>(
    stream: &mut S,
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
    prologue: &[u8],
) -> Result<Option<(StatelessTransportState, [u8; 32], Vec<u8>)>, RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_frame(stream, HANDSHAKE_MAX_LENGTH).await?;
    accept_handshake_message(&request, config, authorized, replay_cache, prologue)
}

type AcceptedHandshake = (StatelessTransportState, [u8; 32], Vec<u8>);

fn accept_handshake_message(
    request: &[u8],
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
    prologue: &[u8],
) -> Result<Option<AcceptedHandshake>, RelayError> {
    if !(HANDSHAKE_MIN_LENGTH..=HANDSHAKE_MAX_LENGTH).contains(&request.len()) {
        return Ok(None);
    }
    let mut handshake = responder_handshake(&config.server_private_key, prologue)?;
    let mut client_payload = [0_u8; HANDSHAKE_MAX_LENGTH];
    if handshake
        .read_message(request, &mut client_payload)
        .is_err()
    {
        return Ok(None);
    }
    let Some(remote_static) = handshake.get_remote_static() else {
        return Ok(None);
    };
    let Ok(client_static) = <[u8; 32]>::try_from(remote_static) else {
        return Ok(None);
    };
    if !authorized.contains(&client_static)
        || !replay_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert_once(request)
    {
        return Ok(None);
    }

    let padding = random_bytes(OsRng.gen_range(32..=80));
    let mut response = [0_u8; HANDSHAKE_MAX_LENGTH];
    let response_length = handshake.write_message(&padding, &mut response)?;
    if response_length > request.len() {
        return Ok(None);
    }
    let noise = handshake.into_stateless_transport_mode()?;
    Ok(Some((
        noise,
        client_static,
        response[..response_length].to_vec(),
    )))
}

fn encode_record(
    noise: &StatelessTransportState,
    nonce: u64,
    inner: &[u8],
) -> Result<Vec<u8>, RelayError> {
    if inner.is_empty() || inner.len() > MAX_INNER_PACKET_LENGTH {
        return Err(RelayError::PacketTooLarge);
    }
    let available_padding = MAX_FRAME_LENGTH
        .saturating_sub(AEAD_TAG_LENGTH + 2 + inner.len())
        .min(MAX_PADDING_LENGTH);
    let padding_length = OsRng.gen_range(0..=available_padding);
    let mut plaintext = Vec::with_capacity(2 + inner.len() + padding_length);
    plaintext.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(inner);
    plaintext.extend_from_slice(&random_bytes(padding_length));
    let mut record = vec![0_u8; plaintext.len() + AEAD_TAG_LENGTH];
    let length = noise.write_message(nonce, &plaintext, &mut record)?;
    record.truncate(length);
    Ok(record)
}

fn decrypt_record(
    noise: &StatelessTransportState,
    nonce: u64,
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext.len() < AEAD_TAG_LENGTH + 2 || ciphertext.len() > MAX_FRAME_LENGTH {
        return None;
    }
    let mut plaintext = vec![0_u8; ciphertext.len()];
    let length = noise.read_message(nonce, ciphertext, &mut plaintext).ok()?;
    if length < 2 {
        return None;
    }
    let inner_length = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
    if inner_length == 0 || inner_length > length.saturating_sub(2) {
        return None;
    }
    Some(plaintext[2..2 + inner_length].to_vec())
}

async fn read_frame<R>(reader: &mut R, maximum_length: usize) -> Result<Vec<u8>, RelayError>
where
    R: AsyncRead + Unpin,
{
    let length = usize::from(reader.read_u16().await?);
    if length == 0 || length > maximum_length {
        return Err(RelayError::InvalidConfiguration);
    }
    let mut frame = vec![0_u8; length];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), RelayError>
where
    W: AsyncWrite + Unpin,
{
    let length = u16::try_from(frame.len()).map_err(|_| RelayError::PacketTooLarge)?;
    writer.write_u16(length).await?;
    writer.write_all(frame).await?;
    writer.flush().await?;
    Ok(())
}

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
