use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::{Rng, RngCore, rngs::OsRng};
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
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};
use zeroize::{Zeroize, Zeroizing};

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const NOISE_PROLOGUE: &[u8] = b"SirinVPN obfuscated UDP transport v1";
const SESSION_ID_LENGTH: usize = 16;
const DATA_HEADER_LENGTH: usize = SESSION_ID_LENGTH + 8;
const AEAD_TAG_LENGTH: usize = 16;
const MAX_DATAGRAM_LENGTH: usize = 1_472;
const MAX_INNER_PACKET_LENGTH: usize =
    MAX_DATAGRAM_LENGTH - DATA_HEADER_LENGTH - AEAD_TAG_LENGTH - 2;
const MAX_PADDING_LENGTH: usize = 48;
const HANDSHAKE_MIN_LENGTH: usize = 144;
const HANDSHAKE_MAX_LENGTH: usize = 512;
const HANDSHAKE_ATTEMPTS: usize = 4;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const CLIENT_REHANDSHAKE_AFTER: Duration = Duration::from_secs(50);
const REPLAY_WINDOW_SIZE: u64 = 128;
const MAX_SERVER_SESSIONS: usize = 4_096;
const MAX_SESSIONS_PER_CLIENT: usize = 4;

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientRelayConfig {
    pub local_listen: SocketAddr,
    pub server_address: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_mark: Option<u32>,
    pub client_private_key: String,
    pub server_public_key: String,
}

impl std::fmt::Debug for ClientRelayConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientRelayConfig")
            .field("local_listen", &self.local_listen)
            .field("server_address", &self.server_address)
            .field("socket_mark", &self.socket_mark)
            .field("client_private_key", &"[REDACTED]")
            .field("server_public_key", &self.server_public_key)
            .finish()
    }
}

impl Drop for ClientRelayConfig {
    fn drop(&mut self) {
        self.client_private_key.zeroize();
    }
}

impl ClientRelayConfig {
    fn decoded_keys(&self) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), RelayError> {
        let private = decode_key(&self.client_private_key)?;
        let public = decode_key(&self.server_public_key)?;
        Ok((Zeroizing::new(private), public))
    }
}

#[derive(Clone)]
pub struct ServerRelayConfig {
    pub listen: SocketAddr,
    pub wireguard_backend: SocketAddr,
    pub server_private_key: Zeroizing<[u8; 32]>,
}

mod authorization;
pub use authorization::{AuthorizedPeers, EndpointPublicationRequest};

type TransportActivity = HashMap<[u8; 32], (TransportKind, Instant, u64)>;

#[derive(Default)]
struct TransportActivityState {
    entries: RwLock<TransportActivity>,
    next_connection_id: AtomicU64,
}

#[derive(Clone, Default)]
pub struct ActiveTransportRegistry(Arc<TransportActivityState>);

pub(crate) struct ActiveTransportConnection {
    registry: ActiveTransportRegistry,
    peer: [u8; 32],
    transport: TransportKind,
    connection_id: u64,
}

impl ActiveTransportRegistry {
    pub(crate) fn record(&self, peer: [u8; 32], transport: TransportKind) {
        self.0
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer, (transport, Instant::now(), 0));
    }

    pub(crate) fn connection(
        &self,
        peer: [u8; 32],
        transport: TransportKind,
    ) -> ActiveTransportConnection {
        let connection_id = loop {
            let candidate = self
                .0
                .next_connection_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if candidate != 0 {
                break candidate;
            }
        };
        let connection = ActiveTransportConnection {
            registry: self.clone(),
            peer,
            transport,
            connection_id,
        };
        connection.record();
        connection
    }

    pub fn is_obfuscated_recent(&self, peer: &[u8; 32], maximum_age: Duration) -> bool {
        self.recent_transport(peer, maximum_age) == Some(TransportKind::ObfuscatedUdp)
    }

    pub fn recent_transport(
        &self,
        peer: &[u8; 32],
        maximum_age: Duration,
    ) -> Option<TransportKind> {
        self.0
            .entries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(peer)
            .and_then(|(transport, seen, _)| (seen.elapsed() <= maximum_age).then_some(*transport))
    }

    pub(crate) fn prune(&self, maximum_age: Duration) {
        self.0
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|_, (_, seen, _)| seen.elapsed() <= maximum_age);
    }
}

impl ActiveTransportConnection {
    pub(crate) fn record(&self) {
        self.registry
            .0
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                self.peer,
                (self.transport, Instant::now(), self.connection_id),
            );
    }
}

impl Drop for ActiveTransportConnection {
    fn drop(&mut self) {
        let mut entries = self
            .registry
            .0
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries
            .get(&self.peer)
            .is_some_and(|(_, _, connection_id)| *connection_id == self.connection_id)
        {
            entries.remove(&self.peer);
        }
    }
}

struct ClientSession {
    id: [u8; SESSION_ID_LENGTH],
    noise: StatelessTransportState,
    next_outbound: u64,
    inbound_replay: ReplayWindow,
}

struct ServerSession {
    id: [u8; SESSION_ID_LENGTH],
    client_static: [u8; 32],
    noise: StatelessTransportState,
    next_outbound: AtomicU64,
    inbound_replay: Mutex<ReplayWindow>,
    client_address: RwLock<SocketAddr>,
    last_seen: Mutex<Instant>,
    backend: Arc<UdpSocket>,
    active: AtomicBool,
}

impl ServerSession {
    fn touch(&self, address: SocketAddr) {
        *self
            .client_address
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = address;
        *self
            .last_seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .elapsed()
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ReplayWindow {
    highest: u64,
    bitmap: u128,
    initialized: bool,
}

impl ReplayWindow {
    fn accepts(&self, sequence: u64) -> bool {
        if !self.initialized || sequence > self.highest {
            return true;
        }
        let distance = self.highest - sequence;
        distance < REPLAY_WINDOW_SIZE && self.bitmap & (1_u128 << distance) == 0
    }

    fn commit(&mut self, sequence: u64) {
        if !self.initialized {
            self.initialized = true;
            self.highest = sequence;
            self.bitmap = 1;
            return;
        }
        if sequence > self.highest {
            let shift = sequence - self.highest;
            self.bitmap = if shift >= REPLAY_WINDOW_SIZE {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = sequence;
        } else {
            self.bitmap |= 1_u128 << (self.highest - sequence);
        }
    }
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
            .is_some_and(|(seen, _)| seen.elapsed() > SESSION_IDLE_TIMEOUT)
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

mod client;
pub use client::{
    run_client_relay, run_client_relay_with_remote_socket_setup,
    run_client_relay_with_socket_protector,
};

pub async fn run_server_relay(
    config: ServerRelayConfig,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
) -> Result<(), RelayError> {
    if config.listen.ip().is_loopback() || !config.wireguard_backend.ip().is_loopback() {
        return Err(RelayError::InvalidConfiguration);
    }
    let socket = if config.listen.is_ipv6() {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.bind(&config.listen.into())?;
        UdpSocket::from_std(socket.into())?
    } else {
        UdpSocket::bind(config.listen).await?
    };
    let socket = Arc::new(socket);
    let sessions: Arc<tokio::sync::RwLock<HashMap<[u8; SESSION_ID_LENGTH], Arc<ServerSession>>>> =
        Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    let replay_cache = Arc::new(Mutex::new(HandshakeReplayCache::default()));
    let probe_limiter = Arc::new(Mutex::new(ProbeLimiter::default()));
    let _cleanup = spawn_session_cleanup(sessions.clone(), authorized.clone(), activity.clone());
    let mut buffer = [0_u8; MAX_DATAGRAM_LENGTH];

    loop {
        let (length, source) = socket.recv_from(&mut buffer).await?;
        let packet = &buffer[..length];
        if let Some((session_id, sequence, ciphertext)) = parse_server_transport_packet(packet) {
            let session = sessions.read().await.get(&session_id).cloned();
            if let Some(session) = session {
                handle_server_transport_packet(
                    &session,
                    sequence,
                    ciphertext,
                    source,
                    &authorized,
                    &activity,
                )
                .await;
                continue;
            }
        }

        if !(HANDSHAKE_MIN_LENGTH..=HANDSHAKE_MAX_LENGTH).contains(&length)
            || !probe_limiter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .allow(source.ip())
        {
            continue;
        }
        let Some((session, response)) =
            accept_server_handshake(packet, source, &config, &authorized, &replay_cache).await?
        else {
            continue;
        };
        let session = Arc::new(session);
        if !insert_server_session(&sessions, session.clone()).await {
            continue;
        }
        activity.record(session.client_static, TransportKind::ObfuscatedUdp);
        socket.send_to(&response, source).await?;
        spawn_backend_forwarder(session, socket.clone());
    }
}

async fn insert_server_session(
    sessions: &tokio::sync::RwLock<HashMap<[u8; SESSION_ID_LENGTH], Arc<ServerSession>>>,
    session: Arc<ServerSession>,
) -> bool {
    let mut sessions = sessions.write().await;
    if sessions.contains_key(&session.id) {
        return false;
    }
    let mut same_client: Vec<_> = sessions
        .iter()
        .filter_map(|(id, existing)| {
            (existing.client_static == session.client_static).then_some((*id, existing.idle_for()))
        })
        .collect();
    same_client.sort_unstable_by_key(|(_, idle)| std::cmp::Reverse(*idle));
    while same_client.len() >= MAX_SESSIONS_PER_CLIENT {
        let (id, _) = same_client.remove(0);
        if let Some(expired) = sessions.remove(&id) {
            expired.active.store(false, Ordering::Release);
        }
    }
    if sessions.len() >= MAX_SERVER_SESSIONS {
        return false;
    }
    sessions.insert(session.id, session);
    true
}

async fn establish_client_session(
    socket: &UdpSocket,
    client_private: &[u8; 32],
    server_public: &[u8; 32],
) -> Result<ClientSession, RelayError> {
    let mut response = [0_u8; MAX_DATAGRAM_LENGTH];
    for _ in 0..HANDSHAKE_ATTEMPTS {
        let mut handshake = initiator_handshake(client_private, server_public)?;
        let padding_length = OsRng.gen_range(48..=144);
        let padding = random_bytes(padding_length);
        let mut request = [0_u8; HANDSHAKE_MAX_LENGTH];
        let request_length = handshake.write_message(&padding, &mut request)?;
        socket.send(&request[..request_length]).await?;
        let received = timeout(HANDSHAKE_TIMEOUT, socket.recv(&mut response)).await;
        let Ok(Ok(length)) = received else {
            continue;
        };
        let mut payload = [0_u8; HANDSHAKE_MAX_LENGTH];
        let Ok(payload_length) = handshake.read_message(&response[..length], &mut payload) else {
            continue;
        };
        if payload_length < SESSION_ID_LENGTH {
            continue;
        }
        let mut id = [0_u8; SESSION_ID_LENGTH];
        id.copy_from_slice(&payload[..SESSION_ID_LENGTH]);
        let noise = handshake.into_stateless_transport_mode()?;
        return Ok(ClientSession {
            id,
            noise,
            next_outbound: 0,
            inbound_replay: ReplayWindow::default(),
        });
    }
    Err(RelayError::HandshakeFailed)
}

async fn accept_server_handshake(
    packet: &[u8],
    source: SocketAddr,
    config: &ServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
) -> Result<Option<(ServerSession, Vec<u8>)>, RelayError> {
    let mut handshake = responder_handshake(&config.server_private_key)?;
    let mut client_payload = [0_u8; HANDSHAKE_MAX_LENGTH];
    if handshake.read_message(packet, &mut client_payload).is_err() {
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
            .insert_once(packet)
    {
        return Ok(None);
    }

    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    backend.connect(config.wireguard_backend).await?;
    let mut id = [0_u8; SESSION_ID_LENGTH];
    OsRng.fill_bytes(&mut id);
    let padding_length = OsRng.gen_range(32..=80);
    let mut response_payload = Vec::with_capacity(SESSION_ID_LENGTH + padding_length);
    response_payload.extend_from_slice(&id);
    response_payload.extend_from_slice(&random_bytes(padding_length));
    let mut response = [0_u8; HANDSHAKE_MAX_LENGTH];
    let response_length = handshake.write_message(&response_payload, &mut response)?;
    if response_length > packet.len() {
        return Ok(None);
    }
    let noise = handshake.into_stateless_transport_mode()?;
    Ok(Some((
        ServerSession {
            id,
            client_static,
            noise,
            next_outbound: AtomicU64::new(0),
            inbound_replay: Mutex::new(ReplayWindow::default()),
            client_address: RwLock::new(source),
            last_seen: Mutex::new(Instant::now()),
            backend,
            active: AtomicBool::new(true),
        },
        response[..response_length].to_vec(),
    )))
}

async fn handle_server_transport_packet(
    session: &ServerSession,
    sequence: u64,
    ciphertext: &[u8],
    source: SocketAddr,
    authorized: &AuthorizedPeers,
    activity: &ActiveTransportRegistry,
) {
    if !authorized.contains(&session.client_static) {
        session.active.store(false, Ordering::Release);
        return;
    }
    {
        let replay = session
            .inbound_replay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !replay.accepts(sequence) {
            return;
        }
    }
    let Some(inner) = decrypt_inner(&session.noise, sequence, ciphertext) else {
        return;
    };
    session
        .inbound_replay
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .commit(sequence);
    session.touch(source);
    activity.record(session.client_static, TransportKind::ObfuscatedUdp);
    let _ = session.backend.send(&inner).await;
}

fn spawn_backend_forwarder(session: Arc<ServerSession>, socket: Arc<UdpSocket>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = [0_u8; MAX_DATAGRAM_LENGTH];
        while session.active.load(Ordering::Acquire) {
            let received =
                timeout(Duration::from_secs(10), session.backend.recv(&mut buffer)).await;
            let Ok(Ok(length)) = received else {
                continue;
            };
            let sequence = session.next_outbound.fetch_add(1, Ordering::Relaxed);
            if sequence == u64::MAX {
                session.active.store(false, Ordering::Release);
                return;
            }
            let Ok(packet) =
                encode_transport_packet(&session.id, sequence, &session.noise, &buffer[..length])
            else {
                continue;
            };
            let address = *session
                .client_address
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _ = socket.send_to(&packet, address).await;
        }
    })
}

fn spawn_session_cleanup(
    sessions: Arc<tokio::sync::RwLock<HashMap<[u8; SESSION_ID_LENGTH], Arc<ServerSession>>>>,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let expired: Vec<_> = sessions
                .read()
                .await
                .iter()
                .filter_map(|(id, session)| {
                    (session.idle_for() > SESSION_IDLE_TIMEOUT
                        || !authorized.contains(&session.client_static))
                    .then_some(*id)
                })
                .collect();
            if !expired.is_empty() {
                let mut sessions = sessions.write().await;
                for id in expired {
                    if let Some(session) = sessions.remove(&id) {
                        session.active.store(false, Ordering::Release);
                    }
                }
            }
            activity.prune(SESSION_IDLE_TIMEOUT);
        }
    })
}

fn encode_transport_packet(
    session_id: &[u8; SESSION_ID_LENGTH],
    sequence: u64,
    noise: &StatelessTransportState,
    inner: &[u8],
) -> Result<Vec<u8>, RelayError> {
    if inner.is_empty() || inner.len() > MAX_INNER_PACKET_LENGTH {
        return Err(RelayError::PacketTooLarge);
    }
    let available_padding = MAX_DATAGRAM_LENGTH
        .saturating_sub(DATA_HEADER_LENGTH + AEAD_TAG_LENGTH + 2 + inner.len())
        .min(MAX_PADDING_LENGTH);
    let padding_length = OsRng.gen_range(0..=available_padding);
    let mut plaintext = Vec::with_capacity(2 + inner.len() + padding_length);
    plaintext.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(inner);
    plaintext.extend_from_slice(&random_bytes(padding_length));
    let mut packet = vec![0_u8; DATA_HEADER_LENGTH + plaintext.len() + AEAD_TAG_LENGTH];
    packet[..SESSION_ID_LENGTH].copy_from_slice(session_id);
    packet[SESSION_ID_LENGTH..DATA_HEADER_LENGTH].copy_from_slice(&sequence.to_be_bytes());
    let encrypted = noise.write_message(sequence, &plaintext, &mut packet[DATA_HEADER_LENGTH..])?;
    packet.truncate(DATA_HEADER_LENGTH + encrypted);
    Ok(packet)
}

fn decrypt_inner(
    noise: &StatelessTransportState,
    sequence: u64,
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext.len() < AEAD_TAG_LENGTH + 2 || ciphertext.len() > MAX_DATAGRAM_LENGTH {
        return None;
    }
    let mut plaintext = vec![0_u8; ciphertext.len()];
    let length = noise
        .read_message(sequence, ciphertext, &mut plaintext)
        .ok()?;
    if length < 2 {
        return None;
    }
    let inner_length = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
    if inner_length == 0 || inner_length > length.saturating_sub(2) {
        return None;
    }
    Some(plaintext[2..2 + inner_length].to_vec())
}

fn parse_transport_packet<'a>(
    packet: &'a [u8],
    expected_session: &[u8; SESSION_ID_LENGTH],
) -> Option<(u64, &'a [u8])> {
    let (session, sequence, ciphertext) = parse_server_transport_packet(packet)?;
    (session == *expected_session).then_some((sequence, ciphertext))
}

fn parse_server_transport_packet(packet: &[u8]) -> Option<([u8; SESSION_ID_LENGTH], u64, &[u8])> {
    if packet.len() < DATA_HEADER_LENGTH + AEAD_TAG_LENGTH + 2 || packet.len() > MAX_DATAGRAM_LENGTH
    {
        return None;
    }
    let mut session = [0_u8; SESSION_ID_LENGTH];
    session.copy_from_slice(&packet[..SESSION_ID_LENGTH]);
    let sequence = u64::from_be_bytes(
        packet[SESSION_ID_LENGTH..DATA_HEADER_LENGTH]
            .try_into()
            .ok()?,
    );
    Some((session, sequence, &packet[DATA_HEADER_LENGTH..]))
}

fn initiator_handshake(
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
) -> Result<HandshakeState, RelayError> {
    let parameters: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| RelayError::InvalidConfiguration)?;
    Ok(Builder::new(parameters)
        .prologue(NOISE_PROLOGUE)?
        .local_private_key(local_private)?
        .remote_public_key(remote_public)?
        .build_initiator()?)
}

fn responder_handshake(local_private: &[u8; 32]) -> Result<HandshakeState, RelayError> {
    let parameters: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| RelayError::InvalidConfiguration)?;
    Ok(Builder::new(parameters)
        .prologue(NOISE_PROLOGUE)?
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

fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn bind_remote_socket(
    server_address: SocketAddr,
    socket_mark: Option<u32>,
    protect: impl FnOnce(&Socket) -> Result<(), RelayError>,
) -> Result<UdpSocket, RelayError> {
    let domain = if server_address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    crate::socket_policy::set_mark(&socket, socket_mark)?;
    socket.set_nonblocking(true)?;
    protect(&socket)?;
    socket.bind(
        &SocketAddr::new(
            if server_address.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            },
            0,
        )
        .into(),
    )?;
    Ok(UdpSocket::from_std(socket.into())?)
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("the obfuscated transport configuration is invalid")]
    InvalidConfiguration,
    #[error("the obfuscated transport handshake failed")]
    HandshakeFailed,
    #[error("the obfuscated transport packet exceeds its safe MTU")]
    PacketTooLarge,
    #[error("the obfuscated transport nonce space is exhausted")]
    NonceExhausted,
    #[error("the obfuscated transport network binding failed")]
    NetworkBindingFailed,
    #[error("the obfuscated transport socket failed")]
    Io(#[from] io::Error),
    #[error("the authenticated transport state is invalid")]
    Noise(#[from] snow::Error),
}

#[cfg(test)]
mod tests;
