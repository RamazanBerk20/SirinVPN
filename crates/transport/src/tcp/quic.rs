//! QUIC carrier that looks like HTTP/3 on the TLS port's UDP twin. TLS 1.3 inside QUIC
//! checks the same certificate pin, and a Noise IK exchange on the first stream authorizes
//! the device and authenticates the server key, as on the TCP transports. WireGuard packets
//! then travel as QUIC DATAGRAM frames, so loss and reordering stay end to end instead of
//! stalling behind retransmissions.
use super::*;
use quinn::{
    ClientConfig as QuicClientConfig, Connection, Endpoint, EndpointConfig, Incoming, RecvStream,
    SendStream, ServerConfig as QuicServerConfig, TokioRuntime, TransportConfig, VarInt,
    crypto::rustls::{
        QuicClientConfig as RustlsClientCrypto, QuicServerConfig as RustlsServerCrypto,
    },
};

const PROLOGUE: &[u8] = b"SirinVPN QUIC transport v1";
const ALPN: &[u8] = b"h3";
/// UDP payload before path MTU discovery: a 1,280-byte tunnel packet plus WireGuard (32),
/// length (2) and QUIC (38) overhead. Discovery may raise it to 1,452.
const INITIAL_MTU: u16 = 1_352;
const IDLE_TIMEOUT_MILLISECONDS: u32 = 60_000;
const MAX_STREAMS: u32 = 8;
const H3_NO_ERROR: u32 = 0x100;
/// An HTTP/3 control stream (type 0) with an empty SETTINGS frame.
const CONTROL_STREAM: &[u8] = &[0x00, 0x04, 0x00];
/// A HEADERS frame whose QPACK field section is the static-table entry `:status 404`.
const NOT_FOUND: &[u8] = &[0x01, 0x03, 0x00, 0x00, 0xdb];

pub async fn run_quic_client_relay<F>(
    config: TlsLikeClientRelayConfig,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
{
    run_quic_client_relay_with_remote_socket_setup(
        config,
        || async { Ok(()) },
        || async { Ok(()) },
        ready,
    )
    .await
}

pub async fn run_quic_client_relay_with_remote_socket_setup<
    F,
    Before,
    BeforeFuture,
    After,
    AfterFuture,
>(
    config: TlsLikeClientRelayConfig,
    before_remote_socket: Before,
    after_remote_socket: After,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
    Before: FnOnce() -> BeforeFuture,
    BeforeFuture: Future<Output = Result<(), RelayError>>,
    After: FnOnce() -> AfterFuture,
    AfterFuture: Future<Output = Result<(), RelayError>>,
{
    run_quic_client_inner(
        config,
        before_remote_socket,
        after_remote_socket,
        |_| Ok(()),
        ready,
    )
    .await
}

pub async fn run_quic_client_relay_with_socket_protector<F, Protect>(
    config: TlsLikeClientRelayConfig,
    protect: Protect,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
    Protect: FnOnce(&Socket) -> Result<(), RelayError>,
{
    run_quic_client_inner(
        config,
        || async { Ok(()) },
        || async { Ok(()) },
        protect,
        ready,
    )
    .await
}

async fn run_quic_client_inner<F, Before, BeforeFuture, After, AfterFuture, Protect>(
    config: TlsLikeClientRelayConfig,
    before_remote_socket: Before,
    after_remote_socket: After,
    protect: Protect,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
    Before: FnOnce() -> BeforeFuture,
    BeforeFuture: Future<Output = Result<(), RelayError>>,
    After: FnOnce() -> AfterFuture,
    AfterFuture: Future<Output = Result<(), RelayError>>,
    Protect: FnOnce(&Socket) -> Result<(), RelayError>,
{
    if !config.local_listen.ip().is_loopback()
        || config.https.as_ref().is_some_and(|https| !https.is_valid())
    {
        return Err(RelayError::InvalidConfiguration);
    }
    let (client_private, server_public, certificate_sha256) = config.decoded_material()?;
    let local_socket = crate::socket_policy::bind_loopback(config.local_listen)?;
    before_remote_socket().await?;
    let socket_result = carrier_socket(config.server_address, config.socket_mark, protect);
    let release_result = after_remote_socket().await;
    release_result?;
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        socket_result?,
        Arc::new(TokioRuntime),
    )?;
    let connection = timeout(CONNECT_TIMEOUT, async {
        endpoint
            .connect_with(
                client_configuration(certificate_sha256)?,
                config.server_address,
                &server_name(&config),
            )
            .map_err(|_| RelayError::InvalidConfiguration)?
            .await
            .map_err(|_| RelayError::HandshakeFailed)
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)??;
    timeout(HANDSHAKE_TIMEOUT, async {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|_| RelayError::HandshakeFailed)?;
        let mut handshake = initiator_handshake(&client_private, &server_public, PROLOGUE)?;
        let mut request = [0_u8; HANDSHAKE_MAX_LENGTH];
        let length = handshake.write_message(&client_handshake_payload(), &mut request)?;
        write_frame(&mut send, &request[..length]).await?;
        let response = read_frame(&mut recv, HANDSHAKE_MAX_LENGTH).await?;
        handshake.read_message(&response, &mut [0_u8; HANDSHAKE_MAX_LENGTH])?;
        Ok::<_, RelayError>(())
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)??;
    ready();

    let mut local_buffer = [0_u8; MAX_INNER_PACKET_LENGTH];
    let mut local_peer = None;
    loop {
        tokio::select! {
            received = local_socket.recv_from(&mut local_buffer) => {
                let (length, peer) = match received {
                    Ok(received) => received,
                    // Windows reports an earlier ICMP port-unreachable on the next receive.
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => continue,
                    Err(error) => return Err(error.into()),
                };
                if !peer.ip().is_loopback() {
                    continue;
                }
                local_peer = Some(peer);
                send_packet(&connection, &local_buffer[..length])?;
            }
            datagram = connection.read_datagram() => {
                let datagram = datagram.map_err(io::Error::from)?;
                if let (Some(inner), Some(peer)) = (unpadded(&datagram), local_peer) {
                    local_socket.send_to(inner, peer).await?;
                }
            }
        }
    }
}

/// Without an HTTPS name, or with one that resolves to a CDN, no name is sent: QUIC goes
/// straight to the VPS, and pairing a CDN-fronted name with its origin would expose it.
fn server_name(config: &TlsLikeClientRelayConfig) -> String {
    config
        .https
        .as_ref()
        .filter(|https| !https.cdn)
        .map_or_else(
            || config.server_address.ip().to_string(),
            |https| https.server_name.clone(),
        )
}

fn client_configuration(certificate_sha256: [u8; 32]) -> Result<QuicClientConfig, RelayError> {
    let mut tls = tls_client_configuration(certificate_sha256)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = RustlsClientCrypto::try_from(tls).map_err(|_| RelayError::InvalidConfiguration)?;
    let mut configuration = QuicClientConfig::new(Arc::new(crypto));
    configuration.transport_config(Arc::new(transport_configuration()));
    Ok(configuration)
}

fn transport_configuration() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .initial_mtu(INITIAL_MTU)
        .max_idle_timeout(Some(VarInt::from_u32(IDLE_TIMEOUT_MILLISECONDS).into()))
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(MAX_STREAMS));
    transport
}

fn carrier_socket(
    server_address: SocketAddr,
    socket_mark: Option<u32>,
    protect: impl FnOnce(&Socket) -> Result<(), RelayError>,
) -> Result<std::net::UdpSocket, RelayError> {
    let socket = Socket::new(
        Domain::for_address(server_address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    crate::socket_policy::set_mark(&socket, socket_mark)?;
    socket.set_nonblocking(true)?;
    protect(&socket)?;
    let unspecified: std::net::IpAddr = if server_address.is_ipv4() {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    };
    socket.bind(&SocketAddr::new(unspecified, 0).into())?;
    Ok(socket.into())
}

/// A length prefix lets small packets, such as WireGuard handshakes and keepalives, carry
/// random padding so their QUIC packet sizes do not repeat. Packets that do not fit the
/// current path are dropped, as the other UDP relay does.
fn send_packet(connection: &Connection, inner: &[u8]) -> Result<(), RelayError> {
    let Some(room) = connection
        .max_datagram_size()
        .and_then(|maximum| maximum.checked_sub(2 + inner.len()))
    else {
        return Ok(());
    };
    let mut datagram = Vec::with_capacity(2 + inner.len() + MAX_PADDING_LENGTH);
    datagram.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    datagram.extend_from_slice(inner);
    datagram.resize(
        datagram.len() + OsRng.gen_range(0..=room.min(MAX_PADDING_LENGTH)),
        0,
    );
    match connection.send_datagram(datagram.into()) {
        Err(quinn::SendDatagramError::ConnectionLost(error)) => Err(io::Error::from(error).into()),
        Err(quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled) => {
            Err(RelayError::HandshakeFailed)
        }
        _ => Ok(()),
    }
}

fn unpadded(datagram: &[u8]) -> Option<&[u8]> {
    let (length, rest) = datagram.split_first_chunk::<2>()?;
    let length = usize::from(u16::from_be_bytes(*length));
    (length > 0).then(|| rest.get(..length)).flatten()
}

pub async fn run_quic_server_relay(
    config: TcpServerRelayConfig,
    mut tls: rustls::ServerConfig,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
) -> Result<(), RelayError> {
    if config.listen.ip().is_loopback() || !config.wireguard_backend.ip().is_loopback() {
        return Err(RelayError::InvalidConfiguration);
    }
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let crypto = RustlsServerCrypto::try_from(Arc::new(tls))
        .map_err(|_| RelayError::InvalidConfiguration)?;
    let mut server = QuicServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(transport_configuration()));
    let socket = Socket::new(
        Domain::for_address(config.listen),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if config.listen.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.bind(&config.listen.into())?;
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server),
        socket.into(),
        Arc::new(TokioRuntime),
    )?;
    let replay_cache = Arc::new(Mutex::new(HandshakeReplayCache::default()));
    let mut probe_limiter = ProbeLimiter::default();
    let global_connections = Arc::new(Semaphore::new(MAX_SERVER_CONNECTIONS));
    let client_connections = ClientConnectionRegistry::default();
    let mut activity_cleanup = tokio::time::interval(Duration::from_secs(30));
    activity_cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => incoming,
            _ = activity_cleanup.tick() => {
                activity.prune(CONNECTION_IDLE_TIMEOUT);
                continue;
            }
        };
        let Some(incoming) = incoming else {
            return Err(RelayError::InvalidConfiguration);
        };
        // Over budget looks like loss, not like a server that refuses.
        if !probe_limiter.allow(incoming.remote_address().ip()) {
            incoming.ignore();
            continue;
        }
        let Ok(global_permit) = global_connections.clone().try_acquire_owned() else {
            incoming.ignore();
            continue;
        };
        let connection_config = config.clone();
        let connection_authorized = authorized.clone();
        let connection_activity = activity.clone();
        let connection_replay = replay_cache.clone();
        let connection_clients = client_connections.clone();
        tokio::spawn(async move {
            let _global_permit = global_permit;
            let _ = serve_connection(
                incoming,
                connection_config,
                connection_authorized,
                connection_activity,
                connection_replay,
                connection_clients,
            )
            .await;
        });
    }
}

async fn serve_connection(
    incoming: Incoming,
    config: TcpServerRelayConfig,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
    replay_cache: Arc<Mutex<HandshakeReplayCache>>,
    client_connections: ClientConnectionRegistry,
) -> Result<(), RelayError> {
    let connection = timeout(HANDSHAKE_TIMEOUT, async {
        incoming
            .accept()
            .map_err(|_| RelayError::HandshakeFailed)?
            .await
            .map_err(|_| RelayError::HandshakeFailed)
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)??;
    let accepted = timeout(HANDSHAKE_TIMEOUT, async {
        // Every HTTP/3 server opens its control stream first, and it must stay open.
        let mut control = connection
            .open_uni()
            .await
            .map_err(|_| RelayError::HandshakeFailed)?;
        control
            .write_all(CONTROL_STREAM)
            .await
            .map_err(|_| RelayError::HandshakeFailed)?;
        let (client_static, response, send) =
            authenticate(&connection, &config, &authorized, &replay_cache).await?;
        Ok::<_, RelayError>((control, client_static, response, send))
    })
    .await;
    let Ok(Ok((_control, client_static, response, mut send))) = accepted else {
        connection.close(VarInt::from_u32(H3_NO_ERROR), b"");
        return Ok(());
    };
    let Some(_client_permit) = client_connections.acquire(client_static) else {
        connection.close(VarInt::from_u32(H3_NO_ERROR), b"");
        return Ok(());
    };
    write_frame(&mut send, &response).await?;
    let _ = send.finish();
    let result =
        relay_server_datagrams(&connection, &config, &authorized, &activity, client_static).await;
    connection.close(VarInt::from_u32(H3_NO_ERROR), b"");
    result
}

/// Requests that are not an authorized Noise exchange get the answer a web server gives an
/// unknown path, on the same connection, until the handshake deadline closes it.
async fn authenticate(
    connection: &Connection,
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
) -> Result<([u8; 32], Vec<u8>, SendStream), RelayError> {
    loop {
        let (mut send, mut recv): (SendStream, RecvStream) = connection
            .accept_bi()
            .await
            .map_err(|_| RelayError::HandshakeFailed)?;
        if let Ok(request) = read_frame(&mut recv, HANDSHAKE_MAX_LENGTH).await
            && let Some((_, client_static, response)) =
                accept_handshake_message(&request, config, authorized, replay_cache, PROLOGUE)?
        {
            return Ok((client_static, response, send));
        }
        let _ = send.write_all(NOT_FOUND).await;
        let _ = send.finish();
    }
}

async fn relay_server_datagrams(
    connection: &Connection,
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    activity: &ActiveTransportRegistry,
    client_static: [u8; 32],
) -> Result<(), RelayError> {
    let connection_activity = activity.connection(client_static, TransportKind::Quic);
    let backend = UdpSocket::bind("127.0.0.1:0").await?;
    backend.connect(config.wireguard_backend).await?;
    let mut backend_buffer = [0_u8; MAX_INNER_PACKET_LENGTH];
    let mut revocation = tokio::time::interval(Duration::from_secs(10));
    revocation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            datagram = connection.read_datagram() => {
                let datagram = datagram.map_err(io::Error::from)?;
                if let Some(inner) = unpadded(&datagram) {
                    connection_activity.record();
                    backend.send(inner).await?;
                }
            }
            received = backend.recv(&mut backend_buffer) => {
                send_packet(connection, &backend_buffer[..received?])?;
            }
            _ = revocation.tick() => {
                if !authorized.contains(&client_static) {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_is_bounded_by_the_length_prefix() {
        assert_eq!(unpadded(&[0, 3, 1, 2, 3, 0, 0]), Some(&[1, 2, 3][..]));
        assert_eq!(unpadded(&[0, 3, 1, 2]), None);
        assert_eq!(unpadded(&[0, 0, 0]), None);
        assert_eq!(unpadded(&[0]), None);
    }

    #[test]
    fn a_cdn_name_is_never_sent_to_the_origin() {
        let mut config = crate::quic_client_relay_config_unmarked(
            "203.0.113.7:443".parse().unwrap(),
            &STANDARD.encode([1_u8; 32]),
            &STANDARD.encode([2_u8; 32]),
            &STANDARD.encode([3_u8; 32]),
        )
        .unwrap();
        assert_eq!(config.local_listen.port(), crate::QUIC_CLIENT_RELAY_PORT);
        assert_eq!(server_name(&config), "203.0.113.7");
        let https = sirinvpn_protocol::HttpsTransport {
            server_name: "vpn.example.org".to_owned(),
            path: "/connect".to_owned(),
            cdn: false,
        };
        config.https = Some(https.clone());
        assert_eq!(server_name(&config), "vpn.example.org");
        config.https = Some(sirinvpn_protocol::HttpsTransport { cdn: true, ..https });
        assert_eq!(server_name(&config), "203.0.113.7");
    }
}
