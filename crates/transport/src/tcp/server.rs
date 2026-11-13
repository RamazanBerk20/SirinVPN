use super::*;

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
pub(super) struct TlsServerMode {
    pub(super) acceptor: TlsAcceptor,
    pub(super) https: Option<sirinvpn_protocol::HttpsTransport>,
    pub(super) discovery_only: bool,
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
    let behind_cdn = tls_acceptor
        .as_ref()
        .and_then(|mode| mode.https.as_ref())
        .is_some_and(|https| https.cdn);
    let global_connections = Arc::new(Semaphore::new(MAX_SERVER_CONNECTIONS));
    let client_connections = ClientConnectionRegistry::default();
    let mut activity_cleanup = tokio::time::interval(Duration::from_secs(30));
    activity_cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = activity_cleanup.tick() => {
                activity.prune(CONNECTION_IDLE_TIMEOUT);
                continue;
            }
        };
        // Descriptor exhaustion or an aborted connection is transient; it must not stop the server.
        let (stream, source) = match accepted {
            Ok(accepted) => accepted,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let mut limiter = probe_limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !(if behind_cdn {
            limiter.allow_global()
        } else {
            limiter.allow(source.ip())
        }) {
            continue;
        }
        drop(limiter);
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

pub(super) async fn handle_server_connection<S>(
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
    let permit = client_connections.acquire(client_static);
    write_frame(&mut stream, &response).await?;
    relay_server_session(
        stream,
        config,
        authorized,
        activity,
        noise,
        client_static,
        outer_protocol,
        permit,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_server_session<S>(
    stream: S,
    config: TcpServerRelayConfig,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
    noise: StatelessTransportState,
    client_static: [u8; 32],
    outer_protocol: TcpOuterProtocol,
    (permit, mut eviction): (ClientConnectionPermit, Eviction),
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Recorded once proven, so a replayed handshake cannot change what the device uses.
    let mut connection_activity = None;

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
            connection_activity
                .get_or_insert_with(|| {
                    permit.prove();
                    activity.connection(client_static, outer_protocol.transport())
                })
                .record();
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
        () = eviction.evicted() => Ok(()),
    }
}
