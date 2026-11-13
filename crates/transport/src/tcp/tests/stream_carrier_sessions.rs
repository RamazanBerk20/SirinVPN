use super::*;

struct TcpServer {
    server: snow::Keypair,
    client: snow::Keypair,
    backend: UdpSocket,
    address: SocketAddr,
    task: tokio::task::JoinHandle<Result<(), RelayError>>,
}

async fn tcp_server() -> TcpServer {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = unused_tcp_port().await;
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let task = tokio::spawn(run_tcp_server_relay(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        authorized,
        ActiveTransportRegistry::default(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    TcpServer {
        server,
        client,
        backend,
        address: SocketAddr::new("127.0.0.1".parse().unwrap(), port),
        task,
    }
}

async fn unused_udp_address() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Starts a client relay and waits until it is authenticated.
async fn client_relay(
    server: &TcpServer,
    local: SocketAddr,
    wireguard: Option<SocketAddr>,
) -> tokio::task::JoinHandle<Result<(), RelayError>> {
    let config = TcpClientRelayConfig {
        local_listen: local,
        server_address: server.address,
        socket_mark: None,
        client_private_key: STANDARD.encode(&server.client.private),
        server_public_key: STANDARD.encode(&server.server.public),
    };
    let ready = Arc::new(AtomicBool::new(false));
    let ready_clone = ready.clone();
    let mark = move || ready_clone.store(true, Ordering::Release);
    let task = match wireguard {
        Some(wireguard) => tokio::spawn(run_tcp_client_relay_pinned(
            config,
            wireguard,
            |_| Ok(()),
            mark,
        )),
        None => tokio::spawn(run_tcp_client_relay(config, mark)),
    };
    timeout(Duration::from_secs(5), async {
        while !ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    task
}

/// Before, `encode_record` failed on an empty datagram and ended the whole relay, so any
/// local user could restart the carrier at will.
#[tokio::test]
async fn an_empty_local_datagram_does_not_end_a_stream_carrier() {
    let server = tcp_server().await;
    let local = unused_udp_address().await;
    let relay = client_relay(&server, local, None).await;
    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    wireguard.send_to(b"", local).await.unwrap();
    wireguard.send_to(b"first", local).await.unwrap();
    let mut buffer = [0_u8; 128];
    let (length, peer) = timeout(
        Duration::from_secs(2),
        server.backend.recv_from(&mut buffer),
    )
    .await
    .unwrap()
    .unwrap();
    // The record after the dropped datagram still used nonce 0, or the server would close.
    assert_eq!(&buffer[..length], b"first");
    wireguard.send_to(b"", local).await.unwrap();
    wireguard.send_to(b"second", local).await.unwrap();
    let (length, _) = timeout(
        Duration::from_secs(2),
        server.backend.recv_from(&mut buffer),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buffer[..length], b"second");
    server.backend.send_to(b"reply", peer).await.unwrap();
    let (length, _) = timeout(Duration::from_secs(2), wireguard.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"reply");
    assert!(!relay.is_finished());
    relay.abort();
    server.task.abort();
}

#[tokio::test]
async fn a_pinned_stream_carrier_ignores_other_local_senders() {
    let server = tcp_server().await;
    let local = unused_udp_address().await;
    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay = client_relay(&server, local, Some(wireguard.local_addr().unwrap())).await;
    let mut buffer = [0_u8; 128];
    attacker.send_to(b"injected", local).await.unwrap();
    wireguard.send_to(b"wireguard", local).await.unwrap();
    let (length, peer) = timeout(
        Duration::from_secs(2),
        server.backend.recv_from(&mut buffer),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buffer[..length], b"wireguard");
    attacker.send_to(b"injected", local).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    server.backend.send_to(b"reply", peer).await.unwrap();
    let (length, _) = timeout(Duration::from_secs(2), wireguard.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"reply");
    assert!(
        timeout(Duration::from_millis(300), attacker.recv_from(&mut buffer))
            .await
            .is_err()
    );
    // Only one packet ever reached the server.
    assert!(
        timeout(
            Duration::from_millis(100),
            server.backend.recv_from(&mut buffer)
        )
        .await
        .is_err()
    );
    relay.abort();
    server.task.abort();
}

/// As on QUIC, a device's newest stream connection wins: stale connections left by roaming
/// must not keep it out of TCP, TLS and HTTPS until the idle timeout. A connection takes a
/// slot once its first record proved the device key.
#[tokio::test]
async fn a_new_stream_connection_from_a_device_replaces_its_oldest() {
    let server = tcp_server().await;
    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buffer = [0_u8; 64];
    let mut relays = Vec::new();
    for _ in 0..=MAX_CONNECTIONS_PER_CLIENT {
        let local = unused_udp_address().await;
        relays.push((local, client_relay(&server, local, None).await));
        wireguard.send_to(b"proof", local).await.unwrap();
        timeout(
            Duration::from_secs(2),
            server.backend.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
    }
    // The first relay's connection was ended for the newest one.
    assert!(
        timeout(Duration::from_secs(2), &mut relays[0].1)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    // The newest one is served.
    let (newest, _) = relays[MAX_CONNECTIONS_PER_CLIENT];
    wireguard.send_to(b"newest", newest).await.unwrap();
    let (length, _) = timeout(
        Duration::from_secs(2),
        server.backend.recv_from(&mut buffer),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buffer[..length], b"newest");
    for (_, relay) in &relays[1..] {
        assert!(!relay.is_finished());
        relay.abort();
    }
    server.task.abort();
}

#[tokio::test]
async fn evicting_a_connection_wakes_only_the_oldest_permit() {
    let registry = ClientConnectionRegistry::default();
    let device = [3_u8; 32];
    let mut permits: Vec<_> = (0..MAX_CONNECTIONS_PER_CLIENT)
        .map(|_| registry.acquire(device))
        .collect();
    for (permit, _) in &permits {
        permit.prove();
    }
    let (other, mut other_eviction) = registry.acquire([4_u8; 32]);
    other.prove();
    // Connections that have not proven the device key end nothing, however many.
    let unproven: Vec<_> = (0..=MAX_CONNECTIONS_PER_CLIENT)
        .map(|_| registry.acquire(device))
        .collect();
    for (_, eviction) in &mut permits {
        assert!(
            timeout(Duration::from_millis(20), eviction.evicted())
                .await
                .is_err()
        );
    }
    let newest = registry.acquire(device);
    newest.0.prove();
    timeout(Duration::from_millis(100), permits[0].1.evicted())
        .await
        .unwrap();
    for (_, eviction) in &mut permits[1..] {
        assert!(
            timeout(Duration::from_millis(20), eviction.evicted())
                .await
                .is_err()
        );
    }
    assert!(
        timeout(Duration::from_millis(20), other_eviction.evicted())
            .await
            .is_err()
    );
    drop(permits);
    drop(unproven);
    drop(newest);
    assert_eq!(registry.0.lock().unwrap().devices.len(), 1);
}

struct DirectServer {
    server: snow::Keypair,
    client: snow::Keypair,
    backend: UdpSocket,
    config: TcpServerRelayConfig,
    authorized: AuthorizedPeers,
    clients: ClientConnectionRegistry,
}

impl DirectServer {
    async fn new() -> Self {
        let server = keypair();
        let client = keypair();
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let authorized = AuthorizedPeers::default();
        authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
        let config = TcpServerRelayConfig {
            listen: "0.0.0.0:0".parse().unwrap(),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        };
        Self {
            server,
            client,
            backend,
            config,
            authorized,
            clients: ClientConnectionRegistry::default(),
        }
    }

    /// Serves one stream with `replay_cache`, sharing the device registry across calls.
    fn serve(
        &self,
        replay_cache: &Arc<Mutex<HandshakeReplayCache>>,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<(), RelayError>>,
    ) {
        let (client, server) = tokio::io::duplex(8_192);
        let task = tokio::spawn(handle_server_connection(
            server,
            self.config.clone(),
            self.authorized.clone(),
            ActiveTransportRegistry::default(),
            replay_cache.clone(),
            self.clients.clone(),
            TcpOuterProtocol::Raw,
        ));
        (client, task)
    }

    fn initiator(&self) -> HandshakeState {
        initiator_handshake(
            &<[u8; 32]>::try_from(self.client.private.as_slice()).unwrap(),
            &<[u8; 32]>::try_from(self.server.public.as_slice()).unwrap(),
            TCP_NOISE_PROLOGUE,
        )
        .unwrap()
    }
}

/// A captured initiator message that the replay cache no longer remembers (180 s later for
/// an unmarked or future-stamped one, or after a restart) still completes a handshake. It
/// must not end the device's live connection: it cannot send a record under the new keys.
async fn replays_do_not_end_a_live_stream_connection(payload: Vec<u8>) {
    let server = DirectServer::new().await;
    let (mut live, live_task) = server.serve(&Arc::default());
    let mut handshake = server.initiator();
    let mut message = [0_u8; HANDSHAKE_MAX_LENGTH];
    let length = handshake.write_message(&payload, &mut message).unwrap();
    let captured = message[..length].to_vec();
    write_frame(&mut live, &captured).await.unwrap();
    let response = read_frame(&mut live, HANDSHAKE_MAX_LENGTH).await.unwrap();
    handshake
        .read_message(&response, &mut [0_u8; HANDSHAKE_MAX_LENGTH])
        .unwrap();
    let noise = handshake.into_stateless_transport_mode().unwrap();
    let mut nonce = 0;
    let mut buffer = [0_u8; 64];
    let mut send = async |live: &mut tokio::io::DuplexStream, body: &[u8]| {
        write_frame(live, &encode_record(&noise, nonce, body).unwrap())
            .await
            .unwrap();
        nonce += 1;
        let (length, _) = timeout(
            Duration::from_secs(2),
            server.backend.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..length], body);
    };
    send(&mut live, b"proof").await;

    let mut replays = Vec::new();
    for _ in 0..=MAX_CONNECTIONS_PER_CLIENT {
        let (mut replay, task) = server.serve(&Arc::default());
        write_frame(&mut replay, &captured).await.unwrap();
        // The server answers, but only the device could read the answer.
        read_frame(&mut replay, HANDSHAKE_MAX_LENGTH).await.unwrap();
        replays.push((replay, task));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!live_task.is_finished());
    send(&mut live, b"still live").await;
    for (_, task) in &replays {
        assert!(!task.is_finished());
        task.abort();
    }
    live_task.abort();
}

#[tokio::test]
async fn a_replayed_handshake_does_not_end_a_live_stream_connection() {
    replays_do_not_end_a_live_stream_connection(client_handshake_payload()).await;
}

#[tokio::test]
async fn a_replayed_unmarked_handshake_does_not_end_a_live_stream_connection() {
    replays_do_not_end_a_live_stream_connection(random_bytes(64)).await;
}
