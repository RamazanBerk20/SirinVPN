use super::*;

#[test]
fn replay_window_accepts_reordering_once_and_rejects_old_packets() {
    let mut replay = ReplayWindow::default();
    for sequence in [4, 2, 3, 2, 132, 4] {
        if replay.accepts(sequence) {
            replay.commit(sequence);
        }
    }
    assert!(!replay.accepts(2));
    assert!(!replay.accepts(3));
    assert!(!replay.accepts(4));
    assert!(replay.accepts(131));
}

#[test]
fn connection_activity_is_removed_without_erasing_a_newer_connection() {
    let registry = ActiveTransportRegistry::default();
    let peer = [7_u8; 32];
    let first = registry.connection(peer, TransportKind::TcpFallback);
    assert_eq!(
        registry.recent_transport(&peer, Duration::from_secs(1)),
        Some(TransportKind::TcpFallback)
    );

    let second = registry.connection(peer, TransportKind::TlsLike);
    assert_eq!(
        registry.recent_transport(&peer, Duration::from_secs(1)),
        Some(TransportKind::TlsLike)
    );
    drop(first);
    assert_eq!(
        registry.recent_transport(&peer, Duration::from_secs(1)),
        Some(TransportKind::TlsLike)
    );
    drop(second);
    assert_eq!(
        registry.recent_transport(&peer, Duration::from_secs(1)),
        None
    );
}

#[tokio::test]
async fn authorized_noise_relay_round_trips_udp_without_a_banner() {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let public = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_address = public.local_addr().unwrap();
    drop(public);

    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let server_task = tokio::spawn(run_server_relay(
        ServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), public_address.port()),
            wireguard_backend: backend_address,
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        authorized,
        ActiveTransportRegistry::default(),
    ));

    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_address = local.local_addr().unwrap();
    drop(local);
    let ready = Arc::new(AtomicBool::new(false));
    let before_remote = Arc::new(AtomicBool::new(false));
    let after_remote = Arc::new(AtomicBool::new(false));
    let ready_clone = ready.clone();
    let before_clone = before_remote.clone();
    let after_clone = after_remote.clone();
    let client_task = tokio::spawn(run_client_relay_with_remote_socket_setup(
        ClientRelayConfig {
            local_listen: local_address,
            server_address: public_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(client.private),
            server_public_key: STANDARD.encode(server.public),
        },
        move || async move {
            assert!(std::net::UdpSocket::bind(local_address).is_err());
            before_clone.store(true, Ordering::Release);
            Ok(())
        },
        move || async move {
            after_clone.store(true, Ordering::Release);
            Ok(())
        },
        move || ready_clone.store(true, Ordering::Release),
    ));

    timeout(Duration::from_secs(5), async {
        while !ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(before_remote.load(Ordering::Acquire));
    assert!(after_remote.load(Ordering::Acquire));

    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    wireguard
        .send_to(b"wireguard packet", local_address)
        .await
        .unwrap();
    let mut backend_buffer = [0_u8; 128];
    let (length, backend_peer) = timeout(
        Duration::from_secs(2),
        backend.recv_from(&mut backend_buffer),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&backend_buffer[..length], b"wireguard packet");
    backend
        .send_to(b"wireguard response", backend_peer)
        .await
        .unwrap();
    let mut response = [0_u8; 128];
    let (length, _) = timeout(Duration::from_secs(2), wireguard.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..length], b"wireguard response");

    client_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn malformed_and_unauthorized_probes_receive_no_response() {
    let server = keypair();
    let unauthorized_client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_address = public.local_addr().unwrap();
    drop(public);
    let server_task = tokio::spawn(run_server_relay(
        ServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), public_address.port()),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        AuthorizedPeers::default(),
        ActiveTransportRegistry::default(),
    ));
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe
        .send_to(&[7_u8; HANDSHAKE_MIN_LENGTH], public_address)
        .await
        .unwrap();
    let mut response = [0_u8; 512];
    assert!(
        timeout(Duration::from_millis(250), probe.recv_from(&mut response))
            .await
            .is_err()
    );

    let client_private = <[u8; 32]>::try_from(unauthorized_client.private.as_slice()).unwrap();
    let server_public = <[u8; 32]>::try_from(server.public.as_slice()).unwrap();
    let mut handshake = initiator_handshake(&client_private, &server_public).unwrap();
    let mut request = [0_u8; HANDSHAKE_MAX_LENGTH];
    let request_length = handshake.write_message(&[3_u8; 48], &mut request).unwrap();
    probe
        .send_to(&request[..request_length], public_address)
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(250), probe.recv_from(&mut response))
            .await
            .is_err()
    );
    server_task.abort();
}

#[tokio::test]
async fn an_authenticated_handshake_datagram_is_accepted_only_once() {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_address = public.local_addr().unwrap();
    drop(public);
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let server_task = tokio::spawn(run_server_relay(
        ServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), public_address.port()),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        authorized,
        ActiveTransportRegistry::default(),
    ));
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_private = <[u8; 32]>::try_from(client.private.as_slice()).unwrap();
    let server_public = <[u8; 32]>::try_from(server.public.as_slice()).unwrap();
    let mut handshake = initiator_handshake(&client_private, &server_public).unwrap();
    let mut request = [0_u8; HANDSHAKE_MAX_LENGTH];
    let request_length = handshake.write_message(&[5_u8; 48], &mut request).unwrap();
    let mut response = [0_u8; HANDSHAKE_MAX_LENGTH];

    probe
        .send_to(&request[..request_length], public_address)
        .await
        .unwrap();
    timeout(Duration::from_secs(1), probe.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    probe
        .send_to(&request[..request_length], public_address)
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(250), probe.recv_from(&mut response))
            .await
            .is_err()
    );
    server_task.abort();
}
