use super::*;

#[tokio::test]
async fn authorized_tcp_relay_round_trips_udp_datagrams() {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_port = unused_tcp_port().await;
    let public_address = SocketAddr::new("127.0.0.1".parse().unwrap(), public_port);
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let activity = ActiveTransportRegistry::default();
    let server_task = tokio::spawn(run_tcp_server_relay(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), public_port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        authorized,
        activity.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_address = local.local_addr().unwrap();
    drop(local);
    let ready = Arc::new(AtomicBool::new(false));
    let before_remote = Arc::new(AtomicBool::new(false));
    let after_remote = Arc::new(AtomicBool::new(false));
    let ready_clone = ready.clone();
    let before_clone = before_remote.clone();
    let after_clone = after_remote.clone();
    let client_public = <[u8; 32]>::try_from(client.public.as_slice()).unwrap();
    let client_task = tokio::spawn(run_tcp_client_relay_with_remote_socket_setup(
        TcpClientRelayConfig {
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
        .send_to(b"tcp packet", local_address)
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
    assert_eq!(&backend_buffer[..length], b"tcp packet");
    backend
        .send_to(b"tcp response", backend_peer)
        .await
        .unwrap();
    let mut response = [0_u8; 128];
    let (length, _) = timeout(Duration::from_secs(2), wireguard.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..length], b"tcp response");
    assert_eq!(
        activity.recent_transport(&client_public, Duration::from_secs(1)),
        Some(TransportKind::TcpFallback)
    );

    client_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn tls_client_releases_remote_socket_setup_after_connect_failure() {
    let server = keypair();
    let client = keypair();
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_address = local.local_addr().unwrap();
    drop(local);
    let closed_address = SocketAddr::new("127.0.0.1".parse().unwrap(), unused_tcp_port().await);
    let before_remote = Arc::new(AtomicBool::new(false));
    let after_remote = Arc::new(AtomicBool::new(false));
    let before_clone = before_remote.clone();
    let after_clone = after_remote.clone();

    let result = run_tls_like_client_relay_with_remote_socket_setup(
        TlsLikeClientRelayConfig {
            local_listen: local_address,
            server_address: closed_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(client.private),
            server_public_key: STANDARD.encode(server.public),
            https: None,
            server_certificate_sha256: STANDARD.encode([7_u8; 32]),
        },
        move || async move {
            before_clone.store(true, Ordering::Release);
            Ok(())
        },
        move || async move {
            after_clone.store(true, Ordering::Release);
            Ok(())
        },
        || panic!("an unavailable endpoint must not become ready"),
    )
    .await;

    assert!(result.is_err());
    assert!(before_remote.load(Ordering::Acquire));
    assert!(after_remote.load(Ordering::Acquire));
}

#[tokio::test]
async fn pinned_tls_and_legacy_tcp_share_one_authenticated_listener() {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_port = unused_tcp_port().await;
    let public_address = SocketAddr::new("127.0.0.1".parse().unwrap(), public_port);
    let authorized = AuthorizedPeers::default();
    let client_public = <[u8; 32]>::try_from(client.public.as_slice()).unwrap();
    authorized.replace([client_public]);
    let activity = ActiveTransportRegistry::default();
    let (acceptor, fingerprint) = tls_acceptor();
    let server_task = tokio::spawn(run_tcp_server_relay_with_tls(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), public_port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        acceptor,
        authorized,
        activity.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let tls_local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tls_local_address = tls_local.local_addr().unwrap();
    drop(tls_local);
    let tls_ready = Arc::new(AtomicBool::new(false));
    let tls_before_remote = Arc::new(AtomicBool::new(false));
    let tls_after_remote = Arc::new(AtomicBool::new(false));
    let tls_ready_clone = tls_ready.clone();
    let tls_before_clone = tls_before_remote.clone();
    let tls_after_clone = tls_after_remote.clone();
    let tls_task = tokio::spawn(run_tls_like_client_relay_with_remote_socket_setup(
        TlsLikeClientRelayConfig {
            local_listen: tls_local_address,
            server_address: public_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(&client.private),
            server_public_key: STANDARD.encode(&server.public),
            https: None,
            server_certificate_sha256: fingerprint.clone(),
        },
        move || async move {
            assert!(std::net::UdpSocket::bind(tls_local_address).is_err());
            tls_before_clone.store(true, Ordering::Release);
            Ok(())
        },
        move || async move {
            tls_after_clone.store(true, Ordering::Release);
            Ok(())
        },
        move || tls_ready_clone.store(true, Ordering::Release),
    ));
    timeout(Duration::from_secs(5), async {
        while !tls_ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(tls_before_remote.load(Ordering::Acquire));
    assert!(tls_after_remote.load(Ordering::Acquire));

    let tls_wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    tls_wireguard
        .send_to(b"tls packet", tls_local_address)
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
    assert_eq!(&backend_buffer[..length], b"tls packet");
    backend
        .send_to(b"tls response", backend_peer)
        .await
        .unwrap();
    let mut response = [0_u8; 128];
    let (length, _) = timeout(
        Duration::from_secs(2),
        tls_wireguard.recv_from(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&response[..length], b"tls response");
    assert_eq!(
        activity.recent_transport(&client_public, Duration::from_secs(1)),
        Some(TransportKind::TlsLike)
    );
    tls_task.abort();
    let _ = tls_task.await;
    timeout(Duration::from_secs(2), async {
        while activity
            .recent_transport(&client_public, Duration::from_secs(1))
            .is_some()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let invalid_local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let invalid_local_address = invalid_local.local_addr().unwrap();
    drop(invalid_local);
    let invalid_result = timeout(
        Duration::from_secs(5),
        run_tls_like_client_relay(
            TlsLikeClientRelayConfig {
                local_listen: invalid_local_address,
                server_address: public_address,
                socket_mark: None,
                client_private_key: STANDARD.encode(&client.private),
                server_public_key: STANDARD.encode(&server.public),
                https: None,
                server_certificate_sha256: STANDARD.encode([99_u8; 32]),
            },
            || panic!("a mismatched certificate pin must not become ready"),
        ),
    )
    .await
    .unwrap();
    assert!(matches!(invalid_result, Err(RelayError::HandshakeFailed)));

    let tcp_local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp_local_address = tcp_local.local_addr().unwrap();
    drop(tcp_local);
    let tcp_ready = Arc::new(AtomicBool::new(false));
    let tcp_ready_clone = tcp_ready.clone();
    let tcp_task = tokio::spawn(run_tcp_client_relay(
        TcpClientRelayConfig {
            local_listen: tcp_local_address,
            server_address: public_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(&client.private),
            server_public_key: STANDARD.encode(&server.public),
        },
        move || tcp_ready_clone.store(true, Ordering::Release),
    ));
    timeout(Duration::from_secs(5), async {
        while !tcp_ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let tcp_wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    tcp_wireguard
        .send_to(b"legacy packet", tcp_local_address)
        .await
        .unwrap();
    let (length, backend_peer) = timeout(
        Duration::from_secs(2),
        backend.recv_from(&mut backend_buffer),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&backend_buffer[..length], b"legacy packet");
    backend
        .send_to(b"legacy response", backend_peer)
        .await
        .unwrap();
    let (length, _) = timeout(
        Duration::from_secs(2),
        tcp_wireguard.recv_from(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&response[..length], b"legacy response");
    assert_eq!(
        activity.recent_transport(&client_public, Duration::from_secs(1)),
        Some(TransportKind::TcpFallback)
    );

    tcp_task.abort();
    let _ = tcp_task.await;
    timeout(Duration::from_secs(2), async {
        while activity
            .recent_transport(&client_public, Duration::from_secs(1))
            .is_some()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    server_task.abort();
}

#[tokio::test]
async fn client_relay_preserves_a_fragmented_inbound_frame_during_outbound_traffic() {
    let server = keypair();
    let client = keypair();
    let server_private = Zeroizing::new(<[u8; 32]>::try_from(server.private.as_slice()).unwrap());
    let server_public = STANDARD.encode(&server.public);
    let client_public = <[u8; 32]>::try_from(client.public.as_slice()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_address = listener.local_addr().unwrap();
    let (fragment_sent, fragment_received) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let authorized = AuthorizedPeers::default();
        authorized.replace([client_public]);
        let replay = Mutex::new(HandshakeReplayCache::default());
        let config = TcpServerRelayConfig {
            listen: "0.0.0.0:443".parse().unwrap(),
            wireguard_backend: "127.0.0.1:51820".parse().unwrap(),
            server_private_key: server_private,
        };
        let (noise, _, response) = accept_server_handshake(
            &mut stream,
            &config,
            &authorized,
            &replay,
            TCP_NOISE_PROLOGUE,
        )
        .await
        .unwrap()
        .unwrap();
        write_frame(&mut stream, &response).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();

        let first = read_frame(&mut reader, MAX_FRAME_LENGTH).await.unwrap();
        assert_eq!(decrypt_record(&noise, 0, &first).unwrap(), b"initial");

        let response = encode_record(&noise, 0, b"fragmented response").unwrap();
        let split = (1..response.len().saturating_sub(1))
            .find(|offset| {
                u16::from_be_bytes([response[*offset], response[*offset + 1]]) as usize
                    > MAX_FRAME_LENGTH
            })
            .unwrap_or(1);
        writer.write_u16(response.len() as u16).await.unwrap();
        writer.write_all(&response[..split]).await.unwrap();
        writer.flush().await.unwrap();
        fragment_sent.send(()).unwrap();

        let second = read_frame(&mut reader, MAX_FRAME_LENGTH).await.unwrap();
        assert_eq!(decrypt_record(&noise, 1, &second).unwrap(), b"competing");
        writer.write_all(&response[split..]).await.unwrap();
        writer.flush().await.unwrap();
    });

    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_address = local.local_addr().unwrap();
    drop(local);
    let ready = Arc::new(AtomicBool::new(false));
    let ready_clone = ready.clone();
    let client_task = tokio::spawn(run_tcp_client_relay(
        TcpClientRelayConfig {
            local_listen: local_address,
            server_address: public_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(client.private),
            server_public_key: server_public,
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

    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    wireguard.send_to(b"initial", local_address).await.unwrap();
    fragment_received.await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    wireguard
        .send_to(b"competing", local_address)
        .await
        .unwrap();
    let mut received = [0_u8; 128];
    let (length, _) = timeout(Duration::from_secs(2), wireguard.recv_from(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..length], b"fragmented response");

    server_task.await.unwrap();
    client_task.abort();
}
