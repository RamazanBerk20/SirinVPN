use super::*;

fn configuration(
    address: SocketAddr,
    client: &snow::Keypair,
    server: &snow::Keypair,
) -> EndpointDiscoveryConfig {
    EndpointDiscoveryConfig {
        server_address: address,
        server_name: TLS_LIKE_SERVER_NAME.into(),
        client_private_key: Zeroizing::new(client.private.as_slice().try_into().unwrap()),
        server_public_key: server.public.as_slice().try_into().unwrap(),
        socket_mark: None,
    }
}

#[tokio::test]
async fn endpoint_discovery_authenticates_noise_independently_from_replaceable_tls_certificates() {
    let server = keypair();
    let client = keypair();
    let stranger = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = unused_tcp_port().await;
    let address = SocketAddr::new("::1".parse().unwrap(), port);
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    authorized
        .publish_endpoint_checkpoint(Some(b"signed checkpoint fixture".to_vec()))
        .unwrap();
    let (acceptor, fingerprint) = tls_acceptor();
    let task = tokio::spawn(run_endpoint_discovery_server(
        TcpServerRelayConfig {
            listen: SocketAddr::new("::".parse().unwrap(), port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(server.private.as_slice().try_into().unwrap()),
        },
        acceptor,
        authorized.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        fetch_endpoint_checkpoint(configuration(address, &client, &server))
            .await
            .unwrap(),
        Some(b"signed checkpoint fixture".to_vec())
    );
    assert!(
        fetch_endpoint_checkpoint(configuration(address, &stranger, &server))
            .await
            .is_err()
    );
    assert!(
        fetch_endpoint_checkpoint(configuration(address, &client, &stranger))
            .await
            .is_err()
    );
    // A VPN data connection continues to require the exact enrolled TLS pin.
    let connector = TlsConnector::from(Arc::new(tls_client_configuration([0_u8; 32]).unwrap()));
    assert!(
        connector
            .connect(
                ServerName::try_from(TLS_LIKE_SERVER_NAME.to_owned()).unwrap(),
                TcpStream::connect(address).await.unwrap()
            )
            .await
            .is_err()
    );
    assert_ne!(fingerprint, STANDARD.encode([0_u8; 32]));
    authorized.replace(std::iter::empty());
    assert!(
        fetch_endpoint_checkpoint(configuration(address, &client, &server))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(80), backend.recv(&mut [0_u8; 128]))
            .await
            .is_err()
    );
    task.abort();
}

#[tokio::test]
async fn discovery_replays_get_only_cover_and_the_old_listener_never_relays_vpn_datagrams() {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = unused_tcp_port().await;
    let address = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let (acceptor, _) = tls_acceptor();
    let task = tokio::spawn(run_endpoint_discovery_server(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(server.private.as_slice().try_into().unwrap()),
        },
        acceptor,
        authorized,
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut handshake = initiator_handshake(
        &client.private.as_slice().try_into().unwrap(),
        &server.public.as_slice().try_into().unwrap(),
        b"SirinVPN signed endpoint discovery v1",
    )
    .unwrap();
    let mut message = [0_u8; 512];
    let length = handshake.write_message(&[0_u8; 96], &mut message).unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {TLS_LIKE_SERVER_NAME}\r\nAuthorization: Bearer {}\r\n\r\n",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&message[..length])
    );
    for replay in [false, true] {
        let connector =
            TlsConnector::from(Arc::new(tls::noise_discovery_tls_configuration().unwrap()));
        let mut stream = connector
            .connect(
                ServerName::try_from(TLS_LIKE_SERVER_NAME.to_owned()).unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&response).contains("<title>Welcome</title>"),
            replay
        );
    }
    let mut raw = TcpStream::connect(address).await.unwrap();
    let mut handshake = initiator_handshake(
        &client.private.as_slice().try_into().unwrap(),
        &server.public.as_slice().try_into().unwrap(),
        TCP_NOISE_PROLOGUE,
    )
    .unwrap();
    let length = handshake.write_message(&[0_u8; 96], &mut message).unwrap();
    raw.write_all(&(length as u16).to_be_bytes()).await.unwrap();
    raw.write_all(&message[..length]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), backend.recv(&mut [0_u8; 128]))
            .await
            .is_err()
    );
    task.abort();
}

#[tokio::test]
async fn encrypted_publication_is_bounded_and_requires_the_application_to_authorize_the_device() {
    let server = keypair();
    let client = keypair();
    let member = keypair();
    let port = unused_tcp_port().await;
    let address = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
    let authorized = AuthorizedPeers::default();
    let owner_key = <[u8; 32]>::try_from(client.public.as_slice()).unwrap();
    authorized.replace([owner_key, member.public.as_slice().try_into().unwrap()]);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
    authorized.set_endpoint_publisher(sender);
    let callback = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            let _ = request.result.send(
                request.device_public_key == owner_key
                    && request.checkpoint == b"valid signed checkpoint",
            );
        }
    });
    let (acceptor, _) = tls_acceptor();
    let task = tokio::spawn(run_endpoint_discovery_server(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
            wireguard_backend: "127.0.0.1:9".parse().unwrap(),
            server_private_key: Zeroizing::new(server.private.as_slice().try_into().unwrap()),
        },
        acceptor,
        authorized,
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        offer_endpoint_checkpoint(
            configuration(address, &client, &server),
            b"valid signed checkpoint"
        )
        .await
        .unwrap()
    );
    assert!(
        !offer_endpoint_checkpoint(
            configuration(address, &member, &server),
            b"valid signed checkpoint"
        )
        .await
        .unwrap()
    );
    assert!(
        !offer_endpoint_checkpoint(
            configuration(address, &client, &server),
            b"invalid checkpoint"
        )
        .await
        .unwrap()
    );
    assert!(
        offer_endpoint_checkpoint(
            configuration(address, &client, &server),
            &vec![0_u8; 24 * 1024 + 1]
        )
        .await
        .is_err()
    );
    task.abort();
    callback.abort();
}
