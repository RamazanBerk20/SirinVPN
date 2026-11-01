use super::*;
use quinn::crypto::rustls::QuicClientConfig as RustlsClientCrypto;

fn quic_server_tls() -> (rustls::ServerConfig, String) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let certificate = CertificateParams::new(vec![TLS_LIKE_SERVER_NAME.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let fingerprint = STANDARD.encode(Sha256::digest(certificate.der().as_ref()));
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
    );
    let configuration = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.der().clone()], private_key)
    .unwrap();
    (configuration, fingerprint)
}

fn unused_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct QuicServer {
    backend: UdpSocket,
    activity: ActiveTransportRegistry,
    address: SocketAddr,
    fingerprint: String,
    server: snow::Keypair,
    client: snow::Keypair,
    task: tokio::task::JoinHandle<Result<(), RelayError>>,
}

async fn quic_server() -> QuicServer {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = unused_udp_port();
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let activity = ActiveTransportRegistry::default();
    let (tls, fingerprint) = quic_server_tls();
    let task = tokio::spawn(run_quic_server_relay(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        tls,
        authorized,
        activity.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    QuicServer {
        backend,
        activity,
        address: SocketAddr::new("127.0.0.1".parse().unwrap(), port),
        fingerprint,
        server,
        client,
        task,
    }
}

fn client_config(server: &QuicServer, client_private: &[u8]) -> TlsLikeClientRelayConfig {
    let local = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    TlsLikeClientRelayConfig {
        local_listen: local.local_addr().unwrap(),
        server_address: server.address,
        socket_mark: None,
        client_private_key: STANDARD.encode(client_private),
        server_public_key: STANDARD.encode(&server.server.public),
        server_certificate_sha256: server.fingerprint.clone(),
        https: None,
    }
}

#[tokio::test]
async fn authorized_quic_relay_round_trips_full_size_datagrams() {
    let server = quic_server().await;
    let config = client_config(&server, &server.client.private);
    let local_address = config.local_listen;
    let ready = Arc::new(AtomicBool::new(false));
    let ready_clone = ready.clone();
    let client_task = tokio::spawn(run_quic_client_relay(config, move || {
        ready_clone.store(true, Ordering::Release)
    }));
    timeout(Duration::from_secs(5), async {
        while !ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // A full WireGuard data packet at the 1,280-byte tunnel MTU, then a keepalive.
    for packet in [
        vec![7_u8; usize::from(crate::QUIC_MTU) + 32],
        vec![4_u8; 32],
    ] {
        wireguard.send_to(&packet, local_address).await.unwrap();
        let mut buffer = [0_u8; 2_048];
        let (length, backend_peer) = timeout(
            Duration::from_secs(2),
            server.backend.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..length], packet.as_slice());
        server.backend.send_to(&packet, backend_peer).await.unwrap();
        let (length, _) = timeout(Duration::from_secs(2), wireguard.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], packet.as_slice());
    }
    let client_public = <[u8; 32]>::try_from(server.client.public.as_slice()).unwrap();
    assert_eq!(
        server
            .activity
            .recent_transport(&client_public, Duration::from_secs(5)),
        Some(TransportKind::Quic)
    );
    client_task.abort();
    server.task.abort();
}

#[tokio::test]
async fn quic_relay_rejects_an_unknown_device_and_a_wrong_pin() {
    let server = quic_server().await;
    let stranger = keypair();
    let unknown = run_quic_client_relay(client_config(&server, &stranger.private), || {
        panic!("an unknown device must not become ready")
    });
    assert!(
        timeout(Duration::from_secs(5), unknown)
            .await
            .unwrap()
            .is_err()
    );

    let mut wrong_pin = client_config(&server, &server.client.private);
    wrong_pin.server_certificate_sha256 = STANDARD.encode([3_u8; 32]);
    let pinned = run_quic_client_relay(wrong_pin, || panic!("a wrong pin must not connect"));
    assert!(
        timeout(Duration::from_secs(5), pinned)
            .await
            .unwrap()
            .is_err()
    );

    let mut buffer = [0_u8; 64];
    assert!(
        timeout(Duration::from_millis(300), server.backend.recv(&mut buffer))
            .await
            .is_err()
    );
    server.task.abort();
}

/// A probe that completes QUIC with any certificate sees an HTTP/3 server: a control stream
/// with SETTINGS and a 404 for its request, and nothing reaches WireGuard.
#[tokio::test]
async fn quic_probe_sees_an_http3_server_that_answers_404() {
    let server = quic_server().await;
    let mut tls = tls::noise_discovery_tls_configuration().unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = Arc::new(RustlsClientCrypto::try_from(tls).unwrap());
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(crypto));
    let connection = timeout(
        Duration::from_secs(2),
        endpoint.connect(server.address, "127.0.0.1").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap()
            .protocol,
        Some(b"h3".to_vec())
    );
    let mut control = connection.accept_uni().await.unwrap();
    let mut settings = [0_u8; 3];
    control.read_exact(&mut settings).await.unwrap();
    assert_eq!(settings, [0x00, 0x04, 0x00]);

    // HEADERS for a GET of / over HTTPS from QPACK static entries, then FIN.
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&[0x01, 0x06, 0x00, 0x00, 0xd1, 0xd7, 0xc1, 0xc0])
        .await
        .unwrap();
    send.finish().unwrap();
    let response = timeout(Duration::from_secs(2), recv.read_to_end(64))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [0x01, 0x03, 0x00, 0x00, 0xdb]);

    let mut buffer = [0_u8; 64];
    assert!(
        timeout(Duration::from_millis(300), server.backend.recv(&mut buffer))
            .await
            .is_err()
    );
    server.task.abort();
}
