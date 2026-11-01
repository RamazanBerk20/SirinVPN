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

/// A QUIC client that accepts any certificate, as an active probe would.
async fn probe(server: &QuicServer) -> (quinn::Endpoint, quinn::Connection) {
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
    (endpoint, connection)
}

async fn request(connection: &quinn::Connection, body: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(body).await.unwrap();
    send.finish().unwrap();
    timeout(Duration::from_secs(2), recv.read_to_end(64))
        .await
        .unwrap()
        .unwrap()
}

/// A probe that completes QUIC with any certificate sees an HTTP/3 server: a control stream
/// with SETTINGS, a 404 for its request, then GOAWAY and an H3_NO_ERROR close. Nothing
/// reaches WireGuard.
#[tokio::test]
async fn quic_probe_sees_an_http3_server_that_answers_404() {
    let server = quic_server().await;
    let (_endpoint, connection) = probe(&server).await;
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
    let response = request(
        &connection,
        &[0x01, 0x06, 0x00, 0x00, 0xd1, 0xd7, 0xc1, 0xc0],
    )
    .await;
    assert_eq!(response, [0x01, 0x03, 0x00, 0x00, 0xdb]);

    // The connection ends like an idle web server's: GOAWAY after stream 0, then close.
    let mut goaway = [0_u8; 3];
    timeout(Duration::from_secs(5), control.read_exact(&mut goaway))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(goaway, [0x07, 0x01, 0x04]);
    assert!(matches!(
        timeout(Duration::from_secs(2), connection.closed()).await.unwrap(),
        quinn::ConnectionError::ApplicationClosed(close) if close.error_code == quinn::VarInt::from_u32(0x100)
    ));

    let mut buffer = [0_u8; 64];
    assert!(
        timeout(Duration::from_millis(300), server.backend.recv(&mut buffer))
            .await
            .is_err()
    );
    server.task.abort();
}

/// Each connection gets one Noise attempt, so a probe cannot buy key exchanges with streams:
/// a valid exchange after a failed one is answered like any other request.
#[tokio::test]
async fn quic_allows_one_noise_attempt_per_connection() {
    let server = quic_server().await;
    let (_endpoint, connection) = probe(&server).await;
    assert_eq!(
        request(&connection, b"junk").await,
        [0x01, 0x03, 0x00, 0x00, 0xdb]
    );
    let client_private = <[u8; 32]>::try_from(server.client.private.as_slice()).unwrap();
    let server_public = <[u8; 32]>::try_from(server.server.public.as_slice()).unwrap();
    let mut handshake = initiator_handshake(
        &client_private,
        &server_public,
        b"SirinVPN QUIC transport v1",
    )
    .unwrap();
    let mut message = [0_u8; HANDSHAKE_MAX_LENGTH];
    let length = handshake
        .write_message(&client_handshake_payload(), &mut message)
        .unwrap();
    let mut frame = (length as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&message[..length]);
    assert_eq!(
        request(&connection, &frame).await,
        [0x01, 0x03, 0x00, 0x00, 0xdb]
    );
    server.task.abort();
}

/// A device's newest connection wins: a carrier that stopped without closing cannot keep the
/// device out until the idle timeout.
#[tokio::test]
async fn a_new_quic_connection_from_a_device_replaces_its_oldest() {
    let server = quic_server().await;
    let mut relays = Vec::new();
    for _ in 0..=MAX_CONNECTIONS_PER_CLIENT {
        let ready = Arc::new(AtomicBool::new(false));
        let ready_clone = ready.clone();
        relays.push(tokio::spawn(run_quic_client_relay(
            client_config(&server, &server.client.private),
            move || ready_clone.store(true, Ordering::Release),
        )));
        timeout(Duration::from_secs(5), async {
            while !ready.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    // The first relay's connection was closed for the newest one; the rest keep running.
    assert!(
        timeout(Duration::from_secs(2), &mut relays[0])
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    for relay in &relays[1..] {
        assert!(!relay.is_finished());
        relay.abort();
    }
    server.task.abort();
}
