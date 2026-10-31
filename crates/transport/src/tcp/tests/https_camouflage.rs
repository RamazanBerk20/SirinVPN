use super::*;
use futures_util::{SinkExt, StreamExt};
use sirinvpn_protocol::HttpsTransport;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

async fn tls_stream(
    address: SocketAddr,
    fingerprint: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let connector = TlsConnector::from(Arc::new(
        tls_client_configuration(decode_fingerprint(fingerprint).unwrap()).unwrap(),
    ));
    connector
        .connect(
            ServerName::try_from(TLS_LIKE_SERVER_NAME.to_owned()).unwrap(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .unwrap()
}

fn authenticated_request(
    port: u16,
    client: &snow::Keypair,
    server: &snow::Keypair,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let private: [u8; 32] = client.private.as_slice().try_into().unwrap();
    let public: [u8; 32] = server.public.as_slice().try_into().unwrap();
    let mut handshake =
        initiator_handshake(&private, &public, b"SirinVPN HTTPS WebSocket transport v1").unwrap();
    let mut bytes = [0_u8; 512];
    let length = handshake.write_message(&[0_u8; 48], &mut bytes).unwrap();
    let mut request = format!("wss://{TLS_LIKE_SERVER_NAME}:{port}/connect")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        format!(
            "Bearer {}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[..length])
        )
        .parse()
        .unwrap(),
    );
    request
}

#[tokio::test]
async fn https_serves_cover_authenticates_before_upgrade_and_rejects_replay_and_unmasked_frames() {
    let server = keypair();
    let client = keypair();
    let stranger = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = unused_tcp_port().await;
    let address = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let activity = ActiveTransportRegistry::default();
    let (acceptor, fingerprint) = tls_acceptor();
    let server_task = tokio::spawn(run_tcp_server_relay_with_https(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(server.private.as_slice().try_into().unwrap()),
        },
        acceptor,
        HttpsTransport {
            server_name: TLS_LIKE_SERVER_NAME.into(),
            path: "/connect".into(),
            cdn: false,
        },
        authorized,
        activity.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    for (path, status) in [
        ("/", "404 Not Found"),
        ("/connect", "404 Not Found"),
        ("/anything", "404 Not Found"),
    ] {
        let mut stream = tls_stream(address, &fingerprint).await;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {TLS_LIKE_SERVER_NAME}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with(&format!("HTTP/1.1 {status}\r\nServer: nginx\r\n")));
        assert!(!response.contains("SirinVPN") && !response.contains("101 Switching"));
    }
    let mut stream = tls_stream(address, &fingerprint).await;
    stream.write_all(b"GET / HTTP/2.0\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n"));
    let unknown = authenticated_request(port, &stranger, &server);
    let error = tokio_tungstenite::client_async(unknown, tls_stream(address, &fingerprint).await)
        .await
        .unwrap_err();
    assert!(
        matches!(error, tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == 404)
    );

    let request = authenticated_request(port, &client, &server);
    let replay = request.clone();
    let (mut websocket, response) =
        tokio_tungstenite::client_async(request, tls_stream(address, &fingerprint).await)
            .await
            .unwrap();
    assert_eq!(response.status(), 101);
    assert!(matches!(
        websocket.next().await,
        Some(Ok(Message::Binary(_)))
    ));
    websocket
        .send(Message::Ping(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert!(
        matches!(timeout(Duration::from_secs(1), websocket.next()).await.unwrap(), Some(Ok(Message::Pong(bytes))) if bytes.as_ref() == [1, 2, 3])
    );
    // Bypass the normal client encoder to send a prohibited unmasked data frame.
    websocket.get_mut().write_all(&[0x82, 1, 42]).await.unwrap();
    let next = timeout(Duration::from_secs(1), websocket.next())
        .await
        .unwrap();
    assert!(!matches!(next, Some(Ok(Message::Binary(_)))));
    let error = tokio_tungstenite::client_async(replay, tls_stream(address, &fingerprint).await)
        .await
        .unwrap_err();
    assert!(
        matches!(error, tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == 404)
    );
    assert!(
        timeout(Duration::from_millis(80), backend.recv(&mut [0_u8; 32]))
            .await
            .is_err()
    );
    server_task.abort();
}

#[tokio::test]
async fn https_crosses_an_edge_that_rejects_raw_tcp_and_requires_the_configured_tls_name() {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = unused_tcp_port().await;
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let (acceptor, fingerprint) = tls_acceptor();
    let https = HttpsTransport {
        server_name: TLS_LIKE_SERVER_NAME.into(),
        path: "/connect".into(),
        cdn: false,
    };
    let server_task = tokio::spawn(run_tcp_server_relay_with_https(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(server.private.as_slice().try_into().unwrap()),
        },
        acceptor,
        https.clone(),
        authorized,
        ActiveTransportRegistry::default(),
    ));
    let edge = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_address = edge.local_addr().unwrap();
    let edge_task = tokio::spawn(async move {
        loop {
            let (mut input, _) = edge.accept().await.unwrap();
            tokio::spawn(async move {
                let mut header = [0_u8; 5];
                if !matches!(
                    timeout(Duration::from_secs(1), input.read_exact(&mut header)).await,
                    Ok(Ok(_))
                ) || header[0] != 0x16
                {
                    return;
                }
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                if length > 16_384 {
                    return;
                }
                let mut record = vec![0_u8; length];
                if !matches!(
                    timeout(Duration::from_secs(1), input.read_exact(&mut record)).await,
                    Ok(Ok(_))
                ) {
                    return;
                }
                let mut hello = header.to_vec();
                hello.extend_from_slice(&record);
                let mut inspector = rustls::server::Acceptor::default();
                inspector
                    .read_tls(&mut std::io::Cursor::new(&hello))
                    .unwrap();
                let Ok(Some(accepted)) = inspector.accept() else {
                    return;
                };
                if accepted.client_hello().server_name() != Some(TLS_LIKE_SERVER_NAME) {
                    return;
                }
                let mut output = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                output.write_all(&hello).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut input, &mut output).await;
            });
        }
    });
    let mut raw = TcpStream::connect(edge_address).await.unwrap();
    raw.write_all(&[0, 150, 0, 0, 0]).await.unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(1), raw.read(&mut [0_u8; 1])).await,
        Ok(Ok(0))
    ));

    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_address = local.local_addr().unwrap();
    drop(local);
    let (ready_tx, ready_rx) = oneshot::channel();
    let client_task = tokio::spawn(run_tls_like_client_relay(
        TlsLikeClientRelayConfig {
            local_listen: local_address,
            server_address: edge_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(client.private),
            server_public_key: STANDARD.encode(server.public),
            server_certificate_sha256: fingerprint,
            https: Some(https),
        },
        || {
            let _ = ready_tx.send(());
        },
    ));
    timeout(Duration::from_secs(3), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for length in [32, 1_280, 1_472] {
        let packet = vec![19; length];
        wireguard.send_to(&packet, local_address).await.unwrap();
        let mut buffer = vec![0_u8; 2_048];
        let (received, peer) = timeout(Duration::from_secs(1), backend.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], packet);
        backend.send_to(&buffer[..received], peer).await.unwrap();
        let received = timeout(Duration::from_secs(1), wireguard.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], packet);
    }
    client_task.abort();
    edge_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn tls_like_client_without_https_sends_no_server_name() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let inspector = tokio::spawn(async move {
        let (mut input, _) = listener.accept().await.unwrap();
        let mut hello = vec![0_u8; 5];
        input.read_exact(&mut hello).await.unwrap();
        hello.resize(5 + usize::from(u16::from_be_bytes([hello[3], hello[4]])), 0);
        input.read_exact(&mut hello[5..]).await.unwrap();
        let mut acceptor = rustls::server::Acceptor::default();
        acceptor
            .read_tls(&mut std::io::Cursor::new(&hello))
            .unwrap();
        let accepted = acceptor.accept().unwrap().unwrap();
        accepted.client_hello().server_name().map(str::to_owned)
    });
    let server = keypair();
    let client = keypair();
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_address = local.local_addr().unwrap();
    drop(local);
    let result = run_tls_like_client_relay(
        TlsLikeClientRelayConfig {
            local_listen: local_address,
            server_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(client.private),
            server_public_key: STANDARD.encode(server.public),
            https: None,
            server_certificate_sha256: STANDARD.encode([7_u8; 32]),
        },
        || panic!("an inspected handshake must not become ready"),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(inspector.await.unwrap(), None);
}

const CDN_PEER: &str = "198.51.100.7";

struct CdnEdge {
    address: SocketAddr,
    server_names: Arc<Mutex<Vec<Option<String>>>>,
    forwarded: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}

/// One test root signs the edge certificates; `cdn_roots` trusts only it under test.
fn cdn_edge_certificate(name: &str) -> (CertificateDer<'static>, Vec<u8>) {
    static ROOT: std::sync::OnceLock<(rcgen::Certificate, KeyPair)> = std::sync::OnceLock::new();
    let (root, root_key) = ROOT.get_or_init(|| {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "SirinVPN test CDN root");
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        (parameters.self_signed(&key).unwrap(), key)
    });
    let _ = super::tls::TEST_CDN_ROOT.set(root.der().clone());
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut parameters = CertificateParams::new(vec![name.to_owned()]).unwrap();
    parameters.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = parameters.signed_by(&key, root, root_key).unwrap();
    (certificate.der().clone(), key.serialize_der())
}

/// Terminates TLS with its own WebPKI certificate, opens a new TLS connection to the
/// origin that accepts any certificate (Cloudflare "Full"), adds proxy headers to the
/// request and forwards the WebSocket. It records what it could read in plaintext.
async fn cdn_edge(origin_port: u16, certificate_name: &str) -> CdnEdge {
    let (certificate, key) = cdn_edge_certificate(certificate_name);
    let mut configuration = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key)),
    )
    .unwrap();
    configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(configuration));
    let origin = TlsConnector::from(Arc::new(
        super::tls::noise_discovery_tls_configuration().unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_names = Arc::new(Mutex::new(Vec::new()));
    let forwarded = Arc::new(Mutex::new(Vec::new()));
    let (names, captured) = (server_names.clone(), forwarded.clone());
    let task = tokio::spawn(async move {
        loop {
            let (input, _) = listener.accept().await.unwrap();
            let (acceptor, origin, names, captured) = (
                acceptor.clone(),
                origin.clone(),
                names.clone(),
                captured.clone(),
            );
            tokio::spawn(async move {
                let Ok(mut input) = acceptor.accept(input).await else {
                    return;
                };
                let name = input.get_ref().1.server_name().map(str::to_owned);
                names.lock().unwrap().push(name.clone());
                let Some(name) = name else {
                    return;
                };
                let Ok(header) = https::read_header(&mut input).await else {
                    return;
                };
                let mut request = header[..header.len() - 2].to_vec();
                request.extend_from_slice(
                    format!("CF-Connecting-IP: {CDN_PEER}\r\nX-Forwarded-For: {CDN_PEER}\r\nX-Forwarded-Proto: https\r\nCDN-Loop: cloudflare\r\nCF-Ray: 8f1d2c3b4a596877-AMS\r\n\r\n").as_bytes(),
                );
                let output = TcpStream::connect(("127.0.0.1", origin_port))
                    .await
                    .unwrap();
                let Ok(mut output) = origin
                    .connect(ServerName::try_from(name).unwrap(), output)
                    .await
                else {
                    return;
                };
                captured.lock().unwrap().extend_from_slice(&request);
                output.write_all(&request).await.unwrap();
                let (mut input_reader, mut input_writer) = tokio::io::split(input);
                let (mut output_reader, mut output_writer) = tokio::io::split(output);
                let upstream = async {
                    let mut buffer = [0_u8; 4_096];
                    while let Ok(length) = input_reader.read(&mut buffer).await {
                        if length == 0 || output_writer.write_all(&buffer[..length]).await.is_err()
                        {
                            break;
                        }
                        captured
                            .lock()
                            .unwrap()
                            .extend_from_slice(&buffer[..length]);
                    }
                };
                let downstream = tokio::io::copy(&mut output_reader, &mut input_writer);
                tokio::select! { _ = upstream => {}, _ = downstream => {} }
            });
        }
    });
    CdnEdge {
        address,
        server_names,
        forwarded,
        task,
    }
}

fn cdn_https() -> HttpsTransport {
    HttpsTransport {
        server_name: TLS_LIKE_SERVER_NAME.into(),
        path: "/connect".into(),
        cdn: true,
    }
}

async fn https_origin(
    client: &snow::Keypair,
    server: &snow::Keypair,
) -> (
    u16,
    String,
    UdpSocket,
    tokio::task::JoinHandle<Result<(), RelayError>>,
) {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = unused_tcp_port().await;
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let (acceptor, fingerprint) = tls_acceptor();
    let task = tokio::spawn(run_tcp_server_relay_with_https(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(server.private.as_slice().try_into().unwrap()),
        },
        acceptor,
        // The origin needs no CDN setting: CDN mode changes only how devices connect.
        HttpsTransport {
            cdn: false,
            ..cdn_https()
        },
        authorized,
        ActiveTransportRegistry::default(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    (port, fingerprint, backend, task)
}

fn cdn_client(
    server_address: SocketAddr,
    client: &snow::Keypair,
    server_public: &[u8],
    fingerprint: &str,
) -> (SocketAddr, TlsLikeClientRelayConfig) {
    let local = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let local_address = local.local_addr().unwrap();
    drop(local);
    (
        local_address,
        TlsLikeClientRelayConfig {
            local_listen: local_address,
            server_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(&client.private),
            server_public_key: STANDARD.encode(server_public),
            server_certificate_sha256: fingerprint.to_owned(),
            https: Some(cdn_https()),
        },
    )
}

#[tokio::test]
async fn https_through_a_cdn_edge_verifies_webpki_sends_the_name_and_hides_tunnel_contents() {
    let server = keypair();
    let client = keypair();
    let (origin_port, fingerprint, backend, server_task) = https_origin(&client, &server).await;
    let edge = cdn_edge(origin_port, TLS_LIKE_SERVER_NAME).await;
    let (local_address, config) = cdn_client(edge.address, &client, &server.public, &fingerprint);
    let (ready_tx, ready_rx) = oneshot::channel();
    let client_task = tokio::spawn(run_tls_like_client_relay(config, || {
        let _ = ready_tx.send(());
    }));
    timeout(Duration::from_secs(3), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for length in [32, 1_280, 1_472] {
        let packet = vec![19; length];
        wireguard.send_to(&packet, local_address).await.unwrap();
        let mut buffer = vec![0_u8; 2_048];
        let (received, peer) = timeout(Duration::from_secs(1), backend.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], packet);
        backend.send_to(&buffer[..received], peer).await.unwrap();
        let received = timeout(Duration::from_secs(1), wireguard.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], packet);
    }
    assert_eq!(
        *edge.server_names.lock().unwrap(),
        [Some(TLS_LIKE_SERVER_NAME.to_owned())]
    );
    // The edge reads the upgrade request, but every tunnel packet stays Noise-encrypted.
    let forwarded = edge.forwarded.lock().unwrap().clone();
    let request = String::from_utf8_lossy(
        &forwarded[..forwarded.windows(4).position(|w| w == b"\r\n\r\n").unwrap()],
    )
    .to_lowercase();
    assert!(request.starts_with("get /connect http/1.1\r\n"));
    assert!(request.contains(&format!("host: {TLS_LIKE_SERVER_NAME}")));
    assert!(request.contains("authorization: bearer "));
    assert!(forwarded.len() > 2 * 1_472);
    assert!(
        !forwarded
            .windows(64)
            .any(|window| window.iter().all(|byte| *byte == 19))
    );
    client_task.abort();
    edge.task.abort();
    server_task.abort();
}

#[tokio::test]
async fn cdn_mode_rejects_the_origin_pin_another_name_and_a_wrong_server_key() {
    let server = keypair();
    let client = keypair();
    let (origin_port, fingerprint, backend, server_task) = https_origin(&client, &server).await;
    let origin = SocketAddr::new("127.0.0.1".parse().unwrap(), origin_port);
    let edge = cdn_edge(origin_port, TLS_LIKE_SERVER_NAME).await;
    let other = cdn_edge(origin_port, "cdn.example.net").await;
    let impostor = keypair();
    for (address, server_public) in [
        // The pinned origin certificate is not WebPKI-valid, so CDN mode refuses it.
        (origin, server.public.as_slice()),
        // A WebPKI certificate for another name.
        (other.address, server.public.as_slice()),
        // A valid edge cannot stand in for the server's Noise IK key.
        (edge.address, impostor.public.as_slice()),
    ] {
        let (_, config) = cdn_client(address, &client, server_public, &fingerprint);
        let result = timeout(
            Duration::from_secs(5),
            run_tls_like_client_relay(config, || {
                panic!("an unauthenticated server must not become ready")
            }),
        )
        .await
        .unwrap();
        assert!(result.is_err());
    }
    assert_eq!(edge.server_names.lock().unwrap().len(), 1);
    assert!(
        timeout(Duration::from_millis(80), backend.recv(&mut [0_u8; 32]))
            .await
            .is_err()
    );
    edge.task.abort();
    other.task.abort();
    server_task.abort();
}

async fn cover_answered(address: SocketAddr, fingerprint: &str) -> bool {
    let connector = TlsConnector::from(Arc::new(
        tls_client_configuration(decode_fingerprint(fingerprint).unwrap()).unwrap(),
    ));
    let Ok(Ok(stream)) = timeout(Duration::from_secs(1), TcpStream::connect(address)).await else {
        return false;
    };
    let name = ServerName::try_from(TLS_LIKE_SERVER_NAME.to_owned()).unwrap();
    let Ok(Ok(mut stream)) = timeout(Duration::from_secs(1), connector.connect(name, stream)).await
    else {
        return false;
    };
    let request = format!("GET / HTTP/1.1\r\nHost: {TLS_LIKE_SERVER_NAME}\r\n\r\n");
    let mut response = Vec::new();
    stream.write_all(request.as_bytes()).await.is_ok()
        && matches!(
            timeout(Duration::from_secs(1), stream.read_to_end(&mut response)).await,
            Ok(Ok(_))
        )
        && response.starts_with(b"HTTP/1.1 404 Not Found\r\n")
}

#[tokio::test]
async fn behind_a_cdn_one_edge_address_cannot_exhaust_a_per_source_budget() {
    for (cdn, answered) in [(false, 12), (true, 16)] {
        let server = keypair();
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = unused_tcp_port().await;
        let (acceptor, fingerprint) = tls_acceptor();
        let task = tokio::spawn(run_tcp_server_relay_with_https(
            TcpServerRelayConfig {
                listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
                wireguard_backend: backend.local_addr().unwrap(),
                server_private_key: Zeroizing::new(server.private.as_slice().try_into().unwrap()),
            },
            acceptor,
            HttpsTransport { cdn, ..cdn_https() },
            AuthorizedPeers::default(),
            ActiveTransportRegistry::default(),
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;
        let address = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let mut count = 0;
        for _ in 0..16 {
            count += usize::from(cover_answered(address, &fingerprint).await);
        }
        // Every client of a CDN edge shares its address; the global budget still applies.
        assert_eq!(count, answered, "cdn={cdn}");
        task.abort();
    }
}

#[tokio::test]
async fn discovery_through_a_cdn_requires_its_webpki_certificate() {
    let server = keypair();
    let client = keypair();
    let (origin_port, _, _, server_task) = https_origin(&client, &server).await;
    let origin = SocketAddr::new("127.0.0.1".parse().unwrap(), origin_port);
    let edge = cdn_edge(origin_port, TLS_LIKE_SERVER_NAME).await;
    for (address, through_cdn, accepted) in [
        // The origin's own certificate is fine for discovery at the VPS address,
        (origin, false, true),
        // but an address claiming to be the CDN must prove it with WebPKI.
        (origin, true, false),
        (edge.address, true, true),
    ] {
        let config = EndpointDiscoveryConfig {
            server_address: address,
            server_name: Some(TLS_LIKE_SERVER_NAME.into()),
            client_private_key: Zeroizing::new(client.private.as_slice().try_into().unwrap()),
            server_public_key: server.public.as_slice().try_into().unwrap(),
            socket_mark: None,
            through_cdn,
        };
        assert_eq!(
            fetch_endpoint_checkpoint(config).await.is_ok(),
            accepted,
            "{address} through_cdn={through_cdn}"
        );
    }
    edge.task.abort();
    server_task.abort();
}
