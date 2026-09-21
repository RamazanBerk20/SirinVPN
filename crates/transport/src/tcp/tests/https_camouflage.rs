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
        },
        authorized,
        activity.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    for (path, status) in [
        ("/", "200 OK"),
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
        assert!(response.starts_with(&format!("HTTP/1.1 {status}\r\n")));
        assert!(!response.contains("SirinVPN") && !response.contains("101 Switching"));
    }
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
