use super::*;

fn status(uptime: u64) -> ServerStatus {
    serde_json::from_value(serde_json::json!({
        "api_version": API_VERSION, "server_name": "Şirin VPS", "connection_state": "connected",
        "interface_up": true, "dns_healthy": true, "transport": "direct_udp", "peer_count": 2,
        "rx_bytes": 42, "tx_bytes": 24, "uptime_seconds": uptime,
    }))
    .unwrap()
}

fn event(status: ServerStatus) -> String {
    format!(
        "event: status\ndata: {}\n\n",
        serde_json::to_string(&ApiEnvelope::new(status)).unwrap()
    )
}

#[tokio::test]
async fn multiple_events_and_comments_are_consumed_without_waiting_for_body_completion() {
    for newline in ["\n", "\r\n"] {
        let body = format!(": keepalive\n\n{}{}", event(status(10)), event(status(11)))
            .replace('\n', newline);
        let mut stream = ManagementStatusStream {
            response: http::Response::new(body).into(),
            buffer: Vec::new(),
        };
        assert_eq!(stream.next_status().await.unwrap(), status(10));
        assert_eq!(stream.next_status().await.unwrap(), status(11));
        assert!(stream.next_status().await.is_err());
    }
}

#[tokio::test]
async fn rejects_oversized_truncated_and_incompatible_events() {
    let mut incompatible = status(1);
    incompatible.api_version = "future".to_owned();
    for body in [
        "x".repeat(MAX_MANAGEMENT_RESPONSE_BYTES + 1),
        event(status(1)).trim_end().to_owned(),
        event(incompatible),
    ] {
        let mut stream = ManagementStatusStream {
            response: http::Response::new(body).into(),
            buffer: Vec::new(),
        };
        assert!(stream.next_status().await.is_err());
    }
    let mut envelope = ApiEnvelope::new(status(1));
    envelope.api_version = "future".to_owned();
    let future = format!(
        "event: status\ndata: {}",
        serde_json::to_string(&envelope).unwrap()
    );
    assert!(matches!(
        decode_event(future.as_bytes()),
        Err(ManagementError::ProtocolMismatch)
    ));
}

#[tokio::test]
async fn stream_endpoint_requires_sse_and_only_unsupported_routes_allow_fallback() {
    use super::super::tests::{certificate, client, tls_server};
    for (response, unsupported) in [
        (
            &b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..],
            true,
        ),
        (
            &b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"[..],
            false,
        ),
        (
            &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n"[..],
            false,
        ),
    ] {
        let (cert, key) = certificate();
        let mut client = client(&cert.pem());
        let (url, task) = tls_server(cert, key, response).await;
        client.base_url = url;
        let error = match client.open_status_stream().await {
            Err(error) => error,
            Ok(_) => panic!("invalid response accepted"),
        };
        assert_eq!(
            matches!(error, ManagementError::StatusStreamingUnsupported),
            unsupported
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn fragmented_tls_events_keep_streaming_beyond_the_normal_request_deadline() {
    use super::super::tests::{certificate, client_with_timeout};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (cert, key) = certificate();
    let mut client = client_with_timeout(&cert.pem(), None);
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    client.base_url = format!("https://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(tls.read_u8().await.unwrap());
        }
        assert!(
            std::str::from_utf8(&request)
                .unwrap()
                .starts_with("GET /v1/status/stream ")
        );
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        for uptime in 0..10 {
            if uptime > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            // HTTP chunk boundaries can bisect JSON, CRLF, and UTF-8 code points.
            for chunk in event(status(uptime))
                .replace('\n', "\r\n")
                .as_bytes()
                .chunks(3)
            {
                tls.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .unwrap();
                tls.write_all(chunk).await.unwrap();
                tls.write_all(b"\r\n").await.unwrap();
                tls.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
        }
        tls.write_all(b"0\r\n\r\n").await.unwrap();
    });
    let mut stream = client.open_status_stream().await.unwrap();
    for uptime in 0..10 {
        assert_eq!(stream.next_status().await.unwrap(), status(uptime));
    }
    assert!(stream.next_status().await.is_err());
    server.await.unwrap();
}
