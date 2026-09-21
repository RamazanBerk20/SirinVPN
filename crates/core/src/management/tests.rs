use super::*;
use crate::LocalIdentity;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) fn client(certificate: &str) -> ManagementClient {
    client_with_timeout(certificate, Some(Duration::from_secs(8)))
}

pub(super) fn client_with_timeout(
    certificate: &str,
    timeout: Option<Duration>,
) -> ManagementClient {
    let owner = LocalIdentity::generate("Local management test").unwrap();
    let profile = serde_json::from_value(serde_json::json!({
        "schema_version": 1, "id": "123e4567-e89b-42d3-a456-426614174000", "name": "Test",
        "endpoint": {"host": "127.0.0.1", "wireguard_port": 51820},
        "client_tunnel_address": "10.77.0.2", "server_tunnel_address": "10.77.0.1",
        "server_wireguard_public_key": owner.public.wireguard_public_key,
        "pinned_server_certificate_pem": certificate,
        "client_management_certificate_pem": owner.public.management_certificate_pem,
        "identity_reference": "test", "role": "owner"
    }))
    .unwrap();
    ManagementClient::with_timeout(&profile, &owner.secret, timeout).unwrap()
}

pub(super) fn certificate() -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let cert = CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert, key)
}

#[tokio::test]
async fn valid_envelopes_and_protocol_rejection_still_work() {
    let (cert, _) = certificate();
    let client = client(&cert.pem());
    let good = http::Response::new(serde_json::to_vec(&ApiEnvelope::new(true)).unwrap());
    assert!(client.decode::<bool>(good.into()).await.unwrap());
    let mut envelope = ApiEnvelope::new(true);
    envelope.api_version = "future".into();
    let future = http::Response::new(serde_json::to_vec(&envelope).unwrap());
    assert!(matches!(
        client.decode::<bool>(future.into()).await,
        Err(ManagementError::ProtocolMismatch)
    ));
}

#[tokio::test]
async fn oversized_bodies_are_rejected_with_and_without_a_content_length() {
    let (cert, _) = certificate();
    let client = client(&cert.pem());
    for status in [200, 403] {
        let body = " ".repeat(MAX_MANAGEMENT_RESPONSE_BYTES + 1);
        let response = http::Response::builder().status(status).body(body).unwrap();
        assert!(matches!(
            client.decode::<bool>(response.into()).await,
            Err(ManagementError::ConnectionFailed)
        ));
    }
    let response = http::Response::builder()
        .header("Content-Length", MAX_MANAGEMENT_RESPONSE_BYTES + 1)
        .body("{}")
        .unwrap();
    assert!(matches!(
        client.decode::<bool>(response.into()).await,
        Err(ManagementError::ConnectionFailed)
    ));
}

pub(super) async fn tls_server(
    cert: rcgen::Certificate,
    key: KeyPair,
    response: &'static [u8],
) -> (String, tokio::task::JoinHandle<()>) {
    let acceptor = tls_acceptor(cert, key);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        if let Ok(mut tls) = acceptor.accept(stream).await {
            let mut request = [0; 8192];
            let _ = tls.read(&mut request).await;
            let _ = tls.write_all(response).await;
            let _ = tls.shutdown().await;
        }
    });
    (format!("https://{address}"), task)
}

fn tls_acceptor(cert: rcgen::Certificate, key: KeyPair) -> tokio_rustls::TlsAcceptor {
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
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

#[tokio::test]
async fn idle_management_connections_expire_before_the_server_header_deadline() {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let (cert, key) = certificate();
    let mut client = client(&cert.pem());
    let acceptor = tls_acceptor(cert, key);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    client.base_url = format!("https://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        let mut connection_id = 0;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            connection_id += 1;
            let acceptor = acceptor.clone();
            connections.spawn(async move {
                let mut tls = BufReader::new(acceptor.accept(stream).await.unwrap());
                let body = serde_json::to_string(&ApiEnvelope::new(connection_id)).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                loop {
                    let mut line = String::new();
                    match tls.read_line(&mut line).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) if line == "\r\n" => {
                            if tls.get_mut().write_all(response.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                    }
                }
            });
        }
    });

    // Consecutive reads reuse one TLS connection; a quiet gap retires it before
    // the real VPS's 10-second header timeout can race the next access refresh.
    assert_eq!(client.get::<u32>("/v1/configuration").await.unwrap(), 1);
    assert_eq!(client.get::<u32>("/v1/membership").await.unwrap(), 1);
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(client.get::<u32>("/v1/membership").await.unwrap(), 2);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn pinned_tls_accepts_only_the_enrolled_certificate_and_never_follows_redirects() {
    let (cert, key) = certificate();
    let client = client(&cert.pem());
    let (url, task) = tls_server(cert, key, b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
    let response = client.client.get(url).send().await.unwrap();
    assert_eq!(response.status(), 307);
    task.await.unwrap();
    let (impostor, key) = certificate();
    let (url, task) = tls_server(impostor, key, b"").await;
    let error = client.client.get(url).send().await.unwrap_err();
    assert!(matches!(
        crate::diagnostics::request_failure(error),
        ManagementError::DiagnosticTlsFailed
    ));
    task.await.unwrap();
}
