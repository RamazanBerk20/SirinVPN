use super::*;

#[tokio::test]
async fn stalled_management_tls_handshake_expires_without_authenticating() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Test owner").unwrap();
    initialize(
        &paths,
        "Test",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51820,
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(
        tls_configuration(&paths, &[owner.public.management_certificate_pem]).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _silent_peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        accept_management_tls(&acceptor, stream, Duration::from_millis(25)),
    )
    .await;
    assert!(result.unwrap().is_none());
}
