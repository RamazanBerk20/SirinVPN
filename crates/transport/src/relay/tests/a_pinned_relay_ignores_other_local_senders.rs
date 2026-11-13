use super::*;

/// The obfuscated UDP relay accepts datagrams only from WireGuard's fixed address and sends
/// replies only there: another local process that speaks first neither hijacks the inbound
/// packets nor injects outbound ones.
#[tokio::test]
async fn a_pinned_relay_ignores_other_local_senders() {
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

    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_address = local.local_addr().unwrap();
    drop(local);
    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ready = Arc::new(AtomicBool::new(false));
    let ready_clone = ready.clone();
    let client_task = tokio::spawn(run_client_relay_pinned(
        ClientRelayConfig {
            local_listen: local_address,
            server_address: public_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(client.private),
            server_public_key: STANDARD.encode(server.public),
        },
        wireguard.local_addr().unwrap(),
        |_| Ok(()),
        move || ready_clone.store(true, Ordering::Release),
    ));
    timeout(Duration::from_secs(5), async {
        while !ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let mut buffer = [0_u8; 128];
    attacker.send_to(b"injected", local_address).await.unwrap();
    // Nothing from the attacker reaches the server.
    assert!(
        timeout(Duration::from_millis(300), backend.recv_from(&mut buffer))
            .await
            .is_err()
    );
    wireguard
        .send_to(b"wireguard", local_address)
        .await
        .unwrap();
    let (length, backend_peer) = timeout(Duration::from_secs(2), backend.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"wireguard");
    // The attacker sends again just before the reply: the reply still goes to WireGuard.
    attacker.send_to(b"injected", local_address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    backend.send_to(b"reply", backend_peer).await.unwrap();
    let (length, _) = timeout(Duration::from_secs(2), wireguard.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"reply");
    assert!(
        timeout(Duration::from_millis(300), attacker.recv_from(&mut buffer))
            .await
            .is_err()
    );

    client_task.abort();
    server_task.abort();
}
