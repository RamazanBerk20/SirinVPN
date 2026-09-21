use super::*;

#[tokio::test]
async fn server_relay_preserves_a_fragmented_inbound_frame_during_outbound_traffic() {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_port = unused_tcp_port().await;
    let public_address = SocketAddr::new("127.0.0.1".parse().unwrap(), public_port);
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let server_task = tokio::spawn(run_tcp_server_relay(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), public_port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        authorized,
        ActiveTransportRegistry::default(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut stream = connect_marked_protected(public_address, None, |_| Ok(()))
        .await
        .unwrap();
    let noise = establish_client_session(
        &mut stream,
        &<[u8; 32]>::try_from(client.private.as_slice()).unwrap(),
        &<[u8; 32]>::try_from(server.public.as_slice()).unwrap(),
        TCP_NOISE_PROLOGUE,
    )
    .await
    .unwrap();
    let first = encode_record(&noise, 0, b"initial").unwrap();
    write_frame(&mut stream, &first).await.unwrap();
    let mut backend_buffer = [0_u8; 128];
    let (length, backend_peer) = timeout(
        Duration::from_secs(2),
        backend.recv_from(&mut backend_buffer),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&backend_buffer[..length], b"initial");

    let second = encode_record(&noise, 1, b"fragmented request").unwrap();
    let split = (1..second.len().saturating_sub(1))
        .find(|offset| {
            u16::from_be_bytes([second[*offset], second[*offset + 1]]) as usize > MAX_FRAME_LENGTH
        })
        .unwrap_or(1);
    stream.write_u16(second.len() as u16).await.unwrap();
    stream.write_all(&second[..split]).await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    backend
        .send_to(b"competing response", backend_peer)
        .await
        .unwrap();
    let response = timeout(
        Duration::from_secs(2),
        read_frame(&mut stream, MAX_FRAME_LENGTH),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        decrypt_record(&noise, 0, &response).unwrap(),
        b"competing response"
    );
    stream.write_all(&second[split..]).await.unwrap();
    stream.flush().await.unwrap();

    let (length, _) = timeout(
        Duration::from_secs(2),
        backend.recv_from(&mut backend_buffer),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&backend_buffer[..length], b"fragmented request");
    server_task.abort();
}

#[tokio::test]
async fn malformed_tcp_probe_receives_no_application_bytes() {
    let server = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_port = unused_tcp_port().await;
    let public_address = SocketAddr::new("127.0.0.1".parse().unwrap(), public_port);
    let server_task = tokio::spawn(run_tcp_server_relay(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), public_port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        AuthorizedPeers::default(),
        ActiveTransportRegistry::default(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut probe = TcpStream::connect(public_address).await.unwrap();
    write_frame(&mut probe, &[7_u8; HANDSHAKE_MIN_LENGTH])
        .await
        .unwrap();
    let mut response = [0_u8; 1];
    let read = timeout(Duration::from_secs(1), probe.read(&mut response)).await;
    assert!(matches!(read, Ok(Ok(0)) | Err(_)));
    server_task.abort();
}

#[tokio::test]
async fn unauthorized_and_replayed_tcp_handshakes_receive_no_application_bytes() {
    let server = keypair();
    let client = keypair();
    let unauthorized = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_port = unused_tcp_port().await;
    let public_address = SocketAddr::new("127.0.0.1".parse().unwrap(), public_port);
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let server_task = tokio::spawn(run_tcp_server_relay(
        TcpServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), public_port),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        authorized,
        ActiveTransportRegistry::default(),
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    let server_public = <[u8; 32]>::try_from(server.public.as_slice()).unwrap();

    let unauthorized_private = <[u8; 32]>::try_from(unauthorized.private.as_slice()).unwrap();
    let mut unauthorized_handshake =
        initiator_handshake(&unauthorized_private, &server_public, TCP_NOISE_PROLOGUE).unwrap();
    let mut unauthorized_request = [0_u8; HANDSHAKE_MAX_LENGTH];
    let unauthorized_length = unauthorized_handshake
        .write_message(&[4_u8; 48], &mut unauthorized_request)
        .unwrap();
    let mut unauthorized_stream = TcpStream::connect(public_address).await.unwrap();
    write_frame(
        &mut unauthorized_stream,
        &unauthorized_request[..unauthorized_length],
    )
    .await
    .unwrap();
    let mut one_byte = [0_u8; 1];
    let read = timeout(
        Duration::from_secs(1),
        unauthorized_stream.read(&mut one_byte),
    )
    .await;
    assert!(matches!(read, Ok(Ok(0)) | Err(_)));

    let client_private = <[u8; 32]>::try_from(client.private.as_slice()).unwrap();
    let mut handshake =
        initiator_handshake(&client_private, &server_public, TCP_NOISE_PROLOGUE).unwrap();
    let mut request = [0_u8; HANDSHAKE_MAX_LENGTH];
    let request_length = handshake.write_message(&[5_u8; 48], &mut request).unwrap();
    let request = &request[..request_length];
    let mut first = TcpStream::connect(public_address).await.unwrap();
    write_frame(&mut first, request).await.unwrap();
    let response = timeout(
        Duration::from_secs(1),
        read_frame(&mut first, HANDSHAKE_MAX_LENGTH),
    )
    .await
    .unwrap()
    .unwrap();
    let mut response_payload = [0_u8; HANDSHAKE_MAX_LENGTH];
    handshake
        .read_message(&response, &mut response_payload)
        .unwrap();

    let mut replay = TcpStream::connect(public_address).await.unwrap();
    write_frame(&mut replay, request).await.unwrap();
    let read = timeout(Duration::from_secs(1), replay.read(&mut one_byte)).await;
    assert!(matches!(read, Ok(Ok(0)) | Err(_)));
    server_task.abort();
}
