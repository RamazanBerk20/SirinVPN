use super::*;

pub async fn run_client_relay<F>(config: ClientRelayConfig, ready: F) -> Result<(), RelayError>
where
    F: FnOnce(),
{
    run_client_relay_with_remote_socket_setup(
        config,
        || async { Ok(()) },
        || async { Ok(()) },
        ready,
    )
    .await
}

pub async fn run_client_relay_with_remote_socket_setup<
    F,
    Before,
    BeforeFuture,
    After,
    AfterFuture,
>(
    config: ClientRelayConfig,
    before_remote_socket: Before,
    after_remote_socket: After,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
    Before: FnOnce() -> BeforeFuture,
    BeforeFuture: Future<Output = Result<(), RelayError>>,
    After: FnOnce() -> AfterFuture,
    AfterFuture: Future<Output = Result<(), RelayError>>,
{
    run_client_relay_inner(
        config,
        before_remote_socket,
        after_remote_socket,
        |_| Ok(()),
        ready,
    )
    .await
}

/// Prepare only the carrier socket before it connects. Platforms can protect
/// and bind that descriptor without changing another task's network routing.
pub async fn run_client_relay_with_socket_protector<F, Protect>(
    config: ClientRelayConfig,
    protect: Protect,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
    Protect: FnOnce(&Socket) -> Result<(), RelayError>,
{
    run_client_relay_inner(
        config,
        || async { Ok(()) },
        || async { Ok(()) },
        protect,
        ready,
    )
    .await
}

async fn run_client_relay_inner<F, Before, BeforeFuture, After, AfterFuture, Protect>(
    config: ClientRelayConfig,
    before_remote_socket: Before,
    after_remote_socket: After,
    protect: Protect,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
    Before: FnOnce() -> BeforeFuture,
    BeforeFuture: Future<Output = Result<(), RelayError>>,
    After: FnOnce() -> AfterFuture,
    AfterFuture: Future<Output = Result<(), RelayError>>,
    Protect: FnOnce(&Socket) -> Result<(), RelayError>,
{
    if !config.local_listen.ip().is_loopback() {
        return Err(RelayError::InvalidConfiguration);
    }
    let (client_private, server_public) = config.decoded_keys()?;
    let local_socket = crate::socket_policy::bind_loopback(config.local_listen)?;
    before_remote_socket().await?;
    let remote_result = async {
        let remote_socket = bind_remote_socket(config.server_address, config.socket_mark, protect)?;
        remote_socket.connect(config.server_address).await?;
        Ok::<_, RelayError>(remote_socket)
    }
    .await;
    let release_result = after_remote_socket().await;
    release_result?;
    let remote_socket = remote_result?;

    let mut session =
        establish_client_session(&remote_socket, &client_private, &server_public).await?;
    ready();

    let mut local_buffer = [0_u8; MAX_DATAGRAM_LENGTH];
    let mut remote_buffer = [0_u8; MAX_DATAGRAM_LENGTH];
    let mut local_peer = None;
    let mut last_server_packet = Instant::now();
    let mut last_local_packet = Instant::now();
    let mut health_interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            received = local_socket.recv_from(&mut local_buffer) => {
                let (length, peer) = received?;
                if !peer.ip().is_loopback() {
                    continue;
                }
                local_peer = Some(peer);
                last_local_packet = Instant::now();
                let packet = encode_transport_packet(
                    &session.id,
                    session.next_outbound,
                    &session.noise,
                    &local_buffer[..length],
                )?;
                session.next_outbound = session
                    .next_outbound
                    .checked_add(1)
                    .ok_or(RelayError::NonceExhausted)?;
                remote_socket.send(&packet).await?;
            }
            received = remote_socket.recv(&mut remote_buffer) => {
                let length = received?;
                let Some((sequence, ciphertext)) = parse_transport_packet(
                    &remote_buffer[..length],
                    &session.id,
                ) else {
                    continue;
                };
                if !session.inbound_replay.accepts(sequence) {
                    continue;
                }
                let Some(inner) = decrypt_inner(&session.noise, sequence, ciphertext) else {
                    continue;
                };
                session.inbound_replay.commit(sequence);
                last_server_packet = Instant::now();
                if let Some(peer) = local_peer {
                    local_socket.send_to(&inner, peer).await?;
                }
            }
            _ = health_interval.tick() => {
                if last_server_packet.elapsed() >= CLIENT_REHANDSHAKE_AFTER
                    && last_local_packet.elapsed() < CLIENT_REHANDSHAKE_AFTER
                {
                    session = establish_client_session(
                        &remote_socket,
                        &client_private,
                        &server_public,
                    )
                    .await?;
                    last_server_packet = Instant::now();
                }
            }
        }
    }
}
