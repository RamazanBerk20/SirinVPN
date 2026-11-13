use super::*;

pub(super) async fn establish_client_session<S>(
    stream: &mut S,
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    prologue: &[u8],
) -> Result<StatelessTransportState, RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(HANDSHAKE_TIMEOUT, async {
        let mut handshake = initiator_handshake(client_private, server_public, prologue)?;
        let payload = client_handshake_payload();
        let mut request = [0_u8; HANDSHAKE_MAX_LENGTH];
        let request_length = handshake.write_message(&payload, &mut request)?;
        write_frame(stream, &request[..request_length]).await?;
        let response = read_frame(stream, HANDSHAKE_MAX_LENGTH).await?;
        let mut payload = [0_u8; HANDSHAKE_MAX_LENGTH];
        handshake.read_message(&response, &mut payload)?;
        Ok(handshake.into_stateless_transport_mode()?)
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)?
}

pub(super) async fn accept_server_handshake<S>(
    stream: &mut S,
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
    prologue: &[u8],
) -> Result<Option<(StatelessTransportState, [u8; 32], Vec<u8>)>, RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_frame(stream, HANDSHAKE_MAX_LENGTH).await?;
    accept_handshake_message(&request, config, authorized, replay_cache, prologue)
}

type AcceptedHandshake = (StatelessTransportState, [u8; 32], Vec<u8>);

/// Like `accept_handshake_message`, and whether the initiator payload carries `binding`.
pub(super) fn accept_bound_handshake_message(
    request: &[u8],
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
    prologue: &[u8],
    binding: Option<&[u8; 32]>,
) -> Result<Option<(AcceptedHandshake, bool)>, RelayError> {
    let mut bound = false;
    let accepted = accept_handshake_message_with(
        request,
        config,
        authorized,
        replay_cache,
        prologue,
        |payload| bound = binding.is_some_and(|binding| handshake_is_bound(payload, binding)),
    )?;
    Ok(accepted.map(|accepted| (accepted, bound)))
}

pub(super) fn accept_handshake_message(
    request: &[u8],
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
    prologue: &[u8],
) -> Result<Option<AcceptedHandshake>, RelayError> {
    accept_handshake_message_with(request, config, authorized, replay_cache, prologue, |_| {})
}

fn accept_handshake_message_with(
    request: &[u8],
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
    prologue: &[u8],
    inspect_payload: impl FnOnce(&[u8]),
) -> Result<Option<AcceptedHandshake>, RelayError> {
    if !(HANDSHAKE_MIN_LENGTH..=HANDSHAKE_MAX_LENGTH).contains(&request.len()) {
        return Ok(None);
    }
    let mut handshake = responder_handshake(&config.server_private_key, prologue)?;
    let mut client_payload = [0_u8; HANDSHAKE_MAX_LENGTH];
    let Ok(client_payload_length) = handshake.read_message(request, &mut client_payload) else {
        return Ok(None);
    };
    let Some(remote_static) = handshake.get_remote_static() else {
        return Ok(None);
    };
    let Ok(client_static) = <[u8; 32]>::try_from(remote_static) else {
        return Ok(None);
    };
    if !authorized.contains(&client_static)
        || !replay_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accept_client_handshake(
                request,
                client_static,
                &client_payload[..client_payload_length],
            )
            .is_ok()
    {
        return Ok(None);
    }
    inspect_payload(&client_payload[..client_payload_length]);

    let padding = random_bytes(OsRng.gen_range(32..=80));
    let mut response = [0_u8; HANDSHAKE_MAX_LENGTH];
    let response_length = handshake.write_message(&padding, &mut response)?;
    if response_length > request.len() {
        return Ok(None);
    }
    let noise = handshake.into_stateless_transport_mode()?;
    Ok(Some((
        noise,
        client_static,
        response[..response_length].to_vec(),
    )))
}

pub(super) fn encode_record(
    noise: &StatelessTransportState,
    nonce: u64,
    inner: &[u8],
) -> Result<Vec<u8>, RelayError> {
    if inner.is_empty() || inner.len() > MAX_INNER_PACKET_LENGTH {
        return Err(RelayError::PacketTooLarge);
    }
    let available_padding = MAX_FRAME_LENGTH
        .saturating_sub(AEAD_TAG_LENGTH + 2 + inner.len())
        .min(MAX_PADDING_LENGTH);
    let padding_length = OsRng.gen_range(0..=available_padding);
    let mut plaintext = Vec::with_capacity(2 + inner.len() + padding_length);
    plaintext.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(inner);
    plaintext.extend_from_slice(&random_bytes(padding_length));
    let mut record = vec![0_u8; plaintext.len() + AEAD_TAG_LENGTH];
    let length = noise.write_message(nonce, &plaintext, &mut record)?;
    record.truncate(length);
    Ok(record)
}

pub(super) fn decrypt_record(
    noise: &StatelessTransportState,
    nonce: u64,
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext.len() < AEAD_TAG_LENGTH + 2 || ciphertext.len() > MAX_FRAME_LENGTH {
        return None;
    }
    let mut plaintext = vec![0_u8; ciphertext.len()];
    let length = noise.read_message(nonce, ciphertext, &mut plaintext).ok()?;
    if length < 2 {
        return None;
    }
    let inner_length = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
    if inner_length == 0 || inner_length > length.saturating_sub(2) {
        return None;
    }
    Some(plaintext[2..2 + inner_length].to_vec())
}

pub(super) async fn read_frame<R>(
    reader: &mut R,
    maximum_length: usize,
) -> Result<Vec<u8>, RelayError>
where
    R: AsyncRead + Unpin,
{
    let length = usize::from(reader.read_u16().await?);
    if length == 0 || length > maximum_length {
        return Err(RelayError::InvalidConfiguration);
    }
    let mut frame = vec![0_u8; length];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

pub(super) async fn write_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), RelayError>
where
    W: AsyncWrite + Unpin,
{
    let length = u16::try_from(frame.len()).map_err(|_| RelayError::PacketTooLarge)?;
    writer.write_u16(length).await?;
    writer.write_all(frame).await?;
    writer.flush().await?;
    Ok(())
}
