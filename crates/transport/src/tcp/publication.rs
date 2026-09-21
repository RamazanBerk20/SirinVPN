//! Owner-authorized publication of an already signed handoff checkpoint. The
//! server application validates authority and state; this layer authenticates
//! the device's Noise key and bounds the encrypted control exchange.
use super::*;

const PROLOGUE: &[u8] = b"SirinVPN signed endpoint publication v1";
const MAX_CHECKPOINT: usize = 24 * 1024;
const MAX_MESSAGE: usize = MAX_CHECKPOINT + 128;

pub async fn offer_endpoint_checkpoint(
    config: EndpointDiscoveryConfig,
    checkpoint: &[u8],
) -> Result<bool, RelayError> {
    offer_endpoint_checkpoint_with_socket_protector(config, checkpoint, |_| Ok(())).await
}

pub async fn offer_endpoint_checkpoint_with_socket_protector<Protect>(
    config: EndpointDiscoveryConfig,
    checkpoint: &[u8],
    protect: Protect,
) -> Result<bool, RelayError>
where
    Protect: FnOnce(&Socket) -> Result<(), RelayError>,
{
    if checkpoint.is_empty() || checkpoint.len() > MAX_CHECKPOINT {
        return Err(RelayError::InvalidConfiguration);
    }
    timeout(Duration::from_secs(6), async {
        let stream = connect_marked_protected(config.server_address, config.socket_mark, protect).await?;
        let connector = TlsConnector::from(Arc::new(tls::noise_discovery_tls_configuration()?));
        let name = ServerName::try_from(config.server_name.clone()).map_err(|_| RelayError::InvalidConfiguration)?;
        let mut stream = connector.connect(name, stream).await.map_err(|_| RelayError::HandshakeFailed)?;
        let mut handshake = initiator_handshake(&config.client_private_key, &config.server_public_key, PROLOGUE)?;
        let mut message = vec![0_u8; MAX_MESSAGE];
        let length = handshake.write_message(checkpoint, &mut message)?;
        let header = format!("POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n", config.server_name);
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(&message[..length]).await?;
        stream.flush().await?;
        let header = https::read_header(&mut stream).await?;
        let mut fields = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut fields);
        if !matches!(response.parse(&header), Ok(httparse::Status::Complete(_))) || response.code != Some(200)
            || response.headers.iter().any(|field| field.name.eq_ignore_ascii_case("transfer-encoding")) { return Err(RelayError::HandshakeFailed); }
        let length = https::one_header(response.headers, "content-length").and_then(|value| value.parse::<usize>().ok()).filter(|length| (48..=256).contains(length)).ok_or(RelayError::HandshakeFailed)?;
        let mut encrypted = vec![0_u8; length];
        stream.read_exact(&mut encrypted).await?;
        let mut result = [0_u8; 256];
        let length = handshake.read_message(&encrypted, &mut result)?;
        if !handshake.is_handshake_finished() { return Err(RelayError::HandshakeFailed); }
        match &result[..length] { b"accepted" => Ok(true), b"rejected" => Ok(false), _ => Err(RelayError::HandshakeFailed) }
    }).await.map_err(|_| RelayError::HandshakeFailed)?
}

pub(super) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    headers: &[httparse::Header<'_>],
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
    client_connections: &ClientConnectionRegistry,
) -> Result<bool, RelayError> {
    if https::one_header(headers, "host").is_none()
        || headers
            .iter()
            .any(|field| field.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Ok(false);
    }
    let Some(length) = https::one_header(headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| (96..=MAX_MESSAGE).contains(length))
    else {
        return Ok(false);
    };
    let mut message = vec![0_u8; length];
    timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut message))
        .await
        .map_err(|_| RelayError::HandshakeFailed)??;
    let mut handshake = responder_handshake(&config.server_private_key, PROLOGUE)?;
    let mut checkpoint = vec![0_u8; MAX_MESSAGE];
    let Ok(length) = handshake.read_message(&message, &mut checkpoint) else {
        return Ok(false);
    };
    if length == 0 || length > MAX_CHECKPOINT {
        return Ok(false);
    }
    checkpoint.truncate(length);
    let Some(client) = handshake
        .get_remote_static()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    else {
        return Ok(false);
    };
    if !authorized.contains(&client) {
        return Ok(false);
    }
    let Some(_permit) = client_connections.acquire(client) else {
        return Ok(false);
    };
    if !replay_cache
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert_once(&message)
    {
        return Ok(false);
    }
    let accepted = authorized
        .offer_endpoint_checkpoint(client, checkpoint)
        .await;
    let mut message = [0_u8; 256];
    let length = handshake.write_message(
        if accepted { b"accepted" } else { b"rejected" },
        &mut message,
    )?;
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {length}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    );
    timeout(HANDSHAKE_TIMEOUT, async {
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(&message[..length]).await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)??;
    Ok(true)
}
