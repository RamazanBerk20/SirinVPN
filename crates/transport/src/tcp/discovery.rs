//! A small control RPC for learning a changed TLS pin or endpoint. Its Noise IK
//! identity pin is independent of the replaceable HTTPS certificate. No datagram
//! relay or private management API is exposed through this channel.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const PROLOGUE: &[u8] = b"SirinVPN signed endpoint discovery v1";
const MAX_CHECKPOINT: usize = 24 * 1024;
const MAX_RESPONSE: usize = MAX_CHECKPOINT + 128;

pub struct EndpointDiscoveryConfig {
    pub server_address: SocketAddr,
    pub server_name: String,
    pub client_private_key: Zeroizing<[u8; 32]>,
    pub server_public_key: [u8; 32],
    pub socket_mark: Option<u32>,
}

/// Returns only Noise-authenticated bytes. The caller must verify the enclosed
/// checkpoint's management signature, identity bindings and increasing generation
/// before using any address, port or certificate from it.
pub async fn fetch_endpoint_checkpoint(
    config: EndpointDiscoveryConfig,
) -> Result<Option<Vec<u8>>, RelayError> {
    fetch_endpoint_checkpoint_with_socket_protector(config, |_| Ok(())).await
}

pub async fn fetch_endpoint_checkpoint_with_socket_protector<Protect>(
    config: EndpointDiscoveryConfig,
    protect: Protect,
) -> Result<Option<Vec<u8>>, RelayError>
where
    Protect: FnOnce(&Socket) -> Result<(), RelayError>,
{
    timeout(Duration::from_secs(5), async {
        let stream =
            connect_marked_protected(config.server_address, config.socket_mark, protect).await?;
        let connector = TlsConnector::from(Arc::new(tls::noise_discovery_tls_configuration()?));
        let name = ServerName::try_from(config.server_name.clone())
            .map_err(|_| RelayError::InvalidConfiguration)?;
        let stream = connector
            .connect(name, stream)
            .await
            .map_err(|_| RelayError::HandshakeFailed)?;
        let mut stream = tokio::io::BufReader::with_capacity(8_192, stream);
        let mut handshake = initiator_handshake(
            &config.client_private_key,
            &config.server_public_key,
            PROLOGUE,
        )?;
        let mut message = [0_u8; HANDSHAKE_MAX_LENGTH];
        let length = handshake.write_message(&random_bytes(96), &mut message)?;
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            config.server_name,
            URL_SAFE_NO_PAD.encode(&message[..length])
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let header = https::read_header(&mut stream).await?;
        let mut fields = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut fields);
        if !matches!(response.parse(&header), Ok(httparse::Status::Complete(_)))
            || response.code != Some(200)
            || response
                .headers
                .iter()
                .any(|field| field.name.eq_ignore_ascii_case("transfer-encoding"))
        {
            return Err(RelayError::HandshakeFailed);
        }
        let length = https::one_header(response.headers, "content-length")
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| (48..=MAX_RESPONSE).contains(n))
            .ok_or(RelayError::HandshakeFailed)?;
        let mut encrypted = vec![0_u8; length];
        stream.read_exact(&mut encrypted).await?;
        let mut payload = vec![0_u8; MAX_RESPONSE];
        let length = handshake.read_message(&encrypted, &mut payload)?;
        if !handshake.is_handshake_finished() || length > MAX_CHECKPOINT {
            return Err(RelayError::HandshakeFailed);
        }
        payload.truncate(length);
        Ok((!payload.is_empty()).then_some(payload))
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)?
}

pub(super) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    headers: &[httparse::Header<'_>],
    config: &TcpServerRelayConfig,
    authorized: &AuthorizedPeers,
    replay_cache: &Mutex<HandshakeReplayCache>,
    client_connections: &ClientConnectionRegistry,
) -> Result<bool, RelayError> {
    if headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        || (headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-length"))
            && https::one_header(headers, "content-length") != Some("0"))
        || https::one_header(headers, "host").is_none()
    {
        return Ok(false);
    }
    let Some(request) = https::one_header(headers, "authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|token| URL_SAFE_NO_PAD.decode(token).ok())
        .filter(|request| (HANDSHAKE_MIN_LENGTH..=HANDSHAKE_MAX_LENGTH).contains(&request.len()))
    else {
        return Ok(false);
    };
    let mut handshake = responder_handshake(&config.server_private_key, PROLOGUE)?;
    if handshake
        .read_message(&request, &mut [0_u8; HANDSHAKE_MAX_LENGTH])
        .is_err()
    {
        return Ok(false);
    }
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
        .insert_once(&request)
    {
        return Ok(false);
    }
    let checkpoint = authorized.endpoint_checkpoint().unwrap_or_default();
    let mut response = vec![0_u8; MAX_RESPONSE];
    let length = handshake.write_message(&checkpoint, &mut response)?;
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {length}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    );
    timeout(HANDSHAKE_TIMEOUT, async {
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(&response[..length]).await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)??;
    Ok(true)
}
