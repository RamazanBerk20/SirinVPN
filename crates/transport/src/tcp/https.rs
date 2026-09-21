use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use sirinvpn_protocol::HttpsTransport;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncBufReadExt, BufReader, DuplexStream, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream, accept_async_with_config, client_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};

const PROLOGUE: &[u8] = b"SirinVPN HTTPS WebSocket transport v1";
const MAX_HTTP_HEADER: usize = 8_192;
const COVER: &str = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Welcome</title><h1>Welcome</h1><p>The service is online.</p></html>\n";

fn websocket_configuration() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(4_096)
        .write_buffer_size(0)
        .max_write_buffer_size(8_192)
        .max_message_size(Some(MAX_FRAME_LENGTH))
        .max_frame_size(Some(MAX_FRAME_LENGTH))
        .accept_unmasked_frames(false)
}

pub(super) async fn client<S, F>(
    local_socket: UdpSocket,
    stream: S,
    https: &HttpsTransport,
    port: u16,
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    ready: F,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(),
{
    let (websocket, noise) = timeout(HANDSHAKE_TIMEOUT, async {
        let mut handshake = initiator_handshake(client_private, server_public, PROLOGUE)?;
        let mut request_message = [0_u8; HANDSHAKE_MAX_LENGTH];
        let length = handshake.write_message(
            &random_bytes(OsRng.gen_range(48..=144)),
            &mut request_message,
        )?;
        let mut request = format!("wss://{}:{}{}", https.server_name, port, https.path)
            .into_client_request()
            .map_err(|_| RelayError::InvalidConfiguration)?;
        request.headers_mut().insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(&request_message[..length])
            )
            .parse()
            .map_err(|_| RelayError::InvalidConfiguration)?,
        );
        let (mut websocket, _) =
            client_async_with_config(request, stream, Some(websocket_configuration()))
                .await
                .map_err(|_| RelayError::HandshakeFailed)?;
        let Some(Ok(Message::Binary(response))) = websocket.next().await else {
            return Err(RelayError::HandshakeFailed);
        };
        if response.len() > HANDSHAKE_MAX_LENGTH {
            return Err(RelayError::HandshakeFailed);
        }
        handshake.read_message(&response, &mut [0_u8; HANDSHAKE_MAX_LENGTH])?;
        Ok((websocket, handshake.into_stateless_transport_mode()?))
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)??;
    let (stream, bridge) = tokio::io::duplex(8_192);
    tokio::select! {
        result = relay_client_session(local_socket, stream, noise, ready) => result,
        result = bridge_records(websocket, bridge) => result,
    }
}

pub(super) async fn server<S>(
    stream: S,
    mode: TlsServerMode,
    config: TcpServerRelayConfig,
    authorized: AuthorizedPeers,
    activity: ActiveTransportRegistry,
    replay_cache: Arc<Mutex<HandshakeReplayCache>>,
    client_connections: ClientConnectionRegistry,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let https = mode.https;
    let discovery_only = mode.discovery_only;
    let mut stream = BufReader::with_capacity(MAX_HTTP_HEADER, stream);
    let first = timeout(HANDSHAKE_TIMEOUT, stream.fill_buf())
        .await
        .map_err(|_| RelayError::HandshakeFailed)??;
    if first.first().is_none_or(|byte| !byte.is_ascii_alphabetic()) {
        if discovery_only {
            return Err(RelayError::HandshakeFailed);
        }
        return handle_server_connection(
            stream,
            config,
            authorized,
            activity,
            replay_cache,
            client_connections,
            TcpOuterProtocol::TlsLike,
        )
        .await;
    }
    let header = timeout(HANDSHAKE_TIMEOUT, read_header(&mut stream))
        .await
        .map_err(|_| RelayError::HandshakeFailed)??;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    if !matches!(request.parse(&header), Ok(httparse::Status::Complete(_))) {
        return cover_response(&mut stream, 404, false).await;
    }
    let head_only = request.method == Some("HEAD");
    let root = matches!(request.method, Some("GET" | "HEAD")) && request.path == Some("/");
    if request.method == Some("GET")
        && request.path == Some("/")
        && super::discovery::serve(
            &mut stream,
            request.headers,
            &config,
            &authorized,
            &replay_cache,
            &client_connections,
        )
        .await?
    {
        return Ok(());
    }
    if request.method == Some("POST")
        && request.path == Some("/")
        && super::publication::serve(
            &mut stream,
            request.headers,
            &config,
            &authorized,
            &replay_cache,
            &client_connections,
        )
        .await?
    {
        return Ok(());
    }
    if discovery_only {
        return cover_response(&mut stream, if root { 200 } else { 404 }, head_only).await;
    }
    let Some(https) = https else {
        return cover_response(&mut stream, if root { 200 } else { 404 }, head_only).await;
    };
    let authority = one_header(request.headers, "host");
    let host_valid = authority.is_some_and(|host| {
        host.eq_ignore_ascii_case(&https.server_name)
            || host.rsplit_once(':').is_some_and(|(name, port)| {
                name.eq_ignore_ascii_case(&https.server_name)
                    && port.parse::<u16>().is_ok_and(|port| port != 0)
            })
    });
    let body_absent = (!request
        .headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("content-length"))
        || one_header(request.headers, "content-length") == Some("0"))
        && !request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("transfer-encoding"));
    let token = one_header(request.headers, "authorization")
        .and_then(|value| value.strip_prefix("Bearer "));
    let authenticated = if request.method == Some("GET")
        && request.path == Some(https.path.as_str())
        && host_valid
        && body_absent
    {
        token
            .and_then(|token| URL_SAFE_NO_PAD.decode(token).ok())
            .filter(|bytes| bytes.len() <= HANDSHAKE_MAX_LENGTH)
            .and_then(|message| {
                accept_handshake_message(&message, &config, &authorized, &replay_cache, PROLOGUE)
                    .ok()
                    .flatten()
            })
    } else {
        None
    };
    let Some((noise, client_static, response)) = authenticated else {
        return cover_response(&mut stream, if root { 200 } else { 404 }, head_only).await;
    };
    let Some(_client_permit) = client_connections.acquire(client_static) else {
        return cover_response(&mut stream, 404, head_only).await;
    };
    let replayed = PrefixedStream {
        prefix: header,
        consumed: 0,
        stream,
    };
    let mut websocket = timeout(
        HANDSHAKE_TIMEOUT,
        accept_async_with_config(replayed, Some(websocket_configuration())),
    )
    .await
    .map_err(|_| RelayError::HandshakeFailed)?
    .map_err(|_| RelayError::HandshakeFailed)?;
    websocket
        .send(Message::Binary(response.into()))
        .await
        .map_err(|_| RelayError::HandshakeFailed)?;
    let (stream, bridge) = tokio::io::duplex(8_192);
    tokio::select! {
        result = relay_server_session(stream, config, authorized, activity, noise, client_static, TcpOuterProtocol::TlsLike) => result,
        result = bridge_records(websocket, bridge) => result,
    }
}

pub(super) fn one_header<'a>(headers: &'a [httparse::Header<'a>], name: &str) -> Option<&'a str> {
    let mut matches = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let value = std::str::from_utf8(matches.next()?.value).ok()?;
    if matches.next().is_some() {
        return None;
    }
    Some(value)
}

pub(super) async fn read_header<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, RelayError> {
    let mut header = Vec::with_capacity(1_024);
    while header.len() < MAX_HTTP_HEADER {
        header.push(stream.read_u8().await?);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(RelayError::HandshakeFailed)
}

async fn cover_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
    head_only: bool,
) -> Result<(), RelayError> {
    let (reason, body) = if code == 200 {
        ("OK", COVER)
    } else {
        ("Not Found", "Not found.\n")
    };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{}",
        body.len(),
        if head_only { "" } else { body }
    );
    timeout(HANDSHAKE_TIMEOUT, async {
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| RelayError::HandshakeFailed)??;
    Ok(())
}

/// Each WebSocket message contains one existing authenticated, padded record.
/// Bounded duplex buffers provide backpressure without spawning detached tasks.
async fn bridge_records<S: AsyncRead + AsyncWrite + Unpin>(
    websocket: WebSocketStream<S>,
    stream: DuplexStream,
) -> Result<(), RelayError> {
    let (mut sink, mut source) = websocket.split();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let outbound = async {
        loop {
            let record = read_frame(&mut reader, MAX_FRAME_LENGTH).await?;
            sink.send(Message::Binary(record.into()))
                .await
                .map_err(|_| RelayError::HandshakeFailed)?;
        }
        #[allow(unreachable_code)]
        Ok::<(), RelayError>(())
    };
    let inbound = async {
        while let Some(message) = source.next().await {
            match message.map_err(|_| RelayError::HandshakeFailed)? {
                Message::Binary(record) if !record.is_empty() => {
                    write_frame(&mut writer, &record).await?
                }
                // Tungstenite validates masking and automatically queues Pong/Close.
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Close(_) => return Ok(()),
                _ => return Err(RelayError::HandshakeFailed),
            }
        }
        Ok(())
    };
    tokio::select! { result = outbound => result, result = inbound => result }
}

struct PrefixedStream<S> {
    prefix: Vec<u8>,
    consumed: usize,
    stream: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.consumed < this.prefix.len() {
            let length = buffer.remaining().min(this.prefix.len() - this.consumed);
            buffer.put_slice(&this.prefix[this.consumed..this.consumed + length]);
            this.consumed += length;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut this.stream).poll_read(context, buffer)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}
