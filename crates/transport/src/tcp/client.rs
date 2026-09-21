use super::*;

pub async fn run_tcp_client_relay<F>(
    config: TcpClientRelayConfig,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
{
    run_tcp_client_relay_with_remote_socket_setup(
        config,
        || async { Ok(()) },
        || async { Ok(()) },
        ready,
    )
    .await
}

pub async fn run_tcp_client_relay_with_remote_socket_setup<
    F,
    Before,
    BeforeFuture,
    After,
    AfterFuture,
>(
    config: TcpClientRelayConfig,
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
    run_tcp_client_inner(
        config,
        before_remote_socket,
        after_remote_socket,
        |_| Ok(()),
        ready,
    )
    .await
}

pub async fn run_tcp_client_relay_with_socket_protector<F, Protect>(
    config: TcpClientRelayConfig,
    protect: Protect,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
    Protect: FnOnce(&Socket) -> Result<(), RelayError>,
{
    run_tcp_client_inner(
        config,
        || async { Ok(()) },
        || async { Ok(()) },
        protect,
        ready,
    )
    .await
}

async fn run_tcp_client_inner<F, Before, BeforeFuture, After, AfterFuture, Protect>(
    config: TcpClientRelayConfig,
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
    let stream_result =
        connect_marked_protected(config.server_address, config.socket_mark, protect).await;
    let release_result = after_remote_socket().await;
    release_result?;
    relay_client_stream(
        local_socket,
        stream_result?,
        &client_private,
        &server_public,
        TCP_NOISE_PROLOGUE,
        ready,
    )
    .await
}

pub async fn run_tls_like_client_relay<F>(
    config: TlsLikeClientRelayConfig,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
{
    run_tls_like_client_relay_with_remote_socket_setup(
        config,
        || async { Ok(()) },
        || async { Ok(()) },
        ready,
    )
    .await
}

pub async fn run_tls_like_client_relay_with_remote_socket_setup<
    F,
    Before,
    BeforeFuture,
    After,
    AfterFuture,
>(
    config: TlsLikeClientRelayConfig,
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
    run_tls_client_inner(
        config,
        before_remote_socket,
        after_remote_socket,
        |_| Ok(()),
        ready,
    )
    .await
}

pub async fn run_tls_like_client_relay_with_socket_protector<F, Protect>(
    config: TlsLikeClientRelayConfig,
    protect: Protect,
    ready: F,
) -> Result<(), RelayError>
where
    F: FnOnce(),
    Protect: FnOnce(&Socket) -> Result<(), RelayError>,
{
    run_tls_client_inner(
        config,
        || async { Ok(()) },
        || async { Ok(()) },
        protect,
        ready,
    )
    .await
}

async fn run_tls_client_inner<F, Before, BeforeFuture, After, AfterFuture, Protect>(
    config: TlsLikeClientRelayConfig,
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
    let (client_private, server_public, certificate_sha256) = config.decoded_material()?;
    let local_socket = crate::socket_policy::bind_loopback(config.local_listen)?;
    before_remote_socket().await?;
    let stream_result =
        connect_marked_protected(config.server_address, config.socket_mark, protect).await;
    let release_result = after_remote_socket().await;
    release_result?;
    let connector = TlsConnector::from(Arc::new(tls_client_configuration(certificate_sha256)?));
    if config.https.as_ref().is_some_and(|https| !https.is_valid()) {
        return Err(RelayError::InvalidConfiguration);
    }
    let server_name = ServerName::try_from(
        config
            .https
            .as_ref()
            .map_or(TLS_LIKE_SERVER_NAME, |https| https.server_name.as_str())
            .to_owned(),
    )
    .map_err(|_| RelayError::InvalidConfiguration)?;
    let tls_stream = timeout(
        HANDSHAKE_TIMEOUT,
        connector.connect(server_name, stream_result?),
    )
    .await
    .map_err(|_| RelayError::HandshakeFailed)?
    .map_err(|_| RelayError::HandshakeFailed)?;
    if let Some(https) = &config.https {
        return https::client(
            local_socket,
            tls_stream,
            https,
            config.server_address.port(),
            &client_private,
            &server_public,
            ready,
        )
        .await;
    }
    relay_client_stream(
        local_socket,
        tls_stream,
        &client_private,
        &server_public,
        TLS_LIKE_NOISE_PROLOGUE,
        ready,
    )
    .await
}
