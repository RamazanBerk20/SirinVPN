//! Runtime.

use super::*;

pub async fn serve(paths: &ServerPaths) -> Result<()> {
    let configuration = load_configuration(paths)?;
    let operational_configuration = load_operational_configuration(paths)?;
    if paths.authorization_required.exists() || fs::symlink_metadata(&paths.authorization).is_ok() {
        // Contain before parsing authority: corrupt state must not leave stale peers active.
        apply_nft_batch(
            &authorization_transaction::containment(&configuration, true),
            "startup authorization containment",
        )
        .await?;
    }
    let measurement_ready = measurement::install(&configuration).await.is_ok();
    let transport_peers = AuthorizedPeers::default();
    let authorization =
        load_runtime_authorization(paths)?.map(|document| Arc::new(RwLock::new(document)));
    let transport_activity = ActiveTransportRegistry::default();
    let state = AppState {
        recovery: Default::default(),
        measurement_ready,
        configuration: configuration.clone(),
        operational_configuration,
        paths: paths.clone(),
        authorization,
        redemption_failures: Arc::new(Mutex::new(HashMap::new())),
        live_metrics: Arc::new(Mutex::new(LiveMetricSampler::default())),
        transport_peers: transport_peers.clone(),
        transport_activity: transport_activity.clone(),
    };
    if let Some(authorization) = &state.authorization {
        let mut current = authorization.write().await;
        authorization_transaction::recover(
            &authorization_transaction::Host(&state),
            &state.recovery,
            &mut current,
        )
        .await?;
    }
    let address = SocketAddr::new(
        configuration.server_tunnel_address,
        configuration.management_port,
    );
    let listener = TcpListener::bind(address)
        .await
        .context("management listener could not bind to the VPN address")?;
    let router = management_router(state.clone());

    if state.authorization.is_some() {
        let cleanup_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut applied = None;
            let mut failures = 0u32;
            let mut retry_at = Instant::now();
            loop {
                interval.tick().await;
                if Instant::now() < retry_at {
                    continue;
                }
                let Some(authorization) = &cleanup_state.authorization else {
                    continue;
                };
                let mut current = authorization.write().await;
                let result = if authorization_transaction::needs_recovery(&cleanup_state.recovery) {
                    authorization_transaction::recover(
                        &authorization_transaction::Host(&cleanup_state),
                        &cleanup_state.recovery,
                        &mut current,
                    )
                    .await
                } else {
                    let mut next = current.clone();
                    next.prune_expired(unix_time());
                    let key = (next.clone(), next.desired_peers(unix_time()));
                    if applied.as_ref() == Some(&key) {
                        continue;
                    }
                    commit_authorization(&cleanup_state, &mut current, next)
                        .await
                        .map_err(|_| anyhow!("authorization reconciliation pending"))
                };
                if result.is_ok() {
                    applied = Some((current.clone(), current.desired_peers(unix_time())));
                    failures = 0;
                } else {
                    failures = failures.saturating_add(1).min(5);
                    retry_at = Instant::now() + Duration::from_secs(1 << failures);
                }
            }
        });
    }

    if state.authorization.is_some() && state.operational_configuration.is_some() {
        let observer = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let _ = endpoint_observation::observe(&observer).await;
            }
        });
    }
    let (publisher, mut publications) = tokio::sync::mpsc::channel(8);
    transport_peers.set_endpoint_publisher(publisher);
    let publication_state = state.clone();
    let publication = async move {
        while let Some(request) = publications.recv().await {
            endpoint_transition::publish_from_transport(&publication_state, request).await;
        }
        Ok::<(), anyhow::Error>(())
    };
    let management = serve_management(listener, state, router);
    if configuration.obfuscated_udp.is_none()
        && configuration.tcp_fallback.is_none()
        && configuration.tls_like.is_none()
    {
        return management.await;
    }
    let encoded_private_key = Zeroizing::new(
        fs::read(&paths.transport_private_key)
            .context("server transport private key is unavailable")?,
    );
    let private_key = decode_private_key(&encoded_private_key, "server transport")?.to_bytes();
    let tls_acceptor = configuration
        .tls_like
        .as_ref()
        .map(|_| {
            transport_tls_configuration(paths, &configuration, &encoded_private_key)
                .map(|configuration| TlsAcceptor::from(Arc::new(configuration)))
        })
        .transpose()?;
    let backend = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        configuration.wireguard_port,
    );
    let discovery_port = configuration.endpoint_discovery_port.filter(|port| {
        configuration
            .tls_like
            .as_ref()
            .is_some_and(|tls| tls.port != *port)
    });
    // Outer IPv6 works independently from IPv6 inside the tunnel, including
    // hostnames whose DNS currently has only AAAA records.
    let listen_address = if std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).is_ok()
    {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let discovery_tls = tls_acceptor.clone();
    let discovery_peers = transport_peers.clone();
    let discovery_relay = async move {
        let Some((port, acceptor)) = discovery_port.zip(discovery_tls) else {
            return std::future::pending::<Result<(), sirinvpn_transport::RelayError>>().await;
        };
        sirinvpn_transport::run_endpoint_discovery_server(
            TcpServerRelayConfig {
                listen: SocketAddr::new(listen_address, port),
                wireguard_backend: backend,
                server_private_key: Zeroizing::new(private_key),
            },
            acceptor,
            discovery_peers,
        )
        .await
    };
    let obfuscated = configuration.obfuscated_udp;
    let udp_peers = transport_peers.clone();
    let udp_activity = transport_activity.clone();
    let udp_relay = async move {
        let Some(endpoint) = obfuscated else {
            return std::future::pending::<Result<(), sirinvpn_transport::RelayError>>().await;
        };
        run_server_relay(
            ServerRelayConfig {
                listen: SocketAddr::new(listen_address, endpoint.port),
                wireguard_backend: backend,
                server_private_key: Zeroizing::new(private_key),
            },
            udp_peers,
            udp_activity,
        )
        .await
    };
    let https = configuration
        .tls_like
        .as_ref()
        .and_then(|endpoint| endpoint.https.clone());
    let tcp = configuration.tcp_fallback;
    let tcp_relay = async move {
        let Some(endpoint) = tcp else {
            return std::future::pending::<Result<(), sirinvpn_transport::RelayError>>().await;
        };
        let relay_config = TcpServerRelayConfig {
            listen: SocketAddr::new(listen_address, endpoint.port),
            wireguard_backend: backend,
            server_private_key: Zeroizing::new(private_key),
        };
        match tls_acceptor {
            Some(acceptor) if https.is_some() => {
                run_tcp_server_relay_with_https(
                    relay_config,
                    acceptor,
                    https.expect("HTTPS was checked"),
                    transport_peers,
                    transport_activity,
                )
                .await
            }
            Some(acceptor) => {
                run_tcp_server_relay_with_tls(
                    relay_config,
                    acceptor,
                    transport_peers,
                    transport_activity,
                )
                .await
            }
            None => run_tcp_server_relay(relay_config, transport_peers, transport_activity).await,
        }
    };
    tokio::select! {
        result = management => result,
        result = udp_relay => result.map_err(anyhow::Error::from),
        result = tcp_relay => result.map_err(anyhow::Error::from),
        result = discovery_relay => result.map_err(anyhow::Error::from),
        result = publication => result,
    }
}

pub(super) fn load_runtime_authorization(
    paths: &ServerPaths,
) -> Result<Option<AuthorizationDocument>> {
    match fs::metadata(&paths.authorization) {
        Ok(_) => {
            let document = load_authorization(&paths.authorization)?;
            if let Some(transition) = &document.endpoint_transition {
                verify_endpoint_transition_signature(&paths.tls_private_key, transition)?;
            }
            Ok(Some(document))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if authorization_is_required(paths)? {
                bail!("required server authorization state is unavailable");
            }
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn serve_management(
    listener: TcpListener,
    state: AppState,
    router: Router,
) -> Result<()> {
    // Bound unauthenticated TLS work as well as authenticated keep-alive sockets.
    let connections = Arc::new(tokio::sync::Semaphore::new(512));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let client_certificates = match &state.authorization {
            Some(authorization) => authorization.read().await.client_certificates(unix_time()),
            None => vec![state.configuration.owner_certificate_pem.clone()],
        };
        let Ok(tls_configuration) = tls_configuration(&state.paths, &client_certificates) else {
            continue;
        };
        let acceptor = TlsAcceptor::from(Arc::new(tls_configuration));
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Some(tls_stream) =
                accept_management_tls(&acceptor, stream, Duration::from_secs(10)).await
            else {
                return;
            };
            let Some(peer_certificate) = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
            else {
                return;
            };
            let caller = CallerIdentity {
                certificate_fingerprint: hex::encode(Sha256::digest(peer_certificate.as_ref())),
            };
            let service = TowerToHyperService::new(router.layer(Extension(caller)));
            let io = TokioIo::new(tls_stream);
            let mut connection = ConnectionBuilder::new(TokioExecutor::new());
            connection
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10));
            connection.http2().max_concurrent_streams(16);
            let _ = connection.serve_connection(io, service).await;
        });
    }
}

pub(super) fn tls_configuration(
    paths: &ServerPaths,
    client_certificates: &[String],
) -> Result<ServerConfig> {
    let certificate_bytes = fs::read(&paths.tls_certificate)?;
    let private_key_bytes = Zeroizing::new(fs::read(&paths.tls_private_key)?);
    tls_configuration_from_material(
        &certificate_bytes,
        private_key_bytes.as_slice(),
        client_certificates,
    )
}

pub(super) fn tls_configuration_from_material(
    certificate_bytes: &[u8],
    private_key_bytes: &[u8],
    client_certificates: &[String],
) -> Result<ServerConfig> {
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(certificate_bytes).collect::<Result<_, _>>()?;
    let private_key = PrivateKeyDer::from_pem_slice(private_key_bytes)
        .map_err(|_| anyhow!("server management key is unavailable"))?;

    let mut client_roots = RootCertStore::empty();
    for certificate_pem in client_certificates {
        let certificates: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(certificate_pem.as_bytes()).collect::<Result<_, _>>()?;
        if certificates.len() != 1 {
            bail!("each client identity must contain exactly one certificate");
        }
        client_roots.add(certificates[0].clone())?;
    }
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots),
        crypto_provider.clone(),
    )
    .build()?;
    let configuration = ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)?;
    Ok(configuration)
}

pub(super) async fn accept_management_tls(
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
    deadline: Duration,
) -> Option<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    tokio::time::timeout(deadline, acceptor.accept(stream))
        .await
        .ok()?
        .ok()
}
