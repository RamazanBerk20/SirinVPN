//! Initialization.

use super::*;

pub fn initialize(
    paths: &ServerPaths,
    server_name: &str,
    owner_certificate_pem: &str,
    server_id: ServerId,
    owner_wireguard_public_key: &str,
    wireguard_port: u16,
) -> Result<BootstrapResult> {
    initialize_with_capabilities(
        paths,
        server_name,
        owner_certificate_pem,
        server_id,
        owner_wireguard_public_key,
        wireguard_port,
        None,
    )
}

pub fn initialize_with_capabilities(
    paths: &ServerPaths,
    server_name: &str,
    owner_certificate_pem: &str,
    server_id: ServerId,
    owner_wireguard_public_key: &str,
    wireguard_port: u16,
    ipv6_tunnel_enabled: Option<bool>,
) -> Result<BootstrapResult> {
    initialize_with_transport_capabilities(
        paths,
        server_name,
        owner_certificate_pem,
        server_id,
        owner_wireguard_public_key,
        wireguard_port,
        ServerCapabilities {
            public_host: None,
            previous_public_host: None,
            alternate_endpoint_hosts: None,
            ipv6_tunnel_enabled,
            obfuscated_udp_port: None,
            tcp_fallback_port: None,
            tls_like_port: None,
            https: None,
            https_certificate: None,
            update_transport_ports: false,
            disable_https: false,
            dns_upstream: None,
            private_dns_records: None,
        },
    )
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServerCapabilities {
    pub public_host: Option<String>,
    pub previous_public_host: Option<String>,
    pub alternate_endpoint_hosts: Option<Vec<String>>,
    pub ipv6_tunnel_enabled: Option<bool>,
    pub obfuscated_udp_port: Option<u16>,
    pub tcp_fallback_port: Option<u16>,
    pub tls_like_port: Option<u16>,
    pub https: Option<sirinvpn_protocol::HttpsTransport>,
    pub https_certificate: Option<HttpsCertificatePaths>,
    pub update_transport_ports: bool,
    pub disable_https: bool,
    pub dns_upstream: Option<DnsUpstream>,
    pub private_dns_records: Option<Vec<PrivateDnsRecord>>,
}

pub fn initialize_with_transport_capabilities(
    paths: &ServerPaths,
    server_name: &str,
    owner_certificate_pem: &str,
    server_id: ServerId,
    owner_wireguard_public_key: &str,
    wireguard_port: u16,
    capabilities: ServerCapabilities,
) -> Result<BootstrapResult> {
    let ServerCapabilities {
        public_host,
        previous_public_host,
        alternate_endpoint_hosts,
        ipv6_tunnel_enabled,
        obfuscated_udp_port,
        tcp_fallback_port,
        tls_like_port,
        https,
        https_certificate,
        update_transport_ports,
        disable_https,
        dns_upstream,
        private_dns_records,
    } = capabilities;
    validate_server_name(server_name)?;
    for host in public_host.iter().chain(previous_public_host.iter()) {
        validate_host(host)?;
    }
    if let Some(hosts) = &alternate_endpoint_hosts {
        anyhow::ensure!(
            public_host
                .as_ref()
                .is_some_and(|host| sirinvpn_protocol::valid_alternate_endpoint_hosts(host, hosts)),
            "alternate addresses require a valid primary endpoint"
        );
    }
    if (disable_https && https.is_some())
        || https.as_ref().is_some_and(|value| !value.is_valid())
        || (https_certificate.is_some() && https.is_none())
        || (https.is_some() && tls_like_port.is_none())
    {
        bail!("HTTPS requires a valid hostname, path and TLS transport port");
    }
    if wireguard_port == 0 {
        bail!("WireGuard port must be non-zero");
    }
    if obfuscated_udp_port.is_some_and(|port| port == 0 || port == wireguard_port) {
        bail!("the Obfuscated UDP port must be non-zero and distinct from WireGuard");
    }
    if tcp_fallback_port.is_some_and(|port| port == 0 || port == wireguard_port) {
        bail!("the TCP fallback port must be non-zero and distinct from WireGuard");
    }
    if tls_like_port.is_some_and(|port| port == 0 || port == wireguard_port) {
        bail!("the TLS-like port must be non-zero and distinct from WireGuard");
    }
    if let Some(tls_port) = tls_like_port
        && tcp_fallback_port != Some(tls_port)
    {
        bail!("the TLS-like and TCP fallback transports must share one public port");
    }
    if let Some(dns_upstream) = &dns_upstream {
        validate_dns_upstream(dns_upstream)?;
    }
    if let Some(private_dns_records) = &private_dns_records {
        validate_private_dns_records(private_dns_records)?;
    }
    let existing_configuration = match fs::metadata(&paths.configuration) {
        Ok(_) => Some(load_configuration(paths).context(
            "existing server configuration is invalid; refusing to replace its identity",
        )?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(mut configuration) = existing_configuration {
        let previous_descriptor = configuration
            .public_endpoint
            .as_ref()
            .map(|endpoint| endpoint.host.as_str())
            .or(previous_public_host.as_deref())
            .or(public_host.as_deref())
            .map(|host| {
                endpoint_transition::configuration_endpoint_descriptor(&configuration, host)
            });
        let initial_discovery_port = configuration
            .endpoint_discovery_port
            .or_else(|| configuration.tls_like.as_ref().map(|tls| tls.port));
        match fs::metadata(&paths.authorization) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if configuration.owner_certificate_pem != owner_certificate_pem {
                    bail!("server is already claimed by a different owner identity");
                }
            }
            Err(error) => return Err(error.into()),
        }
        initialize_authorization(
            paths,
            server_id,
            owner_wireguard_public_key,
            owner_certificate_pem,
        )?;
        let transport_change = obfuscated_udp_port.is_some_and(|port| {
            configuration
                .obfuscated_udp
                .as_ref()
                .is_none_or(|endpoint| update_transport_ports && endpoint.port != port)
        }) || tcp_fallback_port.is_some_and(|port| {
            configuration
                .tcp_fallback
                .as_ref()
                .is_none_or(|endpoint| update_transport_ports && endpoint.port != port)
        }) || tls_like_port.is_some_and(|port| {
            configuration
                .tls_like
                .as_ref()
                .is_none_or(|endpoint| update_transport_ports && endpoint.port != port)
        }) || (update_transport_ports
            && configuration.wireguard_port != wireguard_port)
            || https.as_ref().is_some_and(|https| {
                configuration
                    .tls_like
                    .as_ref()
                    .and_then(|endpoint| endpoint.https.as_ref())
                    != Some(https)
            })
            || https_certificate.is_some()
            || (disable_https
                && configuration
                    .tls_like
                    .as_ref()
                    .is_some_and(|endpoint| endpoint.https.is_some()));
        let endpoint_change = public_host.as_ref().is_some_and(|host| {
            configuration
                .public_endpoint
                .as_ref()
                .is_some_and(|current| &current.host != host)
        }) || alternate_endpoint_hosts
            .as_ref()
            .is_some_and(|hosts| hosts != &configuration.alternate_endpoint_hosts)
            || ipv6_tunnel_enabled
                .is_some_and(|enabled| enabled != configuration.ipv6_tunnel_enabled);
        if (transport_change || endpoint_change) && paths.authorization.exists() {
            let mut authorization = load_authorization(&paths.authorization)?;
            authorization.prune_expired(unix_time());
            anyhow::ensure!(
                authorization.invitations.is_empty()
                    && authorization.enrollment_receipts.is_empty()
                    && authorization.key_rotations.is_empty()
                    && authorization.recovery_receipt.is_none(),
                "cancel active invitations and finish enrollment, recovery and key rotation handoffs before changing transport settings"
            );
        }
        let mut configuration_changed = false;
        if let Some(host) = &public_host {
            let endpoint = ServerEndpoint {
                host: host.clone(),
                wireguard_port: if update_transport_ports {
                    wireguard_port
                } else {
                    configuration.wireguard_port
                },
            };
            configuration_changed |= configuration.public_endpoint.as_ref() != Some(&endpoint);
            configuration.public_endpoint = Some(endpoint);
        }
        if let Some(hosts) = alternate_endpoint_hosts {
            configuration_changed |= hosts != configuration.alternate_endpoint_hosts;
            configuration.alternate_endpoint_hosts = hosts;
        }
        if update_transport_ports {
            if let Ok(authorization) = load_authorization(&paths.authorization) {
                for forward in &authorization.port_forwards {
                    let conflicts = match forward.protocol {
                        PortForwardProtocol::Tcp => {
                            [tcp_fallback_port, tls_like_port].contains(&Some(forward.public_port))
                        }
                        PortForwardProtocol::Udp => {
                            forward.public_port == wireguard_port
                                || obfuscated_udp_port == Some(forward.public_port)
                        }
                    };
                    if conflicts {
                        bail!(
                            "a requested transport port is used by an existing member port forward"
                        );
                    }
                }
            }
            if configuration.wireguard_port != wireguard_port {
                configuration.wireguard_port = wireguard_port;
                configuration_changed = true;
            }
            if let (Some(endpoint), Some(port)) =
                (configuration.obfuscated_udp.as_mut(), obfuscated_udp_port)
            {
                configuration_changed |= endpoint.port != port;
                endpoint.port = port;
            }
            if let (Some(endpoint), Some(port)) =
                (configuration.tcp_fallback.as_mut(), tcp_fallback_port)
            {
                configuration_changed |= endpoint.port != port;
                endpoint.port = port;
            }
            if let (Some(endpoint), Some(port)) = (configuration.tls_like.as_mut(), tls_like_port) {
                configuration_changed |= endpoint.port != port;
                endpoint.port = port;
            }
        }
        if let Some(enabled) = ipv6_tunnel_enabled
            && configuration.ipv6_tunnel_enabled != enabled
        {
            configuration.ipv6_tunnel_enabled = enabled;
            configuration_changed = true;
        }
        if configuration.obfuscated_udp.is_none()
            && let Some(port) = obfuscated_udp_port
        {
            configuration.obfuscated_udp = Some(ensure_transport_identity(paths, port)?);
            configuration_changed = true;
        }
        if configuration.tcp_fallback.is_none()
            && let Some(port) = tcp_fallback_port
        {
            let identity = ensure_transport_identity(paths, port)?;
            configuration.tcp_fallback = Some(TcpFallbackEndpoint {
                port,
                server_public_key: identity.server_public_key,
            });
            configuration_changed = true;
        }
        if configuration.tls_like.is_none()
            && let Some(port) = tls_like_port
        {
            if configuration
                .tcp_fallback
                .as_ref()
                .is_none_or(|endpoint| endpoint.port != port)
            {
                bail!(
                    "the TLS-like capability cannot migrate because the installed TCP fallback uses a different public port"
                );
            }
            configuration.tls_like = Some(ensure_tls_like_identity(paths, port)?);
            configuration_changed = true;
        }
        if let Some(dns_upstream) = dns_upstream
            && configuration.dns_upstream != dns_upstream
        {
            configuration.dns_upstream = dns_upstream;
            configuration_changed = true;
        }
        if let Some(private_dns_records) = private_dns_records
            && configuration.private_dns_records != private_dns_records
        {
            configuration.private_dns_records = private_dns_records;
            configuration_changed = true;
        }
        if let Some(https) = https {
            let endpoint = configuration
                .tls_like
                .as_mut()
                .ok_or_else(|| anyhow!("HTTPS requires a TLS transport"))?;
            configuration.https_certificate_pem = configure_https_identity(
                paths,
                endpoint,
                https,
                https_certificate.as_ref(),
                configuration.https_certificate_pem.as_deref(),
            )?;
            configuration_changed = true;
        }
        if disable_https && let Some(endpoint) = &mut configuration.tls_like {
            *endpoint = ensure_tls_like_identity(paths, endpoint.port)?;
            configuration.https_certificate_pem = None;
            configuration_changed = true;
        }
        if let Some(endpoint) = &mut configuration.public_endpoint {
            endpoint.wireguard_port = configuration.wireguard_port;
        }
        if configuration.public_endpoint.is_some()
            && configuration.endpoint_discovery_port.is_none()
        {
            configuration.endpoint_discovery_port = initial_discovery_port
                .or_else(|| configuration.tls_like.as_ref().map(|tls| tls.port));
            configuration_changed = true;
        }
        let schema_version = if configuration.public_endpoint.is_some() {
            8
        } else if configuration
            .tls_like
            .as_ref()
            .is_some_and(|endpoint| endpoint.https.is_some())
        {
            7
        } else {
            server_dns_configuration_schema_version(
                &configuration.dns_upstream,
                &configuration.private_dns_records,
            )
        };
        if configuration.schema_version != schema_version {
            configuration.schema_version = schema_version;
            configuration_changed = true;
        }
        if configuration_changed {
            validate_configuration(&configuration)?;
            write_json(&paths.configuration, &configuration)?;
            if disable_https && paths.https_private_key.exists() {
                fs::remove_file(&paths.https_private_key)?;
            }
        }
        let endpoint_transition = endpoint_transition::synchronize_configuration_endpoint(
            paths,
            &configuration,
            previous_descriptor,
        )?;
        return Ok(BootstrapResult {
            endpoint_transition,
            wireguard_public_key: configuration.wireguard_public_key,
            management_certificate_pem: fs::read_to_string(&paths.tls_certificate)
                .context("server certificate is unavailable")?,
            server_tunnel_address: configuration.server_tunnel_address,
            wireguard_port: configuration.wireguard_port,
            management_port: configuration.management_port,
            dns_upstream: configuration.dns_upstream,
            private_dns_records: configuration.private_dns_records,
            ipv6_tunnel_enabled: configuration.ipv6_tunnel_enabled,
            obfuscated_udp: configuration.obfuscated_udp,
            tcp_fallback: configuration.tcp_fallback,
            tls_like: configuration.tls_like,
        });
    }

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(&paths.state_directory)
        .context("could not create the SirinVPN state directory")?;
    fs::set_permissions(&paths.state_directory, fs::Permissions::from_mode(0o750))?;

    let wireguard_private = StaticSecret::random_from_rng(OsRng);
    let wireguard_public = PublicKey::from(&wireguard_private);
    let wireguard_private_bytes = Zeroizing::new(wireguard_private.to_bytes());
    let wireguard_private_encoded =
        Zeroizing::new(STANDARD.encode(wireguard_private_bytes.as_ref()));

    let tls_key = KeyPair::generate_for(&PKCS_ED25519)
        .context("could not generate the server management key")?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "SirinVPN local management");
    let mut certificate_parameters = CertificateParams::new(vec!["sirinvpn.local".to_owned()])
        .context("could not prepare the server management certificate")?;
    certificate_parameters.distinguished_name = distinguished_name;
    certificate_parameters.is_ca = IsCa::NoCa;
    certificate_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    certificate_parameters
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(
            10, 77, 0, 1,
        ))));
    let tls_certificate = certificate_parameters
        .self_signed(&tls_key)
        .context("could not self-sign the server management certificate")?;
    let tls_private_pem = Zeroizing::new(tls_key.serialize_pem());

    let obfuscated_udp = obfuscated_udp_port
        .map(|port| ensure_transport_identity(paths, port))
        .transpose()?;
    let tcp_fallback = tcp_fallback_port
        .map(|port| {
            ensure_transport_identity(paths, port).map(|identity| TcpFallbackEndpoint {
                port,
                server_public_key: identity.server_public_key,
            })
        })
        .transpose()?;
    let mut tls_like = tls_like_port
        .map(|port| ensure_tls_like_identity(paths, port))
        .transpose()?;

    let https_certificate_pem = if let Some(https) = https {
        configure_https_identity(
            paths,
            tls_like
                .as_mut()
                .ok_or_else(|| anyhow!("HTTPS requires a TLS transport"))?,
            https,
            https_certificate.as_ref(),
            None,
        )?
    } else {
        None
    };

    write_private(
        &paths.wireguard_private_key,
        wireguard_private_encoded.as_bytes(),
    )?;
    write_private(&paths.tls_private_key, tls_private_pem.as_bytes())?;
    write_private(&paths.tls_certificate, tls_certificate.pem().as_bytes())?;

    let dns_upstream = dns_upstream.unwrap_or_default();
    let private_dns_records = private_dns_records.unwrap_or_default();
    let configuration = ServerConfiguration {
        public_endpoint: public_host.clone().map(|host| ServerEndpoint {
            host,
            wireguard_port,
        }),
        endpoint_discovery_port: public_host
            .as_ref()
            .and_then(|_| tls_like.as_ref().map(|tls| tls.port)),
        alternate_endpoint_hosts: alternate_endpoint_hosts.unwrap_or_default(),
        schema_version: if public_host.is_some() {
            8
        } else if tls_like
            .as_ref()
            .is_some_and(|endpoint| endpoint.https.is_some())
        {
            7
        } else {
            server_dns_configuration_schema_version(&dns_upstream, &private_dns_records)
        },
        https_certificate_pem,
        server_name: server_name.to_owned(),
        interface_name: INTERFACE_NAME.to_owned(),
        tunnel_cidr: TUNNEL_CIDR.to_owned(),
        server_tunnel_address: SERVER_TUNNEL_ADDRESS.parse()?,
        wireguard_port,
        management_port: DEFAULT_MANAGEMENT_PORT,
        wireguard_public_key: STANDARD.encode(wireguard_public.as_bytes()),
        owner_certificate_pem: owner_certificate_pem.to_owned(),
        dns_upstream: dns_upstream.clone(),
        private_dns_records: private_dns_records.clone(),
        ipv6_tunnel_enabled: ipv6_tunnel_enabled.unwrap_or(false),
        obfuscated_udp: obfuscated_udp.clone(),
        tcp_fallback: tcp_fallback.clone(),
        tls_like: tls_like.clone(),
    };
    write_json(&paths.configuration, &configuration)?;
    initialize_authorization(
        paths,
        server_id,
        owner_wireguard_public_key,
        owner_certificate_pem,
    )?;

    let endpoint_transition =
        endpoint_transition::synchronize_configuration_endpoint(paths, &configuration, None)?;

    Ok(BootstrapResult {
        endpoint_transition,
        wireguard_public_key: configuration.wireguard_public_key,
        management_certificate_pem: tls_certificate.pem(),
        server_tunnel_address: configuration.server_tunnel_address,
        wireguard_port,
        management_port: DEFAULT_MANAGEMENT_PORT,
        dns_upstream,
        private_dns_records,
        ipv6_tunnel_enabled: configuration.ipv6_tunnel_enabled,
        obfuscated_udp,
        tcp_fallback,
        tls_like,
    })
}

pub(super) fn ensure_transport_identity(
    paths: &ServerPaths,
    port: u16,
) -> Result<ObfuscatedUdpEndpoint> {
    let private = match fs::read(&paths.transport_private_key) {
        Ok(encoded) => {
            let encoded = Zeroizing::new(encoded);
            decode_private_key(&encoded, "server transport")?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let private = StaticSecret::random_from_rng(OsRng);
            let encoded = Zeroizing::new(STANDARD.encode(private.to_bytes()));
            write_private(&paths.transport_private_key, encoded.as_bytes())?;
            private
        }
        Err(error) => return Err(error.into()),
    };
    Ok(ObfuscatedUdpEndpoint {
        port,
        server_public_key: STANDARD.encode(PublicKey::from(&private).as_bytes()),
    })
}

pub(super) fn ensure_tls_like_identity(paths: &ServerPaths, port: u16) -> Result<TlsLikeEndpoint> {
    let identity = ensure_transport_identity(paths, port)?;
    let encoded = Zeroizing::new(
        fs::read(&paths.transport_private_key)
            .context("server transport private key is unavailable")?,
    );
    let private = decode_private_key(&encoded, "server transport")?;
    let (certificate, _) = tls_like_certificate_material(&private.to_bytes())?;
    Ok(TlsLikeEndpoint {
        port,
        server_public_key: identity.server_public_key,
        certificate_sha256: STANDARD.encode(Sha256::digest(certificate.as_ref())),
        https: None,
    })
}

pub(super) fn tls_like_certificate_material(
    transport_private_key: &[u8; 32],
) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    tls_like_certificate_material_for_name(transport_private_key, TLS_LIKE_SERVER_NAME)
}

pub(super) fn tls_like_certificate_material_for_name(
    transport_private_key: &[u8; 32],
    server_name: &str,
) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let mut hasher = Sha256::new();
    hasher.update(TLS_LIKE_CERTIFICATE_KEY_CONTEXT);
    hasher.update(transport_private_key);
    let seed = Zeroizing::new(<[u8; 32]>::from(hasher.finalize()));
    let signing_key = SigningKey::from_bytes(&seed);
    let pkcs8 = signing_key
        .to_pkcs8_der()
        .context("could not derive the TLS-like certificate key")?;
    let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes());
    let certificate_key = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, &PKCS_ED25519)
        .context("could not load the TLS-like certificate key")?;

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, server_name);
    let mut parameters = CertificateParams::new(vec![server_name.to_owned()])
        .context("could not prepare the TLS-like certificate")?;
    parameters.distinguished_name = distinguished_name;
    parameters.is_ca = IsCa::NoCa;
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = parameters
        .self_signed(&certificate_key)
        .context("could not self-sign the TLS-like certificate")?;
    Ok((
        certificate.der().clone(),
        PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()),
    ))
}

pub(super) fn tls_like_server_configuration_for_name(
    encoded_transport_private_key: &[u8],
    server_name: &str,
) -> Result<ServerConfig> {
    let private = decode_private_key(encoded_transport_private_key, "server transport")?;
    let (certificate, private_key) =
        tls_like_certificate_material_for_name(&private.to_bytes(), server_name)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut configuration = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], PrivateKeyDer::Pkcs8(private_key))?;
    configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(configuration)
}

pub(super) fn decode_private_key(encoded: &[u8], label: &str) -> Result<StaticSecret> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .with_context(|| format!("{label} private key is invalid"))?,
    );
    if STANDARD.encode(decoded.as_slice()).as_bytes() != encoded {
        bail!("{label} private key is not canonical base64");
    }
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{label} private key must contain 32 bytes"))?;
    if key.iter().all(|byte| *byte == 0) {
        bail!("{label} private key is invalid");
    }
    Ok(StaticSecret::from(*Zeroizing::new(key)))
}

pub(super) fn initialize_authorization(
    paths: &ServerPaths,
    server_id: ServerId,
    owner_wireguard_public_key: &str,
    owner_certificate_pem: &str,
) -> Result<()> {
    match load_authorization(&paths.authorization) {
        Ok(document) => {
            if document.server_id != server_id {
                bail!("server authorization state belongs to a different local profile");
            }
            let owner_fingerprint = certificate_fingerprint(owner_certificate_pem)?;
            let owner_matches = document.devices.iter().any(|device| {
                device.certificate_fingerprint == owner_fingerprint
                    && device.wireguard_public_key == owner_wireguard_public_key
                    && document.role_for_device(device) == Some(ServerRole::Owner)
            });
            if !owner_matches {
                bail!("server authorization state belongs to a different owner identity");
            }
            write_private(&paths.authorization_required, b"authorization-schema=1\n")
        }
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|io_error| io_error.kind() == io::ErrorKind::NotFound) =>
        {
            if authorization_is_required(paths)? {
                bail!("required server authorization state is unavailable");
            }
            let authorization_directory = paths
                .authorization
                .parent()
                .context("authorization state path has no parent directory")?;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o750)
                .create(authorization_directory)?;
            fs::set_permissions(authorization_directory, fs::Permissions::from_mode(0o750))?;
            let document = AuthorizationDocument::new_owner(
                server_id,
                owner_wireguard_public_key.to_owned(),
                owner_certificate_pem.to_owned(),
            )?;
            write_authorization(&paths.authorization, &document)?;
            write_private(&paths.authorization_required, b"authorization-schema=1\n")
        }
        Err(error) => Err(error),
    }
}
