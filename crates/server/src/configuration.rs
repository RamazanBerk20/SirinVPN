//! Configuration.

use super::*;

pub fn load_configuration(paths: &ServerPaths) -> Result<ServerConfiguration> {
    let bytes = fs::read(&paths.configuration).context("server configuration is unavailable")?;
    let configuration: ServerConfiguration =
        serde_json::from_slice(&bytes).context("server configuration is invalid")?;
    validate_configuration(&configuration)?;
    Ok(configuration)
}

pub(super) fn load_operational_configuration(
    paths: &ServerPaths,
) -> Result<Option<OperationalConfiguration>> {
    let metadata = match fs::symlink_metadata(&paths.operational_configuration) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_OPERATIONAL_CONFIGURATION_BYTES
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != 0o640
    {
        bail!("server operational configuration is invalid");
    }
    let encoded = fs::read(&paths.operational_configuration)
        .context("server operational configuration is unavailable")?;
    let configuration: OperationalConfiguration =
        serde_json::from_slice(&encoded).context("server operational configuration is invalid")?;
    if configuration.schema_version != OPERATIONAL_CONFIGURATION_SCHEMA_VERSION
        || configuration.ssh_port == 0
        || !is_safe_interface_name(&configuration.external_interface)
    {
        bail!("server operational configuration is invalid");
    }
    Ok(Some(configuration))
}

pub(super) fn is_safe_interface_name(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 15
        && interface
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.:-".contains(character))
}

pub(super) fn validate_configuration(configuration: &ServerConfiguration) -> Result<()> {
    validate_server_dns_configuration(
        configuration.schema_version,
        &configuration.dns_upstream,
        &configuration.private_dns_records,
    )
    .context("server configuration version is unsupported")?;
    validate_server_name(&configuration.server_name)?;
    let https = configuration
        .tls_like
        .as_ref()
        .and_then(|endpoint| endpoint.https.as_ref());
    if (configuration.schema_version < 7 && https.is_some())
        || (configuration.schema_version == 7 && https.is_none())
        || https.is_some_and(|value| !value.is_valid())
        || configuration
            .https_certificate_pem
            .as_ref()
            .is_some_and(|pem| https.is_none() || pem.is_empty() || pem.len() > 65_536)
    {
        bail!("HTTPS transport metadata requires configuration schema 7");
    }
    if (configuration.schema_version == 8) != configuration.public_endpoint.is_some()
        || (configuration.public_endpoint.is_none()
            && !configuration.alternate_endpoint_hosts.is_empty())
    {
        bail!("public endpoint metadata requires configuration schema 8");
    }
    if let Some(endpoint) = &configuration.public_endpoint {
        anyhow::ensure!(
            endpoint.wireguard_port == configuration.wireguard_port,
            "public endpoint port does not match the listener"
        );
        authorization::validate_endpoint_descriptor(
            &endpoint_transition::configuration_endpoint_descriptor(configuration, &endpoint.host),
        )?;
    }
    if configuration.interface_name != INTERFACE_NAME
        || configuration.tunnel_cidr != TUNNEL_CIDR
        || configuration.server_tunnel_address != SERVER_TUNNEL_ADDRESS.parse::<IpAddr>()?
        || configuration.wireguard_port == 0
        || configuration.management_port != DEFAULT_MANAGEMENT_PORT
    {
        bail!("server configuration contains unsupported network settings");
    }
    validate_wireguard_public_key(&configuration.wireguard_public_key)?;
    if let Some(obfuscated) = &configuration.obfuscated_udp {
        if obfuscated.port == 0 || obfuscated.port == configuration.wireguard_port {
            bail!("server configuration contains an invalid Obfuscated UDP port");
        }
        decode_key(&obfuscated.server_public_key)
            .map_err(|_| anyhow!("server configuration contains an invalid transport identity"))?;
    }
    if let Some(tcp) = &configuration.tcp_fallback {
        if tcp.port == 0 || tcp.port == configuration.wireguard_port {
            bail!("server configuration contains an invalid TCP fallback port");
        }
        decode_key(&tcp.server_public_key)
            .map_err(|_| anyhow!("server configuration contains an invalid transport identity"))?;
    }
    if let Some(tls_like) = &configuration.tls_like {
        if tls_like.port == 0 || tls_like.port == configuration.wireguard_port {
            bail!("server configuration contains an invalid TLS-like port");
        }
        if configuration
            .tcp_fallback
            .as_ref()
            .map(|endpoint| endpoint.port)
            != Some(tls_like.port)
        {
            bail!("the TLS-like and TCP fallback transports must share one public port");
        }
        decode_key(&tls_like.server_public_key)
            .map_err(|_| anyhow!("server configuration contains an invalid transport identity"))?;
        let fingerprint = STANDARD
            .decode(&tls_like.certificate_sha256)
            .context("server configuration contains an invalid TLS-like certificate fingerprint")?;
        if fingerprint.len() != 32 || STANDARD.encode(&fingerprint) != tls_like.certificate_sha256 {
            bail!("server configuration contains an invalid TLS-like certificate fingerprint");
        }
    }
    certificate_fingerprint(&configuration.owner_certificate_pem)?;
    Ok(())
}

pub fn validate_state(paths: &ServerPaths) -> Result<()> {
    let configuration = load_configuration(paths)?;
    let encoded_private_key = Zeroizing::new(
        fs::read(&paths.wireguard_private_key)
            .context("server WireGuard private key is unavailable")?,
    );
    validate_wireguard_private_key_binding(&configuration, encoded_private_key.as_slice())?;

    if configuration.obfuscated_udp.is_some()
        || configuration.tcp_fallback.is_some()
        || configuration.tls_like.is_some()
    {
        let encoded = Zeroizing::new(
            fs::read(&paths.transport_private_key)
                .context("server transport private key is unavailable")?,
        );
        validate_transport_private_key_binding(&configuration, encoded.as_slice())?;
    }

    if configuration.tls_like.is_some() {
        let private = Zeroizing::new(fs::read(&paths.transport_private_key)?);
        transport_tls_configuration(paths, &configuration, &private)?;
    }
    let client_certificates = match fs::metadata(&paths.authorization) {
        Ok(_) => {
            let authorization = load_authorization(&paths.authorization)?;
            if let Some(transition) = &authorization.endpoint_transition {
                verify_endpoint_transition_signature(&paths.tls_private_key, transition)?;
            }
            authorization.client_certificates(unix_time())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if authorization_is_required(paths)? {
                bail!("required server authorization state is unavailable");
            }
            vec![configuration.owner_certificate_pem.clone()]
        }
        Err(error) => return Err(error.into()),
    };
    tls_configuration(paths, &client_certificates)?;
    Ok(())
}

pub(super) fn validate_wireguard_private_key_binding(
    configuration: &ServerConfiguration,
    encoded_private_key: &[u8],
) -> Result<()> {
    let decoded_private_key = Zeroizing::new(
        STANDARD
            .decode(encoded_private_key)
            .context("server WireGuard private key is invalid")?,
    );
    let canonical_private_key = Zeroizing::new(STANDARD.encode(decoded_private_key.as_slice()));
    if canonical_private_key.as_bytes() != encoded_private_key {
        bail!("server WireGuard private key is not canonical base64");
    }
    let private_key: [u8; 32] = decoded_private_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("server WireGuard private key must contain 32 bytes"))?;
    let private_key = StaticSecret::from(*Zeroizing::new(private_key));
    let actual_public_key = STANDARD.encode(PublicKey::from(&private_key).as_bytes());
    if actual_public_key != configuration.wireguard_public_key {
        bail!("server WireGuard private key does not match its public identity");
    }
    Ok(())
}

pub(super) fn validate_transport_private_key_binding(
    configuration: &ServerConfiguration,
    encoded_private_key: &[u8],
) -> Result<()> {
    let private = decode_private_key(encoded_private_key, "server transport")?;
    let actual_public_key = STANDARD.encode(PublicKey::from(&private).as_bytes());
    if configuration
        .obfuscated_udp
        .as_ref()
        .is_some_and(|endpoint| endpoint.server_public_key != actual_public_key)
        || configuration
            .tcp_fallback
            .as_ref()
            .is_some_and(|endpoint| endpoint.server_public_key != actual_public_key)
        || configuration
            .tls_like
            .as_ref()
            .is_some_and(|endpoint| endpoint.server_public_key != actual_public_key)
    {
        bail!("server transport private key does not match its public identity");
    }
    if let Some(endpoint) = &configuration.tls_like {
        let certificate = if let Some(pem) = &configuration.https_certificate_pem {
            CertificateDer::from_pem_slice(pem.as_bytes())?
        } else {
            let name = endpoint
                .https
                .as_ref()
                .map_or(TLS_LIKE_SERVER_NAME, |https| https.server_name.as_str());
            tls_like_certificate_material_for_name(&private.to_bytes(), name)?.0
        };
        let actual_fingerprint = STANDARD.encode(Sha256::digest(certificate.as_ref()));
        if endpoint.certificate_sha256 != actual_fingerprint {
            bail!("server transport private key does not match its TLS-like certificate");
        }
    }
    Ok(())
}
