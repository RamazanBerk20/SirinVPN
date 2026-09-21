use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsCertificatePaths {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

pub(super) fn read_https_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?.take(65_537).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= 65_536,
        "HTTPS certificate material is empty or oversized"
    );
    Ok(bytes)
}

pub(super) fn custom_certificate_configuration(
    certificate_pem: &[u8],
    key_pem: &[u8],
    https: &sirinvpn_protocol::HttpsTransport,
) -> Result<(ServerConfig, String)> {
    anyhow::ensure!(https.is_valid(), "invalid HTTPS hostname or path");
    let certificates =
        CertificateDer::pem_slice_iter(certificate_pem).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        !certificates.is_empty() && certificates.len() <= 8,
        "invalid HTTPS certificate chain"
    );
    let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
        .map_err(|_| anyhow!("invalid HTTPS leaf certificate"))?;

    let names = leaf
        .subject_alternative_name()?
        .ok_or_else(|| anyhow!("HTTPS certificate needs a DNS subject alternative name"))?;
    let name_valid = names.value.general_names.iter().any(|name| {
        let x509_parser::extensions::GeneralName::DNSName(name) = name else {
            return false;
        };
        if name.eq_ignore_ascii_case(&https.server_name) {
            return true;
        }
        name.strip_prefix("*.").is_some_and(|suffix| {
            https
                .server_name
                .split_once('.')
                .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case(suffix))
        })
    });
    anyhow::ensure!(
        name_valid,
        "HTTPS certificate does not cover the configured hostname"
    );
    let fingerprint = STANDARD.encode(Sha256::digest(certificates[0].as_ref()));
    let private_key = PrivateKeyDer::from_pem_slice(key_pem)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // rustls checks that the supplied private key matches the certificate.
    let mut configuration = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((configuration, fingerprint))
}

pub(super) fn configure_https_identity(
    paths: &ServerPaths,
    endpoint: &mut TlsLikeEndpoint,
    https: sirinvpn_protocol::HttpsTransport,
    certificate_paths: Option<&HttpsCertificatePaths>,
    current_certificate: Option<&str>,
) -> Result<Option<String>> {
    anyhow::ensure!(https.is_valid(), "invalid HTTPS hostname or path");
    let certificate = if let Some(source) = certificate_paths {
        let certificate = read_https_file(&source.certificate)?;
        let key = read_https_file(&source.private_key)?;
        let certificate_der = CertificateDer::from_pem_slice(&certificate)?;
        let (_, leaf) = x509_parser::parse_x509_certificate(certificate_der.as_ref())
            .map_err(|_| anyhow!("invalid HTTPS certificate"))?;
        anyhow::ensure!(
            leaf.validity().is_valid(),
            "HTTPS certificate has expired or is not yet valid"
        );
        let (_, fingerprint) = custom_certificate_configuration(&certificate, &key, &https)?;
        let pem =
            String::from_utf8(certificate.to_vec()).context("HTTPS certificate is not PEM text")?;
        write_private(&paths.https_private_key, &key)?;
        endpoint.certificate_sha256 = fingerprint;
        Some(pem)
    } else if let Some(certificate) = current_certificate {
        let key = read_https_file(&paths.https_private_key)?;
        let (_, fingerprint) =
            custom_certificate_configuration(certificate.as_bytes(), &key, &https)?;
        endpoint.certificate_sha256 = fingerprint;
        Some(certificate.to_owned())
    } else {
        let encoded = Zeroizing::new(fs::read(&paths.transport_private_key)?);
        let private = decode_private_key(&encoded, "server transport")?;
        let (certificate, _) =
            tls_like_certificate_material_for_name(&private.to_bytes(), &https.server_name)?;
        endpoint.certificate_sha256 = STANDARD.encode(Sha256::digest(certificate.as_ref()));
        None
    };
    endpoint.https = Some(https);
    Ok(certificate)
}

pub(super) fn transport_tls_configuration(
    paths: &ServerPaths,
    configuration: &ServerConfiguration,
    encoded_private_key: &[u8],
) -> Result<ServerConfig> {
    if let Some(certificate) = &configuration.https_certificate_pem {
        let https = configuration
            .tls_like
            .as_ref()
            .and_then(|endpoint| endpoint.https.as_ref())
            .ok_or_else(|| anyhow!("HTTPS certificate has no endpoint metadata"))?;
        let key = read_https_file(&paths.https_private_key)?;
        let (tls, fingerprint) =
            custom_certificate_configuration(certificate.as_bytes(), &key, https)?;
        anyhow::ensure!(
            configuration
                .tls_like
                .as_ref()
                .is_some_and(|endpoint| endpoint.certificate_sha256 == fingerprint),
            "HTTPS certificate pin does not match configured identity"
        );
        Ok(tls)
    } else {
        let name = configuration
            .tls_like
            .as_ref()
            .and_then(|endpoint| endpoint.https.as_ref())
            .map_or(TLS_LIKE_SERVER_NAME, |https| https.server_name.as_str());
        tls_like_server_configuration_for_name(encoded_private_key, name)
    }
}
