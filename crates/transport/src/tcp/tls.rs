use super::*;

#[derive(Debug)]
struct PinnedCertificateVerifier {
    expected_sha256: Option<[u8; 32]>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self
            .expected_sha256
            .is_some_and(|expected| actual != expected)
        {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(super) fn tls_client_configuration(
    certificate_sha256: [u8; 32],
) -> Result<ClientConfig, RelayError> {
    configuration(Some(certificate_sha256))
}

/// Used exclusively by the bounded Noise-authenticated endpoint discovery RPC.
/// The Noise IK server pin authenticates that entire response independently of
/// TLS. VPN relay connections always use `tls_client_configuration` with a pin.
pub(super) fn noise_discovery_tls_configuration() -> Result<ClientConfig, RelayError> {
    configuration(None)
}

/// Discovery and publication accept the VPS's replaceable certificate, but a CDN's
/// certificate must be WebPKI-valid, like the HTTPS transport through it.
pub(super) fn control_tls_configuration(
    config: &super::EndpointDiscoveryConfig,
) -> Result<ClientConfig, RelayError> {
    if config.through_cdn {
        cdn_tls_configuration()
    } else {
        noise_discovery_tls_configuration()
    }
}

fn configuration(certificate_sha256: Option<[u8; 32]>) -> Result<ClientConfig, RelayError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinnedCertificateVerifier {
        expected_sha256: certificate_sha256,
        provider: provider.clone(),
    });
    let mut configuration = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RelayError::InvalidConfiguration)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(configuration)
}

/// HTTPS through a CDN meets the CDN's certificate, so it is verified like a browser
/// would: WebPKI roots and the configured name. The origin pin cannot apply there, and
/// Noise IK inside the WebSocket still authenticates the server.
pub(super) fn cdn_tls_configuration() -> Result<ClientConfig, RelayError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(cdn_roots()),
        provider.clone(),
    )
    .build()
    .map_err(|_| RelayError::InvalidConfiguration)?;
    let mut configuration = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RelayError::InvalidConfiguration)?
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(configuration)
}

#[cfg(test)]
pub(super) static TEST_CDN_ROOT: std::sync::OnceLock<CertificateDer<'static>> =
    std::sync::OnceLock::new();

fn cdn_roots() -> rustls::RootCertStore {
    #[cfg(test)]
    if let Some(root) = TEST_CDN_ROOT.get() {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.clone()).expect("test root");
        return roots;
    }
    system_roots()
}

/// The operating system's trust store. Android keeps PEM files in Conscrypt's updatable
/// directory (Android 14+) or the system image, which rustls-native-certs does not read.
fn system_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    #[cfg(target_os = "android")]
    for directory in [
        "/apex/com.android.conscrypt/cacerts",
        "/system/etc/security/cacerts",
    ] {
        use rustls::pki_types::pem::PemObject;
        for entry in std::fs::read_dir(directory).into_iter().flatten().flatten() {
            if let Ok(certificate) = CertificateDer::from_pem_file(entry.path()) {
                let _ = roots.add(certificate);
            }
        }
        if !roots.is_empty() {
            break;
        }
    }
    #[cfg(not(target_os = "android"))]
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    roots
}

#[cfg(test)]
mod tests {
    #[test]
    fn system_roots_load_from_the_operating_system() {
        assert!(!super::system_roots().is_empty());
    }
}
