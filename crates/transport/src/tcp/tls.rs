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
