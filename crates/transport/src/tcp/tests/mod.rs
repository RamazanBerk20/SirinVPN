use super::*;

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::oneshot;

fn keypair() -> snow::Keypair {
    let parameters: NoiseParams = NOISE_PATTERN.parse().unwrap();
    Builder::new(parameters).generate_keypair().unwrap()
}

async fn unused_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

fn tls_acceptor() -> (TlsAcceptor, String) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let certificate = CertificateParams::new(vec![TLS_LIKE_SERVER_NAME.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let fingerprint = STANDARD.encode(Sha256::digest(certificate.der().as_ref()));
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
    );
    let mut configuration = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.der().clone()], private_key)
    .unwrap();
    configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
    (TlsAcceptor::from(Arc::new(configuration)), fingerprint)
}

mod authorized_tcp_relay_round_trips_udp_datagrams;
mod endpoint_control;
mod https_camouflage;
mod server_relay_preserves_a_fragmented_inbound_frame_during_outbound_traffic;
