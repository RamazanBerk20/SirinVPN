//! TCP, TLS-like and HTTPS relay entry point for `fuzz/`; compiled only under `--cfg fuzzing`.
use super::*;
use std::sync::OnceLock;

const SERVER_NAME: &str = "www.example.com";
const PATH: &str = "/connect";

/// One server connection fed `data` as everything the client sends after TLS.
///
/// The first byte selects raw TCP, the TLS-like server without or with HTTPS, or
/// endpoint discovery only. With bit 2 set, an authorized client's valid handshake
/// precedes `data`, which then reaches the authenticated framing.
pub fn connection(data: &[u8]) {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    static KEYS: OnceLock<(snow::Keypair, snow::Keypair)> = OnceLock::new();
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    });
    let (server_keys, client_keys) = KEYS.get_or_init(|| {
        let parameters: NoiseParams = NOISE_PATTERN.parse().unwrap();
        let generate = || Builder::new(parameters.clone()).generate_keypair().unwrap();
        (generate(), generate())
    });
    let handshake = |prologue| {
        let mut handshake = initiator_handshake(
            &client_keys.private.clone().try_into().unwrap(),
            &server_keys.public.clone().try_into().unwrap(),
            prologue,
        )
        .unwrap();
        let mut message = [0; HANDSHAKE_MAX_LENGTH];
        let length = handshake
            .write_message(&client_handshake_payload(), &mut message)
            .unwrap();
        message[..length].to_vec()
    };
    let framed = |prologue| {
        let message = handshake(prologue);
        [&(message.len() as u16).to_be_bytes()[..], &message].concat()
    };
    let prefix = match (mode & 4 != 0, mode & 3) {
        (true, 0) => framed(TCP_NOISE_PROLOGUE),
        (true, 1) => framed(TLS_LIKE_NOISE_PROLOGUE),
        (true, 2) => format!(
            "GET {PATH} HTTP/1.1\r\nHost: {SERVER_NAME}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {}\r\n\r\n",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(handshake(b"SirinVPN HTTPS WebSocket transport v1"))
        )
        .into_bytes(),
        _ => Vec::new(),
    };

    runtime.block_on(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let config = TcpServerRelayConfig {
            listen: "0.0.0.0:443".parse().unwrap(),
            // The discard port: no decrypted packet is expected, and none is answered.
            wireguard_backend: "127.0.0.1:9".parse().unwrap(),
            server_private_key: Zeroizing::new(server_keys.private.clone().try_into().unwrap()),
        };
        let authorized = AuthorizedPeers::default();
        authorized.replace([client_keys.public.clone().try_into().unwrap()]);
        let activity = ActiveTransportRegistry::default();
        let replay_cache = Arc::new(Mutex::new(HandshakeReplayCache::default()));
        let clients = ClientConnectionRegistry::default();
        let server = async {
            let _ = if mode & 3 == 0 {
                let raw = TcpOuterProtocol::Raw;
                handle_server_connection(
                    server,
                    config,
                    authorized,
                    activity,
                    replay_cache,
                    clients,
                    raw,
                )
                .await
            } else {
                let mode = TlsServerMode {
                    acceptor: acceptor(),
                    https: (mode & 3 == 2).then(|| sirinvpn_protocol::HttpsTransport {
                        server_name: SERVER_NAME.into(),
                        path: PATH.into(),
                    }),
                    discovery_only: mode & 3 == 3,
                };
                https::server(
                    server,
                    mode,
                    config,
                    authorized,
                    activity,
                    replay_cache,
                    clients,
                )
                .await
            };
        };
        let (mut reader, mut writer) = tokio::io::split(client);
        let client = async {
            let _ = writer.write_all(&prefix).await;
            let _ = writer.write_all(data).await;
            let _ = writer.shutdown().await;
            let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
        };
        tokio::join!(server, client);
    });
}

/// `https::server` never uses the acceptor: the TLS session is already established.
fn acceptor() -> TlsAcceptor {
    let configuration = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
    TlsAcceptor::from(Arc::new(configuration))
}
