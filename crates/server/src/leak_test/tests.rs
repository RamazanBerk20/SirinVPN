use super::*;
use rustls::{ClientConfig, pki_types::ServerName};
use sirinvpn_core::LocalIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

pub(crate) fn state(directory: &Path, owner: &LocalIdentity) -> AppState {
    let paths = ServerPaths::under(directory);
    initialize(
        &paths,
        "Leak test",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    AppState {
        recovery: Default::default(),
        measurement_ready: false,
        leak_test_ready: true,
        configuration: load_configuration(&paths).unwrap(),
        operational_configuration: None,
        authorization: Some(Arc::new(RwLock::new(
            load_authorization(&paths.authorization).unwrap(),
        ))),
        paths,
        redemption_failures: Arc::new(Mutex::new(HashMap::new())),
        live_metrics: Arc::new(Mutex::new(LiveMetricSampler::default())),
        transport_peers: AuthorizedPeers::default(),
        transport_activity: ActiveTransportRegistry::default(),
        speed_test: Default::default(),
    }
}

pub(crate) fn caller(owner: &LocalIdentity) -> CallerIdentity {
    CallerIdentity {
        certificate_fingerprint: certificate_fingerprint(&owner.public.management_certificate_pem)
            .unwrap(),
    }
}

#[test]
fn only_tunnel_traffic_to_the_two_leak_addresses_is_redirected_to_private_listeners() {
    let ipv4_only = rules("sirinvpn0", "10.77.0.1".parse().unwrap(), None, 8443);
    assert!(ipv4_only.contains(
        "leak_test_prerouting iifname \"sirinvpn0\" ip daddr 192.0.2.77 tcp dport 8443 dnat ip to 10.77.0.1:8443\n"
    ));
    assert!(!ipv4_only.contains("ip6"));
    let server_ipv6: Ipv6Addr = "fd12:3456:789a::1".parse().unwrap();
    let dual = rules(
        "sirinvpn0",
        "10.77.0.1".parse().unwrap(),
        Some(server_ipv6),
        8443,
    );
    assert!(dual.contains(
        "iifname \"sirinvpn0\" ip6 daddr 2001:db8::77 tcp dport 8443 dnat ip6 to [fd12:3456:789a::1]:8443\n"
    ));
    assert!(dual.contains(
        "leak_test_input iifname != \"sirinvpn0\" ip6 daddr fd12:3456:789a::1 tcp dport 8443 drop\n"
    ));
    // Reapplying replaces the rules instead of accumulating them.
    assert!(dual.contains("flush chain inet sirinvpn_measurement leak_test_prerouting\n"));
    assert!(dual.contains("flush chain inet sirinvpn_measurement leak_test_input\n"));
    for rule in dual.lines().filter(|line| line.contains("dnat")) {
        assert!(rule.contains("iifname \"sirinvpn0\""), "{rule}");
    }
    assert_eq!(dual.matches("dnat").count(), 2);
}

#[tokio::test]
async fn observation_echoes_only_the_connection_address_to_a_current_device() {
    let directory = tempfile::tempdir().unwrap();
    let owner = LocalIdentity::generate("Leak test owner").unwrap();
    let state = state(directory.path(), &owner);
    let source: IpAddr = "10.77.0.2".parse().unwrap();
    let denied = observe_handler(
        State(state.clone()),
        Extension(CallerIdentity {
            certificate_fingerprint: "unknown".into(),
        }),
        Extension(PeerAddress(source)),
    )
    .await;
    assert!(matches!(
        denied,
        Err(ApiError {
            status: StatusCode::FORBIDDEN,
            ..
        })
    ));
    let Json(envelope) = observe_handler(
        State(state.clone()),
        Extension(caller(&owner)),
        Extension(PeerAddress(source)),
    )
    .await
    .unwrap_or_else(|_| panic!("owner rejected"));
    assert_eq!(
        serde_json::to_value(&envelope.payload).unwrap(),
        serde_json::json!({ "source_address": "10.77.0.2" })
    );
    state
        .authorization
        .as_ref()
        .unwrap()
        .write()
        .await
        .devices
        .clear();
    assert!(
        observe_handler(
            State(state),
            Extension(caller(&owner)),
            Extension(PeerAddress(source)),
        )
        .await
        .is_err()
    );
}

const REQUEST: &[u8] =
    b"GET /v1/leak-test HTTP/1.1\r\nHost: sirinvpn.local\r\nConnection: close\r\n\r\n";

/// The client side of the pinned management TLS, as the core leak-test client configures it.
pub(crate) fn client_tls(state: &AppState, owner: &LocalIdentity) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in
        CertificateDer::pem_slice_iter(&fs::read(&state.paths.tls_certificate).unwrap())
    {
        roots.add(certificate.unwrap()).unwrap();
    }
    Arc::new(
        ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            CertificateDer::pem_slice_iter(owner.public.management_certificate_pem.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap(),
            PrivateKeyDer::from_pem_slice(owner.secret.management_private_key_pem.as_bytes())
                .unwrap(),
        )
        .unwrap(),
    )
}

fn observed_source(response: &[u8]) -> IpAddr {
    let response = String::from_utf8_lossy(response);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    let envelope: ApiEnvelope<LeakTestObservation> = serde_json::from_str(body).unwrap();
    envelope.payload.source_address
}

/// The client reaches a leak-test address by the certificate's DNS name; the real management
/// server must accept that name and report the address the connection came from.
#[tokio::test]
async fn pinned_management_tls_by_name_reports_the_connection_source() {
    let directory = tempfile::tempdir().unwrap();
    let owner = LocalIdentity::generate("Leak test owner").unwrap();
    let state = state(directory.path(), &owner);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_management(
        listener,
        state.clone(),
        management_router(state.clone()),
    ));
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut tls = TlsConnector::from(client_tls(&state, &owner))
        .connect(
            ServerName::try_from(sirinvpn_protocol::MANAGEMENT_SERVER_NAME).unwrap(),
            stream,
        )
        .await
        .unwrap();
    tls.write_all(REQUEST).await.unwrap();
    let mut response = Vec::new();
    // A missing TLS close_notify after the body is irrelevant here.
    let _ = tls.read_to_end(&mut response).await;
    server.abort();
    assert_eq!(observed_source(&response), address.ip());
}

/// One leak-test request from a thread inside `namespace`, so that namespace's routes decide
/// the path exactly as the client's own routes would.
async fn observe_from_namespace(
    namespace: &str,
    destination: IpAddr,
    tls: Arc<ClientConfig>,
) -> IpAddr {
    let namespace = Path::new("/run/netns").join(namespace);
    let thread = std::thread::spawn(move || {
        nix::sched::setns(
            fs::File::open(namespace).unwrap(),
            nix::sched::CloneFlags::CLONE_NEWNET,
        )
        .unwrap();
        let stream = std::net::TcpStream::connect_timeout(
            &SocketAddr::new(destination, 8443),
            Duration::from_secs(10),
        )
        .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let connection = rustls::ClientConnection::new(
            tls,
            ServerName::try_from(sirinvpn_protocol::MANAGEMENT_SERVER_NAME).unwrap(),
        )
        .unwrap();
        let mut tls = rustls::StreamOwned::new(connection, stream);
        io::Write::write_all(&mut tls, REQUEST).unwrap();
        let mut response = Vec::new();
        let _ = io::Read::read_to_end(&mut tls, &mut response);
        response
    });
    // Joining off the runtime thread keeps the in-process server running.
    let response = tokio::task::spawn_blocking(move || thread.join().unwrap())
        .await
        .unwrap();
    observed_source(&response)
}

/// A real WireGuard link from the full-tunnel `member0` namespace to this in-process server,
/// whose owner device is 10.77.0.2. Returns the server's and the owner's private IPv6 addresses.
pub(crate) async fn tunnel_member0(
    directory: &Path,
    state: &mut AppState,
    owner: &LocalIdentity,
) -> (Ipv6Addr, Ipv6Addr) {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    state.configuration.ipv6_tunnel_enabled = true;
    let document = state.authorization.as_ref().unwrap().read().await.clone();
    let server_v6 =
        sirinvpn_protocol::ipv6_tunnel_address(document.server_id, Ipv4Addr::new(10, 77, 0, 1))
            .unwrap();
    let owner_v6 =
        sirinvpn_protocol::ipv6_tunnel_address(document.server_id, Ipv4Addr::new(10, 77, 0, 2))
            .unwrap();
    let owner_key = directory.join("owner-wireguard.key");
    write_private(&owner_key, owner.secret.wireguard_private_key.as_bytes()).unwrap();
    let prepare = serde_json::json!({
        "server_private_key_path": state.paths.wireguard_private_key,
        "server_ipv6": server_v6,
        "devices": [{"index": 0, "ipv4": "10.77.0.2", "ipv6": owner_v6, "private_key_path": owner_key}]
    });
    let mut child = Command::new("python3")
        .args(["tests/network/member_lifecycle.py", "prepare"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&prepare).unwrap())
        .await
        .unwrap();
    assert!(child.wait().await.unwrap().success());
    // Full-tunnel routes in the member namespace, as the client installs them.
    for family in ["-4", "-6"] {
        let status = Command::new("ip")
            .args([
                "-n", "member0", family, "route", "add", "default", "dev", "client0",
            ])
            .status()
            .await
            .unwrap();
        assert!(status.success());
    }
    sync_wireguard_peers(&state.configuration, &document)
        .await
        .unwrap();
    (server_v6, owner_v6)
}

#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-leak-test.sh"]
async fn kernel_leak_addresses_reach_the_vps_only_through_the_tunnel() {
    let directory = tempfile::tempdir().unwrap();
    let owner = LocalIdentity::generate("Leak test owner").unwrap();
    let mut state = state(directory.path(), &owner);
    let (server_v6, owner_v6) = tunnel_member0(directory.path(), &mut state, &owner).await;
    install(&state.configuration, Some(server_v6))
        .await
        .unwrap();
    let router = management_router(state.clone());
    for address in [
        IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1)),
        IpAddr::V6(server_v6),
    ] {
        let listener = TcpListener::bind((address, 8443)).await.unwrap();
        tokio::spawn(serve_management(listener, state.clone(), router.clone()));
    }
    let tls = client_tls(&state, &owner);
    assert_eq!(
        observe_from_namespace("member0", IpAddr::V4(LEAK_TEST_IPV4), tls.clone()).await,
        IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2))
    );
    assert_eq!(
        observe_from_namespace("member0", IpAddr::V6(LEAK_TEST_IPV6), tls).await,
        IpAddr::V6(owner_v6)
    );
}
