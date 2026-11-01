use super::*;
use crate::leak_test::tests::{caller, client_tls, state};
use rustls::pki_types::ServerName;
use sirinvpn_core::LocalIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

/// An Owner, an Admin and an ordinary Member, each with one device.
fn fixture() -> (tempfile::TempDir, AppState, [CallerIdentity; 3]) {
    let directory = tempfile::tempdir().unwrap();
    let owner = LocalIdentity::generate("Speed test owner").unwrap();
    let state = state(directory.path(), &owner);
    let mut document = state.authorization.as_ref().unwrap().blocking_write();
    for (name, administrator) in [("admin", true), ("member", false)] {
        let member_id = MemberId::new();
        document.members.push(MemberRecord {
            id: member_id,
            name: name.into(),
            role: ServerRole::Member,
            administrator,
            suspended: false,
            policy: Default::default(),
        });
        let mut device = document.devices[0].clone();
        device.id = DeviceId::new();
        device.member_id = member_id;
        device.certificate_fingerprint = name.into();
        document.devices.push(device);
    }
    drop(document);
    let identity = |fingerprint: &str| CallerIdentity {
        certificate_fingerprint: fingerprint.into(),
    };
    let callers = [caller(&owner), identity("admin"), identity("member")];
    (directory, state, callers)
}

fn status<T>(result: Result<T, ApiError>) -> StatusCode {
    result.map_or_else(|error| error.status, |_| StatusCode::OK)
}

#[test]
fn one_transfer_runs_at_a_time_and_each_device_waits_between_tests() {
    let mut limiter = Limiter::default();
    let now = Instant::now();
    limiter.start("a", false, now).unwrap();
    let busy = limiter.start("b", false, now).unwrap_err();
    assert_eq!(busy.status, StatusCode::CONFLICT);
    // A device's upload may follow its own download before that connection has closed.
    limiter.start("a", true, now).unwrap();
    let wait = limiter
        .start("a", false, now + Duration::from_secs(20))
        .unwrap_err();
    assert_eq!(wait.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(wait.message, "wait 41 seconds before the next speed test");
    // A client that stops reading holds the slot only until the transfer limit.
    limiter.start("b", false, now + TRANSFER_LIMIT).unwrap();
    // Start times are forgotten after the cooldown, so the map stays bounded.
    limiter.start("a", false, now + COOLDOWN).unwrap();
    assert_eq!(limiter.started.len(), 2);
}

#[tokio::test(start_paused = true)]
async fn only_managers_download_and_the_stream_stops_at_its_caps() {
    let (_directory, state, [owner, admin, member]) =
        tokio::task::spawn_blocking(fixture).await.unwrap();
    let download = |caller| download_handler(State(state.clone()), Extension(caller));
    assert_eq!(
        status(download(member.clone()).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(latency_handler(State(state.clone()), Extension(member)).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(latency_handler(State(state.clone()), Extension(admin.clone())).await),
        StatusCode::OK
    );
    let mut body = download(owner)
        .await
        .unwrap()
        .into_body()
        .into_data_stream();
    let mut received = 0;
    while let Some(chunk) = body.next().await {
        received += chunk.unwrap().len() as u64;
    }
    assert_eq!(received, SPEED_TEST_MAX_BYTES);
    // The ended stream freed the slot for another device.
    drop(body);
    let mut body = download(admin)
        .await
        .unwrap()
        .into_body()
        .into_data_stream();
    assert!(body.next().await.is_some());
    tokio::time::advance(TRANSFER_LIMIT).await;
    assert!(body.next().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn uploads_are_counted_and_cut_off_at_the_caps() {
    let (_directory, state, [owner, admin, member]) =
        tokio::task::spawn_blocking(fixture).await.unwrap();
    let upload = |caller, body| upload_handler(State(state.clone()), Extension(caller), body);
    assert_eq!(
        status(upload(member, Body::from(vec![0; 10])).await),
        StatusCode::FORBIDDEN
    );
    let Json(envelope) = upload(owner.clone(), Body::from(vec![0; 100_000]))
        .await
        .unwrap_or_else(|error| panic!("{}", error.message));
    assert_eq!(envelope.payload.received_bytes, 100_000);
    let chunks = (SPEED_TEST_MAX_BYTES / ZEROS.len() as u64 + 1) as usize;
    let oversized = futures_util::stream::iter(
        std::iter::repeat_n(Bytes::from_static(&ZEROS), chunks).map(Ok::<_, Infallible>),
    );
    assert_eq!(
        status(upload(admin, Body::from_stream(oversized)).await),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // A body that never ends is cut off at the time limit (paused time advances itself).
    state.speed_test.lock().unwrap().started.clear();
    let stalled = futures_util::stream::pending::<Result<Bytes, Infallible>>();
    assert_eq!(
        status(upload(owner, Body::from_stream(stalled)).await),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

/// Both directions through the real pinned-TLS management server. The upload is far above the
/// router's 64 KiB body limit, which must not apply to the streamed speed-test body.
#[tokio::test]
async fn transfers_run_through_the_management_server() {
    let directory = tempfile::tempdir().unwrap();
    let owner = LocalIdentity::generate("Speed test owner").unwrap();
    let state = state(directory.path(), &owner);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_management(
        listener,
        state.clone(),
        management_router(state.clone()),
    ));
    let connect = || async {
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        TlsConnector::from(client_tls(&state, &owner))
            .connect(
                ServerName::try_from(sirinvpn_protocol::MANAGEMENT_SERVER_NAME).unwrap(),
                stream,
            )
            .await
            .unwrap()
    };
    let mut tls = connect().await;
    tls.write_all(b"POST /v1/speed-test/upload HTTP/1.1\r\nHost: sirinvpn.local\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
    for _ in 0..32 {
        tls.write_all(format!("{:x}\r\n", ZEROS.len()).as_bytes())
            .await
            .unwrap();
        tls.write_all(&ZEROS).await.unwrap();
        tls.write_all(b"\r\n").await.unwrap();
    }
    tls.write_all(b"0\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    let envelope: ApiEnvelope<SpeedTestUpload> = serde_json::from_str(body).unwrap();
    assert_eq!(envelope.payload.received_bytes, 32 * ZEROS.len() as u64);

    let mut tls = connect().await;
    tls.write_all(b"GET /v1/speed-test/download HTTP/1.1\r\nHost: sirinvpn.local\r\n\r\n")
        .await
        .unwrap();
    let mut received = vec![0; 1 << 20];
    tls.read_exact(&mut received).await.unwrap();
    let head = String::from_utf8_lossy(&received[..256]);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains("application/octet-stream"));
    server.abort();
}

/// The real client from the full-tunnel `member0` namespace, over real WireGuard, to the real
/// management server: both directions run their full eight seconds through a 100 Mbit/s
/// bottleneck, latency rises under load, and an immediate second run is refused by the cooldown.
#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-speed-test.sh"]
async fn kernel_speed_test_measures_the_tunnel_to_the_vps() {
    let directory = tempfile::tempdir().unwrap();
    let owner = LocalIdentity::generate("Speed test owner").unwrap();
    let mut state = state(directory.path(), &owner);
    crate::leak_test::tests::tunnel_member0(directory.path(), &mut state, &owner).await;
    // Below 1 GiB per eight seconds, so neither direction ends early at the byte limit.
    let tbf = |interface| {
        [
            "qdisc", "add", "dev", interface, "root", "tbf", "rate", "100mbit", "burst", "64kb",
            "latency", "50ms",
        ]
    };
    let mut download = Command::new("tc");
    download.args(tbf("sirinvpn0"));
    let mut upload = Command::new("ip");
    upload
        .args(["netns", "exec", "member0", "tc"])
        .args(tbf("client0"));
    for mut command in [download, upload] {
        assert!(command.status().await.unwrap().success());
    }
    let listener = TcpListener::bind((Ipv4Addr::new(10, 77, 0, 1), 8443))
        .await
        .unwrap();
    tokio::spawn(serve_management(
        listener,
        state.clone(),
        management_router(state.clone()),
    ));
    let profile: sirinvpn_protocol::ServerProfile = serde_json::from_value(serde_json::json!({
        "schema_version": 1, "id": ServerId::new(), "name": "Speed test",
        "endpoint": {"host": "192.0.2.1", "wireguard_port": 51820},
        "client_tunnel_address": "10.77.0.2", "server_tunnel_address": "10.77.0.1",
        "server_wireguard_public_key": state.configuration.wireguard_public_key,
        "pinned_server_certificate_pem": fs::read_to_string(&state.paths.tls_certificate).unwrap(),
        "client_management_certificate_pem": owner.public.management_certificate_pem,
        "identity_reference": "test", "role": "owner"
    }))
    .unwrap();
    let secret = owner.secret.clone();
    let thread = std::thread::spawn(move || {
        nix::sched::setns(
            fs::File::open("/run/netns/member0").unwrap(),
            nix::sched::CloneFlags::CLONE_NEWNET,
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let first = runtime.block_on(sirinvpn_core::diagnostics::speed_test(&profile, &secret));
        let second = runtime.block_on(sirinvpn_core::diagnostics::speed_test(&profile, &secret));
        (first, second)
    });
    // Joining off the runtime thread keeps the in-process server running.
    let (first, second) = tokio::task::spawn_blocking(move || thread.join().unwrap())
        .await
        .unwrap();
    let result = first.unwrap_or_else(|error| panic!("{error}"));
    println!("speed test over the kernel tunnel: {result:?}");
    for rate in [
        result.download_bits_per_second,
        result.upload_bits_per_second,
    ] {
        assert!((50_000_000..=105_000_000).contains(&rate), "{result:?}");
    }
    let idle = result.idle_latency_micros.unwrap();
    // The bottleneck queue fills under load.
    assert!(result.download_latency_micros.unwrap() > idle, "{result:?}");
    assert!(result.upload_latency_micros.unwrap() > idle, "{result:?}");
    let refused = second.unwrap_err().to_string();
    assert!(
        refused.starts_with("The speed test didn't start: wait "),
        "{refused}"
    );
    assert!(state.speed_test.lock().unwrap().running.is_none());
}
