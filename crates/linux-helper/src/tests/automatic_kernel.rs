//! Real carriers, WireGuard, TLS authorization, packet continuity and leak checks.
use super::*;
use sirinvpn_core::{LocalIdentity, ManagementClient};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    time::Instant,
};

#[derive(Clone)]
struct KernelRunner {
    runtime: Arc<tokio::runtime::Runtime>,
    relays: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
}
impl CommandRunner for KernelRunner {
    fn kick_tunnel(&self, source: Ipv4Addr, destination: Ipv4Addr) {
        SystemRunner.kick_tunnel(source, destination);
    }
    fn tunnel_probe(&self, source: Ipv4Addr, destination: Ipv4Addr) -> bool {
        SystemRunner.tunnel_probe(source, destination)
    }
    fn optimize_session(&self) {
        let _ = LinuxNetworkHelper::new(self.clone(), "/run/sirinvpn".into()).optimize_session();
    }
    fn measure_candidate(
        &self,
        r: &TunnelConnectRequest,
        endpoint: IpAddr,
        p: &MeasureSessionRequest,
    ) -> Option<sirinvpn_protocol::TransportQualitySample> {
        SystemRunner.measure_candidate(r, endpoint, p)
    }
    fn run(&self, program: &str, args: &[&str], input: Option<&[u8]>) -> Result<()> {
        if program == "resolvectl" {
            return Ok(());
        }
        if program == "systemctl" {
            if let ["is-active", "--quiet", unit] = args {
                if self
                    .relays
                    .lock()
                    .unwrap()
                    .get(*unit)
                    .is_some_and(|task| !task.is_finished())
                {
                    return Ok(());
                }
                bail!("carrier is not running");
            }
            if let [action, unit] = args
                && unit.starts_with("sirinvpn-transport@")
            {
                let mut tasks = self.relays.lock().unwrap();
                if *action == "stop" {
                    if let Some(task) = tasks.remove(*unit) {
                        task.abort();
                    }
                    return Ok(());
                }
                if *action == "start" {
                    if tasks.contains_key(*unit) {
                        return Ok(());
                    }
                    let kind = unit
                        .trim_start_matches("sirinvpn-transport@")
                        .trim_end_matches(".service");
                    let config: ClientTransportConfig = serde_json::from_slice(&fs::read(
                        format!("/run/sirinvpn/transport-{kind}.json"),
                    )?)?;
                    let (send, ready) = std::sync::mpsc::channel();
                    let task = self.runtime.spawn(async move {
                        let ready = || {
                            let _ = send.send(());
                        };
                        let result = match config {
                            ClientTransportConfig::LegacyObfuscatedUdp(c) => {
                                run_client_relay(c, ready).await
                            }
                            ClientTransportConfig::Current(
                                CurrentClientTransportConfig::TcpFallback(c),
                            ) => run_tcp_client_relay(c, ready).await,
                            ClientTransportConfig::Current(
                                CurrentClientTransportConfig::TlsLike(c),
                            ) => run_tls_like_client_relay(c, ready).await,
                        };
                        if let Err(error) = result {
                            eprintln!("carrier stopped: {error}");
                        }
                    });
                    if ready.recv_timeout(Duration::from_secs(5)).is_err() {
                        task.abort();
                        bail!("carrier was not ready");
                    }
                    tasks.insert(unit.to_string(), task);
                }
            }
            return Ok(());
        }
        SystemRunner.run(program, args, input)
    }
    fn output(&self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
        if program == "systemctl" {
            return Ok(b"disabled\n".to_vec());
        }
        if program == "resolvectl" {
            return Ok(Vec::new());
        }
        SystemRunner.output(program, args)
    }
    fn output_with_timeout(&self, p: &str, a: &[&str], timeout: Duration) -> Result<Vec<u8>> {
        if matches!(p, "systemctl" | "resolvectl") {
            self.output(p, a)
        } else {
            SystemRunner.output_with_timeout(p, a, timeout)
        }
    }
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn python(mode: &str, input: Option<&[u8]>) {
    let mut child = Command::new("python3")
        .args(["tests/network/automatic_transport.py", mode])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    assert!(child.wait().unwrap().success(), "fixture {mode}");
}

fn wait_connected(helper: &LinuxNetworkHelper<KernelRunner>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        helper.reconcile_persistent_once(true).unwrap();
        if helper.status().unwrap().state == ConnectionState::Connected {
            return;
        }
        assert!(Instant::now() < deadline, "handshake deadline");
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "requires disposable container: sh tests/network/run-automatic-transport.sh"]
fn kernel_automatic_transport_continuity_and_soak() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let directory = tempfile::tempdir().unwrap();
    let paths = sirinvpn_server::ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Automatic test owner").unwrap();
    let id = ServerId::new();
    let result = sirinvpn_server::initialize_with_transport_capabilities(
        &paths,
        "Automatic test",
        &owner.public.management_certificate_pem,
        id,
        &owner.public.wireguard_public_key,
        51820,
        sirinvpn_server::ServerCapabilities {
            ipv6_tunnel_enabled: Some(true),
            obfuscated_udp_port: Some(51821),
            tcp_fallback_port: Some(51822),
            tls_like_port: Some(51822),
            ..Default::default()
        },
    )
    .unwrap();
    let server_v6 = ipv6_tunnel_address(id, "10.77.0.1".parse().unwrap()).unwrap();
    python(
        "prepare",
        Some(
            &serde_json::to_vec(
                &serde_json::json!({"private_key": paths.wireguard_private_key, "ipv6": server_v6}),
            )
            .unwrap(),
        ),
    );
    let server_binary = std::env::var("SIRINVPN_TEST_SERVER").unwrap();
    let _server = Child(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                "auto-vps",
                &server_binary,
                "--state-directory",
            ])
            .arg(directory.path())
            .arg("serve")
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let _echo = Child(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                "auto-vps",
                "python3",
                "tests/network/automatic_transport.py",
                "serve",
            ])
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    thread::sleep(Duration::from_millis(500));
    let profile: sirinvpn_protocol::ServerProfile = serde_json::from_value(serde_json::json!({
        "schema_version": 1, "id": id, "name": "Test", "endpoint": {"host": "198.18.0.1", "wireguard_port": 51820},
        "client_tunnel_address": "10.77.0.2", "server_tunnel_address": "10.77.0.1",
        "server_wireguard_public_key": result.wireguard_public_key, "pinned_server_certificate_pem": result.management_certificate_pem,
        "client_management_certificate_pem": owner.public.management_certificate_pem, "identity_reference": "test", "role": "owner",
        "ipv6_tunnel_enabled": true, "obfuscated_udp": result.obfuscated_udp, "tcp_fallback": result.tcp_fallback, "tls_like": result.tls_like
    })).unwrap();
    let selections = sirinvpn_transport::TransportEngine
        .plan(&profile, sirinvpn_protocol::TransportPreference::Automatic)
        .unwrap();
    assert_eq!(selections.len(), 4);
    let mut request = request();
    request.schema_version = 8;
    request.policy = Some(ConnectionPolicy {
        kill_switch: true,
        automatic_reconnect: true,
        connect_on_startup: false,
    });
    request.server_id = id;
    request.endpoint_host = "198.18.0.1".into();
    request.endpoint_port = 51820;
    request.server_public_key = profile.server_wireguard_public_key.clone();
    request.private_key = owner.secret.wireguard_private_key.clone();
    request.client_address = "10.77.0.2".parse().unwrap();
    request.dns_address = "10.77.0.1".parse().unwrap();
    request.client_ipv6_address = ipv6_tunnel_address(id, request.client_address);
    request.reconnect_candidates = policy_transport_candidates(&selections);
    request.mtu_policy = Some(sirinvpn_protocol::MtuPolicy::Automatic);
    let runner = KernelRunner {
        runtime: Arc::new(tokio::runtime::Runtime::new().unwrap()),
        relays: Default::default(),
    };
    let helper = Arc::new(LinuxNetworkHelper::new(
        runner.clone(),
        "/run/sirinvpn".into(),
    ));
    let mut times = Vec::new();
    let mut setup_times = Vec::new();
    let mut handshake_times = Vec::new();
    let mut reply_times = Vec::new();
    for _ in 0..20 {
        let start = Instant::now();
        helper.connect(&request).unwrap();
        setup_times.push(start.elapsed().as_millis());
        let configured = Instant::now();
        wait_connected(&helper);
        handshake_times.push(configured.elapsed().as_millis());
        let connected = Instant::now();
        assert!(runner.tunnel_probe(request.client_address, request.dns_address));
        reply_times.push(connected.elapsed().as_millis());
        times.push(start.elapsed().as_millis());
        helper.disconnect().unwrap();
    }
    times.sort_unstable();
    println!(
        "20 direct connections: median={}ms p95={}ms (real networking, simulated systemd/resolved)",
        times[10], times[18]
    );
    for (stage, mut times) in [
        ("helper setup", setup_times),
        ("handshake observation", handshake_times),
        ("private TCP reachability", reply_times),
    ] {
        times.sort_unstable();
        println!("{stage}: median={}ms p95={}ms", times[10], times[18]);
    }
    assert!(
        times[18] < 1000,
        "repeat connections exceeded the lab target"
    );
    helper
        .connect_managed(&crate::ManagedConnectRequest {
            expected_server_id: None,
            request: request.clone(),
            profile: profile.clone(),
            secret: owner.secret.clone(),
        })
        .unwrap();
    wait_connected(&helper);
    let epoch = helper.status().unwrap().counter_epoch;
    let monitor = helper.clone();
    let supervisor = thread::spawn(move || monitor.supervise().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let worst_gap = Arc::new(AtomicU64::new(0));
    let flow_count = Arc::new(AtomicU64::new(0));
    let flow_stop = stop.clone();
    let gap = worst_gap.clone();
    let count = flow_count.clone();
    let flow = thread::spawn(move || {
        let mut stream = TcpStream::connect("10.77.0.1:19000").unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        stream.set_nodelay(true).unwrap();
        while !flow_stop.load(Ordering::Relaxed) {
            let start = Instant::now();
            stream.write_all(&[0x5a; 4096]).unwrap();
            let mut bytes = [0; 4096];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, [0x5a; 4096]);
            gap.fetch_max(start.elapsed().as_millis() as u64, Ordering::Relaxed);
            count.fetch_add(1, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(50));
        }
    });
    let client = ManagementClient::new(&profile, &owner.secret).unwrap();
    assert!(
        runner
            .runtime
            .block_on(client.configuration())
            .unwrap()
            .isolated_measurement_enabled
    );
    assert!(
        runner
            .runtime
            .block_on(client.measurement_lease(owner.public.wireguard_public_key.clone()))
            .is_err()
    );
    let probe = LocalIdentity::generate("Isolated test").unwrap();
    let lease = runner
        .runtime
        .block_on(client.measurement_lease(probe.public.wireguard_public_key.clone()))
        .unwrap();
    assert!(
        runner
            .runtime
            .block_on(client.measurement_lease(probe.public.wireguard_public_key.clone()))
            .is_err()
    );
    let probe_request = MeasureSessionRequest {
        server_id: id,
        counter_epoch: epoch.clone().unwrap(),
        lease,
        private_key: probe.secret.wireguard_private_key.clone(),
    };
    python("probe-isolation", Some(&serde_json::to_vec(&serde_json::json!({
        "private_key": probe.secret.wireguard_private_key, "server_public_key": request.server_public_key
    })).unwrap()));
    for candidate in &request.reconnect_candidates {
        let before = helper.status().unwrap();
        let next = request_for_reconnect_candidate(&request, candidate);
        let sample = runner
            .measure_candidate(&next, "198.18.0.1".parse().unwrap(), &probe_request)
            .expect("carrier measurement");
        assert!(sample.stable());
        assert_eq!(helper.status().unwrap().counter_epoch, before.counter_epoch);
        assert_eq!(helper.status().unwrap().transport, before.transport);
        let _lock = helper.lock_operations().unwrap();
        let mut state = helper.read_state().unwrap();
        let desired = helper.read_persistent().unwrap();
        helper
            .change_quality_transport(&desired, &next, &mut state)
            .unwrap();
        assert!(helper.guard_is_verified(&next, desired.endpoint));
        assert_eq!(helper.status().unwrap().counter_epoch, epoch);
        for address in [
            "10.77.0.1:53".parse::<SocketAddr>().unwrap(),
            SocketAddr::new(server_v6.into(), 19000),
        ] {
            let sock = UdpSocket::bind(if address.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            })
            .unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            sock.send_to(b"encrypted", address).unwrap();
            let mut data = [0; 16];
            assert_eq!(sock.recv(&mut data).unwrap(), 9);
        }
        println!(
            "isolated measurement and in-place handoff: {:?}",
            next.transport
        );
        drop(_lock);
        let before = flow_count.load(Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_secs(5);
        while flow_count.load(Ordering::Relaxed) == before {
            assert!(
                Instant::now() < deadline,
                "existing TCP stream stalled on {:?}",
                next.transport
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
    {
        let _lock = helper.lock_operations().unwrap();
        let mut state = helper.read_state().unwrap();
        let previous = state.transport;
        let desired = helper.read_persistent().unwrap();
        let mut unavailable =
            request_for_reconnect_candidate(&request, &request.reconnect_candidates[1]);
        unavailable.endpoint_port = 53009;
        assert!(
            helper
                .change_quality_transport(&desired, &unavailable, &mut state)
                .is_err()
        );
        assert_eq!(state.transport, previous);
        assert_eq!(helper.status().unwrap().counter_epoch, epoch);
    }
    runner
        .runtime
        .block_on(client.remove_measurement_lease(probe.public.wireguard_public_key))
        .unwrap();
    // Unknown/expired probe keys cannot re-enter authenticated carriers.
    assert!(
        runner
            .measure_candidate(
                &request_for_reconnect_candidate(&request, &request.reconnect_candidates[1]),
                "198.18.0.1".parse().unwrap(),
                &probe_request
            )
            .is_none()
    );
    {
        let _lock = helper.lock_operations().unwrap();
        let mut state = helper.read_state().unwrap();
        let desired = helper.read_persistent().unwrap();
        helper
            .change_quality_transport(&desired, &request, &mut state)
            .unwrap();
    }
    python("delay-direct", None);
    let soak = std::env::var("SIRINVPN_SOAK_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);
    let deadline = Instant::now() + Duration::from_secs(soak);
    let mut optimized = false;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_secs(1));
        let status = helper.status().unwrap();
        assert_eq!(status.state, ConnectionState::Connected);
        assert_eq!(status.counter_epoch, epoch);
        {
            // Status alone cannot detect WireGuard roaming back onto a delayed
            // old path. Validate its actual endpoint under the operation lock.
            let _lock = helper.lock_operations().unwrap();
            let desired = helper.read_persistent().unwrap();
            let state = helper.read_state().unwrap();
            let active = current_persistent_request(&desired, Some(&state));
            assert!(helper.carrier_endpoint_matches(&active, desired.endpoint));
        }
        optimized |= status.transport != Some(TransportKind::DirectUdp);
        // SO_BINDTODEVICE forces a real underlay attempt. Neither IPv4 nor IPv6
        // packets may escape unencrypted, even while candidates are prepared.
        for address in [
            "198.18.0.1:19000".parse::<SocketAddr>().unwrap(),
            "[fdba::1]:19000".parse().unwrap(),
        ] {
            let sock = socket2::Socket::new(
                if address.is_ipv6() {
                    socket2::Domain::IPV6
                } else {
                    socket2::Domain::IPV4
                },
                socket2::Type::DGRAM,
                None,
            )
            .unwrap();
            sock.bind_device(Some(b"eth-test")).unwrap();
            assert!(sock.send_to(b"must be blocked", &address.into()).is_err());
        }
    }
    assert!(
        optimized,
        "live optimization did not replace the consistently slower carrier"
    );
    println!(
        "{soak}s automatic soak: no interface replacement or TCP reset; largest echo gap={}ms",
        worst_gap.load(Ordering::Relaxed)
    );
    worst_gap.store(0, Ordering::Relaxed);
    // TLS and raw TCP share one endpoint. Blocking it must try beyond the first
    // alternate carrier without replacing the established WireGuard session.
    {
        let _lock = helper.lock_operations().unwrap();
        let mut state = helper.read_state().unwrap();
        let desired = helper.read_persistent().unwrap();
        let candidate = request
            .reconnect_candidates
            .iter()
            .find(|candidate| candidate.transport == TransportKind::TlsLike)
            .unwrap();
        let next = request_for_reconnect_candidate(&request, candidate);
        helper
            .change_quality_transport(&desired, &next, &mut state)
            .unwrap();
    }
    let before_failure = helper.status().unwrap().transport.unwrap();
    let port = request
        .reconnect_candidates
        .iter()
        .find(|c| c.transport == before_failure)
        .unwrap()
        .endpoint_port;
    let protocol = if matches!(
        before_failure,
        TransportKind::TcpFallback | TransportKind::TlsLike
    ) {
        "tcp"
    } else {
        "udp"
    };
    let mut fault = format!(
        "add table inet carrier_fault\nadd chain inet carrier_fault output {{ type filter hook output priority -50; policy accept; }}\nadd rule inet carrier_fault output meta mark 51820 {protocol} dport {port} drop\n"
    );
    let one_way = std::env::var("SIRINVPN_FAULT_ONE_WAY").as_deref() == Ok("1");
    if !one_way {
        fault.push_str(&format!("add chain inet carrier_fault input {{ type filter hook input priority -50; policy accept; }}\nadd rule inet carrier_fault input {protocol} sport {port} drop\n"));
    }
    println!("forcing carrier outage; outbound only: {one_way}");
    SystemRunner
        .run("nft", &["-f", "-"], Some(fault.as_bytes()))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(50);
    let mut report = Instant::now();
    loop {
        thread::sleep(Duration::from_millis(250));
        let status = helper.status().unwrap();
        if report.elapsed() >= Duration::from_secs(5) {
            let state = helper.read_state().unwrap();
            println!(
                "blocked carrier: {:?}, health {:?}",
                state.transport,
                state.quality.as_ref().map(|q| &q.health)
            );
            report = Instant::now();
        }
        assert_eq!(
            status.counter_epoch, epoch,
            "recovery replaced the active WireGuard interface"
        );
        if status.state == ConnectionState::Connected && status.transport != Some(before_failure) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "confirmed carrier blocking did not recover"
        );
    }
    SystemRunner
        .run("nft", &["delete", "table", "inet", "carrier_fault"], None)
        .unwrap();
    println!("confirmed carrier blocking recovered without replacing WireGuard");
    stop.store(true, Ordering::Relaxed);
    flow.join().unwrap();
    println!(
        "forced outage: original TCP stream resumed without reset; largest echo gap={}ms",
        worst_gap.load(Ordering::Relaxed)
    );
    helper.disconnect().unwrap();
    supervisor.join().unwrap();
}
