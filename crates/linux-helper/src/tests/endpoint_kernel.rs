//! Real IPv6 outer WireGuard and scoped DNS; invoked only inside the policy fixture.
use super::*;
use sirinvpn_protocol::{
    EndpointDescriptor, EndpointIdentity, TcpFallbackEndpoint, TlsLikeEndpoint,
};

struct EndpointKernelRunner;
impl CommandRunner for EndpointKernelRunner {
    fn run(&self, program: &str, args: &[&str], input: Option<&[u8]>) -> Result<()> {
        if matches!(program, "systemctl" | "resolvectl") {
            return Ok(());
        }
        SystemRunner.run(program, args, input)
    }
    fn output(&self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
        if program == "systemctl" {
            return Ok(b"disabled\n".to_vec());
        }
        if program == "resolvectl" {
            return Ok(b"Link 2 (probe0): 203.0.113.53 2001:db8::53\n".to_vec());
        }
        SystemRunner.output(program, args)
    }
    fn endpoint_addresses(&self, host: &str, servers: &[SocketAddr]) -> Vec<IpAddr> {
        SystemRunner.endpoint_addresses(host, servers)
    }
}

pub(super) fn check_endpoints() {
    let dir = tempfile::tempdir().unwrap();
    let helper = LinuxNetworkHelper::new(EndpointKernelRunner, dir.path().join("runtime"));
    let run = |mode| {
        assert!(
            Command::new("python3")
                .args(["tests/network/endpoint_packets.py", mode])
                .status()
                .unwrap()
                .success()
        );
    };
    run("prepare");
    let identity = sirinvpn_core::LocalIdentity::generate("IPv6 endpoint").unwrap();
    let client = sirinvpn_core::LocalIdentity::generate("IPv6 client").unwrap();
    let mut request = request();
    request.schema_version = 10;
    request.policy = Some(ConnectionPolicy {
        kill_switch: true,
        automatic_reconnect: false,
        connect_on_startup: false,
    });
    request.mtu_policy = Some(sirinvpn_protocol::MtuPolicy::Automatic);
    request.endpoint_host = "2001:db8::8".into();
    request.private_key = client.secret.wireguard_private_key.to_string();
    request.server_public_key = identity.public.wireguard_public_key.clone();
    request.endpoint_identity = Some(EndpointIdentity {
        server_id: request.server_id,
        generation: 1,
        server_wireguard_public_key: identity.public.wireguard_public_key.clone(),
        pinned_server_certificate_pem: identity.public.management_certificate_pem,
        descriptor: EndpointDescriptor {
            endpoint: ServerEndpoint {
                host: request.endpoint_host.clone(),
                wireguard_port: request.endpoint_port,
            },
            alternate_endpoint_hosts: vec!["203.0.113.9".into()],
            endpoint_discovery_port: Some(443),
            ipv6_tunnel_enabled: false,
            obfuscated_udp: None,
            tcp_fallback: Some(TcpFallbackEndpoint {
                port: 443,
                server_public_key: STANDARD.encode([17_u8; 32]),
            }),
            tls_like: Some(TlsLikeEndpoint {
                port: 443,
                server_public_key: STANDARD.encode([17_u8; 32]),
                certificate_sha256: STANDARD.encode([18_u8; 32]),
                https: None,
            }),
        },
    });
    request.endpoint_dns_servers = vec![
        "203.0.113.53:53".parse().unwrap(),
        "[2001:db8::53]:53".parse().unwrap(),
    ];
    validate_request(&request).unwrap();
    let endpoint = "2001:db8::8".parse::<IpAddr>().unwrap();
    if let Err(error) = helper.apply_policy_guard(&request, endpoint) {
        eprintln!(
            "expected: {}",
            serde_json::to_string(&crate::enforcement::guard_objects(&request, endpoint)).unwrap()
        );
        eprintln!(
            "observed: {}",
            String::from_utf8_lossy(
                &SystemRunner
                    .output("nft", &["-j", "list", "table", "inet", "sirinvpn_guard"])
                    .unwrap_or_default()
            )
        );
        panic!("{error}");
    }
    run("normal");
    let answers = vec![
        "203.0.113.8".parse::<IpAddr>().unwrap(),
        "2001:db8::8".parse().unwrap(),
    ];
    for server in &request.endpoint_dns_servers {
        for host in ["udp.endpoint.test", "tcp.endpoint.test"] {
            assert_eq!(endpoint_resolution::resolve(host, &[*server]), answers);
        }
        assert!(endpoint_resolution::resolve("wrong.endpoint.test", &[*server]).is_empty());
    }
    let started = std::time::Instant::now();
    assert!(
        endpoint_resolution::resolve("slow.endpoint.test", &request.endpoint_dns_servers)
            .is_empty()
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a trickled response exceeded the DNS operation deadline"
    );
    println!(
        "OS endpoint DNS: real marked IPv4/IPv6 UDP and truncated-to-TCP exchanges; mismatched IDs and trickled responses rejected"
    );
    helper
        .apply_policy_guard_with_controls(&request, endpoint, &["203.0.113.9:443".parse().unwrap()])
        .unwrap();
    run("controls");
    helper.apply_policy_guard(&request, endpoint).unwrap();
    run("normal");
    helper
        .write_state(&RuntimeState::for_policy(&request))
        .unwrap();
    helper.disconnect().unwrap();

    // The sibling namespace is an actual WireGuard peer reached over IPv6.
    SystemRunner
        .run(
            "ip",
            &[
                "-n",
                "sirin-peer",
                "link",
                "add",
                "endpoint-wg",
                "type",
                "wireguard",
            ],
            None,
        )
        .unwrap();
    SystemRunner
        .run(
            "ip",
            &[
                "netns",
                "exec",
                "sirin-peer",
                "wg",
                "set",
                "endpoint-wg",
                "listen-port",
                "51821",
                "private-key",
                "/dev/stdin",
                "peer",
                &client.public.wireguard_public_key,
                "allowed-ips",
                "10.77.0.2/32",
            ],
            Some(identity.secret.wireguard_private_key.as_bytes()),
        )
        .unwrap();
    SystemRunner
        .run(
            "ip",
            &["-n", "sirin-peer", "link", "set", "endpoint-wg", "up"],
            None,
        )
        .unwrap();
    SystemRunner
        .run(
            "ip",
            &[
                "-n",
                "sirin-peer",
                "route",
                "add",
                "10.77.0.2/32",
                "dev",
                "endpoint-wg",
            ],
            None,
        )
        .unwrap();
    SystemRunner
        .run("ip", &["route", "delete", "10.77.0.1/32"], None)
        .unwrap();
    request.endpoint_port = 51821;
    request
        .endpoint_identity
        .as_mut()
        .unwrap()
        .descriptor
        .endpoint
        .wireguard_port = 51821;
    for kill in [true, false] {
        request.policy.as_mut().unwrap().kill_switch = kill;
        helper.connect(&request).unwrap();
        for _ in 0..50 {
            helper.reconcile_persistent_once(true).unwrap();
            if helper.status().unwrap().state == ConnectionState::Connected {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(helper.status().unwrap().state, ConnectionState::Connected);
        assert!(SystemRunner.succeeds("ping", &["-n", "-c", "1", "-W", "2", "10.77.0.1"]));
        let peers = SystemRunner
            .output("wg", &["show", INTERFACE_NAME, "endpoints"])
            .unwrap();
        assert!(String::from_utf8_lossy(&peers).contains("[2001:db8::8]:51821"));
        let desired = helper.read_persistent().unwrap();
        assert_eq!(desired.endpoint, endpoint);
        assert_eq!(desired.request.policy, request.policy);
        assert!(!helper.status().unwrap().ipv6_tunneled);
        helper.pause_session(request.server_id).unwrap();
        assert!(helper.status().unwrap().waiting_for_user);
        helper.disconnect_session(request.server_id).unwrap();
        println!(
            "real WireGuard IPv6 outer endpoint: encrypted IPv4 tunnel traffic, kill_switch={kill}, inner IPv6 disabled"
        );
    }
    SystemRunner
        .run(
            "ip",
            &["-n", "sirin-peer", "link", "delete", "endpoint-wg"],
            None,
        )
        .unwrap();
    SystemRunner
        .run(
            "ip",
            &["route", "add", "10.77.0.1/32", "via", "203.0.113.8"],
            None,
        )
        .unwrap();
}

#[test]
#[ignore = "requires disposable networking; tests/network/run-policy-kernel.sh kernel_endpoint_ipv6_dns"]
fn kernel_endpoint_ipv6_dns() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let interfaces: Vec<serde_json::Value> =
        serde_json::from_slice(&SystemRunner.output("ip", &["-j", "link", "show"]).unwrap())
            .unwrap();
    assert!(interfaces.len() == 1 && interfaces[0]["ifname"] == "lo");
    assert!(
        Command::new("python3")
            .args(["tests/network/policy_packets.py", "prepare"])
            .status()
            .unwrap()
            .success()
    );
    check_endpoints();
}
