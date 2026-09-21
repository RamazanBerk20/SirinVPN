use super::*;

use sirinvpn_protocol::ServerEndpoint;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use uuid::Uuid;

type RecordedCommand = (String, Vec<String>, Vec<u8>);

#[derive(Clone, Default)]
struct RecordingRunner {
    commands: Arc<Mutex<Vec<RecordedCommand>>>,
    route_conflict: bool,
    fail_apply: bool,
    fail_service_start: bool,
    cleanup_residue: bool,
    emulate_tunnel: bool,
    apply_failed: Arc<AtomicBool>,
    guard_exists: Arc<AtomicBool>,
    interface_exists: Arc<AtomicBool>,
    latest_handshake_unix: Arc<AtomicU64>,
}

impl CommandRunner for RecordingRunner {
    fn run(&self, program: &str, arguments: &[&str], stdin: Option<&[u8]>) -> Result<()> {
        if program == "ip" && arguments == ["link", "show", INTERFACE_NAME] {
            if self.cleanup_residue && self.apply_failed.load(Ordering::SeqCst) {
                return Ok(());
            }
            if self.emulate_tunnel && self.interface_exists.load(Ordering::SeqCst) {
                return Ok(());
            }
            bail!("not found")
        }
        if program == "nft" && arguments == ["list", "table", "inet", "sirinvpn_guard"] {
            if self.guard_exists.load(Ordering::SeqCst) {
                return Ok(());
            }
            bail!("not found")
        }
        if self.emulate_tunnel
            && program == "nft"
            && arguments == ["list", "table", "inet", "sirinvpn_client"]
            && self.interface_exists.load(Ordering::SeqCst)
        {
            return Ok(());
        }
        if program == "nft" && arguments.first() == Some(&"list") {
            bail!("not found")
        }
        if self.fail_apply
            && program == "resolvectl"
            && arguments == ["domain", INTERFACE_NAME, "~."]
        {
            self.apply_failed.store(true, Ordering::SeqCst);
            bail!("injected apply failure")
        }
        if self.fail_service_start
            && program == "systemctl"
            && arguments == ["restart", RECONNECT_UNIT]
        {
            bail!("injected service start failure")
        }
        if program == "nft"
            && arguments == ["-f", "-"]
            && stdin.is_some_and(|input| String::from_utf8_lossy(input).contains("sirinvpn_guard"))
        {
            self.guard_exists.store(true, Ordering::SeqCst);
        }
        if program == "nft" && arguments == ["delete", "table", "inet", "sirinvpn_guard"] {
            self.guard_exists.store(false, Ordering::SeqCst);
        }
        if self.emulate_tunnel
            && program == "ip"
            && arguments == ["link", "add", INTERFACE_NAME, "type", "wireguard"]
        {
            self.interface_exists.store(true, Ordering::SeqCst);
        }
        if self.emulate_tunnel && program == "ip" && arguments == ["link", "delete", INTERFACE_NAME]
        {
            self.interface_exists.store(false, Ordering::SeqCst);
        }
        self.commands.lock().unwrap().push((
            program.to_owned(),
            arguments.iter().map(|value| (*value).to_owned()).collect(),
            stdin.unwrap_or_default().to_vec(),
        ));
        Ok(())
    }

    fn output(&self, program: &str, arguments: &[&str]) -> Result<Vec<u8>> {
        if program == "nft" && arguments == ["-j", "list", "tables"] {
            return Ok(serde_json::to_vec(
                &serde_json::json!({"nftables": if self.guard_exists.load(Ordering::SeqCst) {
                vec![serde_json::json!({"table":{"family":"inet","name":"sirinvpn_guard"}})]
            } else { Vec::<serde_json::Value>::new() }}),
            )?);
        }
        if program == "ip" && arguments == ["-4", "route", "show", "table", ROUTING_TABLE] {
            bail!("ipv4: FIB table does not exist")
        }
        if self.route_conflict
            && program == "ip"
            && arguments == ["-details", "-4", "route", "show", "table", "all"]
        {
            return Ok(b"unicast default dev another-vpn table 51820 proto static\n".to_vec());
        }
        if self.emulate_tunnel && self.interface_exists.load(Ordering::SeqCst) {
            if program == "ip" && arguments == ["-details", "-4", "route", "show", "table", "all"] {
                return Ok(b"unicast default dev sirinvpn0 table 51820 proto static\n".to_vec());
            }
            if program == "ip"
                && (arguments == ["-4", "rule", "show", "priority", RULE_TUNNEL_PRIORITY]
                    || arguments == ["-4", "rule", "show", "priority", RULE_MAIN_PRIORITY])
            {
                return Ok(b"10000: from all lookup main\n".to_vec());
            }
            if program == "wg" && arguments == ["show", INTERFACE_NAME, "latest-handshakes"] {
                return Ok(format!(
                    "peer\t{}\n",
                    self.latest_handshake_unix.load(Ordering::SeqCst)
                )
                .into_bytes());
            }
        }
        self.run(program, arguments, None)?;
        Ok(Vec::new())
    }
}

pub(crate) fn request() -> TunnelConnectRequest {
    TunnelConnectRequest {
        endpoint_identity: None,
        endpoint_checkpoint: None,
        endpoint_publication_enabled: false,
        endpoint_dns_servers: Vec::new(),
        mtu_policy: None,
        policy: None,
        schema_version: 1,
        server_id: ServerId(Uuid::new_v4()),
        endpoint_host: "203.0.113.8".into(),
        endpoint_port: 51_820,
        transport: TransportKind::DirectUdp,
        server_transport_public_key: None,
        https: None,
        server_certificate_sha256: None,
        reconnect_candidates: Vec::new(),
        client_address: Ipv4Addr::new(10, 77, 0, 2),
        client_ipv6_address: None,
        server_public_key: STANDARD.encode([8_u8; 32]),
        private_key: STANDARD.encode([7_u8; 32]),
        dns_address: Ipv4Addr::new(10, 77, 0, 1),
        mtu: 1_420,
        persistent_protection: false,
        routing: TunnelRoutingPolicy::default(),
    }
}

fn selection(
    transport: TransportKind,
    port: u16,
    key: Option<String>,
    mtu: u16,
) -> TransportSelection {
    TransportSelection {
        kind: transport,
        network_endpoint: ServerEndpoint {
            host: "203.0.113.8".to_owned(),
            wireguard_port: port,
        },
        wireguard_endpoint: ServerEndpoint {
            host: "127.0.0.1".to_owned(),
            wireguard_port: port,
        },
        mtu,
        server_transport_public_key: key,
        https: None,
        server_certificate_sha256: None,
    }
}

fn persistent_automatic_request() -> TunnelConnectRequest {
    let mut request = request();
    request.schema_version = 2;
    request.persistent_protection = true;
    request.reconnect_candidates = vec![
        ReconnectCandidate {
            transport: TransportKind::DirectUdp,
            endpoint_port: 51_820,
            server_transport_public_key: None,
            https: None,
            server_certificate_sha256: None,
            mtu: 1_420,
        },
        ReconnectCandidate {
            transport: TransportKind::ObfuscatedUdp,
            endpoint_port: 443,
            server_transport_public_key: Some(STANDARD.encode([9_u8; 32])),
            https: None,
            server_certificate_sha256: None,
            mtu: 1_320,
        },
        ReconnectCandidate {
            transport: TransportKind::TcpFallback,
            endpoint_port: 443,
            server_transport_public_key: Some(STANDARD.encode([10_u8; 32])),
            https: None,
            server_certificate_sha256: None,
            mtu: 1_280,
        },
    ];
    request
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct LegacyTunnelConnectRequestV6 {
    schema_version: u16,
    server_id: ServerId,
    endpoint_host: String,
    endpoint_port: u16,
    #[serde(default)]
    transport: TransportKind,
    #[serde(default)]
    server_transport_public_key: Option<String>,
    client_address: Ipv4Addr,
    server_public_key: String,
    private_key: String,
    dns_address: Ipv4Addr,
    #[serde(default)]
    client_ipv6_address: Option<Ipv6Addr>,
    mtu: u16,
    #[serde(default)]
    persistent_protection: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct LegacyPersistentConnectionV6 {
    schema_version: u16,
    request: LegacyTunnelConnectRequestV6,
    endpoint: IpAddr,
    #[serde(default)]
    obfuscated_udp: Option<PersistentObfuscatedUdp>,
    #[serde(default)]
    tcp_fallback: Option<PersistentTcpFallback>,
}

mod private_key_is_only_sent_over_stdin;
mod route_transition_allows_roaming_then_cycles_automatic_transport;
mod stale_automatic_attempts_cycle_candidates_and_replace_the_guard_atomically;
mod tcp_transport_uses_a_tagged_runtime_config_that_legacy_helpers_reject;

mod endpoint_kernel;
mod kernel_policy;
mod policy_tests;
mod session_kernel;

mod automatic_kernel;
