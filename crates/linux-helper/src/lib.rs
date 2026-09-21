#![forbid(unsafe_code)]

mod applications;
mod authorization;
pub use authorization::{VPN_CONTROL_COMMANDS, authorize_invoking_user, vpn_control_action};
mod cleanup;
mod endpoint_resolution;
mod endpoints;
mod enforcement;
mod handoff;
mod lifecycle;
mod managed;
mod measurement;
mod mtu;
mod ownership;
mod persistence;
mod policy;
mod policy_lifecycle;
mod policy_supervision;
mod quality;
mod session_control;
mod tunnel;
pub use managed::ManagedConnectRequest;

mod routing;
use routing::*;
mod reconnect;
use reconnect::*;
mod startup_status;
mod system;
pub use startup_status::startup_service_enabled;

pub use system::{
    CommandRunner, KILL_SWITCH_SERVICE, POLKIT_POLICY, RECONNECT_SERVICE, SystemRunner,
    TRANSPORT_SERVICE, install_system_integration, read_connect_request, require_root,
    run_transport_relay, run_transport_relay_for,
};

use anyhow::{Result, anyhow, bail};
#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use fs2::FileExt;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sirinvpn_protocol::ipv6_tunnel_address;
use sirinvpn_protocol::{ConnectionState, INTERFACE_NAME, ServerId, TransportKind, validate_host};
use sirinvpn_transport::{
    CLIENT_RELAY_PORT, ClientRelayConfig, TCP_CLIENT_RELAY_PORT, TLS_LIKE_CLIENT_RELAY_PORT,
    TcpClientRelayConfig, TlsLikeClientRelayConfig, TransportSelection, client_relay_config,
    run_client_relay, run_tcp_client_relay, run_tls_like_client_relay, tcp_client_relay_config,
    tls_like_client_relay_config,
};
use std::{
    collections::{BTreeSet, hash_map::DefaultHasher},
    fs,
    hash::{Hash, Hasher},
    io,
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const ROUTING_TABLE: &str = "51820";
const DNS_RULE_PRIORITY: &str = "9990";
const LAN_RULE_PRIORITY_START: u16 = 9_991;
const RULE_TUNNEL_PRIORITY: &str = "10000";
const RULE_MAIN_PRIORITY: &str = "10001";
const KILL_SWITCH_UNIT: &str = "sirinvpn-killswitch.service";
const RECONNECT_UNIT: &str = "sirinvpn-reconnect.service";
const TRANSPORT_UNIT: &str = "sirinvpn-transport.service";
const HANDSHAKE_GRACE_SECONDS: u64 = 30;
// WireGuard rekeys after 120 seconds and rejects a session after 180 seconds.
// Let its own rekey and retry timers run before rebuilding a healthy interface.
const HANDSHAKE_STALE_SECONDS: u64 = 240;
const SUPERVISOR_POLL_SECONDS: u64 = 5;
const MAX_RECONNECT_BACKOFF_SECONDS: u64 = 60;

#[cfg(test)]
const MAX_INCLUDED_ROUTES: usize = 32;
const IPV4_LAN_ROUTES: [&str; 6] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
];
const IPV6_LAN_ROUTES: [&str; 3] = ["fc00::/7", "fe80::/10", "ff00::/8"];

pub use sirinvpn_tunnel_model::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RuntimeState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_guard_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint_monitor: Option<endpoints::EndpointMonitor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quality: Option<quality::QualityController>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtu: Option<sirinvpn_protocol::MtuStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtu_sampled_at_unix: Option<u64>,
    schema_version: u16,
    server_id: ServerId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<ConnectionPolicy>,
    #[serde(default)]
    has_connected: bool,
    #[serde(default)]
    initial_attempts: u8,
    #[serde(default)]
    waiting_for_user: bool,
    #[serde(default)]
    enforcement: Option<KillSwitchState>,
    #[serde(default)]
    observed_at_boot_seconds: Option<u64>,
    #[serde(default)]
    persistent_protection: bool,
    #[serde(default)]
    reconnecting: bool,
    #[serde(default)]
    applied_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_ipv6_address: Option<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "TransportKind::is_direct_udp")]
    transport: TransportKind,
    #[serde(default)]
    transport_fallback_enabled: bool,
    #[serde(
        default,
        skip_serializing_if = "TunnelRoutingPolicy::is_legacy_default"
    )]
    routing: TunnelRoutingPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_address: Option<Ipv4Addr>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistentConnection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    resolved_endpoints: Vec<endpoints::ResolvedEndpoint>,
    schema_version: u16,
    request: TunnelConnectRequest,
    endpoint: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    obfuscated_udp: Option<PersistentObfuscatedUdp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_fallback: Option<PersistentTcpFallback>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extended_routing: Option<TunnelRoutingPolicy>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistentObfuscatedUdp {
    server_transport_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistentTcpFallback {
    server_transport_public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum ClientTransportConfig {
    LegacyObfuscatedUdp(ClientRelayConfig),
    Current(CurrentClientTransportConfig),
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "transport",
    content = "configuration",
    rename_all = "snake_case"
)]
enum CurrentClientTransportConfig {
    TcpFallback(TcpClientRelayConfig),
    TlsLike(TlsLikeClientRelayConfig),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconcileOutcome {
    Healthy,
    AwaitingHandshake,
    ReconnectPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RouteTransition {
    detected_at_unix: u64,
    prior_handshake_unix: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SupervisorContext {
    network_changed_at_unix: Option<u64>,
    physical_route_available: Option<bool>,
    route_transition: Option<RouteTransition>,
}

#[derive(Debug, Default)]
struct NetworkEpochTracker {
    network_changed_at_unix: Option<u64>,
    initialized: bool,
    physical_route: Option<u64>,
    last_handshake_unix: u64,
    route_transition: Option<RouteTransition>,
}

impl NetworkEpochTracker {
    fn observe(
        &mut self,
        physical_route: Option<u64>,
        latest_handshake_unix: Option<u64>,
        now: u64,
    ) {
        if !self.initialized {
            self.initialized = true;
            self.physical_route = physical_route;
            if let Some(handshake) = latest_handshake_unix {
                self.last_handshake_unix = handshake;
            }
            return;
        }

        if physical_route != self.physical_route {
            self.network_changed_at_unix = Some(now);
            self.physical_route = physical_route;
            self.route_transition = physical_route.map(|_| RouteTransition {
                detected_at_unix: now,
                prior_handshake_unix: self.last_handshake_unix,
            });
        }

        if let Some(handshake) = latest_handshake_unix {
            if self.route_transition.is_some_and(|transition| {
                handshake > transition.prior_handshake_unix
                    && handshake_timestamp_is_recent(handshake, now)
            }) {
                self.route_transition = None;
            }
            self.last_handshake_unix = handshake;
        }
    }

    fn context(&self) -> SupervisorContext {
        SupervisorContext {
            network_changed_at_unix: self.network_changed_at_unix,
            physical_route_available: self.initialized.then_some(self.physical_route.is_some()),
            route_transition: self.route_transition,
        }
    }
}

pub struct LinuxNetworkHelper<R = SystemRunner> {
    runner: R,
    runtime_directory: PathBuf,
    persistent_directory: PathBuf,
    namespace_directory: PathBuf,
}

impl LinuxNetworkHelper<SystemRunner> {
    pub fn system() -> Self {
        Self {
            runner: SystemRunner,
            runtime_directory: PathBuf::from("/run/sirinvpn"),
            persistent_directory: PathBuf::from("/var/lib/sirinvpn"),
            namespace_directory: PathBuf::from("/etc/netns"),
        }
    }
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub fn new(runner: R, runtime_directory: PathBuf) -> Self {
        let persistent_directory = runtime_directory.join("persistent");
        let namespace_directory = runtime_directory.join("netns-config");
        Self {
            runner,
            runtime_directory,
            persistent_directory,
            namespace_directory,
        }
    }
}

fn disconnected_status() -> LocalTunnelStatus {
    LocalTunnelStatus {
        application_routing_supported: cfg!(target_os = "linux"),
        application_routing_backend: Some(
            sirinvpn_tunnel_model::ApplicationRoutingBackend::LinuxNamespace,
        ),
        application_routing_ready: None,
        transport_quality_supported: true,
        transport_quality: None,
        endpoint_updates_supported: true,
        endpoint_checkpoint: None,
        mtu_detection_supported: true,
        https_transport_supported: true,
        mtu: None,
        connection_control_supported: true,
        recovery_in_progress: false,
        startup_service_enabled: None,
        supervisor_status_known: None,
        policy: None,
        independent_policy_supported: true,
        kill_switch_state: Some(KillSwitchState::Off),
        connect_on_startup: false,
        waiting_for_user: false,
        traffic_metrics_supported: true,
        byte_counters_available: Some(false),
        included_routes: None,
        state: ConnectionState::Disconnected,
        interface_name: INTERFACE_NAME.to_owned(),
        server_id: None,
        rx_bytes: 0,
        tx_bytes: 0,
        rx_packets: None,
        tx_packets: None,
        tunnel_uptime_seconds: None,
        counter_epoch: None,
        ipv6_blocked: false,
        ipv6_tunneled: false,
        transport: None,
        kill_switch_enabled: false,
        auto_reconnect_enabled: false,
        transport_fallback_enabled: false,
        routing_mode: TunnelRoutingMode::FullTunnel,
        allow_lan: false,
    }
}

fn ipv6_blocked_for_state(state: &RuntimeState, ipv6_tunneled: bool) -> bool {
    // Status is intentionally readable without privilege, while nftables inspection requires
    // CAP_NET_ADMIN. A retained runtime state means the atomic apply completed; persistent
    // protection uses the dual-family guard and an IPv4-only transient session uses client6.
    state.routing.mode == TunnelRoutingMode::FullTunnel
        && !ipv6_tunneled
        && (state.persistent_protection || state.client_ipv6_address.is_none())
}

const CLIENT_FIREWALL: &str = r#"table inet sirinvpn_client {
  chain premangle {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto udp meta mark set ct mark
  }
  chain postmangle {
    type filter hook postrouting priority mangle; policy accept;
    meta l4proto udp ct mark set meta mark
  }
}
"#;

#[cfg(test)]
mod tests;
