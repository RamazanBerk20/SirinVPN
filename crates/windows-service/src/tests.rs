use crate::{
    Operation, ServiceError, StatusWait,
    firewall_plan::{Condition, FirewallPlan, Layer},
    network_plan::tunnel_routes,
    state::{SavedConnection, SessionPhase, authorize},
};
use sirinvpn_tunnel_model::{ConnectionPolicy, TunnelConnectRequest, TunnelRoutingPolicy};
use std::net::IpAddr;
mod applications;

fn request() -> TunnelConnectRequest {
    serde_json::from_value(serde_json::json!({
        "schema_version": 7,
        "server_id": "c6e6d11a-9933-48bf-b58b-fd4c2d386cd4",
        "endpoint_host": "198.51.100.9", "endpoint_port": 51820,
        "client_address": "10.77.0.2", "dns_address": "10.77.0.1",
        "server_public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "private_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        "mtu": 1380,
        "policy": {"kill_switch": true, "automatic_reconnect": true, "connect_on_startup": false}
    }))
    .unwrap()
}

// Packet-oriented checks exercise leak cases rather than counting generated
// filters. Unmatched traffic in a selected-route policy follows the host policy.
struct Flow {
    application: Option<(Vec<u8>, String)>,
    remote: IpAddr,
    port: u16,
    interface: u64,
    service: bool,
    system: bool,
    protocol: u8,
}
fn allowed(plan: &FirewallPlan, flow: Flow, boot: bool) -> bool {
    let layer = if flow.remote.is_ipv6() {
        Layer::ConnectV6
    } else {
        Layer::ConnectV4
    };
    plan.rules
        .iter()
        .filter(|rule| {
            rule.layer == layer
                && rule.boot == boot
                && rule.conditions.iter().all(|condition| match condition {
                    Condition::ServiceApplication => flow.service,
                    Condition::SystemUser => flow.system,
                    Condition::Application(expected) => flow
                        .application
                        .as_ref()
                        .is_some_and(|(id, _)| id == expected),
                    Condition::User(expected) => flow
                        .application
                        .as_ref()
                        .is_some_and(|(_, sid)| sid == expected),
                    Condition::Interface(luid) => *luid == flow.interface,
                    Condition::Remote(network) => network.contains(&flow.remote),
                    Condition::RemotePort(port) => *port == flow.port,
                    Condition::Protocol(protocol) => *protocol == flow.protocol,
                    Condition::Loopback => flow.remote.is_loopback(),
                    _ => false,
                })
        })
        .max_by_key(|rule| rule.weight)
        .is_none_or(|rule| rule.permit)
}
fn web(remote: &str, interface: u64) -> Flow {
    Flow {
        application: None,
        remote: remote.parse().unwrap(),
        port: 443,
        interface,
        service: false,
        system: false,
        protocol: 6,
    }
}

#[test]
fn full_tunnel_and_boot_policy_do_not_leak_over_a_physical_interface() {
    let mut request = request();
    request.routing = TunnelRoutingPolicy::full_tunnel(true);
    let plan = FirewallPlan::for_tunnel(&request, &[], Some(500));
    assert!(!allowed(&plan, web("203.0.113.20", 12), false));
    assert!(allowed(&plan, web("203.0.113.20", 500), false));
    assert!(!allowed(&plan, web("203.0.113.20", 500), true));
    assert!(allowed(&plan, web("192.168.1.1", 12), false));
    assert!(allowed(&plan, web("192.168.1.1", 12), true));
    assert!(!allowed(&plan, web("10.77.0.1", 12), false));
    assert!(!allowed(&plan, web("10.77.0.1", 12), true));
    let mut dns = web("192.168.1.1", 12);
    dns.port = 53;
    assert!(!allowed(&plan, dns, true));
    let mut dns = web("10.77.0.1", 500);
    dns.port = 53;
    assert!(allowed(&plan, dns, false));
    assert!(!allowed(&plan, web("2001:db8::5", 12), false));
}

#[test]
fn only_authenticated_service_carriers_get_an_underlay_exception() {
    let request = request();
    let endpoint = "198.51.100.9:51820".parse().unwrap();
    let plan = FirewallPlan::for_tunnel(&request, &[endpoint], None);
    let carrier = |system, service, port, protocol| Flow {
        application: None,
        remote: "198.51.100.9".parse().unwrap(),
        interface: 12,
        system,
        service,
        port,
        protocol,
    };
    assert!(allowed(&plan, carrier(true, true, 51820, 17), false));
    assert!(!allowed(&plan, carrier(false, true, 51820, 17), false));
    assert!(!allowed(&plan, carrier(true, false, 51820, 17), false));
    assert!(!allowed(&plan, carrier(true, true, 53, 17), false));
    assert!(!allowed(&plan, carrier(true, true, 51820, 6), false));
    assert!(!allowed(&plan, carrier(true, true, 51820, 17), true));
}

#[test]
fn selected_routes_protect_selected_destinations_and_keep_lan_opt_out_precise() {
    let mut request = request();
    request.routing =
        TunnelRoutingPolicy::selected_routes(["198.18.0.0/15".into(), "172.0.0.0/8".into()], true)
            .unwrap();
    let plan = FirewallPlan::for_tunnel(&request, &[], None);
    assert!(!allowed(&plan, web("198.18.1.1", 12), false));
    assert!(allowed(&plan, web("203.0.113.20", 12), false));
    let routes = tunnel_routes(&request);
    let routed = |address: &str| {
        routes
            .iter()
            .any(|route| route.contains(&address.parse::<IpAddr>().unwrap()))
    };
    assert!(routed("198.18.1.1"));
    assert!(routed("172.15.255.254"));
    assert!(!routed("172.16.0.1"));
    assert!(!routed("172.31.255.254"));
    assert!(routed("172.32.0.1"));
    assert!(routed("10.77.0.1"));
    assert!(!routed("192.168.1.1"));
}

#[test]
fn startup_and_service_recovery_are_independent_and_session_owner_is_enforced() {
    let boot = uuid::Uuid::new_v4();
    let next_boot = uuid::Uuid::new_v4();
    let mut saved = SavedConnection {
        schema_version: 1,
        owner_sid: "S-1-5-21-100-200-300-1001".into(),
        boot_nonce: boot,
        phase: SessionPhase::Active,
        request: request(),
        endpoints: Vec::new(),
        routes: Vec::new(),
        applications: Vec::new(),
    };
    saved.validate().unwrap();
    let owner = Some(saved.owner_sid.as_str());
    assert!(authorize(owner, &saved.owner_sid, false, &Operation::Disconnect).is_ok());
    assert!(
        authorize(
            owner,
            "S-1-5-21-100-200-300-1002",
            false,
            &Operation::Status
        )
        .is_err()
    );
    assert!(saved.may_resume_after_restart(boot));
    assert!(!saved.may_resume_after_restart(next_boot));
    saved.request.policy = Some(ConnectionPolicy {
        kill_switch: true,
        automatic_reconnect: false,
        connect_on_startup: true,
    });
    assert!(!saved.may_resume_after_restart(boot));
    assert!(saved.may_resume_after_restart(next_boot));
    saved.phase = SessionPhase::Held;
    assert!(!saved.may_resume_after_restart(boot));
    assert!(saved.may_resume_after_restart(next_boot));
    saved.phase = SessionPhase::Disconnecting;
    assert!(!saved.may_resume_after_restart(next_boot));
}

#[test]
fn persistent_guard_contains_no_stale_adapter_or_service_socket_exceptions() {
    use crate::firewall_plan::ControlSocket;
    let request = request();
    let plan = FirewallPlan::for_tunnel(
        &request,
        &["198.51.100.9:51820".parse().unwrap()],
        Some(500),
    )
    .with_control(&[ControlSocket {
        address: "192.168.1.1:53".parse().unwrap(),
        protocol: 17,
        interface_luid: 12,
    }]);
    let persistent = FirewallPlan {
        persistent: true,
        rules: plan.persistent_rules(),
    };
    assert!(!allowed(&persistent, web("203.0.113.20", 500), false));
    let control = |service, system, interface| Flow {
        application: None,
        remote: "192.168.1.1".parse().unwrap(),
        port: 53,
        interface,
        service,
        system,
        protocol: 17,
    };
    assert!(allowed(&plan, control(true, true, 12), false));
    assert!(!allowed(&plan, control(false, true, 12), false));
    assert!(!allowed(&plan, control(true, false, 12), false));
    assert!(!allowed(&plan, control(true, true, 500), false));
    assert!(!allowed(&persistent, control(true, true, 12), false));
    assert!(!allowed(&plan, control(true, true, 12), true));
    assert!(
        plan.dynamic_rules()
            .iter()
            .all(|rule| rule.permit && !rule.boot)
    );
}

#[test]
fn full_tunnel_lan_routes_keep_private_dns_inside_the_adapter() {
    let mut request = request();
    request.routing = TunnelRoutingPolicy::full_tunnel(true);
    let routes = tunnel_routes(&request);
    let routed = |address: &str| {
        routes
            .iter()
            .any(|route| route.contains(&address.parse::<IpAddr>().unwrap()))
    };
    assert!(routed("198.51.100.42"));
    assert!(routed("10.77.0.1"));
    assert!(!routed("192.168.0.3"));
    assert!(!routed("172.16.0.1"));
    assert!(!routed("169.254.22.23"));
}

#[test]
fn reachable_subnet_routes_stay_in_the_tunnel_above_lan_access() {
    let mut request = request();
    request.routing = TunnelRoutingPolicy::full_tunnel(true);
    request.subnet_routes.reachable = vec!["192.168.1.0/24".into()];
    assert!(crate::network_plan::validate(&request).is_ok());
    let routes = tunnel_routes(&request);
    let routed = |address: &str| {
        routes
            .iter()
            .any(|route| route.contains(&address.parse::<IpAddr>().unwrap()))
    };
    assert!(routed("192.168.1.20"));
    assert!(!routed("192.168.2.20"));
    let plan = FirewallPlan::for_tunnel(&request, &[], Some(500));
    assert!(allowed(&plan, web("192.168.1.20", 500), false));
    assert!(!allowed(&plan, web("192.168.1.20", 12), false));
    assert!(!allowed(&plan, web("192.168.1.20", 12), true));
    assert!(allowed(&plan, web("192.168.2.20", 12), false));

    request.routing =
        TunnelRoutingPolicy::selected_routes(["198.51.100.0/24".to_owned()], false).unwrap();
    let allowed_ips = crate::network_plan::allowed_ips(&request);
    assert!(allowed_ips.contains(&"192.168.1.0/24".parse().unwrap()));
    // Windows consumes routes; it never forwards a LAN.
    request.subnet_routes.announced = vec!["192.168.9.0/24".into()];
    assert!(crate::network_plan::validate(&request).is_err());
}

/// The idle snapshot shape the service publishes, for tests of status logic.
pub(crate) fn idle_status() -> sirinvpn_tunnel_model::LocalTunnelStatus {
    serde_json::from_value(serde_json::json!({
        "state":"disconnected", "interface_name":"SirinVPN",
        "rx_bytes":0, "tx_bytes":0, "ipv6_blocked":false, "ipv6_tunneled":false,
        "kill_switch_enabled":false, "auto_reconnect_enabled":false,
        "transport_fallback_enabled":false, "routing_mode":"full_tunnel", "allow_lan":false
    }))
    .unwrap()
}

#[test]
fn administrators_may_inspect_or_end_another_users_session_but_not_take_it_over() {
    let owner = "S-1-5-21-100-200-300-1001";
    let other = "S-1-5-21-100-200-300-1002";
    let server = sirinvpn_protocol::ServerId::new();
    let wait = StatusWait {
        after: None,
        timeout_ms: 1000,
    };
    let observe_or_end = [
        Operation::Status,
        Operation::WaitForChange(wait),
        Operation::Disconnect,
        Operation::DisconnectSession(server),
    ];
    let control = [
        Operation::Connect(request()),
        Operation::Resume(server),
        Operation::PauseSession(server),
        Operation::PauseForKeyRotation(server),
        Operation::ReconnectSession(server),
    ];
    for operation in observe_or_end.iter().chain(&control) {
        // No session: anyone may start or query; the owner may do anything.
        assert!(authorize(None, other, false, operation).is_ok());
        assert!(authorize(Some(owner), owner, false, operation).is_ok());
        assert!(matches!(
            authorize(Some(owner), other, false, operation),
            Err(ServiceError::OwnedByAnotherUser)
        ));
    }
    for operation in &observe_or_end {
        assert!(authorize(Some(owner), other, true, operation).is_ok());
    }
    for operation in &control {
        assert!(matches!(
            authorize(Some(owner), other, true, operation),
            Err(ServiceError::OwnedByAnotherUser)
        ));
    }
}

#[test]
fn relay_sessions_pin_a_fixed_wireguard_port_and_report_it_when_taken() {
    use crate::network_plan::{require_free_port, uses_fixed_port, wireguard_listen_port};
    use sirinvpn_protocol::TransportKind;
    assert_eq!(wireguard_listen_port(TransportKind::DirectUdp), None);
    for kind in [
        TransportKind::ObfuscatedUdp,
        TransportKind::TcpFallback,
        TransportKind::TlsLike,
        TransportKind::Quic,
    ] {
        assert_eq!(
            wireguard_listen_port(kind),
            Some(crate::WIREGUARD_LISTEN_PORT)
        );
    }
    assert_eq!(crate::WIREGUARD_LISTEN_PORT, 1023);
    let direct = request();
    assert_eq!(direct.transport, TransportKind::DirectUdp);
    assert!(!uses_fixed_port(&direct));

    let mut probed = None;
    let taken = require_free_port(|port| {
        probed = Some(port);
        Err(std::io::ErrorKind::AddrInUse.into())
    });
    assert_eq!(probed, Some(1023));
    let message = taken.unwrap_err().to_string();
    assert_eq!(
        message,
        "Another program is using the local port SirinVPN needs (127.0.0.1:1023). Close it and try again."
    );
    assert!(require_free_port(|_| Ok(())).is_ok());
    // Other probe failures (for example access denied) are not misreported.
    assert!(require_free_port(|_| Err(std::io::ErrorKind::PermissionDenied.into())).is_ok());
}
