use crate::{
    firewall_plan::{Condition, FirewallPlan, Layer},
    network_plan::tunnel_routes,
    state::{SavedConnection, SessionPhase},
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
    assert!(saved.authorize(&saved.owner_sid).is_ok());
    assert!(saved.authorize("S-1-5-21-100-200-300-1002").is_err());
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
