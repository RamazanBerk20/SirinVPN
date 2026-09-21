use super::*;
use crate::{application_plan::*, network_plan};
use sirinvpn_protocol::{EndpointDescriptor, EndpointIdentity, MtuPolicy, ServerEndpoint};

const OWNER: &str = "S-1-5-21-100-200-300-1001";
fn application_request() -> TunnelConnectRequest {
    let identity = sirinvpn_core::LocalIdentity::generate("Windows application test").unwrap();
    let mut request = request();
    request.schema_version = 11;
    request.mtu_policy = Some(MtuPolicy::Automatic);
    request.routing = TunnelRoutingPolicy::selected_applications(false);
    request.server_public_key = identity.public.wireguard_public_key.clone();
    request.endpoint_identity = Some(EndpointIdentity {
        server_id: request.server_id,
        server_wireguard_public_key: request.server_public_key.clone(),
        pinned_server_certificate_pem: identity.public.management_certificate_pem,
        generation: 1,
        descriptor: EndpointDescriptor {
            endpoint: ServerEndpoint {
                host: request.endpoint_host.clone(),
                wireguard_port: request.endpoint_port,
            },
            alternate_endpoint_hosts: Vec::new(),
            endpoint_discovery_port: None,
            ipv6_tunnel_enabled: false,
            obfuscated_udp: None,
            tcp_fallback: None,
            tls_like: None,
        },
    });
    request
}
fn selection() -> SelectedApplication {
    SelectedApplication {
        executable: r"C:\Apps\client.exe".into(),
        app_id: r"\device\harddiskvolume3\apps\client.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
    }
}
fn selected(remote: &str, interface: u64) -> Flow {
    Flow {
        application: Some((selection().app_id, OWNER.into())),
        ..web(remote, interface)
    }
}

#[test]
fn selected_executable_cannot_escape_on_an_underlay_or_ipv6() {
    let request = application_request();
    network_plan::validate(&request).unwrap();
    let plan = FirewallPlan::for_tunnel(&request, &[], Some(500)).with_applications(
        &[selection()],
        OWNER,
        request.client_address,
        Some(500),
    );
    assert!(allowed(&plan, selected("203.0.113.20", 500), false));
    for remote in ["203.0.113.20", "192.168.1.1", "2001:db8::20"] {
        assert!(!allowed(&plan, selected(remote, 12), false));
        assert!(!allowed(&plan, selected(remote, 500), true));
    }
    assert!(!allowed(&plan, selected("2001:db8::20", 500), false));
    assert!(allowed(&plan, web("203.0.113.20", 12), false));
    assert!(allowed(&plan, web("2001:db8::20", 12), false));
    let mut other_user = selected("203.0.113.20", 12);
    other_user.application.as_mut().unwrap().1 = "S-1-5-21-100-200-300-1002".into();
    assert!(allowed(&plan, other_user, false));
    let mut raw = selected("203.0.113.20", 500);
    raw.protocol = 1;
    assert!(!allowed(&plan, raw, false));
    assert!(allowed(&plan, selected("127.0.0.1", 1), false));
    let persistent = FirewallPlan {
        persistent: true,
        rules: plan.persistent_rules(),
    };
    assert!(!allowed(&persistent, selected("203.0.113.20", 12), false));
    assert!(!allowed(&persistent, selected("203.0.113.20", 500), false));
    assert!(
        persistent
            .rules
            .iter()
            .all(|rule| rule.bind_address.is_none())
    );
    let closed = FirewallPlan::for_tunnel(&request, &[], None).with_applications(
        &[selection()],
        OWNER,
        request.client_address,
        None,
    );
    assert!(!allowed(&closed, selected("203.0.113.20", 12), false));
    assert!(closed.rules.iter().all(|rule| rule.bind_address.is_none()));
}

#[test]
fn application_mode_requires_protection_and_owns_only_its_weak_default_route() {
    let mut request = application_request();
    network_plan::validate(&request).unwrap();
    let routes = network_plan::tunnel_routes(&request);
    assert!(routes.contains(&"0.0.0.0/0".parse().unwrap()));
    assert!(routes.contains(&"10.77.0.1/32".parse().unwrap()));
    assert!(!routes.contains(&"0.0.0.0/1".parse().unwrap()));
    request.policy.as_mut().unwrap().kill_switch = false;
    assert!(network_plan::validate(&request).is_err());
    request.policy.as_mut().unwrap().kill_switch = true;
    request.routing.allow_lan = true;
    assert!(network_plan::validate(&request).is_err());
    let mut route = network_plan::RouteRecord {
        tunnel: true,
        interface_luid: 500,
        interface_index: 50,
        destination: "0.0.0.0/0".into(),
        next_hop: "0.0.0.0".parse().unwrap(),
        scope_id: 0,
        metric: network_plan::APPLICATION_ROUTE_METRIC,
    };
    assert!(route.validate());
    route.destination = "0.0.0.0/1".into();
    assert!(!route.validate());
}

#[test]
fn path_and_ipc_validation_reject_system_launch_and_remote_file_requests() {
    for path in [
        r"\\server\share\app.exe",
        r"\\?\C:\Apps\app.exe",
        r"C:app.exe",
        r"C:\Apps\..\app.exe",
        r"C:\Apps\app.exe:stream",
        r"C:\Apps\app.cmd",
        r"C:\Apps.\app.exe",
        r"C:/Apps/app.exe",
        r"C:\Apps\\app.exe",
    ] {
        assert!(!valid_executable_path(path), "{path}");
    }
    assert!(valid_executable_path(r"C:\Program Files\Example\app.exe"));
    assert!(selection().validate());
    let mut invalid = selection();
    invalid.app_id = r"\device\mup\server\app.exe"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(!invalid.validate());
    let request = serde_json::json!({"server_id": application_request().server_id, "executable": r"C:\Apps\client.exe", "arguments": ["--elevated"], "owner_sid": "S-1-5-18" });
    assert!(
        crate::Operation::from_helper(
            "route-application",
            Some(&serde_json::to_vec(&request).unwrap())
        )
        .is_err()
    );
}

#[test]
fn current_selection_survives_recovery_but_cannot_downgrade_its_state_schema() {
    let saved = SavedConnection {
        schema_version: 2,
        owner_sid: OWNER.into(),
        boot_nonce: uuid::Uuid::new_v4(),
        phase: SessionPhase::Active,
        request: application_request(),
        endpoints: Vec::new(),
        routes: Vec::new(),
        applications: vec![selection()],
    };
    saved.validate().unwrap();
    let bytes = serde_json::to_vec(&saved).unwrap();
    let mut restored: SavedConnection = serde_json::from_slice(&bytes).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored.applications, saved.applications);
    assert!(restored.authorize("S-1-5-21-100-200-300-1002").is_err());
    restored.schema_version = 1;
    assert!(restored.validate().is_err());
    restored.schema_version = 2;
    restored.request.routing = TunnelRoutingPolicy::full_tunnel(false);
    assert!(restored.validate().is_err());
}
