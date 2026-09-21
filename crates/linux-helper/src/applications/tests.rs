use super::*;
mod kernel;

#[test]
fn application_dns_avoids_host_resolver_delegation_and_unowned_files() {
    let temporary = tempfile::tempdir().unwrap();
    let helper = LinuxNetworkHelper::new(SystemRunner, temporary.path().into());
    helper
        .write_application_dns("10.77.0.1".parse().unwrap())
        .unwrap();
    let directory = helper.namespace_directory.join(NAMESPACE);
    assert!(
        fs::read_to_string(directory.join("resolv.conf"))
            .unwrap()
            .starts_with("nameserver 10.77.0.1\n")
    );
    let nss = fs::read_to_string(directory.join("nsswitch.conf")).unwrap();
    assert_eq!(
        nss.lines().find(|line| line.starts_with("hosts:")).unwrap(),
        "hosts: files dns"
    );
    fs::remove_file(directory.join("resolv.conf")).unwrap();
    let innocent = temporary.path().join("innocent");
    fs::write(&innocent, "preserve me").unwrap();
    std::os::unix::fs::symlink(&innocent, directory.join("resolv.conf")).unwrap();
    helper
        .write_application_dns("10.77.0.2".parse().unwrap())
        .unwrap();
    assert_eq!(fs::read_to_string(&innocent).unwrap(), "preserve me");
    fs::write(
        helper.namespace_directory.join(".sirinvpn-apps-owner"),
        "somebody else",
    )
    .unwrap();
    assert!(
        helper
            .write_application_dns("10.77.0.3".parse().unwrap())
            .is_err()
    );
}

#[test]
fn routing_scope_survives_reconnect_and_rejects_downgrade() {
    let mut request = application_request();
    request.schema_version = 10;
    request.routing =
        TunnelRoutingPolicy::selected_routes(["198.51.100.0/24".into()], false).unwrap();
    // Regression: latest endpoint-capable requests used to reject all custom routing.
    assert_eq!(request.schema_version, 10);
    validate_request(&request).unwrap();
    request.routing = TunnelRoutingPolicy::selected_applications(false);
    assert!(validate_request(&request).is_err());
    request.schema_version = 11;
    validate_request(&request).unwrap();
    let candidate = ReconnectCandidate {
        transport: request.transport,
        endpoint_port: request.endpoint_port,
        server_transport_public_key: request.server_transport_public_key.clone(),
        server_certificate_sha256: None,
        https: None,
        mtu: request.mtu,
    };
    let next = request_for_reconnect_candidate(&request, &candidate);
    assert_eq!(next.schema_version, 11);
    assert_eq!(next.routing, request.routing);
    assert_eq!(next.desired_schema(), 6);
    assert_eq!(wireguard_allowed_ips(&request), "0.0.0.0/0");
}

fn application_request() -> TunnelConnectRequest {
    use sirinvpn_protocol::{EndpointDescriptor, EndpointIdentity, MtuPolicy, ServerEndpoint};
    let identity = sirinvpn_core::LocalIdentity::generate("Application routing test").unwrap();
    let mut request = crate::tests::request();
    request.schema_version = 11;
    request.policy = Some(ConnectionPolicy::default());
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

#[test]
fn application_forwarding_does_not_apply_dns_blocks_to_other_apps() {
    let mut request = crate::tests::request();
    request.routing = TunnelRoutingPolicy::selected_applications(true);
    let guard = enforcement::guard_objects(&request, "203.0.113.8".parse().unwrap());
    let text = serde_json::to_string(&guard).unwrap();
    assert!(!text.contains("\"drop\""));
    let app = firewall::objects(&request);
    assert!(serde_json::to_string(&app).unwrap().contains("\"snat\""));
    let commands = firewall::transaction(&app);
    assert!(!commands.iter().any(|cmd| cmd.get("delete").is_some()));
    assert_eq!(
        commands
            .iter()
            .filter(|cmd| cmd.get("flush").is_some())
            .count(),
        3
    );
}
