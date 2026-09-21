use super::*;

#[test]
fn legacy_configuration_defaults_new_capability_flags_off() {
    let configuration: CurrentConfiguration = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "interface_name": "sirinvpn0",
        "tunnel_cidr": "10.77.0.0/24",
        "dns_address": "10.77.0.1",
        "wireguard_port": 51820,
        "management_port": 8443,
        "ipv6_tunnel_enabled": false,
        "advanced_invitations_enabled": true
    }))
    .unwrap();
    assert!(configuration.advanced_invitations_enabled);
    assert!(!configuration.ownership_transfer_enabled);
    assert!(!configuration.key_rotation_enabled);
    assert!(!configuration.peer_isolation_enabled);
    assert!(!configuration.port_forwarding_enabled);
    assert!(!configuration.member_lifecycle_enabled);
    assert_eq!(configuration.obfuscated_udp, None);
    assert_eq!(configuration.tcp_fallback, None);
    assert_eq!(configuration.dns_upstream, DnsUpstream::Recursive);
    assert!(configuration.private_dns_records.is_empty());
    let serialized = serde_json::to_value(configuration).unwrap();
    assert!(serialized.get("dns_upstream").is_none());
    assert!(serialized.get("private_dns_records").is_none());
    assert!(serialized.get("peer_isolation_enabled").is_none());
    assert!(serialized.get("port_forwarding_enabled").is_none());
    assert!(serialized.get("member_lifecycle_enabled").is_none());

    let member: MemberSummary = serde_json::from_value(serde_json::json!({
        "id": MemberId::new(), "name": "Legacy member", "role": "member", "devices": []
    }))
    .unwrap();
    assert!(!member.suspended);
    assert!(
        serde_json::to_value(member)
            .unwrap()
            .get("suspended")
            .is_none()
    );
    assert!(serde_json::from_str::<MemberDevicesRevokeRequest>("{}").is_err());
    assert!(serde_json::from_str::<MemberSuspensionUpdateRequest>("{}").is_err());

    let device: DeviceSummary = serde_json::from_value(serde_json::json!({
        "id": DeviceId::new(),
        "member_id": MemberId::new(),
        "name": "Legacy device",
        "client_tunnel_address": "10.77.0.3"
    }))
    .unwrap();
    assert!(!device.peer_communication_enabled);
    assert_eq!(device.recent_handshake, None);
    assert!(
        serde_json::to_value(&device)
            .unwrap()
            .get("recent_handshake")
            .is_none()
    );
    assert!(
        serde_json::to_value(device)
            .unwrap()
            .get("peer_communication_enabled")
            .is_none()
    );

    let snapshot: MembershipSnapshot = serde_json::from_value(serde_json::json!({
        "members": [],
        "active_invitations": []
    }))
    .unwrap();
    assert!(snapshot.port_forwards.is_empty());
    assert!(
        serde_json::to_value(snapshot)
            .unwrap()
            .get("port_forwards")
            .is_none()
    );
}
