use super::*;

#[test]
fn device_platform_and_blocking_flag_are_optional() {
    let legacy = serde_json::json!({
        "id": DeviceId::new(),
        "member_id": MemberId::new(),
        "name": "Legacy device",
        "client_tunnel_address": "10.77.0.3"
    });
    let device: DeviceSummary = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(device.platform, None);
    assert_eq!(serde_json::to_value(&device).unwrap(), legacy);
    // A platform added after this release reaches this app as text it does not know.
    let mut newer = legacy;
    newer["platform"] = "macos".into();
    let device: DeviceSummary = serde_json::from_value(newer.clone()).unwrap();
    assert_eq!(device.platform.as_deref(), Some("macos"));
    assert_eq!(serde_json::to_value(&device).unwrap(), newer);

    let status = serde_json::json!({
        "api_version": "v1", "server_name": "Legacy server", "connection_state": "connected",
        "interface_up": true, "dns_healthy": true, "transport": "direct_udp",
        "peer_count": 1, "rx_bytes": 0, "tx_bytes": 0, "uptime_seconds": 0
    });
    let mut parsed: ServerStatus = serde_json::from_value(status.clone()).unwrap();
    assert_eq!(parsed.dns_blocklist_enabled, None);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), status);
    parsed.dns_blocklist_enabled = Some(false);
    assert_eq!(
        serde_json::to_value(&parsed).unwrap()["dns_blocklist_enabled"],
        false
    );

    let configuration: CurrentConfiguration = serde_json::from_value(serde_json::json!({
        "api_version": "v1", "interface_name": "sirinvpn0", "tunnel_cidr": "10.77.0.0/24",
        "dns_address": "10.77.0.1", "wireguard_port": 51820, "management_port": 8443,
        "ipv6_tunnel_enabled": false
    }))
    .unwrap();
    assert!(!configuration.device_platforms_enabled);
    assert!(
        serde_json::to_value(configuration)
            .unwrap()
            .get("device_platforms_enabled")
            .is_none()
    );

    // The report always targets the calling device: a body that names one is rejected.
    assert!(
        serde_json::from_value::<DevicePlatformUpdateRequest>(
            serde_json::json!({"platform": "linux", "device_id": DeviceId::new()})
        )
        .is_err()
    );
    assert_eq!(
        serde_json::from_value::<DevicePlatformUpdateRequest>(
            serde_json::json!({"platform": "android"})
        )
        .unwrap()
        .platform,
        "android"
    );
}
