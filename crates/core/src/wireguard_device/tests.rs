use super::*;
use qrcode::{EcLevel, QrCode};
use sirinvpn_protocol::{DeviceId, ServerEndpoint, ServerId, ServerRole};
use std::net::Ipv4Addr;

fn profile(host: &str, ipv6_tunnel_enabled: bool) -> ServerProfile {
    ServerProfile {
        schema_version: 1,
        id: ServerId::new(),
        name: "Home".into(),
        favorite: false,
        endpoint: ServerEndpoint {
            host: host.into(),
            wireguard_port: 51_820,
        },
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: None,
        endpoint_generation: 0,
        pending_previous_endpoint: None,
        pending_previous_transports: None,
        client_tunnel_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
        server_tunnel_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1)),
        server_wireguard_public_key: STANDARD.encode([7; 32]),
        pinned_server_certificate_pem: "certificate".into(),
        client_management_certificate_pem: "client-certificate".into(),
        identity_reference: "identity".into(),
        role: ServerRole::Owner,
        administrator: false,
        member_id: None,
        device_id: None,
        ipv6_tunnel_enabled,
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
        subnet_routes: Default::default(),
    }
}

fn summary(draft: &WireGuardDeviceDraft, host: u8) -> DeviceSummary {
    DeviceSummary {
        id: DeviceId::new(),
        member_id: draft.request().target_member_id.unwrap_or_default(),
        name: draft.request().device_name.clone(),
        client_tunnel_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, host)),
        identity_fingerprint: String::new(),
        peer_communication_enabled: false,
        recent_handshake: None,
        wireguard_only: true,
        subnet_routes: Vec::new(),
    }
}

fn value<'a>(config: &'a str, key: &str) -> &'a str {
    config
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key} = ")))
        .unwrap()
}

#[test]
fn configuration_carries_the_locally_generated_keys_and_vps_resolver() {
    let profile = profile("vpn.example.test", false);
    let draft = WireGuardDeviceDraft::new(
        &profile,
        "Ayşe",
        "Ayşe's iPhone 15",
        None,
        Default::default(),
    )
    .unwrap();
    let request = draft.request().clone();
    crate::validate_preshared_key(&request.preshared_key).unwrap();
    let response = summary(&draft, 9);
    let config = draft.finish(response).unwrap();
    let text = config.expose();
    assert_eq!(
        crate::wireguard_public_key_from_private(value(text, "PrivateKey")).unwrap(),
        request.wireguard_public_key
    );
    assert_eq!(value(text, "PresharedKey"), request.preshared_key);
    assert_eq!(value(text, "Address"), "10.77.0.9/32");
    assert_eq!(value(text, "DNS"), "10.77.0.1");
    assert_eq!(
        value(text, "PublicKey"),
        profile.server_wireguard_public_key
    );
    assert_eq!(value(text, "Endpoint"), "vpn.example.test:51820");
    assert_eq!(value(text, "AllowedIPs"), "0.0.0.0/0, ::/0");
    assert_eq!(config.file_name(), "Ay-e-s-iPhone-1.conf");
    assert!(!format!("{config:?}").contains(value(text, "PrivateKey")));
    // The official apps scan the plain configuration text.
    assert!(QrCode::with_error_correction_level(text, EcLevel::L).is_ok());
}

#[test]
fn ipv6_tunnels_and_ipv6_endpoints_render_in_wireguard_syntax() {
    let profile = profile("2001:db8::4", true);
    let draft =
        WireGuardDeviceDraft::new(&profile, "Home", "Router", None, Default::default()).unwrap();
    let response = summary(&draft, 12);
    let config = draft.finish(response).unwrap();
    let ipv6 = ipv6_tunnel_address(profile.id, Ipv4Addr::new(10, 77, 0, 12)).unwrap();
    assert_eq!(
        value(config.expose(), "Address"),
        format!("10.77.0.12/32, {ipv6}/128")
    );
    assert_eq!(value(config.expose(), "Endpoint"), "[2001:db8::4]:51820");
}

#[test]
fn responses_that_do_not_describe_the_requested_device_are_rejected() {
    let profile = profile("203.0.113.4", false);
    let target = MemberId::new();
    let draft = || {
        WireGuardDeviceDraft::new(
            &profile,
            "Family",
            "Tablet",
            Some(target),
            Default::default(),
        )
        .unwrap()
    };
    assert!(draft().finish(summary(&draft(), 30)).is_ok());
    for mutate in [
        (|device: &mut DeviceSummary| device.wireguard_only = false) as fn(&mut DeviceSummary),
        |device| device.name = "Other".into(),
        |device| device.member_id = MemberId::new(),
        |device| device.client_tunnel_address = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
        |device| device.client_tunnel_address = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 224)),
        |device| device.client_tunnel_address = "fd00::3".parse().unwrap(),
    ] {
        let draft = draft();
        let mut response = summary(&draft, 30);
        mutate(&mut response);
        assert!(matches!(
            draft.finish(response),
            Err(WireGuardDeviceError::ResponseMismatch)
        ));
    }
    assert!(
        WireGuardDeviceDraft::new(
            &profile,
            "Family",
            "Tablet",
            Some(target),
            MemberPolicy {
                device_limit: Some(1),
                ..Default::default()
            },
        )
        .is_err()
    );
    assert!(WireGuardDeviceDraft::new(&profile, "Family", " ", None, Default::default()).is_err());
}

#[test]
fn saved_configuration_is_private_and_never_replaces_a_file() {
    let directory = tempfile::tempdir().unwrap();
    let profile = profile("203.0.113.4", false);
    let draft =
        WireGuardDeviceDraft::new(&profile, "Home", "Router", None, Default::default()).unwrap();
    let response = summary(&draft, 5);
    let config = draft.finish(response).unwrap();
    let path = directory.path().join(config.file_name());
    config.save(&path).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), config.expose());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(config.save(&path).is_err());
    assert_eq!(config_file_name("..."), "sirinvpn.conf");
    assert_eq!(config_file_name("GL.iNet router"), "GL.iNet-router.conf");
}
