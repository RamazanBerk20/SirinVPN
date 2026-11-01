use super::kernel::{inspect, probe};
use super::*;
use crate::wireguard_device::create_wireguard_device_handler;
use sirinvpn_core::WireGuardDeviceDraft;
use sirinvpn_protocol::{MemberPolicy, WireGuardDeviceCreateRequest};

fn request(
    document: &AuthorizationDocument,
    target: Option<&MemberRecord>,
) -> WireGuardDeviceCreateRequest {
    WireGuardDeviceCreateRequest {
        server_id: document.server_id,
        endpoint: ServerEndpoint {
            host: "203.0.113.4".into(),
            wireguard_port: 51820,
        },
        member_name: target.map_or_else(|| "Router household".into(), |member| member.name.clone()),
        device_name: "Router".into(),
        target_member_id: target.map(|member| member.id),
        member_policy: MemberPolicy::default(),
        wireguard_public_key: STANDARD.encode([21_u8; 32]),
        preshared_key: STANDARD.encode([22_u8; 32]),
    }
}

#[tokio::test]
async fn wireguard_device_authority_and_input_are_checked_before_mutation() {
    let (_directory, state) = fixture();
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    let (owner, admin, family) = (&before.devices[0], &before.devices[1], &before.devices[2]);
    let mut cases = vec![
        (family, request(&before, None), StatusCode::FORBIDDEN),
        (
            admin,
            request(&before, Some(&before.members[0])),
            StatusCode::FORBIDDEN,
        ),
        (
            family,
            request(&before, Some(&before.members[2])),
            StatusCode::FORBIDDEN,
        ),
    ];
    let mut duplicate = request(&before, None);
    duplicate.wireguard_public_key = before.devices[3].wireguard_public_key.clone();
    cases.push((owner, duplicate, StatusCode::CONFLICT));
    let mut malformed = request(&before, None);
    malformed.preshared_key = "not a key".into();
    cases.push((owner, malformed, StatusCode::BAD_REQUEST));
    let mut foreign = request(&before, None);
    foreign.server_id = ServerId::new();
    cases.push((owner, foreign, StatusCode::CONFLICT));
    let mut renamed = request(&before, Some(&before.members[2]));
    renamed.member_name = "Renamed family".into();
    cases.push((owner, renamed, StatusCode::CONFLICT));
    let mut restricted = request(&before, Some(&before.members[2]));
    restricted.member_policy.device_limit = Some(4);
    cases.push((admin, restricted, StatusCode::BAD_REQUEST));
    for (caller, request, status) in cases {
        let result = create_wireguard_device_handler(
            State(state.clone()),
            Extension(identity(caller)),
            Json(request),
        )
        .await;
        assert_eq!(result.err().unwrap().status, status);
    }
    assert_eq!(*state.authorization.as_ref().unwrap().read().await, before);
    assert_eq!(
        load_authorization(&state.paths.authorization).unwrap(),
        before
    );

    // An Owner phone that only runs a WireGuard app cannot be the last Owner device.
    let mut document = state.authorization.as_ref().unwrap().write().await;
    let address = document.allocate_member_address().unwrap();
    let owner_member = document.members[0].id;
    document.devices.push(DeviceRecord {
        id: DeviceId::new(),
        member_id: owner_member,
        name: "Owner phone".into(),
        client_tunnel_address: address,
        wireguard_public_key: STANDARD.encode([23_u8; 32]),
        management_certificate_pem: String::new(),
        certificate_fingerprint: String::new(),
        peer_communication_enabled: false,
        preshared_key: Some(STANDARD.encode([24_u8; 32])),
        subnet_routes: Vec::new(),
    });
    document.schema_version = document.required_schema_version();
    drop(document);
    let result = revoke_device_handler(
        State(state.clone()),
        Extension(identity(owner)),
        AxumPath(owner.id.to_string()),
    )
    .await;
    assert_eq!(result.err().unwrap().status, StatusCode::CONFLICT);
}

#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-member-lifecycle.sh <name>"]
async fn kernel_wireguard_only_device_connects_with_its_exported_configuration_until_revoked() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let (directory, mut state) = fixture();
    state.configuration.ipv6_tunnel_enabled = true;
    let document = state.authorization.as_ref().unwrap().read().await.clone();
    let server_ipv6 = ipv6_tunnel_address(document.server_id, Ipv4Addr::new(10, 77, 0, 1)).unwrap();
    let mut prepare = Command::new("python3")
        .args(["tests/network/member_lifecycle.py", "prepare"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    prepare.stdin.take().unwrap().write_all(serde_json::to_string(&serde_json::json!({
        "devices": [], "server_private_key_path": state.paths.wireguard_private_key, "server_ipv6": server_ipv6,
    })).unwrap().as_bytes()).await.unwrap();
    assert!(prepare.wait().await.unwrap().success());

    let mut profile = super::recovery::profile(&state, &document, 0);
    profile.endpoint.host = "127.0.0.1".into();
    profile.ipv6_tunnel_enabled = true;
    let draft = WireGuardDeviceDraft::new(
        &profile,
        "Router household",
        "Router",
        None,
        MemberPolicy::default(),
    )
    .unwrap();
    let public_key = draft.request().wireguard_public_key.clone();
    let device = create_wireguard_device_handler(
        State(state.clone()),
        Extension(identity(&document.devices[0])),
        Json(draft.request().clone()),
    )
    .await
    .unwrap()
    .0
    .payload;
    let config = draft.finish(device.clone()).unwrap();
    let current = state.authorization.as_ref().unwrap().read().await.clone();
    assert_eq!(current.schema_version, 7);
    assert_eq!(
        load_authorization(&state.paths.authorization).unwrap(),
        current
    );
    assert!(
        !state
            .transport_peers
            .contains(&decode_key(&public_key).unwrap())
    );
    assert!(
        state
            .transport_peers
            .contains(&decode_key(&document.devices[1].wireguard_public_key).unwrap())
    );
    assert_eq!(
        current.client_certificates(unix_time()),
        document.client_certificates(unix_time())
    );

    // Stock wireguard-tools apply the exported file, as a WireGuard app or router would.
    let path = directory.path().join("wgrouter.conf");
    config.save(&path).unwrap();
    let applied = Command::new("python3")
        .args([
            "tests/network/member_lifecycle.py",
            "conf",
            path.to_str().unwrap(),
            "9",
        ])
        .status()
        .await
        .unwrap();
    assert!(applied.success());
    probe(9, false, true).await;
    probe(9, true, true).await;
    let kernel_keys = inspect("wg", &["show", "sirinvpn0", "preshared-keys"]).await;
    assert!(kernel_keys.contains(&format!("{public_key}\t{}", preshared_key(config.expose()))));
    println!("an exported WireGuard configuration connects through Direct UDP");

    let snapshot = revoke_device_handler(
        State(state.clone()),
        Extension(identity(&document.devices[0])),
        AxumPath(device.id.to_string()),
    )
    .await
    .unwrap()
    .0
    .payload;
    assert!(
        snapshot
            .members
            .iter()
            .all(|member| member.id != device.member_id)
    );
    probe(9, false, false).await;
    assert!(
        !inspect("wg", &["show", "sirinvpn0", "peers"])
            .await
            .contains(&public_key)
    );
    let revoked = state.authorization.as_ref().unwrap().read().await.clone();
    assert_eq!(revoked.schema_version, document.schema_version);
    assert!(
        revoked
            .members
            .iter()
            .all(|member| member.name != "Router household")
    );
}

fn preshared_key(config: &str) -> &str {
    config
        .lines()
        .find_map(|line| line.strip_prefix("PresharedKey = "))
        .unwrap()
}
