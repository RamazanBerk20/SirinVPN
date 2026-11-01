use super::*;
use sirinvpn_protocol::DeviceSubnetRoutesUpdateRequest;

fn update(
    state: &AppState,
    caller: &DeviceRecord,
    target: &DeviceRecord,
    routes: &[&str],
) -> impl std::future::Future<Output = Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError>> {
    update_device_subnet_routes_handler(
        State(state.clone()),
        Extension(identity(caller)),
        AxumPath(target.id.to_string()),
        Json(DeviceSubnetRoutesUpdateRequest {
            routes: routes.iter().map(|route| route.to_string()).collect(),
        }),
    )
}

#[tokio::test]
async fn only_the_owner_assigns_valid_routes_to_their_own_devices() {
    let (_directory, state) = fixture();
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    let (owner, admin, family) = (&before.devices[0], &before.devices[1], &before.devices[2]);
    for (caller, target, routes, status) in [
        (admin, owner, ["192.168.1.0/24"], StatusCode::FORBIDDEN),
        (family, owner, ["192.168.1.0/24"], StatusCode::FORBIDDEN),
        (owner, family, ["192.168.1.0/24"], StatusCode::BAD_REQUEST),
        (owner, admin, ["192.168.1.0/24"], StatusCode::BAD_REQUEST),
        (owner, owner, ["192.168.1.1/24"], StatusCode::BAD_REQUEST),
        (owner, owner, ["10.77.0.0/24"], StatusCode::BAD_REQUEST),
        (owner, owner, ["0.0.0.0/0"], StatusCode::BAD_REQUEST),
    ] {
        let result = update(&state, caller, target, &routes).await;
        assert_eq!(result.err().unwrap().status, status, "{routes:?}");
    }
    let mut unknown = owner.clone();
    unknown.id = DeviceId::new();
    let result = update(&state, owner, &unknown, &["192.168.1.0/24"]).await;
    assert_eq!(result.err().unwrap().status, StatusCode::NOT_FOUND);
    // An unchanged list answers without touching networking.
    let snapshot = update(&state, owner, owner, &[]).await.unwrap().0.payload;
    assert!(
        snapshot
            .members
            .iter()
            .flat_map(|member| &member.devices)
            .all(|device| device.subnet_routes.is_empty())
    );
    assert_eq!(*state.authorization.as_ref().unwrap().read().await, before);
    assert_eq!(
        load_authorization(&state.paths.authorization).unwrap(),
        before
    );
}

#[tokio::test]
async fn subnet_route_rules_admit_only_peer_enabled_devices_and_answers() {
    let (_directory, state) = fixture();
    let mut document = state.authorization.as_ref().unwrap().read().await.clone();
    assert!(subnet_route_nft_rules(&state.configuration, &document).is_empty());
    document.devices[0].peer_communication_enabled = true;
    document.devices[0].subnet_routes = vec!["192.168.1.0/24".into(), "10.20.0.0/20".into()];
    document.schema_version = document.required_schema_version();
    document.validate().unwrap();
    let rules = subnet_route_nft_rules(&state.configuration, &document);
    assert_eq!(
        rules,
        concat!(
            "add rule inet sirinvpn_filter port_forward iifname \"sirinvpn0\" oifname \"sirinvpn0\" ip saddr @peer_communication4 ip daddr { 10.20.0.0/20, 192.168.1.0/24 } accept\n",
            "add rule inet sirinvpn_filter port_forward iifname \"sirinvpn0\" oifname \"sirinvpn0\" ip saddr { 10.20.0.0/20, 192.168.1.0/24 } ip daddr @peer_communication4 ct state established,related accept\n",
        )
    );
    // Both port forwards and routes share the chain flush, also without operational state.
    let batch = port_forward_nft_batch(
        &state.configuration,
        state.operational_configuration.as_ref(),
        &document,
    )
    .unwrap()
    .unwrap();
    assert!(batch.starts_with("flush chain inet sirinvpn_filter port_forward\n"));
    assert!(batch.ends_with(&rules));
    let mut without_forwards = document.clone();
    without_forwards.port_forwards.clear();
    assert_eq!(
        port_forward_nft_batch(&state.configuration, None, &without_forwards)
            .unwrap()
            .unwrap(),
        format!("flush chain inet sirinvpn_filter port_forward\n{rules}")
    );

    // The router's peer permission is the switch; turning it off closes its networks.
    document.devices[0].peer_communication_enabled = false;
    assert!(subnet_route_nft_rules(&state.configuration, &document).is_empty());
    let routes = |document: &AuthorizationDocument| {
        document
            .desired_peers(unix_time())
            .into_iter()
            .flat_map(|peer| peer.subnet_routes)
            .collect::<Vec<_>>()
    };
    assert!(routes(&document).is_empty());
    document.devices[0].peer_communication_enabled = true;
    assert_eq!(routes(&document).len(), 2);
}

async fn nft(arguments: &[&str]) {
    assert!(
        Command::new("nft")
            .args(arguments)
            .status()
            .await
            .unwrap()
            .success()
    );
}

async fn reach(source: &str, destination: &str, open: bool) {
    let status = Command::new("python3")
        .args([
            "tests/network/subnet_routes.py",
            "probe",
            source,
            destination,
            if open { "open" } else { "blocked" },
        ])
        .status()
        .await
        .unwrap();
    assert!(
        status.success(),
        "{source} -> {destination} should be open: {open}"
    );
}

#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-member-lifecycle.sh <name>"]
async fn kernel_subnet_routes_reach_a_router_lan_only_from_peer_enabled_devices() {
    use super::kernel::inspect;
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let (directory, state) = fixture();
    // An Owner home server becomes the router; device 4 stays isolated from peers.
    let router = {
        let mut document = state.authorization.as_ref().unwrap().write().await;
        let identity = LocalIdentity::generate("Home server").unwrap();
        let id = DeviceId::new();
        write_private(
            &directory.path().join(format!("{id}.key")),
            identity.secret.wireguard_private_key.as_bytes(),
        )
        .unwrap();
        let address = document.allocate_member_address().unwrap();
        let owner = document.members[0].id;
        document.devices.push(DeviceRecord {
            id,
            member_id: owner,
            name: "Home server".into(),
            client_tunnel_address: address,
            certificate_fingerprint: certificate_fingerprint(
                &identity.public.management_certificate_pem,
            )
            .unwrap(),
            wireguard_public_key: identity.public.wireguard_public_key,
            management_certificate_pem: identity.public.management_certificate_pem,
            peer_communication_enabled: true,
            preshared_key: None,
            subnet_routes: Vec::new(),
        });
        document.devices[4].peer_communication_enabled = false;
        write_authorization(&state.paths.authorization, &document).unwrap();
        document.devices.last().unwrap().clone()
    };
    let document = state.authorization.as_ref().unwrap().read().await.clone();
    let address = |device: &DeviceRecord| device.client_tunnel_address.to_string();
    let key = |device: &DeviceRecord| directory.path().join(format!("{}.key", device.id));
    let peers: Vec<_> = [1, 4]
        .map(|index| {
            let device = &document.devices[index];
            serde_json::json!({"index": index, "ipv4": address(device), "private_key_path": key(device)})
        })
        .into();
    let configuration = serde_json::json!({
        "server_private_key_path": state.paths.wireguard_private_key,
        "router": {"ipv4": address(&router), "private_key_path": key(&router)},
        "peers": peers,
    });
    let mut prepare = Command::new("python3")
        .args(["tests/network/subnet_routes.py", "prepare"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    prepare
        .stdin
        .take()
        .unwrap()
        .write_all(configuration.to_string().as_bytes())
        .await
        .unwrap();
    assert!(prepare.wait().await.unwrap().success());
    sync_wireguard_peers(&state.configuration, &document)
        .await
        .unwrap();
    sync_peer_isolation(&state.configuration, &document)
        .await
        .unwrap();
    sync_port_forwards(
        &state.configuration,
        state.operational_configuration.as_ref(),
        &document,
    )
    .await
    .unwrap();
    let (allowed, isolated) = (address(&document.devices[1]), "member4");
    reach("member1", &address(&router), true).await;
    reach("member1", "203.0.113.50", true).await;
    reach("member1", "192.168.1.10", false).await;
    println!("before routes: peers reach the router's tunnel address, not its LAN");

    let owner = &document.devices[0];
    assert!(
        update(&state, owner, &router, &["192.168.1.0/24"])
            .await
            .is_ok()
    );
    let kernel_routes = || {
        inspect(
            "ip",
            &["-4", "route", "show", "dev", "sirinvpn0", "proto", "static"],
        )
    };
    assert_eq!(kernel_routes().await.trim(), "192.168.1.0/24 scope link");
    let allowed_ips = inspect("wg", &["show", "sirinvpn0", "allowed-ips"]).await;
    assert!(
        allowed_ips
            .lines()
            .any(|line| line.starts_with(&router.wireguard_public_key)
                && line.ends_with(&format!("{}/32 192.168.1.0/24", address(&router))))
    );
    reach("member1", "192.168.1.10", true).await;
    reach(isolated, "192.168.1.10", false).await;
    // LAN hosts only answer: they cannot start connections to peers or leave through the VPS.
    reach("lan", &allowed, false).await;
    reach("lan", "203.0.113.50", false).await;
    reach("lan", "10.77.0.1", false).await;
    reach("member1", "203.0.113.50", true).await;
    println!("routes: the peer-enabled device reaches the LAN; isolation and LAN containment hold");

    // A stopped server flushes its runtime rules (firewall.sh isolate-runtime), but the peer
    // and route stay: LAN hosts still reach neither the VPS nor the internet.
    for set in ["peer_communication4", "peer_communication6"] {
        nft(&["flush", "set", "inet", "sirinvpn_filter", set]).await;
    }
    nft(&["flush", "chain", "inet", "sirinvpn_filter", "port_forward"]).await;
    reach("member1", "192.168.1.10", false).await;
    reach("lan", "203.0.113.50", false).await;
    reach("lan", "10.77.0.1", false).await;
    let current = state.authorization.as_ref().unwrap().read().await.clone();
    sync_peer_isolation(&state.configuration, &current)
        .await
        .unwrap();
    sync_port_forwards(
        &state.configuration,
        state.operational_configuration.as_ref(),
        &current,
    )
    .await
    .unwrap();
    reach("member1", "192.168.1.10", true).await;
    println!("stopped: the tunnel-source guard keeps LAN hosts contained");

    // A range the VPS already routes elsewhere is refused before any change.
    assert!(
        Command::new("ip")
            .args(["route", "add", "172.20.0.0/16", "dev", "eth-test"])
            .status()
            .await
            .unwrap()
            .success()
    );
    let result = update(&state, owner, &router, &["172.20.1.0/24"]).await;
    assert_eq!(result.err().unwrap().status, StatusCode::CONFLICT);
    assert_eq!(kernel_routes().await.trim(), "192.168.1.0/24 scope link");

    let set_peer_of = |device: &DeviceRecord, enabled| {
        update_device_peer_communication_handler(
            State(state.clone()),
            Extension(identity(owner)),
            AxumPath(device.id.to_string()),
            Json(DevicePeerCommunicationUpdateRequest { enabled }),
        )
    };
    // A VPS route that appears later for the same range leaves it inactive; commits go on.
    let host = |arguments: &'static [&'static str]| async move {
        assert!(
            Command::new("ip")
                .args(arguments)
                .status()
                .await
                .unwrap()
                .success()
        );
    };
    host(&[
        "route",
        "delete",
        "192.168.1.0/24",
        "dev",
        "sirinvpn0",
        "proto",
        "static",
    ])
    .await;
    host(&["route", "add", "192.168.1.0/24", "dev", "eth-test"]).await;
    assert!(set_peer_of(&document.devices[4], true).await.is_ok());
    assert!(kernel_routes().await.trim().is_empty());
    // The Owner sees which range is inactive.
    let snapshot = membership_handler(State(state.clone()), Extension(identity(owner)))
        .await
        .unwrap()
        .0
        .payload;
    let summary = snapshot
        .members
        .iter()
        .flat_map(|member| &member.devices)
        .find(|device| device.id == router.id)
        .unwrap();
    assert_eq!(summary.inactive_subnet_routes, ["192.168.1.0/24"]);
    reach("member1", "192.168.1.10", false).await;
    host(&["route", "delete", "192.168.1.0/24", "dev", "eth-test"]).await;
    // What the runtime loop retries while a range is inactive: no authorization change.
    let current = state.authorization.as_ref().unwrap().read().await.clone();
    sync_subnet_kernel_routes("sirinvpn0", &current.desired_peers(unix_time()))
        .await
        .unwrap();
    assert_eq!(kernel_routes().await.trim(), "192.168.1.0/24 scope link");
    assert!(inactive_subnet_routes().is_empty());
    reach("member1", "192.168.1.10", true).await;
    assert!(set_peer_of(&document.devices[4], false).await.is_ok());

    // The router's own peer permission is the switch.
    let set_peer = |enabled| set_peer_of(&router, enabled);
    assert!(set_peer(false).await.is_ok());
    assert!(kernel_routes().await.trim().is_empty());
    reach("member1", "192.168.1.10", false).await;
    assert!(set_peer(true).await.is_ok());
    reach("member1", "192.168.1.10", true).await;
    // Revocation removes the record, its AllowedIPs and the kernel route.
    assert!(
        revoke_device_handler(
            State(state.clone()),
            Extension(identity(owner)),
            AxumPath(router.id.to_string()),
        )
        .await
        .is_ok()
    );
    assert!(kernel_routes().await.trim().is_empty());
    assert!(
        !inspect("wg", &["show", "sirinvpn0", "allowed-ips"])
            .await
            .contains("192.168.1.0/24")
    );
    reach("member1", "192.168.1.10", false).await;
    println!(
        "subnet routes: assignment, VPS route conflicts, peer permission and revocation passed"
    );
}
