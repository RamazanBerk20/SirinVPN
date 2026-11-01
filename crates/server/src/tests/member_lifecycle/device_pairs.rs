use super::subnet_routes::{nft, reach};
use super::*;

fn pair(device: &DeviceRecord, peer: &DeviceRecord, one_way: bool) -> DevicePair {
    DevicePair {
        device_id: device.id,
        peer_device_id: peer.id,
        one_way,
    }
}

fn put(
    state: &AppState,
    caller: &DeviceRecord,
    pair: DevicePair,
) -> impl std::future::Future<Output = Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError>> {
    set_device_pair_handler(
        State(state.clone()),
        Extension(identity(caller)),
        Json(pair),
    )
}

fn remove(
    state: &AppState,
    caller: &DeviceRecord,
    device: &DeviceRecord,
    peer: &DeviceRecord,
) -> impl std::future::Future<Output = Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError>> {
    delete_device_pair_handler(
        State(state.clone()),
        Extension(identity(caller)),
        AxumPath((device.id.to_string(), peer.id.to_string())),
    )
}

fn address(device: &DeviceRecord) -> String {
    device.client_tunnel_address.to_string()
}

/// Like `reach`, but every probe reuses one ICMP identifier and so one conntrack flow.
async fn reach_in_flow(source: &str, destination: &str, open: bool) {
    let state = if open { "open" } else { "blocked" };
    let status = Command::new("python3")
        .args([
            "tests/network/subnet_routes.py",
            "probe",
            source,
            destination,
            state,
        ])
        .args(["-e", "4242"])
        .status()
        .await
        .unwrap();
    assert!(
        status.success(),
        "the {source} -> {destination} flow should be open: {open}"
    );
}

#[tokio::test]
async fn pair_rules_admit_paired_flows_and_only_answers_one_way() {
    let (_directory, state) = fixture();
    let mut document = state.authorization.as_ref().unwrap().read().await.clone();
    let mut configuration = state.configuration.clone();
    configuration.ipv6_tunnel_enabled = false;
    assert!(
        device_pair_nft_rules(&configuration, &document)
            .unwrap()
            .is_empty()
    );
    let [owner, admin, family, other] = [0, 1, 2, 4].map(|index| document.devices[index].clone());
    document
        .set_device_pair(pair(&family, &other, false))
        .unwrap();
    document
        .set_device_pair(pair(&admin, &owner, true))
        .unwrap();
    let (o, a, f, x) = (
        address(&owner),
        address(&admin),
        address(&family),
        address(&other),
    );
    let rule =
        "add rule inet sirinvpn_filter port_forward iifname \"sirinvpn0\" oifname \"sirinvpn0\"";
    assert_eq!(
        device_pair_nft_rules(&configuration, &document).unwrap(),
        format!(
            "{rule} ip saddr . ip daddr {{ {f} . {x}, {x} . {f}, {a} . {o} }} accept\n\
             {rule} ip saddr . ip daddr {{ {o} . {a} }} ct direction reply ct state established,related accept\n"
        )
    );
    configuration.ipv6_tunnel_enabled = true;
    let ipv6 = |device: &DeviceRecord| {
        let IpAddr::V4(address) = device.client_tunnel_address else {
            unreachable!()
        };
        ipv6_tunnel_address(document.server_id, address).unwrap()
    };
    let rules = device_pair_nft_rules(&configuration, &document).unwrap();
    assert_eq!(rules.lines().count(), 4);
    assert!(rules.contains(&format!(
        "{rule} ip6 saddr . ip6 daddr {{ {} . {} }} ct direction reply ct state established,related accept\n",
        ipv6(&owner),
        ipv6(&admin)
    )));

    // An inactive member's pairs leave the ruleset until reactivation.
    configuration.ipv6_tunnel_enabled = false;
    document
        .set_member_suspended(other.member_id, true)
        .unwrap();
    assert!(
        !device_pair_nft_rules(&configuration, &document)
            .unwrap()
            .contains(&x)
    );

    // A pair the router answers opens its networks to the device that starts.
    document.devices[0].peer_communication_enabled = false;
    document
        .set_device_subnet_routes(owner.id, vec!["192.168.1.0/24".into()])
        .unwrap();
    let routes = subnet_route_nft_rules(&configuration, &document);
    assert_eq!(
        routes,
        format!(
            "{rule} ip saddr {{ {a} }} ip daddr {{ 192.168.1.0/24 }} accept\n\
             {rule} ip saddr {{ 192.168.1.0/24 }} ip daddr {{ {a} }} ct direction reply ct state established,related accept\n"
        )
    );
    // Pairs and routes share the runtime chain and its flush.
    let batch = port_forward_nft_batch(
        &configuration,
        state.operational_configuration.as_ref(),
        &document,
    )
    .unwrap()
    .unwrap();
    assert!(batch.starts_with("flush chain inet sirinvpn_filter port_forward\n"));
    assert!(batch.contains(&device_pair_nft_rules(&configuration, &document).unwrap()));
    assert!(batch.ends_with(&routes));
}

#[tokio::test]
async fn pairs_need_peer_communication_authority_over_both_devices() {
    let (_directory, state) = fixture();
    {
        let mut document = state.authorization.as_ref().unwrap().write().await;
        document.members[2].policy.manage_own_peer_communication = true;
        let [owner, family, family_laptop, other] =
            [0, 2, 3, 4].map(|index| document.devices[index].clone());
        document.device_pairs = vec![
            pair(&family, &family_laptop, false),
            pair(&owner, &other, true),
        ];
        document.schema_version = document.required_schema_version();
        write_authorization(&state.paths.authorization, &document).unwrap();
    }
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    let [owner, admin, family, family_laptop, other] =
        [0, 1, 2, 3, 4].map(|index| &before.devices[index]);
    for (caller, device, peer, status) in [
        // A member with the permission pairs only their own devices.
        (family, family, other, StatusCode::FORBIDDEN),
        (family, owner, family, StatusCode::FORBIDDEN),
        // Without it, not at all.
        (other, other, family, StatusCode::FORBIDDEN),
        (owner, owner, owner, StatusCode::BAD_REQUEST),
        // Admins manage ordinary members, not themselves or the Owner.
        (admin, admin, family, StatusCode::FORBIDDEN),
        (admin, owner, family, StatusCode::FORBIDDEN),
    ] {
        let result = put(&state, caller, pair(device, peer, false)).await;
        assert_eq!(result.err().unwrap().status, status, "{}", device.name);
    }
    let mut unknown = other.clone();
    unknown.id = DeviceId::new();
    let result = put(&state, owner, pair(owner, &unknown, false)).await;
    assert_eq!(result.err().unwrap().status, StatusCode::NOT_FOUND);
    // Removing needs the same authority, and the pair.
    let result = remove(&state, family, family, other).await;
    assert_eq!(result.err().unwrap().status, StatusCode::FORBIDDEN);
    let result = remove(&state, admin, family, other).await;
    assert_eq!(result.err().unwrap().status, StatusCode::NOT_FOUND);

    // A stored pair answers without touching networking; members see only pairs of their devices.
    let snapshot = put(&state, family, pair(family, family_laptop, false))
        .await
        .unwrap()
        .0
        .payload;
    assert_eq!(snapshot.device_pairs, [pair(family, family_laptop, false)]);
    let snapshot = put(&state, admin, pair(family, family_laptop, false))
        .await
        .unwrap()
        .0
        .payload;
    assert_eq!(snapshot.device_pairs, before.device_pairs);
    for (caller, pairs) in [
        (family, &before.device_pairs[..1]),
        (owner, &before.device_pairs[..]),
    ] {
        let snapshot = membership_handler(State(state.clone()), Extension(identity(caller)))
            .await
            .unwrap()
            .0
            .payload;
        assert_eq!(snapshot.device_pairs, pairs, "{}", caller.name);
    }
    assert_eq!(*state.authorization.as_ref().unwrap().read().await, before);
    assert_eq!(
        load_authorization(&state.paths.authorization).unwrap(),
        before
    );
}

#[test]
fn encrypted_vps_backups_carry_device_pairs() {
    let (_directory, state) = fixture();
    let mut document = load_authorization(&state.paths.authorization).unwrap();
    let [owner, other] = [0, 4].map(|index| document.devices[index].clone());
    document
        .set_device_pair(pair(&owner, &other, true))
        .unwrap();
    write_authorization(&state.paths.authorization, &document).unwrap();
    let certificate = &owner.management_certificate_pem;
    let snapshot = export_backup_state(&state.paths, document.server_id, certificate).unwrap();
    let envelope_directory = tempfile::tempdir().unwrap();
    let envelope = envelope_directory
        .path()
        .join("pairs.sirinvpn-server-backup");
    write_encrypted_server_backup(
        &envelope,
        snapshot.as_slice(),
        "correct horse battery staple",
    )
    .unwrap();
    // The client's reader accepts schema 9 before anything reaches the new VPS.
    let decrypted =
        read_encrypted_server_backup(&envelope, "correct horse battery staple").unwrap();
    let target_directory = tempfile::tempdir().unwrap();
    let target = ServerPaths::under(target_directory.path());
    restore_backup_state(
        &target,
        document.server_id,
        certificate,
        decrypted.snapshot(),
    )
    .unwrap();
    assert_eq!(load_authorization(&target.authorization).unwrap(), document);
}

#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-member-lifecycle.sh <name>"]
async fn kernel_device_pairs_admit_paired_devices_and_one_way_answers() {
    use super::kernel::inspect;
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let (directory, state) = fixture();
    // Every device is isolated; Family manages its own pairs; an Owner home server shares
    // its LAN.
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
            peer_communication_enabled: false,
            preshared_key: None,
            subnet_routes: vec!["192.168.1.0/24".into()],
        });
        for device in &mut document.devices {
            device.peer_communication_enabled = false;
        }
        document.members[2].policy.manage_own_peer_communication = true;
        document.schema_version = document.required_schema_version();
        write_authorization(&state.paths.authorization, &document).unwrap();
        document.devices.last().unwrap().clone()
    };
    let document = state.authorization.as_ref().unwrap().read().await.clone();
    let key = |device: &DeviceRecord| directory.path().join(format!("{}.key", device.id));
    let peers: Vec<_> = [1, 2, 3, 4]
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
    let apply = |document: AuthorizationDocument| {
        let state = state.clone();
        async move {
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
        }
    };
    apply(document.clone()).await;
    let [owner, admin, family, family_laptop, other] =
        [0, 1, 2, 3, 4].map(|index| document.devices[index].clone());
    reach("member2", &address(&family_laptop), false).await;
    reach("member2", "203.0.113.50", true).await;
    println!("isolated: devices reach the internet, not each other");

    // Family pairs its own two devices both ways.
    assert!(
        put(&state, &family, pair(&family, &family_laptop, false))
            .await
            .is_ok()
    );
    reach("member2", &address(&family_laptop), true).await;
    reach("member3", &address(&family), true).await;
    // An unpaired device reaches neither, and neither reaches it.
    reach("member4", &address(&family), false).await;
    reach("member4", &address(&family_laptop), false).await;
    reach("member2", &address(&other), false).await;
    println!("both ways: the paired devices reach each other; an unpaired device reaches neither");

    // The Owner lets the Admin start connections to Family; Family only answers, even in a
    // flow it started while the pair went both ways.
    assert!(
        put(&state, &owner, pair(&admin, &family, false))
            .await
            .is_ok()
    );
    reach_in_flow("member2", &address(&admin), true).await;
    assert!(
        put(&state, &owner, pair(&admin, &family, true))
            .await
            .is_ok()
    );
    reach_in_flow("member2", &address(&admin), false).await;
    reach("member1", &address(&family), true).await;
    reach("member2", &address(&admin), false).await;
    println!("one way: the starting device is answered; the answering device cannot start");

    // A pair the router answers opens its LAN to the device that starts, and only to it.
    let kernel_routes = || {
        inspect(
            "ip",
            &["-4", "route", "show", "dev", "sirinvpn0", "proto", "static"],
        )
    };
    assert!(kernel_routes().await.trim().is_empty());
    assert!(
        put(&state, &owner, pair(&other, &router, true))
            .await
            .is_ok()
    );
    assert_eq!(kernel_routes().await.trim(), "192.168.1.0/24 scope link");
    reach("member4", "192.168.1.10", true).await;
    reach("member4", &address(&router), true).await;
    reach("member1", "192.168.1.10", false).await;
    reach("router", &address(&other), false).await;
    reach("lan", &address(&other), false).await;
    println!("router: the paired device reaches the LAN; others and the LAN cannot start");

    // Suspension closes a member's pairs, and the router's LAN with them; reactivation
    // restores both.
    let suspend = |suspended| {
        update_member_suspension_handler(
            State(state.clone()),
            Extension(identity(&owner)),
            AxumPath(other.member_id.to_string()),
            Json(MemberSuspensionUpdateRequest { suspended }),
        )
    };
    assert!(suspend(true).await.is_ok());
    assert!(kernel_routes().await.trim().is_empty());
    reach("member4", &address(&router), false).await;
    assert!(suspend(false).await.is_ok());
    reach("member4", "192.168.1.10", true).await;
    println!("suspension: pairs close and return with the member");

    // A stopped server flushes the runtime chain (firewall.sh isolate-runtime): pairs close.
    nft(&["flush", "chain", "inet", "sirinvpn_filter", "port_forward"]).await;
    reach("member2", &address(&family_laptop), false).await;
    apply(state.authorization.as_ref().unwrap().read().await.clone()).await;
    reach("member2", &address(&family_laptop), true).await;

    // Unpairing, in either order, and revocation remove the access.
    assert!(remove(&state, &owner, &family, &admin).await.is_ok());
    reach("member1", &address(&family), false).await;
    assert!(
        revoke_device_handler(
            State(state.clone()),
            Extension(identity(&owner)),
            AxumPath(family_laptop.id.to_string()),
        )
        .await
        .is_ok()
    );
    let current = state.authorization.as_ref().unwrap().read().await.clone();
    assert_eq!(current.device_pairs, [pair(&other, &router, true)]);
    reach("member2", &address(&family_laptop), false).await;
    println!(
        "device pairs: direction, router networks, suspension, unpairing and revocation passed"
    );
}
