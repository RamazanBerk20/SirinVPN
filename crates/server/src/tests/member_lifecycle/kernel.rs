use super::*;

struct FaultHost<'a> {
    state: &'a AppState,
    faults: Mutex<VecDeque<(authorization_transaction::Stage, bool)>>,
}
impl authorization_transaction::Effects for FaultHost<'_> {
    fn intent(
        &self,
        previous: &AuthorizationDocument,
        next: &AuthorizationDocument,
        generation: u64,
    ) -> Result<()> {
        authorization_transaction::Host(self.state).intent(previous, next, generation)
    }
    fn authority(&self) -> Result<AuthorizationDocument> {
        authorization_transaction::Host(self.state).authority()
    }
    async fn execute(
        &self,
        stage: authorization_transaction::Stage,
        document: &AuthorizationDocument,
    ) -> Result<()> {
        let fault = {
            let mut faults = self.faults.lock().unwrap();
            if faults
                .front()
                .is_some_and(|(candidate, _)| *candidate == stage)
            {
                faults.pop_front()
            } else {
                None
            }
        };
        if fault == Some((stage, false)) {
            bail!("fixture failure before effect");
        }
        authorization_transaction::Host(self.state)
            .execute(stage, document)
            .await?;
        if fault.is_some() {
            bail!("fixture failure after effect");
        }
        Ok(())
    }
}

async fn inspect(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().await.unwrap();
    assert!(output.status.success(), "{program} inspection failed");
    String::from_utf8(output.stdout).unwrap()
}

async fn assert_runtime(state: &AppState, document: &AuthorizationDocument) {
    let peers = inspect("wg", &["show", "sirinvpn0", "peers"]).await;
    let actual: HashSet<_> = peers.lines().map(str::to_owned).collect();
    let expected: HashSet<_> = document
        .desired_peers(unix_time())
        .iter()
        .map(|peer| peer.public_key.clone())
        .collect();
    assert_eq!(actual, expected);
    for device in &document.devices {
        assert_eq!(
            state
                .transport_peers
                .contains(&decode_key(&device.wireguard_public_key).unwrap()),
            document.access_for_device(device).is_some()
        );
    }
    let isolation = inspect(
        "nft",
        &[
            "list",
            "set",
            "inet",
            "sirinvpn_filter",
            "peer_communication4",
        ],
    )
    .await;
    let isolation6 = inspect(
        "nft",
        &[
            "list",
            "set",
            "inet",
            "sirinvpn_filter",
            "peer_communication6",
        ],
    )
    .await;
    for device in document
        .devices
        .iter()
        .filter(|device| device.peer_communication_enabled)
    {
        let active = document.access_for_device(device).is_some();
        assert_eq!(
            isolation.contains(&device.client_tunnel_address.to_string()),
            active
        );
        let IpAddr::V4(address) = device.client_tunnel_address else {
            unreachable!()
        };
        assert_eq!(
            isolation6.contains(
                &ipv6_tunnel_address(document.server_id, address)
                    .unwrap()
                    .to_string()
            ),
            active
        );
    }
    let forwarding = inspect(
        "nft",
        &[
            "list",
            "chain",
            "ip",
            "sirinvpn_nat",
            "port_forward_prerouting",
        ],
    )
    .await;
    let active_forward = document.port_forwards.iter().any(|forward| {
        document.devices.iter().any(|device| {
            device.id == forward.device_id && document.access_for_device(device).is_some()
        })
    });
    assert_eq!(forwarding.contains("18080"), active_forward);
    assert_eq!(
        load_authorization(&state.paths.authorization).unwrap(),
        *document
    );
}

async fn probe(index: usize, ipv6: bool, available: bool) {
    let output = Command::new("python3")
        .args([
            "tests/network/member_lifecycle.py",
            "probe",
            &index.to_string(),
            if ipv6 { "6" } else { "4" },
            if available { "open" } else { "blocked" },
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "device {index} IPv{} availability did not match {available}",
        if ipv6 { 6 } else { 4 }
    );
}

#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-member-lifecycle.sh"]
async fn kernel_member_lifecycle_updates_access_and_rolls_back_failed_storage() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let (directory, mut state) = fixture();
    state.configuration.ipv6_tunnel_enabled = true;
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    let devices: Vec<_> = before.devices.iter().enumerate().skip(1).map(|(index, device)| {
        let IpAddr::V4(address) = device.client_tunnel_address else { unreachable!() };
        serde_json::json!({"index": index, "ipv4": address, "ipv6": ipv6_tunnel_address(before.server_id, address).unwrap(),
            "private_key_path": directory.path().join(format!("{}.key", device.id))})
    }).collect();
    let configuration = serde_json::json!({"devices": devices,
        "server_private_key_path": state.paths.wireguard_private_key,
        "server_ipv6": ipv6_tunnel_address(before.server_id, Ipv4Addr::new(10,77,0,1)).unwrap()});
    let mut prepare = Command::new("python3")
        .args(["tests/network/member_lifecycle.py", "prepare"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    prepare
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&configuration).unwrap().as_bytes())
        .await
        .unwrap();
    assert!(prepare.wait().await.unwrap().success());
    sync_wireguard_peers(&state.configuration, &before)
        .await
        .unwrap();
    sync_peer_isolation(&state.configuration, &before)
        .await
        .unwrap();
    let batch = port_forward_nft_batch(
        &state.configuration,
        state.operational_configuration.as_ref(),
        &before,
    )
    .unwrap()
    .unwrap();
    let mut validate = Command::new("nft")
        .args(["-c", "-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    validate
        .stdin
        .take()
        .unwrap()
        .write_all(batch.as_bytes())
        .await
        .unwrap();
    assert!(validate.wait().await.unwrap().success());
    sync_port_forwards(
        &state.configuration,
        state.operational_configuration.as_ref(),
        &before,
    )
    .await
    .unwrap();
    assert_runtime(&state, &before).await;
    println!("initial access configured");
    for index in [2, 3, 4] {
        for ipv6 in [false, true] {
            probe(index, ipv6, true).await;
        }
    }
    let target_id = before.members[2].id;
    let owner = || Extension(identity(&before.devices[0]));
    let set_suspension = |suspended| {
        update_member_suspension_handler(
            State(state.clone()),
            owner(),
            AxumPath(target_id.to_string()),
            Json(MemberSuspensionUpdateRequest { suspended }),
        )
    };

    // Exercise the real kernel with the production transaction and controlled OS
    // boundary failures. The former fixed .new staging path is no longer used.
    use authorization_transaction::{Effects, Stage};
    let mut current = state.authorization.as_ref().unwrap().write().await;
    let warm_peers = current.desired_peers(unix_time());
    let mut next = current.clone();
    next.devices[2].peer_communication_enabled = false;
    assert_eq!(warm_peers, next.desired_peers(unix_time()));
    let faults = FaultHost {
        state: &state,
        faults: Mutex::new(VecDeque::from([
            (Stage::Forwarding, true),
            (Stage::Isolation, false),
        ])),
    };
    assert!(
        authorization_transaction::commit(&faults, &state.recovery, &mut current, next)
            .await
            .is_err()
    );
    assert!(authorization_transaction::needs_recovery(&state.recovery));
    assert_eq!(warm_peers, current.desired_peers(unix_time()));
    for ipv6 in [false, true] {
        probe(2, ipv6, false).await;
    }
    authorization_transaction::recover(
        &authorization_transaction::Host(&state),
        &state.recovery,
        &mut current,
    )
    .await
    .unwrap();
    assert_eq!(*current, before);
    assert_runtime(&state, &before).await;
    for ipv6 in [false, true] {
        probe(2, ipv6, true).await;
    }
    // Persistence failure before rename still restores all actual networking.
    let faults = FaultHost {
        state: &state,
        faults: Mutex::new(VecDeque::from([(Stage::Persist, false)])),
    };
    let mut next = current.clone();
    next.devices[2].peer_communication_enabled = false;
    assert!(
        authorization_transaction::commit(&faults, &state.recovery, &mut current, next)
            .await
            .is_err()
    );
    assert_runtime(&state, &before).await;
    assert!(faults.authority().is_ok());
    drop(current);
    println!(
        "warm-cache partial rollback was contained and recovered; failed persistence restored policy"
    );

    assert!(set_suspension(true).await.is_ok());
    let suspended = state.authorization.as_ref().unwrap().read().await.clone();
    assert_runtime(&state, &suspended).await;
    println!("member suspended");
    for index in [2, 3] {
        for ipv6 in [false, true] {
            probe(index, ipv6, false).await;
        }
    }
    probe(4, false, true).await;
    probe(4, true, true).await;
    // A second suspension is safe, and restart projections preserve the suspension.
    assert!(set_suspension(true).await.is_ok());
    sync_wireguard_peers(
        &state.configuration,
        &load_authorization(&state.paths.authorization).unwrap(),
    )
    .await
    .unwrap();
    assert_runtime(&state, &suspended).await;
    assert!(set_suspension(false).await.is_ok());
    assert_runtime(&state, &before).await;
    println!("same member devices reactivated; waiting for their next WireGuard handshake");
    for index in [2, 3] {
        for ipv6 in [false, true] {
            probe(index, ipv6, true).await;
        }
    }
    assert!(
        revoke_member_devices_handler(
            State(state.clone()),
            owner(),
            AxumPath(target_id.to_string()),
            Json(MemberDevicesRevokeRequest { confirmed: true })
        )
        .await
        .is_ok()
    );
    let revoked = state.authorization.as_ref().unwrap().read().await.clone();
    assert_runtime(&state, &revoked).await;
    assert_eq!(revoked.devices.len(), before.devices.len() - 2);
    assert!(revoked.port_forwards.is_empty());
    for device in &before.devices[2..4] {
        assert!(
            !state
                .transport_peers
                .contains(&decode_key(&device.wireguard_public_key).unwrap())
        );
    }
    for index in [2, 3] {
        for ipv6 in [false, true] {
            probe(index, ipv6, false).await;
        }
    }
    probe(4, false, true).await;
    assert!(
        revoke_member_devices_handler(
            State(state.clone()),
            owner(),
            AxumPath(target_id.to_string()),
            Json(MemberDevicesRevokeRequest { confirmed: true })
        )
        .await
        .is_ok()
    );
    println!(
        "member lifecycle: IPv4/IPv6 traffic, WireGuard peers, relay authorization, nftables, storage rollback, restart and retry passed"
    );
}
