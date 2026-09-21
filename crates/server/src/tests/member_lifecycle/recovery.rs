use super::*;
use sirinvpn_core::{DecodedRecoveryKey, RecoveryKeyDraft};
use sirinvpn_protocol::{RecoveryKeyResponse, RecoveryPolicy, ServerProfile};

fn profile(state: &AppState, document: &AuthorizationDocument, index: usize) -> ServerProfile {
    let device = &document.devices[index];
    let member = document
        .members
        .iter()
        .find(|member| member.id == device.member_id)
        .unwrap();
    serde_json::from_value(serde_json::json!({
        "schema_version": 1, "id": document.server_id, "name": "Local display alias",
        "endpoint": { "host": "203.0.113.4", "wireguard_port": state.configuration.wireguard_port },
        "client_tunnel_address": device.client_tunnel_address,
        "server_tunnel_address": state.configuration.server_tunnel_address,
        "server_wireguard_public_key": state.configuration.wireguard_public_key,
        "pinned_server_certificate_pem": fs::read_to_string(&state.paths.tls_certificate).unwrap(),
        "client_management_certificate_pem": device.management_certificate_pem,
        "identity_reference": "test-recovery", "role": member.role, "administrator": member.administrator,
        "member_id": member.id, "device_id": device.id,
        "obfuscated_udp": state.configuration.obfuscated_udp,
        "tcp_fallback": state.configuration.tcp_fallback, "tls_like": state.configuration.tls_like,
    })).unwrap()
}

async fn create(
    state: &AppState,
    document: &AuthorizationDocument,
    index: usize,
    draft: &RecoveryKeyDraft,
) -> RecoveryKeyResponse {
    crate::recovery::create_key_handler(
        State(state.clone()),
        Extension(identity(&document.devices[index])),
        Json(draft.request().clone()),
    )
    .await
    .unwrap()
    .0
    .payload
}

#[tokio::test]
async fn recovery_default_permissions_and_confirmation_do_not_mutate_authorization() {
    let (_directory, state) = fixture();
    let document = state.authorization.as_ref().unwrap().read().await.clone();
    for index in [1, 2] {
        let draft = RecoveryKeyDraft::new(&profile(&state, &document, index), None).unwrap();
        let denied = crate::recovery::create_key_handler(
            State(state.clone()),
            Extension(identity(&document.devices[index])),
            Json(draft.request().clone()),
        )
        .await;
        assert_eq!(denied.err().unwrap().status, StatusCode::FORBIDDEN);
    }
    let draft = RecoveryKeyDraft::new(&profile(&state, &document, 0), None).unwrap();
    let mut request = draft.request().clone();
    request.confirmed = false;
    let denied = crate::recovery::create_key_handler(
        State(state.clone()),
        Extension(identity(&document.devices[0])),
        Json(request),
    )
    .await;
    assert_eq!(denied.err().unwrap().status, StatusCode::BAD_REQUEST);
    assert_eq!(
        *state.authorization.as_ref().unwrap().read().await,
        document
    );
}

#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-recovery-policy.sh"]
async fn kernel_offline_recovery_consumes_authority_and_revokes_all_previous_owner_keys() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let (directory, mut state) = fixture();
    state.configuration.ipv6_tunnel_enabled = true;
    let mut document = state.authorization.as_ref().unwrap().read().await.clone();
    let owner2 = LocalIdentity::generate("Other lost Owner device").unwrap();
    document.devices.push(DeviceRecord {
        id: DeviceId::new(),
        member_id: document.members[0].id,
        name: "Other lost Owner device".into(),
        client_tunnel_address: document.allocate_member_address().unwrap(),
        certificate_fingerprint: certificate_fingerprint(&owner2.public.management_certificate_pem)
            .unwrap(),
        wireguard_public_key: owner2.public.wireguard_public_key,
        management_certificate_pem: owner2.public.management_certificate_pem,
        peer_communication_enabled: true,
    });
    write_authorization(&state.paths.authorization, &document).unwrap();
    *state.authorization.as_ref().unwrap().write().await = document.clone();
    let server_ipv6 = ipv6_tunnel_address(document.server_id, Ipv4Addr::new(10, 77, 0, 1)).unwrap();
    let mut prepare = Command::new("python3")
        .args(["tests/network/member_lifecycle.py", "prepare"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    prepare.stdin.take().unwrap().write_all(serde_json::to_string(&serde_json::json!({
        "devices": [], "server_private_key_path": state.paths.wireguard_private_key, "server_ipv6": server_ipv6,
    })).unwrap().as_bytes()).await.unwrap();
    assert!(prepare.wait().await.unwrap().success());

    let admin_id = document.members[1].id;
    let _ = crate::recovery::policy_handler(
        State(state.clone()),
        Extension(identity(&document.devices[0])),
        Json(RecoveryPolicy {
            administrator_member_ids: vec![admin_id],
        }),
    )
    .await
    .unwrap();
    let admin_draft = RecoveryKeyDraft::new(&profile(&state, &document, 1), None).unwrap();
    let admin_response = create(&state, &document, 1, &admin_draft).await;
    assert_eq!(admin_response.claims.issuer_member_id, admin_id);
    admin_draft.finish(admin_response).unwrap();
    let disabled = crate::recovery::policy_handler(
        State(state.clone()),
        Extension(identity(&document.devices[0])),
        Json(RecoveryPolicy::default()),
    )
    .await
    .unwrap()
    .0
    .payload;
    assert!(disabled.key.is_none());
    let draft = RecoveryKeyDraft::new(&profile(&state, &document, 0), None).unwrap();
    let response = create(&state, &document, 0, &draft).await;
    assert_eq!(create(&state, &document, 0, &draft).await, response);
    let code = draft.finish(response.clone()).unwrap();
    let decoded = DecodedRecoveryKey::decode(&code).unwrap();
    let bootstrap = decoded.bootstrap_profile();
    let key_path = directory.path().join("offline.key");
    write_private(&key_path, decoded.secret().wireguard_private_key.as_bytes()).unwrap();
    super::policy_enrollment::probe(serde_json::json!({"mode": "bootstrap", "key": key_path, "ipv4": "10.77.0.254",
        "ipv6": ipv6_tunnel_address(document.server_id, Ipv4Addr::new(10,77,0,254)).unwrap(), "server_ipv6": server_ipv6})).await;

    let registered = load_authorization(&state.paths.authorization).unwrap();
    assert_eq!(registered.schema_version, 4);
    let snapshot = export_backup_state(
        &state.paths,
        document.server_id,
        &state.configuration.owner_certificate_pem,
    )
    .unwrap();
    let restore_directory = tempfile::tempdir().unwrap();
    let restore_paths = ServerPaths::under(restore_directory.path());
    restore_backup_state(
        &restore_paths,
        document.server_id,
        &state.configuration.owner_certificate_pem,
        snapshot.as_slice(),
    )
    .unwrap();
    assert_eq!(
        load_authorization(&restore_paths.authorization).unwrap(),
        registered
    );

    let caller = CallerIdentity {
        certificate_fingerprint: certificate_fingerprint(
            &bootstrap.client_management_certificate_pem,
        )
        .unwrap(),
    };
    let permanent = LocalIdentity::generate("Recovered Owner").unwrap();
    let request = decoded.request(&permanent.public, "Recovered Owner".into());
    let wrong_caller = crate::recovery::enroll_handler(
        State(state.clone()),
        Extension(identity(&document.devices[1])),
        Json(request.clone()),
    )
    .await;
    assert_eq!(wrong_caller.err().unwrap().status, StatusCode::FORBIDDEN);
    let mut unconfirmed = request.clone();
    unconfirmed.confirmed = false;
    assert_eq!(
        crate::recovery::enroll_handler(
            State(state.clone()),
            Extension(caller.clone()),
            Json(unconfirmed)
        )
        .await
        .err()
        .unwrap()
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        *state.authorization.as_ref().unwrap().read().await,
        registered
    );

    let result = crate::recovery::enroll_handler(
        State(state.clone()),
        Extension(caller.clone()),
        Json(request.clone()),
    )
    .await
    .unwrap()
    .0
    .payload;
    let recovered = decoded
        .permanent_profile(&result, &permanent.public, "recovered-owner".into())
        .unwrap();
    assert_eq!(recovered.role, ServerRole::Owner);
    assert_eq!(result.member_id, document.members[0].id);
    assert_eq!(
        crate::recovery::enroll_handler(
            State(state.clone()),
            Extension(caller.clone()),
            Json(request)
        )
        .await
        .unwrap()
        .0
        .payload,
        result
    );
    let attacker = LocalIdentity::generate("Replayed recovery").unwrap();
    assert_eq!(
        crate::recovery::enroll_handler(
            State(state.clone()),
            Extension(caller),
            Json(decoded.request(&attacker.public, "Replay".into()))
        )
        .await
        .err()
        .unwrap()
        .status,
        StatusCode::CONFLICT
    );

    let mut current = state.authorization.as_ref().unwrap().write().await;
    assert!(current.recovery_key.is_none());
    assert!(current.recovery_policy.administrator_member_ids.is_empty());
    assert_eq!(
        current
            .devices
            .iter()
            .filter(|device| device.member_id == result.member_id)
            .count(),
        1
    );
    for device in &document.devices {
        assert_eq!(
            current.devices.iter().any(|saved| saved.id == device.id),
            device.member_id != result.member_id
        );
    }
    let live_peers = String::from_utf8(
        Command::new("wg")
            .args(["show", "sirinvpn0", "peers"])
            .output()
            .await
            .unwrap()
            .stdout,
    )
    .unwrap();
    for device in document
        .devices
        .iter()
        .filter(|device| device.member_id == result.member_id)
    {
        assert!(!live_peers.contains(&device.wireguard_public_key));
        assert!(
            current
                .device_for_fingerprint(&device.certificate_fingerprint)
                .is_none()
        );
    }
    assert!(live_peers.contains(&permanent.public.wireguard_public_key));
    let expiry = current.recovery_receipt.as_ref().unwrap().expires_at_unix;
    let mut next = current.clone();
    next.prune_expired(expiry);
    commit_authorization(&state, &mut current, next)
        .await
        .unwrap();
    assert!(current.recovery_authorization(expiry).is_none());
    assert!(
        !current
            .desired_peers(expiry)
            .iter()
            .any(|peer| peer.public_key == response.claims.recovery_wireguard_public_key)
    );
    assert_eq!(
        load_authorization(&state.paths.authorization).unwrap(),
        *current
    );
}
