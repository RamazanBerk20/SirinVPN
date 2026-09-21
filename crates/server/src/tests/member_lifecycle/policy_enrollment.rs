use super::*;
use sirinvpn_protocol::MemberPolicy;

pub(super) async fn probe(configuration: serde_json::Value) {
    let mut command = Command::new("python3")
        .arg("tests/network/invitation_policy.py")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    command
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&configuration).unwrap().as_bytes())
        .await
        .unwrap();
    assert!(
        command.wait().await.unwrap().success(),
        "invitation packet policy failed"
    );
}

fn request(
    document: &AuthorizationDocument,
    bootstrap: &LocalIdentity,
    max_uses: u16,
) -> InvitationCreateRequest {
    InvitationCreateRequest {
        recipient_names: true,
        server_id: document.server_id,
        endpoint: ServerEndpoint {
            host: "203.0.113.4".into(),
            wireguard_port: 51820,
        },
        member_name: "Invited family".into(),
        device_name: "Independent device".into(),
        target_member_id: None,
        administrator: false,
        max_uses,
        member_policy: MemberPolicy {
            device_limit: Some(2),
            add_own_devices: true,
            ..Default::default()
        },
        expires_in_seconds: 600,
        token_hash: hex::encode(Sha256::digest(b"kernel-only-test-token")),
        bootstrap_wireguard_public_key: bootstrap.public.wireguard_public_key.clone(),
        bootstrap_management_certificate_pem: bootstrap.public.management_certificate_pem.clone(),
    }
}

fn redemption(grant: &InvitationCreateResponse, permanent: &LocalIdentity) -> EnrollmentRequest {
    EnrollmentRequest {
        names: Some(sirinvpn_protocol::EnrollmentNames {
            member_name: grant
                .claims
                .target_member_id
                .is_none()
                .then(|| "Chosen nickname".into()),
            device_name: "My phone".into(),
        }),
        claims: grant.claims.clone(),
        signature: grant.signature.clone(),
        token: "kernel-only-test-token".into(),
        device_wireguard_public_key: permanent.public.wireguard_public_key.clone(),
        device_management_certificate_pem: permanent.public.management_certificate_pem.clone(),
    }
}

#[tokio::test]
async fn member_invitation_authority_and_scope_are_checked_before_mutation() {
    let (_directory, state) = fixture();
    let document = state.authorization.as_ref().unwrap().read().await.clone();
    let bootstrap = LocalIdentity::generate("Test bootstrap").unwrap();
    let ordinary = identity(&document.devices[2]);
    let result = create_invitation_handler(
        State(state.clone()),
        Extension(ordinary),
        Json(request(&document, &bootstrap, 2)),
    )
    .await;
    assert_eq!(result.err().unwrap().status, StatusCode::FORBIDDEN);
    let mut admin_request = request(&document, &bootstrap, 2);
    admin_request.administrator = true;
    let result = create_invitation_handler(
        State(state.clone()),
        Extension(identity(&document.devices[1])),
        Json(admin_request),
    )
    .await;
    assert_eq!(result.err().unwrap().status, StatusCode::FORBIDDEN);
    assert_eq!(
        *state.authorization.as_ref().unwrap().read().await,
        document
    );
    let snapshot = membership_handler(State(state), Extension(identity(&document.devices[2])))
        .await
        .unwrap()
        .0
        .payload;
    assert_eq!(snapshot.members.len(), 1);
    assert_eq!(snapshot.members[0].id, document.devices[2].member_id);
}

#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-invitation-policy.sh"]
async fn kernel_reusable_enrollment_quarantines_bootstrap_and_enforces_limits_atomically() {
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
        .spawn()
        .unwrap();
    prepare.stdin.take().unwrap().write_all(serde_json::to_string(&serde_json::json!({
        "devices": [], "server_private_key_path": state.paths.wireguard_private_key, "server_ipv6": server_ipv6,
    })).unwrap().as_bytes()).await.unwrap();
    assert!(prepare.wait().await.unwrap().success());
    let bootstrap = LocalIdentity::generate("Reusable bootstrap").unwrap();
    let grant = create_invitation_handler(
        State(state.clone()),
        Extension(identity(&document.devices[0])),
        Json(request(&document, &bootstrap, 3)),
    )
    .await
    .unwrap()
    .0
    .payload;
    let bootstrap_path = directory.path().join("bootstrap.key");
    write_private(
        &bootstrap_path,
        bootstrap.secret.wireguard_private_key.as_bytes(),
    )
    .unwrap();
    let IpAddr::V4(bootstrap_ip) = grant.claims.bootstrap_tunnel_address else {
        unreachable!()
    };
    probe(serde_json::json!({"mode":"bootstrap", "key":bootstrap_path, "ipv4":bootstrap_ip,
        "ipv6":ipv6_tunnel_address(document.server_id, bootstrap_ip).unwrap(), "server_ipv6":server_ipv6})).await;

    let caller = CallerIdentity {
        certificate_fingerprint: certificate_fingerprint(
            &bootstrap.public.management_certificate_pem,
        )
        .unwrap(),
    };
    let first = LocalIdentity::generate("First permanent").unwrap();
    let second = LocalIdentity::generate("Second permanent").unwrap();
    let first_request = redemption(&grant, &first);
    let mut missing_names = first_request.clone();
    missing_names.names = None;
    assert!(
        enrollment_handler(
            State(state.clone()),
            Extension(caller.clone()),
            Json(missing_names)
        )
        .await
        .is_err()
    );
    let (first_result, second_result) = tokio::join!(
        enrollment_handler(
            State(state.clone()),
            Extension(caller.clone()),
            Json(first_request.clone())
        ),
        enrollment_handler(
            State(state.clone()),
            Extension(caller.clone()),
            Json(redemption(&grant, &second))
        ),
    );
    let first_result = first_result.unwrap().0.payload;
    let second_result = second_result.unwrap().0.payload;
    assert_eq!(first_result.names, first_request.names);
    let stored_names = state.authorization.as_ref().unwrap().read().await.clone();
    assert_eq!(
        stored_names
            .members
            .iter()
            .find(|m| m.id == first_result.member_id)
            .unwrap()
            .name,
        "Chosen nickname"
    );
    assert_eq!(
        stored_names
            .devices
            .iter()
            .find(|d| d.id == first_result.device_id)
            .unwrap()
            .name,
        "My phone"
    );
    // Display names do not merge members or authorize additional access.
    assert_ne!(first_result.member_id, second_result.member_id);
    assert_ne!(first_result.device_id, second_result.device_id);
    assert_ne!(
        first_result.client_tunnel_address,
        second_result.client_tunnel_address
    );
    let retry = enrollment_handler(
        State(state.clone()),
        Extension(caller.clone()),
        Json(first_request.clone()),
    )
    .await
    .unwrap()
    .0
    .payload;
    assert_eq!(retry, first_result);
    let mut changed_retry = first_request.clone();
    changed_retry.names.as_mut().unwrap().device_name = "Changed on retry".into();
    assert!(
        enrollment_handler(
            State(state.clone()),
            Extension(caller.clone()),
            Json(changed_retry)
        )
        .await
        .is_err()
    );
    assert_eq!(
        state
            .authorization
            .as_ref()
            .unwrap()
            .read()
            .await
            .invitations[0]
            .uses_consumed,
        2
    );
    let third = LocalIdentity::generate("Third permanent").unwrap();
    let _ = enrollment_handler(
        State(state.clone()),
        Extension(caller.clone()),
        Json(redemption(&grant, &third)),
    )
    .await
    .unwrap();
    assert!(
        state
            .authorization
            .as_ref()
            .unwrap()
            .read()
            .await
            .invitations
            .is_empty()
    );
    assert_eq!(
        enrollment_handler(
            State(state.clone()),
            Extension(caller.clone()),
            Json(first_request)
        )
        .await
        .unwrap()
        .0
        .payload,
        first_result
    );
    let fourth = LocalIdentity::generate("Exhausted grant").unwrap();
    assert!(
        enrollment_handler(
            State(state.clone()),
            Extension(caller),
            Json(redemption(&grant, &fourth))
        )
        .await
        .is_err()
    );

    let permanent_path = directory.path().join("permanent.key");
    write_private(
        &permanent_path,
        first.secret.wireguard_private_key.as_bytes(),
    )
    .unwrap();
    let IpAddr::V4(permanent_ip) = first_result.client_tunnel_address else {
        unreachable!()
    };
    probe(serde_json::json!({"mode":"permanent", "key":permanent_path, "ipv4":permanent_ip,
        "ipv6":ipv6_tunnel_address(document.server_id, permanent_ip).unwrap(), "server_ipv6":server_ipv6})).await;
    let extra_bootstrap = LocalIdentity::generate("Own device invitation").unwrap();
    let current = state.authorization.as_ref().unwrap().read().await.clone();
    let mut own_request = request(&current, &extra_bootstrap, 2);
    own_request.target_member_id = Some(first_result.member_id);
    own_request.member_name = "Chosen nickname".into();
    own_request.member_policy = MemberPolicy::default();
    let first_caller = CallerIdentity {
        certificate_fingerprint: certificate_fingerprint(&first.public.management_certificate_pem)
            .unwrap(),
    };
    let own_grant = create_invitation_handler(
        State(state.clone()),
        Extension(first_caller),
        Json(own_request),
    )
    .await
    .unwrap()
    .0
    .payload;
    let own_caller = CallerIdentity {
        certificate_fingerprint: certificate_fingerprint(
            &extra_bootstrap.public.management_certificate_pem,
        )
        .unwrap(),
    };
    let second_device = LocalIdentity::generate("Second owned device").unwrap();
    let mut reassignment = redemption(&own_grant, &second_device);
    reassignment.names.as_mut().unwrap().member_name = Some("Unauthorized rename".into());
    assert!(
        enrollment_handler(
            State(state.clone()),
            Extension(own_caller.clone()),
            Json(reassignment)
        )
        .await
        .is_err()
    );
    let added = enrollment_handler(
        State(state.clone()),
        Extension(own_caller.clone()),
        Json(redemption(&own_grant, &second_device)),
    )
    .await
    .unwrap()
    .0
    .payload;
    assert_eq!(added.member_id, first_result.member_id);
    let over_limit = LocalIdentity::generate("Over device limit").unwrap();
    assert_eq!(
        enrollment_handler(
            State(state.clone()),
            Extension(own_caller),
            Json(redemption(&own_grant, &over_limit))
        )
        .await
        .err()
        .unwrap()
        .status,
        StatusCode::CONFLICT
    );
    let stored = load_authorization(&state.paths.authorization).unwrap();
    assert_eq!(stored, *state.authorization.as_ref().unwrap().read().await);
    assert_eq!(stored.schema_version, 3);
    assert_eq!(
        stored
            .enrollment_receipts
            .iter()
            .filter(|receipt| receipt.invitation_id == grant.claims.invitation_id)
            .count(),
        3
    );
}
