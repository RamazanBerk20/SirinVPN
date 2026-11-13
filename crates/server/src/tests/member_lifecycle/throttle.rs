//! Member-reachable mutations and status streams have per-device budgets.
use super::*;
use sirinvpn_protocol::MeasurementLeaseRequest;

#[tokio::test]
async fn a_member_device_hits_429_after_its_mutation_budget_but_managers_do_not() {
    let (_directory, state) = fixture();
    let document = state.authorization.as_ref().unwrap().read().await.clone();
    let remove = |device: &DeviceRecord| {
        crate::measurement::remove(
            State(state.clone()),
            Extension(identity(device)),
            Json(MeasurementLeaseRequest {
                public_key: STANDARD.encode([7; 32]),
            }),
        )
    };
    let (owner, member, sibling) = (
        &document.devices[0],
        &document.devices[2],
        &document.devices[3],
    );
    for _ in 0..MEMBER_MUTATIONS_PER_MINUTE {
        assert!(remove(member).await.is_ok());
    }
    let limited = remove(member).await.unwrap_err();
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.code, ErrorCode::RateLimited);
    // The budget is per device, and Owners/Admins are not limited.
    assert!(remove(sibling).await.is_ok());
    for _ in 0..3 * MEMBER_MUTATIONS_PER_MINUTE {
        assert!(remove(owner).await.is_ok());
    }
    // A revoked identity still gets its 403, not a budget answer.
    let unknown = CallerIdentity {
        certificate_fingerprint: "unknown".into(),
    };
    for _ in 0..=MEMBER_MUTATIONS_PER_MINUTE {
        let error = crate::measurement::remove(
            State(state.clone()),
            Extension(unknown.clone()),
            Json(MeasurementLeaseRequest {
                public_key: STANDARD.encode([7; 32]),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }
}

/// Prepare is charged to the old identity, commit to the new one; both are the same device.
#[tokio::test]
async fn key_rotation_cannot_refresh_a_member_devices_budget() {
    let (_directory, state) = fixture();
    let mut document = state.authorization.as_ref().unwrap().read().await.clone();
    let device_id = document.devices[2].id;
    // One earlier change, so the budget runs out on a commit.
    assert!(limit_mutation(&state, &document, &identity(&document.devices[2])).is_ok());
    let mut charged = 1;
    let mut pending = None;
    for round in 0..MEMBER_MUTATIONS_PER_MINUTE {
        let old = identity(
            document
                .devices
                .iter()
                .find(|device| device.id == device_id)
                .unwrap(),
        );
        if limit_mutation(&state, &document, &old).is_err() {
            break;
        }
        charged += 1;
        let next = LocalIdentity::generate("Rotated").unwrap();
        let request = KeyRotationPrepareRequest {
            rotation_id: KeyRotationId::new(),
            server_id: document.server_id,
            new_wireguard_public_key: next.public.wireguard_public_key.clone(),
            new_management_certificate_pem: next.public.management_certificate_pem.clone(),
            new_wireguard_preshared_key: None,
        };
        document
            .prepare_key_rotation(&old.certificate_fingerprint, &request, 100 + round as u64)
            .unwrap();
        let new = CallerIdentity {
            certificate_fingerprint: certificate_fingerprint(
                &next.public.management_certificate_pem,
            )
            .unwrap(),
        };
        if limit_mutation(&state, &document, &new).is_err() {
            pending = Some((request.rotation_id, new));
            break;
        }
        charged += 1;
        document
            .commit_key_rotation(request.rotation_id, &new.certificate_fingerprint, 100)
            .unwrap();
    }
    assert_eq!(charged, MEMBER_MUTATIONS_PER_MINUTE);
    // The handler refuses the commit before any work.
    let (rotation_id, new) = pending.expect("the budget ran out between prepare and commit");
    *state.authorization.as_ref().unwrap().write().await = document.clone();
    let limited = crate::enrollment::commit_key_rotation_handler(
        State(state.clone()),
        Extension(new),
        AxumPath(rotation_id.to_string()),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        *state.authorization.as_ref().unwrap().read().await,
        document
    );
}

#[tokio::test]
async fn one_members_devices_share_a_member_wide_budget() {
    let (_directory, state) = fixture();
    let mut document = state.authorization.as_ref().unwrap().read().await.clone();
    // Family (devices 2 and 3) gets a third device.
    let extra = LocalIdentity::generate("Family 2").unwrap();
    let mut third = document.devices[3].clone();
    third.id = DeviceId::new();
    third.client_tunnel_address = document.allocate_member_address().unwrap();
    third.certificate_fingerprint =
        certificate_fingerprint(&extra.public.management_certificate_pem).unwrap();
    third.management_certificate_pem = extra.public.management_certificate_pem;
    third.wireguard_public_key = extra.public.wireguard_public_key;
    document.devices.push(third);
    let devices = [2, 3, 5].map(|index| identity(&document.devices[index]));
    let mut allowed = 0;
    for _ in 0..MEMBER_MUTATIONS_PER_MINUTE {
        for device in &devices {
            allowed += usize::from(limit_mutation(&state, &document, device).is_ok());
        }
    }
    assert_eq!(allowed, MEMBER_WIDE_MUTATIONS_PER_MINUTE);
    // Another person is not affected.
    assert!(limit_mutation(&state, &document, &identity(&document.devices[4])).is_ok());
}

#[tokio::test]
async fn each_device_holds_at_most_two_status_streams() {
    let (_directory, state) = fixture();
    let member = state.authorization.as_ref().unwrap().read().await.devices[2].clone();
    let open = || {
        crate::status_stream::status_stream_handler(
            State(state.clone()),
            Extension(identity(&member)),
        )
    };
    let first = open().await.unwrap_or_else(|_| panic!("first stream"));
    let _second = open().await.unwrap_or_else(|_| panic!("second stream"));
    let Err(error) = open().await else {
        panic!("third stream was accepted");
    };
    assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
    drop(first);
    assert!(open().await.is_ok());
}

#[tokio::test]
async fn redemption_failures_do_not_outlive_their_window() {
    let (_directory, state) = fixture();
    let expired = InvitationId::new();
    record_redemption_failure(&state, expired, 100);
    // Checking another grant prunes the expired one and records nothing for itself.
    assert!(!redemption_is_limited(&state, InvitationId::new(), 200));
    assert!(state.redemption_failures.lock().unwrap().is_empty());
    let active = InvitationId::new();
    for _ in 0..5 {
        record_redemption_failure(&state, active, 300);
    }
    assert!(redemption_is_limited(&state, active, 330));
    assert!(!redemption_is_limited(&state, active, 360));
}
