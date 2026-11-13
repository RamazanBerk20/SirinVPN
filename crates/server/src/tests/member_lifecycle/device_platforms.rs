use super::*;

async fn report(state: &AppState, caller: &DeviceRecord, platform: &str) -> Result<(), ApiError> {
    update_device_platform_handler(
        State(state.clone()),
        Extension(identity(caller)),
        Json(DevicePlatformUpdateRequest {
            platform: platform.into(),
        }),
    )
    .await
    .map(|_| ())
}

#[tokio::test]
async fn a_device_records_only_its_own_known_platform_without_a_commit() {
    let (_directory, state) = fixture();
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    report(&state, &before.devices[2], "android").await.unwrap();
    // A commit would need this host's missing firewall tooling and leave recovery pending.
    assert!(!crate::authorization_transaction::needs_recovery(
        &state.recovery
    ));
    for unknown in ["macos", "Android", ""] {
        let result = report(&state, &before.devices[2], unknown).await;
        assert_eq!(result.err().unwrap().status, StatusCode::BAD_REQUEST);
    }
    let snapshot = membership_handler(
        State(state.clone()),
        Extension(identity(&before.devices[1])),
    )
    .await
    .unwrap()
    .0
    .payload;
    let platforms: Vec<_> = snapshot
        .members
        .iter()
        .flat_map(|member| &member.devices)
        .filter_map(|device| Some((device.id, device.platform.clone()?)))
        .collect();
    assert_eq!(platforms, [(before.devices[2].id, "android".to_owned())]);

    state.authorization.as_ref().unwrap().write().await.members[2].suspended = true;
    let suspended = report(&state, &before.devices[3], "linux").await;
    assert_eq!(suspended.err().unwrap().status, StatusCode::FORBIDDEN);
    // Only the platform changed in memory; the stored document is as it was.
    let reloaded = load_authorization(&state.paths.authorization).unwrap();
    assert_eq!(
        reloaded.device_platforms,
        HashMap::from([(before.devices[2].id, "android".to_owned())])
    );
    let mut after = state.authorization.as_ref().unwrap().read().await.clone();
    after.members[2].suspended = false;
    after.device_platforms.clear();
    assert_eq!(after, before);
}

#[tokio::test]
async fn platform_reports_spend_budget_only_when_they_write() {
    let (_directory, state) = fixture();
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    let (reported, fresh) = (&before.devices[2], &before.devices[3]);
    report(&state, reported, "android").await.unwrap();
    // Repeats write nothing, so they neither spend nor need budget.
    for _ in 0..2 * MEMBER_MUTATIONS_PER_MINUTE {
        report(&state, reported, "linux").await.unwrap();
    }
    for _ in 0..MEMBER_MUTATIONS_PER_MINUTE - 1 {
        assert!(limit_mutation(&state, &before, &identity(fresh)).is_ok());
    }
    report(&state, fresh, "linux").await.unwrap();
    let mut other = before.clone();
    other.device_platforms.clear();
    let exhausted = &before.devices[4];
    for _ in 0..MEMBER_MUTATIONS_PER_MINUTE {
        let _ = limit_mutation(&state, &other, &identity(exhausted));
    }
    let limited = report(&state, exhausted, "windows").await.unwrap_err();
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
}
