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
async fn a_device_reports_only_its_own_known_platform() {
    let (_directory, state) = fixture();
    let before = {
        let mut document = state.authorization.as_ref().unwrap().write().await;
        document.devices[2].platform = Some("android".into());
        document.clone()
    };
    // Only the caller's own record holds this platform, so no commit is needed and none of
    // this test host's missing firewall tooling is reached.
    report(&state, &before.devices[2], "android").await.unwrap();
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
        .map(|device| (device.id, device.platform.clone()))
        .collect();
    assert!(platforms.contains(&(before.devices[2].id, Some("android".into()))));
    assert_eq!(
        platforms
            .iter()
            .filter(|(_, platform)| platform.is_some())
            .count(),
        1
    );

    state.authorization.as_ref().unwrap().write().await.members[2].suspended = true;
    let suspended = report(&state, &before.devices[3], "linux").await;
    assert_eq!(suspended.err().unwrap().status, StatusCode::FORBIDDEN);
    let mut after = state.authorization.as_ref().unwrap().read().await.clone();
    after.members[2].suspended = false;
    assert_eq!(after, before);
}
