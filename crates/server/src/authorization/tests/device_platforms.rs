use super::*;

#[test]
fn platforms_live_beside_the_document_and_never_change_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authorization.json");
    let mut state = state();
    add_member(&mut state, "Family", false);
    state.schema_version = state.required_schema_version();
    write_authorization(&path, &state).unwrap();
    let document = fs::read(&path).unwrap();
    let fingerprint = state.endpoint_authorization_fingerprint().unwrap();
    let (owner, family) = (state.devices[0].id, state.devices[1].id);

    state
        .record_device_platform(&path, family, "android")
        .unwrap();
    // An entry for a device that no longer exists is dropped on the next write.
    state
        .device_platforms
        .insert(DeviceId::new(), "linux".into());
    state
        .record_device_platform(&path, owner, "windows")
        .unwrap();
    assert_eq!(state.device_platforms.len(), 2);
    for (device, platform) in [(DeviceId::new(), "linux"), (owner, "macos")] {
        assert!(
            state
                .record_device_platform(&path, device, platform)
                .is_err()
        );
    }
    // The document, and so its schema and the endpoint binding, is untouched.
    assert_eq!(fs::read(&path).unwrap(), document);
    assert_eq!(
        state.endpoint_authorization_fingerprint().unwrap(),
        fingerprint
    );
    let loaded = load_authorization(&path).unwrap();
    assert_eq!(loaded, state);
    let snapshot = loaded.snapshot(0);
    let platform = |id| {
        let mut devices = snapshot.members.iter().flat_map(|m| &m.devices);
        devices.find(|d| d.id == id).unwrap().platform.clone()
    };
    assert_eq!(platform(family).as_deref(), Some("android"));
    assert_eq!(platform(owner).as_deref(), Some("windows"));

    // An unreadable file or one a newer server wrote only loses icons.
    let platforms = path.with_file_name("device-platforms.json");
    fs::write(&platforms, b"not json").unwrap();
    assert!(
        load_authorization(&path)
            .unwrap()
            .device_platforms
            .is_empty()
    );
    let newer = serde_json::json!({ family.to_string(): "macos" });
    fs::write(&platforms, serde_json::to_vec(&newer).unwrap()).unwrap();
    assert!(
        load_authorization(&path)
            .unwrap()
            .device_platforms
            .is_empty()
    );
}

#[test]
fn a_device_platform_is_set_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authorization.json");
    let mut state = state();
    state.schema_version = state.required_schema_version();
    write_authorization(&path, &state).unwrap();
    let owner = state.devices[0].id;
    let platforms = path.with_file_name("device-platforms.json");

    state.record_device_platform(&path, owner, "linux").unwrap();
    let written = fs::read(&platforms).unwrap();
    // A later, different report is accepted but changes nothing and writes nothing.
    fs::remove_file(&platforms).unwrap();
    for platform in ["windows", "android", "linux"] {
        state
            .record_device_platform(&path, owner, platform)
            .unwrap();
    }
    assert!(!platforms.exists());
    assert_eq!(state.device_platforms[&owner], "linux");
    assert!(!written.is_empty());
}
