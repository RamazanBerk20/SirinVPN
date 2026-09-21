use super::*;
use sirinvpn_platform::files;

#[test]
fn current_preferences_survive_restart_and_remain_server_scoped_and_private() {
    let directory = tempfile::tempdir().unwrap();
    let id = ServerId::new();
    let other = ServerId::new();
    let store = ConnectionPreferenceStore::new(directory.path().join("preferences"));
    let preferences = ConnectionPreferences {
        android_applications: None,
        manual_mtu: Some(1300),
        transport: TransportPreference::DirectUdp,
        network_profile: NetworkProfile::Restricted,
        policy: ConnectionPolicy::legacy(true),
        routing: TunnelRoutingPolicy::selected_routes(["198.51.100.0/24".into()], true).unwrap(),
    };
    store.set(id, preferences.clone()).unwrap();
    files::validate_private_file(&files::open_no_follow(&store.path(id)).unwrap()).unwrap();
    drop(store);
    let store = ConnectionPreferenceStore::new(directory.path().join("preferences"));
    assert_eq!(store.get(id).unwrap(), preferences);
    assert_eq!(store.get(other).unwrap(), ConnectionPreferences::default());
    store.forget(id).unwrap();
    assert_eq!(store.get(id).unwrap(), ConnectionPreferences::default());
    assert_eq!(fs::read_dir(&store.directory).unwrap().count(), 0);
}

#[test]
fn invalid_or_future_files_are_preserved_and_invalid_routes_never_replace_saved_preferences() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConnectionPreferenceStore::new(directory.path().to_owned());
    let id = ServerId::new();
    for content in [
        "broken".into(),
        r#"{"schema_version":3,"preferences":{}}"#.into(),
        " ".repeat(16385),
    ] {
        fs::write(store.path(id), &content).unwrap();
        assert!(store.get(id).is_err());
        assert!(store.set(id, ConnectionPreferences::default()).is_err());
        assert_eq!(fs::read_to_string(store.path(id)).unwrap(), content);
    }
    fs::remove_file(store.path(id)).unwrap();
    store.set(id, ConnectionPreferences::default()).unwrap();
    let invalid = ConnectionPreferences {
        routing: TunnelRoutingPolicy {
            mode: TunnelRoutingMode::SelectedRoutes,
            included_routes: vec!["not a CIDR".into()],
            allow_lan: false,
        },
        ..Default::default()
    };
    assert!(store.set(id, invalid).is_err());
    assert_eq!(store.get(id).unwrap(), ConnectionPreferences::default());
    assert!(
        store
            .set(
                id,
                ConnectionPreferences {
                    transport: TransportPreference::TlsLike,
                    policy: ConnectionPolicy::legacy(true),
                    ..Default::default()
                }
            )
            .is_ok()
    );
}

#[test]
fn legacy_bundle_migrates_without_changing_boot_or_session_policy() {
    for enabled in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let store = ConnectionPreferenceStore::new(directory.path().to_owned());
        let id = ServerId::new();
        let old = serde_json::json!({"schema_version":1,"preferences": {
            "transport":"automatic", "network_profile":"restricted", "persistent_protection":enabled,
            "routing":{"mode":"full_tunnel","allow_lan":true}
        }}).to_string();
        fs::write(store.path(id), &old).unwrap();
        let migrated = store.get(id).unwrap();
        assert_eq!(migrated.policy, ConnectionPolicy::legacy(enabled));
        assert_eq!(fs::read_to_string(store.path(id)).unwrap(), old);
        store.set(id, migrated.clone()).unwrap();
        assert_eq!(store.get(id).unwrap(), migrated);
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(store.path(id)).unwrap()).unwrap();
        assert_eq!(saved["schema_version"], 2);
        assert!(saved["preferences"].get("persistent_protection").is_none());
    }
}

#[test]
fn all_independent_preferences_persist_including_manual_tls() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConnectionPreferenceStore::new(directory.path().to_owned());
    for kill in [false, true] {
        for reconnect in [false, true] {
            for startup in [false, true] {
                let id = ServerId::new();
                let wanted = ConnectionPreferences {
                    policy: ConnectionPolicy {
                        kill_switch: kill,
                        automatic_reconnect: reconnect,
                        connect_on_startup: startup,
                    },
                    transport: TransportPreference::TlsLike,
                    ..Default::default()
                };
                store.set(id, wanted.clone()).unwrap();
                assert_eq!(
                    ConnectionPreferenceStore::new(directory.path().to_owned())
                        .get(id)
                        .unwrap(),
                    wanted
                );
            }
        }
    }
}

#[test]
fn incomplete_new_policy_does_not_default_missing_flags_or_overwrite_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConnectionPreferenceStore::new(directory.path().to_owned());
    let id = ServerId::new();
    let content = r#"{"schema_version":2,"preferences":{"transport":"automatic","network_profile":"automatic","routing":{},"policy":{"kill_switch":true}}}"#;
    fs::write(store.path(id), content).unwrap();
    assert!(store.get(id).is_err());
    assert!(store.set(id, ConnectionPreferences::default()).is_err());
    assert_eq!(fs::read_to_string(store.path(id)).unwrap(), content);
}

#[test]
fn application_routing_requires_its_new_schema_and_retains_no_launch_details() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConnectionPreferenceStore::new(directory.path().to_owned());
    let id = ServerId::new();
    let preferences = ConnectionPreferences {
        routing: TunnelRoutingPolicy::selected_applications(true),
        ..Default::default()
    };
    store.set(id, preferences.clone()).unwrap();
    assert_eq!(store.get(id).unwrap(), preferences);
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(store.path(id)).unwrap()).unwrap();
    assert_eq!(document["schema_version"], 4);
    assert!(document["preferences"].get("executable").is_none());
    assert!(document["preferences"].get("arguments").is_none());
    document["schema_version"] = 3.into();
    let bytes = serde_json::to_vec(&document).unwrap();
    fs::write(store.path(id), &bytes).unwrap();
    assert!(store.get(id).is_err());
    assert!(store.set(id, preferences).is_err());
    assert_eq!(fs::read(store.path(id)).unwrap(), bytes);
}

#[test]
fn android_packages_require_version_five_and_retain_only_the_current_selection() {
    use sirinvpn_protocol::{AndroidApplicationMode, AndroidApplicationRouting};
    let directory = tempfile::tempdir().unwrap();
    let store = ConnectionPreferenceStore::new(directory.path().to_owned());
    let id = ServerId::new();
    let mut preferences = ConnectionPreferences {
        android_applications: Some(AndroidApplicationRouting {
            mode: AndroidApplicationMode::Include,
            packages: vec!["org.example.browser".into()],
        }),
        ..Default::default()
    };
    store.set(id, preferences.clone()).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(store.path(id)).unwrap()).unwrap();
    assert_eq!(document["schema_version"], 5);
    assert_eq!(store.get(id).unwrap(), preferences);
    document["schema_version"] = 4.into();
    let bytes = serde_json::to_vec(&document).unwrap();
    fs::write(store.path(id), &bytes).unwrap();
    assert!(store.get(id).is_err());
    assert!(store.set(id, preferences.clone()).is_err());
    assert_eq!(fs::read(store.path(id)).unwrap(), bytes);
    document["schema_version"] = 5.into();
    fs::write(store.path(id), serde_json::to_vec(&document).unwrap()).unwrap();
    preferences.android_applications.as_mut().unwrap().packages = vec!["org.example.mail".into()];
    store.set(id, preferences).unwrap();
    assert!(
        !fs::read_to_string(store.path(id))
            .unwrap()
            .contains("org.example.browser")
    );
}
