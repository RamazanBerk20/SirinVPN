use super::*;

#[test]
fn tray_pause_reconnect_and_switch_preserve_all_four_policies() {
    for kill in [false, true] {
        for reconnect in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let runner = runner();
            let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
            let request = independent(kill, reconnect, true);
            helper.connect(&request).unwrap();
            runner.base.commands.lock().unwrap().clear();
            let paused = helper.pause_session(request.server_id).unwrap();
            assert!(paused.waiting_for_user);
            assert_eq!(paused.policy, request.policy);
            helper.reconcile_persistent_once(true).unwrap();
            assert!(helper.status().unwrap().waiting_for_user);
            let restarted = helper.reconnect_session(request.server_id).unwrap();
            assert!(!restarted.waiting_for_user);
            assert_eq!(restarted.policy, request.policy);
            let mut next = request.clone();
            next.server_id = ServerId::new();
            next.endpoint_host = "203.0.113.25".into();
            next.endpoint_port = 51821;
            let result = helper
                .switch_session(&SwitchConnectRequest {
                    expected_server_id: request.server_id,
                    request: next.clone(),
                })
                .unwrap();
            assert_eq!(result.server_id, Some(next.server_id));
            assert_eq!(result.policy, request.policy);
            assert_eq!(runner.base.guard_exists.load(Ordering::SeqCst), kill);
            assert_eq!(
                helper.read_persistent().unwrap().request.server_id,
                next.server_id
            );
            assert!(
                runner
                    .base
                    .commands
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(p, a, _)| !(p == "nft"
                        && a == &["delete", "table", "inet", "sirinvpn_guard"]))
            );
            if kill {
                assert!(helper.guard_is_verified(&next, "203.0.113.25".parse().unwrap()));
            }
            // A stale confirmation cannot affect the replacement session.
            assert!(matches!(
                helper.disconnect_session(request.server_id),
                Err(HelperError::ActivePolicy)
            ));
            assert_eq!(helper.status().unwrap().server_id, Some(next.server_id));
            let stopped = helper.disconnect_session(next.server_id).unwrap();
            assert_eq!(stopped.state, ConnectionState::Disconnected);
            assert!(!helper.persistent_path().exists());
            assert!(!runner.base.guard_exists.load(Ordering::SeqCst));
        }
    }
}

#[test]
fn failed_handoffs_and_policy_changes_never_release_the_old_guard() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    let request = independent(true, true, false);
    helper.connect(&request).unwrap();
    let mut next = request.clone();
    next.server_id = ServerId::new();
    next.endpoint_host = "203.0.113.25".into();
    for policy in [
        ConnectionPolicy::default(),
        ConnectionPolicy {
            kill_switch: true,
            automatic_reconnect: false,
            connect_on_startup: false,
        },
    ] {
        let mut modified = next.clone();
        modified.policy = Some(policy);
        assert!(
            helper
                .switch_session(&SwitchConnectRequest {
                    expected_server_id: request.server_id,
                    request: modified
                })
                .is_err()
        );
        assert!(helper.guard_is_verified(&request, helper.read_persistent().unwrap().endpoint));
    }
    let mut modified = next.clone();
    modified.routing.allow_lan = true;
    assert!(
        helper
            .switch_session(&SwitchConnectRequest {
                expected_server_id: request.server_id,
                request: modified
            })
            .is_err()
    );
    runner.transaction_failed.store(true, Ordering::SeqCst);
    assert!(
        helper
            .switch_session(&SwitchConnectRequest {
                expected_server_id: request.server_id,
                request: next
            })
            .is_err()
    );
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    assert_eq!(
        helper.read_persistent().unwrap().request.server_id,
        request.server_id
    );
    assert!(helper.status().unwrap().waiting_for_user);
    runner.transaction_failed.store(false, Ordering::SeqCst);
    helper.reconnect_session(request.server_id).unwrap();
    assert_eq!(helper.status().unwrap().server_id, Some(request.server_id));
}
