use super::*;
use crate::enforcement::{GuardSpec, deny_all_guard_objects};

/// A reboot wipes /run and the kernel ruleset; saved intent in /var/lib remains.
fn reboot(helper: &LinuxNetworkHelper<PolicyRunner>, runner: &PolicyRunner) {
    let _ = fs::remove_file(helper.state_path());
    *runner.guard.lock().unwrap() = None;
    runner.base.guard_exists.store(false, Ordering::SeqCst);
    runner.base.interface_exists.store(false, Ordering::SeqCst);
}

fn damage_saved_request(helper: &LinuxNetworkHelper<PolicyRunner>) {
    let mut saved: Value =
        serde_json::from_slice(&fs::read(helper.persistent_path()).unwrap()).unwrap();
    // A rule a newer helper might tighten: the saved value no longer validates.
    saved["request"]["mtu"] = 1.into();
    fs::write(
        helper.persistent_path(),
        serde_json::to_vec(&saved).unwrap(),
    )
    .unwrap();
    assert!(helper.read_persistent().is_err());
}

/// Before, boot required the full saved request to validate: after a helper upgrade
/// that rejected it, no guard was installed while "block until connected" was on.
#[test]
fn boot_blocks_from_the_guard_spec_when_the_saved_request_no_longer_validates() {
    for allow_lan in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let runner = runner();
        let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
        let mut request = independent(true, true, true);
        request.routing.allow_lan = allow_lan;
        helper.connect(&request).unwrap();
        let spec = helper.read_guard_spec().unwrap();
        assert_eq!(spec, GuardSpec::for_request(&request));
        reboot(&helper, &runner);
        damage_saved_request(&helper);
        helper.restore_kill_switch().unwrap();
        assert_eq!(
            runner.guard.lock().unwrap().clone(),
            deny_all_guard_objects(Some(&spec))
        );
        // Without even a readable spec, boot still blocks everything but loopback and DHCP.
        reboot(&helper, &runner);
        fs::write(helper.guard_spec_path(), b"{").unwrap();
        helper.restore_kill_switch().unwrap();
        let fallback = runner.guard.lock().unwrap().clone().unwrap();
        assert_eq!(Some(fallback.clone()), deny_all_guard_objects(None));
        assert!(
            fallback
                .iter()
                .any(|object| object["chain"]["policy"] == "drop")
        );
        // An explicit Disconnect still releases it without reading the request.
        helper.disconnect().unwrap();
        assert!(helper.guard_is_absent().unwrap());
        assert!(!helper.guard_spec_path().exists());
    }
}

#[test]
fn a_spec_without_boot_blocking_installs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    helper.connect(&independent(true, true, false)).unwrap();
    reboot(&helper, &runner);
    damage_saved_request(&helper);
    assert!(helper.restore_kill_switch().is_err());
    assert!(runner.guard.lock().unwrap().is_none());
}

/// Before, saved intent without a running session showed "Disconnected" with the kill
/// switch Off, and Connect to another server failed with ActivePolicy.
#[test]
fn saved_intent_after_reboot_is_reported_and_replaced_by_connect_elsewhere() {
    for kill in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let runner = runner();
        let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
        let request = independent(kill, true, false);
        helper.connect(&request).unwrap();
        reboot(&helper, &runner);
        let status = helper.status().unwrap();
        assert_ne!(status.state, ConnectionState::Disconnected);
        assert!(status.waiting_for_user);
        assert_eq!(status.server_id, Some(request.server_id));
        assert_eq!(status.policy, request.policy);
        assert_eq!(
            status.kill_switch_state,
            Some(if kill {
                KillSwitchState::Unknown
            } else {
                KillSwitchState::Off
            })
        );
        // Connecting elsewhere, with any policy, replaces it.
        let mut other = independent(!kill, false, false);
        other.endpoint_host = "203.0.113.25".into();
        let connected = helper.connect(&other).unwrap();
        assert_eq!(connected.server_id, Some(other.server_id));
        assert_eq!(
            helper.read_persistent().unwrap().request.server_id,
            other.server_id
        );
        assert_eq!(runner.base.guard_exists.load(Ordering::SeqCst), !kill);
    }
}

#[test]
fn saved_intent_after_reboot_can_be_resumed_or_disconnected() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    let request = independent(true, true, false);
    helper.connect(&request).unwrap();
    reboot(&helper, &runner);
    let resumed = helper.resume(request.server_id).unwrap();
    assert!(!resumed.waiting_for_user);
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    reboot(&helper, &runner);
    helper.disconnect().unwrap();
    assert_eq!(
        helper.status().unwrap().state,
        ConnectionState::Disconnected
    );
}

/// A leftover boot guard for replaced intent is released when the new session needs none;
/// a guard of a running session is never released this way.
#[test]
fn only_a_stale_guard_is_released_by_connect_without_kill_switch() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    let request = independent(true, true, true);
    helper.connect(&request).unwrap();
    let mut other = independent(false, true, false);
    other.endpoint_host = "203.0.113.25".into();
    assert!(matches!(
        helper.connect(&other),
        Err(HelperError::ActivePolicy)
    ));
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    reboot(&helper, &runner);
    helper.restore_kill_switch().unwrap();
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    helper.connect(&other).unwrap();
    assert!(helper.guard_is_absent().unwrap());
}

#[test]
fn carrier_relays_run_unprivileged_with_only_the_mark_capability() {
    for unit in [
        TRANSPORT_SERVICE,
        include_str!("../../../../../packaging/systemd/sirinvpn-transport@.service"),
    ] {
        assert!(unit.contains("DynamicUser=yes"));
        assert!(!unit.contains("User=root"));
        assert!(unit.contains("LoadCredential=config:/run/sirinvpn/transport"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_ADMIN\n"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN\n"));
        assert!(unit.contains("SystemCallFilter=@system-service"));
        assert!(unit.contains("RestartPreventExitStatus=98"));
        assert!(unit.contains("NoNewPrivileges=yes"));
    }
}

fn output_policy(objects: &[Value]) -> &Value {
    &objects
        .iter()
        .find(|object| object["chain"]["name"] == "output")
        .unwrap()["chain"]["policy"]
}

fn drops(objects: &[Value], address: &str) -> bool {
    objects.iter().any(|object| {
        let expressions = object["rule"]["expr"].as_array();
        expressions.is_some_and(|expressions| {
            expressions.last() == Some(&serde_json::json!({"drop": null}))
                && expressions.iter().any(|expression| {
                    expression["match"]["right"]["prefix"]["addr"] == address
                        || expression["match"]["right"] == address
                })
        })
    })
}

/// Before, the boot fallback for SelectedRoutes installed `output policy drop`, blocking
/// the whole host although that mode's guard accepts everything but its routes and DNS.
/// A spec from an older helper has no routes and still blocks the whole host.
#[test]
fn boot_fallback_for_selected_routes_drops_only_the_selected_routes() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    let mut request = independent(true, true, true);
    request.routing =
        TunnelRoutingPolicy::selected_routes(["198.51.100.0/24".to_owned()], false).unwrap();
    validate_request(&request).unwrap();
    helper.connect(&request).unwrap();
    let spec = helper.read_guard_spec().unwrap();
    reboot(&helper, &runner);
    damage_saved_request(&helper);
    helper.restore_kill_switch().unwrap();
    let guard = runner.guard.lock().unwrap().clone().unwrap();
    assert_eq!(Some(guard.clone()), deny_all_guard_objects(Some(&spec)));
    assert_eq!(output_policy(&guard), "accept");
    assert!(drops(&guard, "198.51.100.0"));
    assert!(drops(&guard, &request.dns_address.to_string()));
    assert!(
        !guard
            .iter()
            .any(|object| object["rule"]["chain"] == "forward")
    );

    // The spec an older helper wrote: same fields, no routes.
    let mut old: Value =
        serde_json::from_slice(&fs::read(helper.guard_spec_path()).unwrap()).unwrap();
    old.as_object_mut()
        .unwrap()
        .remove("selected_routes")
        .unwrap();
    fs::write(helper.guard_spec_path(), serde_json::to_vec(&old).unwrap()).unwrap();
    let old = helper.read_guard_spec().unwrap();
    assert_eq!(
        output_policy(&deny_all_guard_objects(Some(&old)).unwrap()),
        "drop"
    );
    // An unparsable route never yields a more open guard.
    let mut damaged: Value = serde_json::to_value(&spec).unwrap();
    damaged["selected_routes"]["included_routes"] = serde_json::json!(["not a route"]);
    let damaged: GuardSpec = serde_json::from_value(damaged).unwrap();
    assert_eq!(
        output_policy(&deny_all_guard_objects(Some(&damaged)).unwrap()),
        "drop"
    );
    // Other devices' LANs must not land in the world-readable spec; such a session blocks
    // the whole host at boot as before.
    request.subnet_routes.reachable = vec!["10.20.0.0/20".to_owned()];
    let spec = GuardSpec::for_request(&request);
    assert!(!serde_json::to_string(&spec).unwrap().contains("10.20.0.0"));
    assert_eq!(
        output_policy(&deny_all_guard_objects(Some(&spec)).unwrap()),
        "drop"
    );
}
