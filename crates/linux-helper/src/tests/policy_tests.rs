//! State-machine tests use command doubles. Packet tests are separate and opt-in.
use super::*;
mod endpoints;
mod https;
mod route_metadata;
mod session_control;
use crate::enforcement::guard_objects;
use serde_json::Value;

#[derive(Clone, Default)]
struct PolicyRunner {
    base: RecordingRunner,
    guard: Arc<Mutex<Option<Vec<Value>>>>,
    inspection_failed: Arc<AtomicBool>,
    transaction_failed: Arc<AtomicBool>,
    physical_route: Arc<Mutex<Option<String>>>,
}
impl CommandRunner for PolicyRunner {
    fn tunnel_probe(&self, _: Ipv4Addr, _: Ipv4Addr) -> bool {
        self.base.latest_handshake_unix.load(Ordering::SeqCst) > 0
    }
    fn run(&self, p: &str, a: &[&str], input: Option<&[u8]>) -> Result<()> {
        if p == "nft" && a == ["-j", "-f", "-"] {
            if self.transaction_failed.load(Ordering::SeqCst) {
                bail!("injected atomic failure");
            }
            let value: Value = serde_json::from_slice(input.unwrap())?;
            *self.guard.lock().unwrap() = Some(
                value["nftables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|v| v.get("add").cloned())
                    .collect(),
            );
            self.base.guard_exists.store(true, Ordering::SeqCst);
        }
        if p == "nft" && a == ["delete", "table", "inet", "sirinvpn_guard"] {
            *self.guard.lock().unwrap() = None;
        }
        self.base.run(p, a, input)
    }
    fn output(&self, p: &str, a: &[&str]) -> Result<Vec<u8>> {
        if p == "ip" && a == ["-4", "route", "show", "table", "main", "default"] {
            return Ok(self
                .physical_route
                .lock()
                .unwrap()
                .as_deref()
                .unwrap_or("")
                .as_bytes()
                .to_vec());
        }
        if p == "wg" && a == ["show", INTERFACE_NAME, "endpoints"] {
            let commands = self.base.commands.lock().unwrap();
            return Ok(commands
                .iter()
                .rev()
                .find_map(|(program, arguments, _)| {
                    if program != "wg" {
                        return None;
                    }
                    arguments
                        .windows(2)
                        .find(|pair| pair[0] == "endpoint")
                        .map(|pair| {
                            let key = arguments.windows(2).find(|pair| pair[0] == "peer").unwrap();
                            format!("{} {}", key[1], pair[1]).into_bytes()
                        })
                })
                .unwrap_or_default());
        }
        if p == "nft"
            && a == ["-j", "list", "tables"]
            && self.inspection_failed.load(Ordering::SeqCst)
        {
            bail!("injected inspection failure");
        }
        if p == "nft" && a == ["-j", "list", "table", "inet", "sirinvpn_guard"] {
            if self.inspection_failed.load(Ordering::SeqCst) {
                bail!("injected inspection failure");
            }
            let guard = self.guard.lock().unwrap();
            return Ok(serde_json::to_vec(
                &serde_json::json!({"nftables": guard.as_ref().ok_or_else(|| anyhow!("missing guard"))?}),
            )?);
        }
        self.base.output(p, a)
    }
}
fn independent(kill: bool, reconnect: bool, boot: bool) -> TunnelConnectRequest {
    let mut request = request();
    request.schema_version = 7;
    request.policy = Some(ConnectionPolicy {
        kill_switch: kill,
        automatic_reconnect: reconnect,
        connect_on_startup: boot,
    });
    request
}
fn runner() -> PolicyRunner {
    PolicyRunner {
        base: RecordingRunner {
            emulate_tunnel: true,
            ..Default::default()
        },
        ..Default::default()
    }
}
fn expire(helper: &LinuxNetworkHelper<PolicyRunner>, connected: bool) {
    let mut state = helper.read_state().unwrap();
    state.applied_at_unix = now_unix().saturating_sub(300);
    state.has_connected = connected;
    helper.write_state(&state).unwrap();
}

#[test]
fn four_independent_failure_policies_and_explicit_disconnect() {
    for kill in [false, true] {
        for reconnect in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let runner = runner();
            let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
            let request = independent(kill, reconnect, false);
            let started = helper.connect(&request).unwrap();
            assert_eq!(started.kill_switch_enabled, kill);
            assert_eq!(started.auto_reconnect_enabled, reconnect);
            assert!(!started.connect_on_startup);
            runner
                .base
                .latest_handshake_unix
                .store(now_unix(), Ordering::SeqCst);
            helper.reconcile_persistent_once(true).unwrap();
            assert!(helper.read_state().unwrap().has_connected);
            assert_eq!(helper.status().unwrap().state, ConnectionState::Connected);
            runner.base.latest_handshake_unix.store(0, Ordering::SeqCst);
            expire(&helper, true);
            let mut state = helper.read_state().unwrap();
            let health = &mut state.quality.get_or_insert_with(Default::default).health;
            let now = now_unix();
            for age in [25, 20, 15, 10, 5, 0] {
                health.record(now - age, Some(0), Some(0), false);
            }
            helper.write_state(&state).unwrap();
            helper.reconcile_persistent_once(true).unwrap();
            let failed = helper.status().unwrap();
            assert_eq!(failed.waiting_for_user, !reconnect);
            assert_eq!(runner.base.guard_exists.load(Ordering::SeqCst), kill);
            assert_eq!(
                failed.kill_switch_state,
                Some(if kill {
                    KillSwitchState::Blocking
                } else {
                    KillSwitchState::Off
                })
            );
            let attempts = helper.read_state().unwrap().initial_attempts;
            helper.reconcile_persistent_once(true).unwrap();
            assert_eq!(helper.read_state().unwrap().initial_attempts, attempts);
            if !reconnect {
                // Manual resume keeps the guard. Selecting another server or changing policy does not.
                let mut other = request.clone();
                other.server_id = ServerId::new();
                assert!(matches!(
                    helper.connect(&other),
                    Err(HelperError::ActivePolicy)
                ));
                other = request.clone();
                other.policy.as_mut().unwrap().kill_switch = !kill;
                assert!(matches!(
                    helper.connect(&other),
                    Err(HelperError::ActivePolicy)
                ));
                helper.resume(request.server_id).unwrap();
                assert_eq!(runner.base.guard_exists.load(Ordering::SeqCst), kill);
            }
            helper.disconnect().unwrap();
            assert!(!runner.base.guard_exists.load(Ordering::SeqCst));
            assert!(!helper.persistent_path().exists());
            assert_eq!(
                helper.status().unwrap().kill_switch_state,
                Some(KillSwitchState::Off)
            );
        }
    }
}

#[test]
fn bounded_initial_selection_does_not_enable_established_session_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().to_owned());
    let mut request = independent(true, false, false);
    request.reconnect_candidates = persistent_automatic_request().reconnect_candidates.clone();
    helper.connect(&request).unwrap();
    assert!(
        runner
            .base
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, args, _)| {
                program == "systemctl" && args == &["restart", RECONNECT_UNIT]
            })
    );
    runner.base.commands.lock().unwrap().clear();
    helper.reconcile_persistent_once(false).unwrap();
    assert!(
        !runner
            .base
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, args, _)| {
                program == "ip" && args == &["link", "delete", INTERFACE_NAME]
            })
    );
    for expected in [TransportKind::ObfuscatedUdp, TransportKind::TcpFallback] {
        expire(&helper, false);
        helper.reconcile_persistent_once(true).unwrap();
        assert_eq!(helper.status().unwrap().transport, Some(expected));
        assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    }
    expire(&helper, false);
    helper.reconcile_persistent_once(true).unwrap();
    assert!(helper.status().unwrap().waiting_for_user);
    assert_eq!(helper.read_state().unwrap().initial_attempts, 3);
    assert!(
        !runner
            .base
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(p, a, _)| p == "nft" && a == &["delete", "table", "inet", "sirinvpn_guard"])
    );
}

#[test]
fn helper_apply_service_and_inspection_failures_do_not_release_a_working_guard() {
    for service_failure in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let runner = PolicyRunner {
            base: RecordingRunner {
                emulate_tunnel: true,
                fail_apply: !service_failure,
                fail_service_start: service_failure,
                ..Default::default()
            },
            ..Default::default()
        };
        let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().to_owned());
        let result = helper.connect(&independent(true, false, false));
        assert_eq!(result.is_err(), service_failure);
        assert!(runner.base.guard_exists.load(Ordering::SeqCst));
        let mut state = helper.read_state().unwrap();
        state.observed_at_boot_seconds = Some(0);
        helper.write_state(&state).unwrap();
        assert_eq!(
            helper.status().unwrap().kill_switch_state,
            Some(KillSwitchState::Unknown)
        );
        runner.inspection_failed.store(true, Ordering::SeqCst);
        assert!(helper.reconcile_persistent_once(true).is_err());
        assert_eq!(
            helper.status().unwrap().kill_switch_state,
            Some(KillSwitchState::Failed)
        );
        assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    }
}

#[test]
fn boot_policy_is_independent_and_does_not_invent_post_disconnect_lockdown() {
    for kill in [false, true] {
        for boot in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let runner = runner();
            let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().to_owned());
            helper.connect(&independent(kill, false, boot)).unwrap();
            let commands = runner.base.commands.lock().unwrap().clone();
            assert!(commands.iter().any(|(p, a, _)| p == "systemctl"
                && a == &[if boot { "enable" } else { "disable" }, RECONNECT_UNIT]));
            assert!(commands.iter().any(|(p, a, _)| p == "systemctl"
                && a == &[
                    if boot && kill { "enable" } else { "disable" },
                    KILL_SWITCH_UNIT
                ]));
            fs::remove_file(helper.state_path()).unwrap();
            runner.base.guard_exists.store(false, Ordering::SeqCst);
            *runner.guard.lock().unwrap() = None;
            helper.restore_kill_switch().unwrap();
            assert_eq!(
                runner.base.guard_exists.load(Ordering::SeqCst),
                boot && kill
            );
            if !boot {
                helper.supervise().unwrap();
                assert!(!helper.state_path().exists());
            }
        }
    }
    assert!(!RECONNECT_SERVICE.contains("Requires=sirinvpn-killswitch.service"));
}

#[test]
fn boot_waits_for_network_without_attempts_then_connects_without_transition_grace() {
    for kill in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let runner = runner();
        let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().to_owned());
        helper.connect(&independent(kill, false, true)).unwrap();
        helper.cleanup_tunnel_owned().unwrap();
        fs::remove_file(helper.state_path()).unwrap();
        let offline = SupervisorContext {
            physical_route_available: Some(false),
            ..Default::default()
        };
        for _ in 0..2 {
            helper
                .reconcile_persistent_once_with_context(true, offline)
                .unwrap();
            assert_eq!(helper.read_state().unwrap().initial_attempts, 0);
            assert!(!runner.base.interface_exists.load(Ordering::SeqCst));
            assert_eq!(runner.base.guard_exists.load(Ordering::SeqCst), kill);
        }
        let started = std::time::Instant::now();
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(50));
                *runner.physical_route.lock().unwrap() =
                    Some("default via 192.0.2.1 dev wlan0 metric 100\n".into());
            });
            assert!(helper.wait_for_network_or_handshake(
                Duration::from_secs(60),
                Some(None),
                None
            ));
        });
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "network readiness must interrupt backoff"
        );
        let online = SupervisorContext {
            physical_route_available: Some(true),
            network_changed_at_unix: Some(now_unix()),
            route_transition: Some(RouteTransition {
                detected_at_unix: now_unix(),
                prior_handshake_unix: 0,
            }),
        };
        helper
            .reconcile_persistent_once_with_context(true, online)
            .unwrap();
        assert_eq!(helper.read_state().unwrap().initial_attempts, 1);
        assert!(runner.base.interface_exists.load(Ordering::SeqCst));
        assert_eq!(runner.base.guard_exists.load(Ordering::SeqCst), kill);
        // A reply received during apply must not start a fresh five-second wait.
        runner
            .base
            .latest_handshake_unix
            .store(now_unix(), Ordering::SeqCst);
        let started = std::time::Instant::now();
        assert!(!helper.wait_for_network_or_handshake(
            Duration::from_secs(5),
            helper.physical_default_route_fingerprint(),
            Some(Some(0))
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}

#[test]
fn verification_rejects_rule_changes_extra_accepts_and_future_or_stale_observations() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().to_owned());
    let request = independent(true, false, false);
    helper.connect(&request).unwrap();
    let expected = guard_objects(&request, "203.0.113.8".parse().unwrap());
    runner.guard.lock().unwrap().as_mut().unwrap().swap(2, 3);
    assert!(!helper.guard_is_verified(&request, "203.0.113.8".parse().unwrap()));
    *runner.guard.lock().unwrap() = Some(expected.clone());
    runner
        .guard
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .push(serde_json::json!({"rule":{"expr":[{"accept":null}]}}));
    assert!(!helper.guard_is_verified(&request, "203.0.113.8".parse().unwrap()));
    *runner.guard.lock().unwrap() = Some(expected);
    let mut state = helper.read_state().unwrap();
    state.observed_at_boot_seconds = Some(crate::enforcement::boot_seconds().unwrap() + 100);
    assert_eq!(state.effective_kill_switch(), KillSwitchState::Unknown);
}

#[test]
fn schema_boundary_and_legacy_policy_are_explicit() {
    for enabled in [false, true] {
        let mut legacy = request();
        legacy.persistent_protection = enabled;
        assert_eq!(
            legacy.connection_policy(),
            ConnectionPolicy::legacy(enabled)
        );
        let mut current = independent(enabled, !enabled, false);
        current.schema_version = 6;
        assert!(validate_request(&current).is_err());
        current.schema_version = 7;
        current.persistent_protection = true;
        assert!(validate_request(&current).is_err());
    }
}

#[test]
fn key_rotation_pause_preserves_independent_policy_and_guard_and_checks_server_scope() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().to_owned());
    let request = independent(true, false, false);
    helper.connect(&request).unwrap();
    assert!(helper.pause_for_key_rotation(ServerId::new()).is_err());
    let status = helper.pause_for_key_rotation(request.server_id).unwrap();
    assert!(status.waiting_for_user);
    assert_eq!(status.policy, request.policy);
    assert_eq!(status.kill_switch_state, Some(KillSwitchState::Blocking));
    helper.reconcile_persistent_once(true).unwrap();
    assert!(helper.status().unwrap().waiting_for_user);
    let mut rotated = request.clone();
    rotated.private_key = STANDARD.encode([11_u8; 32]);
    helper.connect(&rotated).unwrap();
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    assert!(
        !runner
            .base
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(p, a, _)| p == "nft" && a == &["delete", "table", "inet", "sirinvpn_guard"])
    );
}

#[test]
fn legacy_enabled_policy_adoption_retains_boot_and_recovery_during_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().to_owned());
    let mut request = request();
    request.persistent_protection = true;
    helper.connect(&request).unwrap();
    let status = helper.pause_for_key_rotation(request.server_id).unwrap();
    assert_eq!(status.policy, Some(ConnectionPolicy::legacy(true)));
    assert_eq!(helper.read_persistent().unwrap().schema_version, 2);
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
}

#[test]
fn independent_fallback_plan_accepts_pinned_tls_without_changing_recovery() {
    let mut request = independent(true, false, false);
    request.reconnect_candidates = persistent_automatic_request().reconnect_candidates.clone();
    request.reconnect_candidates.push(ReconnectCandidate {
        transport: TransportKind::TlsLike,
        endpoint_port: 443,
        server_transport_public_key: Some(STANDARD.encode([12_u8; 32])),
        https: None,
        server_certificate_sha256: Some(STANDARD.encode([13_u8; 32])),
        mtu: 1280,
    });
    validate_request(&request).unwrap();
    let tls = request_for_reconnect_candidate(&request, &request.reconnect_candidates[3]);
    assert_eq!(tls.schema_version, 7);
    assert_eq!(tls.policy, request.policy);
    let mut concrete = tls;
    concrete.reconnect_candidates.clear();
    validate_request(&concrete).unwrap();
}

#[test]
fn incomplete_runtime_or_failed_inspection_never_becomes_an_off_policy() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().to_owned());
    helper.connect(&independent(true, false, false)).unwrap();
    runner.inspection_failed.store(true, Ordering::SeqCst);
    assert!(helper.disconnect().is_err());
    assert!(helper.state_path().exists());
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    let mut state = helper.read_state().unwrap();
    state.policy = None;
    helper.write_state(&state).unwrap();
    assert!(helper.status().is_err());
}

#[test]
fn quality_transition_keeps_the_interface_and_routes_and_verifies_the_guard() {
    let directory = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().into());
    let mut request = independent(true, false, false);
    request.reconnect_candidates = persistent_automatic_request().reconnect_candidates.clone();
    helper.connect(&request).unwrap();
    let desired = helper.read_persistent().unwrap();
    let mut state = helper.read_state().unwrap();
    let next = next_persistent_request(&desired, request.transport);
    runner.transaction_failed.store(true, Ordering::SeqCst);
    assert!(
        helper
            .change_quality_transport(&desired, &next, &mut state)
            .is_err()
    );
    assert!(runner.base.interface_exists.load(Ordering::SeqCst));
    assert!(helper.guard_is_verified(&request, desired.endpoint));
    runner.transaction_failed.store(false, Ordering::SeqCst);
    // The relay starts, but the private exchange cannot verify the new path.
    // Rollback must restore the old endpoint while retaining the live interface.
    assert!(
        helper
            .change_quality_transport(&desired, &next, &mut state)
            .is_err()
    );
    assert_eq!(state.transport, request.transport);
    assert!(helper.carrier_endpoint_matches(&request, desired.endpoint));
    assert!(runner.base.interface_exists.load(Ordering::SeqCst));
    assert!(helper.guard_is_verified(&request, desired.endpoint));
    runner
        .base
        .latest_handshake_unix
        .store(now_unix(), Ordering::SeqCst);
    runner.base.commands.lock().unwrap().clear();
    assert_eq!(
        helper
            .change_quality_transport(&desired, &next, &mut state)
            .unwrap(),
        ReconcileOutcome::Healthy
    );
    assert!(helper.guard_is_verified(&next, desired.endpoint));
    assert_eq!(state.policy, request.policy);
    assert!(!state.connection_policy().automatic_reconnect);
    assert!(
        runner
            .base
            .commands
            .lock()
            .unwrap()
            .iter()
            .all(|(program, args, _)| {
                !(program == "ip" && args == &["link", "delete", INTERFACE_NAME])
                    && !(program == "resolvectl")
                    && !(program == "nft" && args == &["delete", "table", "inet", "sirinvpn_guard"])
            })
    );
}
