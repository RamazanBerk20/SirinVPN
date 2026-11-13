//! The helper can die between any two system commands (SIGKILL, OOM, power loss of the
//! process, a `systemctl restart` of the supervisor). For every prefix of each
//! transition's command sequence this kills it there, lets the supervisor recover, and
//! checks the device is tunnelled or blocked: never leaking while kill-switch intent is
//! saved, and never reported Off or Disconnected while a guard is installed.
use super::*;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::AtomicUsize,
};

const NEVER: usize = usize::MAX;

#[derive(Clone)]
struct CrashRunner {
    inner: PolicyRunner,
    calls: Arc<AtomicUsize>,
    crash_at: Arc<AtomicUsize>,
}

struct Crashed;

impl CrashRunner {
    fn step(&self) {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == self.crash_at.load(Ordering::SeqCst) {
            // The command at this step never runs; neither does anything after it.
            std::panic::panic_any(Crashed);
        }
    }
}

impl CommandRunner for CrashRunner {
    fn tunnel_probe(&self, client: Ipv4Addr, dns: Ipv4Addr) -> bool {
        self.step();
        self.inner.tunnel_probe(client, dns)
    }
    fn run(&self, p: &str, a: &[&str], input: Option<&[u8]>) -> Result<()> {
        self.step();
        self.inner.run(p, a, input)
    }
    fn output(&self, p: &str, a: &[&str]) -> Result<Vec<u8>> {
        self.step();
        self.inner.output(p, a)
    }
    fn output_with_timeout(&self, p: &str, a: &[&str], timeout: Duration) -> Result<Vec<u8>> {
        self.step();
        self.inner.output_with_timeout(p, a, timeout)
    }
}

type Helper = LinuxNetworkHelper<CrashRunner>;

struct Fixture {
    _dir: tempfile::TempDir,
    helper: Helper,
    runner: CrashRunner,
}

fn fixture(setup: &dyn Fn(&Fixture)) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let runner = CrashRunner {
        inner: runner(),
        calls: Arc::default(),
        crash_at: Arc::new(AtomicUsize::new(NEVER)),
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    let fixture = Fixture {
        _dir: dir,
        helper,
        runner,
    };
    // Every reply counts as a handshake, so a rebuilt tunnel is healthy at once.
    fixture
        .runner
        .inner
        .base
        .latest_handshake_unix
        .store(now_unix(), Ordering::SeqCst);
    setup(&fixture);
    fixture
}

fn reboot(fixture: &Fixture) {
    let base = &fixture.runner.inner.base;
    let _ = fs::remove_file(fixture.helper.state_path());
    *fixture.runner.inner.guard.lock().unwrap() = None;
    base.guard_exists.store(false, Ordering::SeqCst);
    base.interface_exists.store(false, Ordering::SeqCst);
}

/// The supervisor's next passes after a crash (systemd restarts it on failure).
fn recover(fixture: &Fixture) {
    for _ in 0..3 {
        let _ = fixture.helper.reconcile_persistent_once(true);
    }
}

fn check(name: &str, step: usize, fixture: &Fixture) {
    let helper = &fixture.helper;
    let guarded = fixture
        .runner
        .inner
        .base
        .guard_exists
        .load(Ordering::SeqCst);
    let tunnelled = fixture
        .runner
        .inner
        .base
        .interface_exists
        .load(Ordering::SeqCst);
    let intent = helper.persistent_path().exists();
    let kill_switch = helper
        .read_guard_spec()
        .is_some_and(|spec| spec.policy.kill_switch);
    assert!(
        !intent || !kill_switch || guarded,
        "{name}, crash at step {step}: kill-switch intent is saved but nothing blocks \
         (tunnel up: {tunnelled})"
    );
    // A running session's guard must also be the exact one for its request.
    if intent && kill_switch && helper.state_path().exists() {
        let desired = helper.read_persistent().unwrap();
        let state = helper.read_state().unwrap();
        let request = current_persistent_request(&desired, Some(&state));
        assert!(
            helper.guard_is_verified(&request, desired.endpoint),
            "{name}, crash at step {step}: the guard is not the one for the saved session"
        );
    }
    if guarded {
        let status = helper.status().unwrap();
        assert_ne!(
            status.state,
            ConnectionState::Disconnected,
            "{name}, crash at step {step}: a guard blocks traffic but status says Disconnected"
        );
        assert!(
            status
                .phase()
                .is_some_and(|phase| phase != sirinvpn_tunnel_model::TunnelPhase::Idle),
            "{name}, crash at step {step}: a guard blocks traffic but the phase is {:?}",
            status.phase()
        );
        assert_ne!(
            status.kill_switch_state,
            Some(KillSwitchState::Off),
            "{name}, crash at step {step}: a guard blocks traffic but status says Off"
        );
    }
}

/// Runs `operation` once to count its steps, then crashes it at each one in turn.
fn every_step(
    name: &str,
    setup: &dyn Fn(&Fixture),
    operation: &dyn Fn(&Fixture),
    after_crash: &dyn Fn(&Fixture),
) {
    let complete = fixture(setup);
    let start = complete.runner.calls.load(Ordering::SeqCst);
    operation(&complete);
    let steps = complete.runner.calls.load(Ordering::SeqCst) - start;
    assert!(steps > 0, "{name} ran no commands");
    after_crash(&complete);
    recover(&complete);
    check(name, steps, &complete);
    for step in 0..steps {
        let fixture = fixture(setup);
        let start = fixture.runner.calls.load(Ordering::SeqCst);
        fixture
            .runner
            .crash_at
            .store(start + step, Ordering::SeqCst);
        match catch_unwind(AssertUnwindSafe(|| operation(&fixture))) {
            Err(payload) if payload.is::<Crashed>() => {}
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(()) => panic!("{name}: step {step} of {steps} was never reached"),
        }
        fixture.runner.crash_at.store(NEVER, Ordering::SeqCst);
        after_crash(&fixture);
        recover(&fixture);
        check(name, step, &fixture);
    }
}

fn session(kill: bool, boot: bool) -> TunnelConnectRequest {
    let mut request = independent(kill, true, boot);
    request.reconnect_candidates = vec![
        ReconnectCandidate {
            transport: TransportKind::DirectUdp,
            endpoint_port: 51_820,
            server_transport_public_key: None,
            https: None,
            server_certificate_sha256: None,
            mtu: 1_420,
        },
        ReconnectCandidate {
            transport: TransportKind::TcpFallback,
            endpoint_port: 443,
            server_transport_public_key: Some(STANDARD.encode([9_u8; 32])),
            https: None,
            server_certificate_sha256: None,
            mtu: 1_280,
        },
    ];
    request
}

fn connected(kill: bool, boot: bool) -> impl Fn(&Fixture) {
    move |fixture: &Fixture| {
        fixture.helper.connect(&session(kill, boot)).unwrap();
        fixture.helper.reconcile_persistent_once(true).unwrap();
    }
}

fn nothing(_: &Fixture) {}

#[test]
fn connect_survives_a_crash_at_every_step() {
    for boot in [false, true] {
        every_step(
            "connect",
            &nothing,
            &|fixture| {
                let _ = fixture.helper.connect(&session(true, boot));
            },
            &nothing,
        );
    }
}

#[test]
fn switch_survives_a_crash_at_every_step() {
    for kill in [false, true] {
        let first = session(kill, false);
        every_step(
            "switch",
            &|fixture| {
                fixture.helper.connect(&first).unwrap();
                fixture.helper.reconcile_persistent_once(true).unwrap();
            },
            &|fixture| {
                let mut next = session(kill, false);
                next.endpoint_host = "203.0.113.25".into();
                let _ = fixture.helper.switch_session(&SwitchConnectRequest {
                    expected_server_id: fixture.helper.read_state().unwrap().server_id,
                    request: next,
                });
            },
            &nothing,
        );
    }
}

#[test]
fn disconnect_survives_a_crash_at_every_step() {
    every_step(
        "disconnect",
        &connected(true, true),
        &|fixture| {
            let _ = fixture.helper.disconnect();
        },
        &nothing,
    );
}

#[test]
fn carrier_replacement_survives_a_crash_at_every_step() {
    every_step(
        "carrier replacement",
        &|fixture| {
            connected(true, false)(fixture);
            // The established path failed: the next pass rebuilds on the next carrier.
            let mut state = fixture.helper.read_state().unwrap();
            state.applied_at_unix = now_unix().saturating_sub(300);
            state.has_connected = false;
            state.initial_attempts = 1;
            fixture.helper.write_state(&state).unwrap();
            let base = &fixture.runner.inner.base;
            base.interface_exists.store(false, Ordering::SeqCst);
        },
        &|fixture| {
            let _ = fixture.helper.reconcile_persistent_once(true);
        },
        &nothing,
    );
}

#[test]
fn boot_survives_a_crash_at_every_step() {
    every_step(
        "boot",
        &|fixture| {
            connected(true, true)(fixture);
            reboot(fixture);
        },
        &|fixture| {
            let _ = fixture.helper.restore_kill_switch();
            let _ = fixture.helper.reconcile_persistent_once(true);
        },
        &nothing,
    );
}

/// A crash, then a reboot before the supervisor ran again: boot must still protect.
#[test]
fn a_reboot_after_any_crashed_transition_still_boots_protected() {
    every_step(
        "connect then reboot",
        &nothing,
        &|fixture| {
            let _ = fixture.helper.connect(&session(true, true));
        },
        &|fixture| {
            reboot(fixture);
            let _ = fixture.helper.restore_kill_switch();
        },
    );
}
