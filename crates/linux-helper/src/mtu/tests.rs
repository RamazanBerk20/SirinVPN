use super::*;
use std::cell::{Cell, RefCell};

#[test]
fn automatic_sessions_negotiate_an_mtu_safe_for_every_candidate() {
    let mut request = crate::tests::request();
    request.mtu_policy = Some(MtuPolicy::Automatic);
    assert_eq!(session_mtu(&request), 1420);
    request.reconnect_candidates.push(ReconnectCandidate {
        transport: TransportKind::TcpFallback,
        endpoint_port: 443,
        server_transport_public_key: Some(request.server_public_key.clone()),
        server_certificate_sha256: None,
        https: None,
        mtu: 1280,
    });
    assert_eq!(initial_mtu(&request).unwrap().configured, 1280);
    request.mtu = 1200;
    assert_eq!(session_mtu(&request), 1200);
}

struct MtuRunner {
    maximum: Cell<u16>,
    /// Replies to drop, regardless of size, before answering normally again.
    lose: Cell<u16>,
    icmp: bool,
    applied: Cell<Option<u16>>,
    calls: RefCell<Vec<String>>,
}
impl CommandRunner for MtuRunner {
    fn run(&self, program: &str, args: &[&str], _: Option<&[u8]>) -> Result<()> {
        assert_eq!(program, "ip");
        assert_eq!(&args[..5], &["link", "set", "dev", INTERFACE_NAME, "mtu"]);
        self.applied.set(Some(args[5].parse().unwrap()));
        Ok(())
    }
    fn output(&self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
        assert_eq!(program, "ping");
        self.calls.borrow_mut().push(args.join(" "));
        assert!(args.windows(2).any(|pair| pair == ["-I", INTERFACE_NAME]));
        let index = args.iter().position(|arg| *arg == "-s").unwrap();
        let size: u16 = args[index + 1].parse().unwrap();
        if self.lose.get() > 0 {
            self.lose.set(self.lose.get() - 1);
            bail!("simulated packet loss");
        }
        if !self.icmp || size + 28 > self.maximum.get() {
            bail!("simulated packet loss");
        }
        Ok(Vec::new())
    }
}

fn fixture(
    policy: MtuPolicy,
    maximum: u16,
    icmp: bool,
) -> (
    tempfile::TempDir,
    LinuxNetworkHelper<MtuRunner>,
    TunnelConnectRequest,
) {
    let directory = tempfile::tempdir().unwrap();
    let helper = LinuxNetworkHelper {
        runner: MtuRunner {
            maximum: Cell::new(maximum),
            lose: Cell::new(0),
            icmp,
            applied: Cell::new(None),
            calls: RefCell::default(),
        },
        runtime_directory: directory.path().join("run"),
        persistent_directory: directory.path().join("state"),
        namespace_directory: directory.path().join("netns-config"),
    };
    let mut request = crate::tests::request();
    request.schema_version = 8;
    request.policy = Some(ConnectionPolicy::default());
    request.mtu_policy = Some(policy);
    if let MtuPolicy::Manual { value } = policy {
        request.mtu = value;
    }
    (directory, helper, request)
}

#[test]
fn safe_mtu_requires_delivery_and_manual_values_are_not_automatically_changed() {
    for policy in [MtuPolicy::Automatic, MtuPolicy::Manual { value: 1420 }] {
        let (_directory, helper, request) = fixture(policy, 1300, true);
        validate_request(&request).unwrap();
        let mut state = RuntimeState::for_policy(&request);
        helper.inspect_mtu(&request, &mut state, None);
        // A first lower result is only evidence; a later round confirms it.
        let first = state.mtu.unwrap();
        assert_eq!(first.suggested, Some(1280));
        assert_eq!(first.outcome, MtuProbeOutcome::Pending);
        assert_eq!(helper.runner.applied.get(), None);
        helper.inspect_mtu(&request, &mut state, None);
        assert_eq!(state.mtu.unwrap().outcome, MtuProbeOutcome::Pending);
        later(&mut state, MTU_CONFIRM_SECONDS);
        helper.inspect_mtu(&request, &mut state, None);
        let measured = state.mtu.unwrap();
        assert_eq!(measured.suggested, Some(1280));
        assert_eq!(measured.outcome, MtuProbeOutcome::Measured);
        assert_eq!(
            helper.runner.applied.get(),
            (policy == MtuPolicy::Automatic).then_some(1280)
        );
        let calls = helper.runner.calls.borrow().len();
        helper.inspect_mtu(&request, &mut state, None);
        assert_eq!(
            helper.runner.calls.borrow().len(),
            calls,
            "current measurement must not create continuous probe traffic"
        );
    }
}

fn later(state: &mut RuntimeState, seconds: u64) {
    state.mtu_sampled_at_unix = state.mtu_sampled_at_unix.map(|at| at - seconds);
}

/// Before, each size needed two consecutive replies, so one lost reply at the ceiling
/// settled on a smaller MTU that was applied and never probed again.
#[test]
fn one_lost_reply_does_not_lower_the_mtu() {
    let (_directory, helper, request) = fixture(MtuPolicy::Automatic, 1500, true);
    let mut state = RuntimeState::for_policy(&request);
    // The first reply is lost; one loss decides nothing.
    helper.runner.lose.set(1);
    helper.inspect_mtu(&request, &mut state, None);
    let mtu = state.mtu.unwrap();
    assert_eq!(mtu.outcome, MtuProbeOutcome::Measured);
    assert_eq!(mtu.suggested, Some(1420));
    assert_eq!(mtu.configured, 1420);
    assert_eq!(helper.runner.applied.get(), None);
}

#[test]
fn a_lower_result_not_seen_again_is_never_applied() {
    let (_directory, helper, request) = fixture(MtuPolicy::Automatic, 1300, true);
    let mut state = RuntimeState::for_policy(&request);
    helper.inspect_mtu(&request, &mut state, None);
    assert_eq!(state.mtu.unwrap().outcome, MtuProbeOutcome::Pending);
    helper.runner.maximum.set(1500);
    later(&mut state, MTU_CONFIRM_SECONDS);
    helper.inspect_mtu(&request, &mut state, None);
    let mtu = state.mtu.unwrap();
    assert_eq!(mtu.outcome, MtuProbeOutcome::Measured);
    assert_eq!(mtu.configured, 1420);
    assert_eq!(helper.runner.applied.get(), None);
}

#[test]
fn a_lowered_mtu_is_probed_again_and_recovers() {
    let (_directory, helper, request) = fixture(MtuPolicy::Automatic, 1300, true);
    let mut state = RuntimeState::for_policy(&request);
    helper.inspect_mtu(&request, &mut state, None);
    later(&mut state, MTU_CONFIRM_SECONDS);
    helper.inspect_mtu(&request, &mut state, None);
    assert_eq!(state.mtu.unwrap().configured, 1280);
    helper.runner.maximum.set(1500);
    // Not before the recovery interval: no continuous probe traffic.
    let calls = helper.runner.calls.borrow().len();
    helper.inspect_mtu(&request, &mut state, None);
    assert_eq!(helper.runner.calls.borrow().len(), calls);
    later(&mut state, MTU_RECOVERY_SECONDS);
    helper.inspect_mtu(&request, &mut state, None);
    let mtu = state.mtu.unwrap();
    assert_eq!(mtu.outcome, MtuProbeOutcome::Measured);
    assert_eq!(mtu.configured, 1420);
    assert_eq!(helper.runner.applied.get(), Some(1420));
}

#[test]
fn unavailable_icmp_is_unknown_and_ipv6_never_uses_a_subminimum_mtu() {
    let (_directory, helper, request) = fixture(MtuPolicy::Automatic, 576, false);
    let mut state = RuntimeState::for_policy(&request);
    helper.inspect_mtu(&request, &mut state, None);
    assert_eq!(state.mtu.unwrap().outcome, MtuProbeOutcome::IcmpUnavailable);
    assert_eq!(helper.runner.applied.get(), None);
    let (_directory, helper, mut request) = fixture(MtuPolicy::Automatic, 1200, true);
    request.client_ipv6_address = Some("fd00::2".parse().unwrap());
    let mut state = RuntimeState::for_policy(&request);
    helper.inspect_mtu(&request, &mut state, None);
    assert_eq!(state.mtu.unwrap().outcome, MtuProbeOutcome::NoUsableMtu);
    assert_eq!(helper.runner.applied.get(), None);
    request.mtu_policy = Some(MtuPolicy::Manual { value: 1200 });
    request.mtu = 1200;
    assert!(validate_request(&request).is_err());
}

#[test]
#[ignore = "requires a disposable network namespace; use tests/network/run-mtu-path.sh"]
fn kernel_mtu_probe_recovers_packet_delivery_without_changing_routing_or_firewall() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let run = |mode| {
        assert!(
            Command::new("python3")
                .args(["tests/network/mtu_path.py", mode])
                .status()
                .unwrap()
                .success()
        )
    };
    run("prepare");
    let directory = tempfile::tempdir().unwrap();
    let helper = LinuxNetworkHelper::new(SystemRunner, directory.path().to_owned());
    let rules_before = SystemRunner
        .output("nft", &["-j", "list", "ruleset"])
        .unwrap();
    let routes_before = SystemRunner
        .output("ip", &["-j", "route", "show", "table", "all"])
        .unwrap();
    let mut request = crate::tests::request();
    request.policy = Some(ConnectionPolicy::default());
    request.set_mtu_policy(MtuPolicy::Automatic).unwrap();
    let mut state = RuntimeState::for_policy(&request);
    helper.inspect_mtu(&request, &mut state, None);
    later(&mut state, MTU_CONFIRM_SECONDS);
    helper.inspect_mtu(&request, &mut state, None);
    assert_eq!(state.mtu.unwrap().configured, 1280);
    assert_eq!(state.mtu.unwrap().outcome, MtuProbeOutcome::Measured);
    let actual: serde_json::Value = serde_json::from_slice(
        &SystemRunner
            .output("ip", &["-j", "link", "show", "dev", INTERFACE_NAME])
            .unwrap(),
    )
    .unwrap();
    assert_eq!(actual[0]["mtu"], 1280);
    SystemRunner
        .run(
            "ip",
            &["link", "set", "dev", INTERFACE_NAME, "mtu", "1420"],
            None,
        )
        .unwrap();
    request
        .set_mtu_policy(MtuPolicy::Manual { value: 1420 })
        .unwrap();
    let mut state = RuntimeState::for_policy(&request);
    helper.inspect_mtu(&request, &mut state, None);
    later(&mut state, MTU_CONFIRM_SECONDS);
    helper.inspect_mtu(&request, &mut state, None);
    assert_eq!(state.mtu.unwrap().configured, 1420);
    assert_eq!(state.mtu.unwrap().suggested, Some(1280));
    let actual: serde_json::Value = serde_json::from_slice(
        &SystemRunner
            .output("ip", &["-j", "link", "show", "dev", INTERFACE_NAME])
            .unwrap(),
    )
    .unwrap();
    assert_eq!(actual[0]["mtu"], 1420);
    assert_eq!(
        rules_before,
        SystemRunner
            .output("nft", &["-j", "list", "ruleset"])
            .unwrap()
    );
    assert_eq!(
        routes_before,
        SystemRunner
            .output("ip", &["-j", "route", "show", "table", "all"])
            .unwrap()
    );
    run("block");
    let mut state = RuntimeState::for_policy(&request);
    helper.inspect_mtu(&request, &mut state, None);
    assert_eq!(state.mtu.unwrap().outcome, MtuProbeOutcome::IcmpUnavailable);
}
