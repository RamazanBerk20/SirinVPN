//! Real interfaces/routing/nftables; only absent container services are doubled.
use super::*;

struct SessionRunner;
impl CommandRunner for SessionRunner {
    fn run(&self, program: &str, args: &[&str], input: Option<&[u8]>) -> Result<()> {
        if matches!(program, "systemctl" | "resolvectl") {
            return Ok(());
        }
        SystemRunner.run(program, args, input)
    }
    fn output(&self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
        if program == "systemctl" {
            return Ok(b"disabled\n".to_vec());
        }
        SystemRunner.output(program, args)
    }
}

pub(super) fn check_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let helper = LinuxNetworkHelper::new(SessionRunner, dir.path().join("run"));
    let probe = |mode| {
        assert!(
            Command::new("python3")
                .args(["tests/network/policy_packets.py", mode])
                .status()
                .unwrap()
                .success()
        )
    };
    for kill in [false, true] {
        for reconnect in [false, true] {
            let mut request = request();
            request.schema_version = 7;
            request.policy = Some(ConnectionPolicy {
                kill_switch: kill,
                automatic_reconnect: reconnect,
                connect_on_startup: false,
            });
            helper.connect(&request).unwrap();
            assert!(SystemRunner.succeeds("ip", &["link", "show", INTERFACE_NAME]));
            let paused = helper.pause_session(request.server_id).unwrap();
            assert!(paused.waiting_for_user);
            probe(if kill { "full" } else { "off" });
            let mut state = helper.read_state().unwrap();
            state.applied_at_unix = 1;
            helper.write_state(&state).unwrap();
            helper.reconcile_persistent_once(true).unwrap();
            assert!(!SystemRunner.succeeds("ip", &["link", "show", INTERFACE_NAME]));
            helper.reconnect_session(request.server_id).unwrap();
            assert!(SystemRunner.succeeds("ip", &["link", "show", INTERFACE_NAME]));
            let mut next = request.clone();
            next.server_id = ServerId::new();
            next.endpoint_host = "203.0.113.9".into();
            next.server_public_key = STANDARD.encode([9_u8; 32]);
            let next_status = helper
                .switch_session(&crate::SwitchConnectRequest {
                    expected_server_id: request.server_id,
                    request: next.clone(),
                })
                .unwrap();
            assert_eq!(next_status.server_id, Some(next.server_id));
            assert_eq!(next_status.policy, request.policy);
            assert!(SystemRunner.succeeds("ip", &["link", "show", INTERFACE_NAME]));
            assert!(helper.disconnect_session(request.server_id).is_err());
            helper.pause_session(next.server_id).unwrap();
            if kill {
                assert!(helper.guard_is_verified(&next, "203.0.113.9".parse().unwrap()));
            }
            probe(if kill { "handoff" } else { "off" });
            helper.disconnect_session(next.server_id).unwrap();
            probe("off");
            println!(
                "native session operations: kill={kill}, reconnect={reconnect}; real WireGuard interface, IPv4/IPv6/DNS policy retained"
            );
        }
    }
}
