//! Current service enablement only; no activity or manual-disconnect history.
use super::*;

/// `show` succeeds for disabled units as well. A failed query must remain unknown.
/// Enabled means registered for boot, not that boot or a VPN handshake succeeded.
pub fn startup_service_enabled(runner: &impl CommandRunner) -> Option<bool> {
    let output = runner
        .output_with_timeout(
            "systemctl",
            &[
                "show",
                RECONNECT_UNIT,
                "--property=UnitFileState",
                "--value",
            ],
            Duration::from_secs(2),
        )
        .ok()?;
    match std::str::from_utf8(&output).ok()?.trim() {
        "enabled" => Some(true),
        "disabled" | "masked" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Observation(Option<&'static str>);
    impl CommandRunner for Observation {
        fn run(&self, _: &str, _: &[&str], _: Option<&[u8]>) -> Result<()> {
            panic!("a status query must not mutate services");
        }
        fn output(&self, program: &str, arguments: &[&str]) -> Result<Vec<u8>> {
            assert_eq!(program, "systemctl");
            assert_eq!(
                arguments,
                [
                    "show",
                    RECONNECT_UNIT,
                    "--property=UnitFileState",
                    "--value"
                ]
            );
            Ok(self
                .0
                .ok_or_else(|| anyhow!("bus unavailable"))?
                .as_bytes()
                .to_vec())
        }
    }
    #[test]
    fn disabled_is_distinct_from_unreadable_temporary_or_missing_service() {
        for (output, expected) in [
            (Some("enabled\n"), Some(true)),
            (Some("disabled\n"), Some(false)),
            (Some("masked\n"), Some(false)),
            (Some("enabled-runtime\n"), None),
            (Some(""), None),
            (None, None),
        ] {
            assert_eq!(startup_service_enabled(&Observation(output)), expected);
        }
    }

    #[test]
    fn stalled_service_query_is_terminated_and_reaped() {
        let start = std::time::Instant::now();
        assert!(
            SystemRunner
                .output_with_timeout("sleep", &["10"], Duration::from_millis(20))
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
