//! Read-only report on the authorization transaction: its state, containment, the recovery
//! intent and whether the kernel's WireGuard peers match the stored authorization. It never
//! changes anything; `/v1/diagnostics` appends it and root runs `authorization doctor`.
use super::*;
use crate::authorization_transaction::{Phase, journal::Consistency};
use crate::diagnostics::check;
use sirinvpn_protocol::{DiagnosticCheck, DiagnosticLevel, DiagnosticReport};

#[derive(clap::Subcommand)]
pub enum AuthorizationCommand {
    /// Print the read-only authorization report as JSON.
    Doctor,
}

pub async fn run(command: AuthorizationCommand, paths: &ServerPaths) -> Result<DiagnosticReport> {
    match command {
        AuthorizationCommand::Doctor => {
            let configuration = load_configuration(paths)?;
            let document = load_runtime_authorization(paths)?;
            Ok(crate::diagnostics::report(
                inspect(paths, &configuration, document.as_ref(), None).await,
            ))
        }
    }
}

/// What the running service knows that the disk and kernel do not.
pub(super) struct Live {
    pub phase: Phase,
    pub retry_in: Option<Duration>,
}

pub(super) fn live(state: &AppState) -> Live {
    let recovery = state.recovery.lock().unwrap_or_else(|e| e.into_inner());
    Live {
        phase: recovery.phase.clone(),
        retry_in: recovery
            .retry_at
            .map(|at| at.saturating_duration_since(Instant::now())),
    }
}

pub(super) async fn inspect(
    paths: &ServerPaths,
    configuration: &ServerConfiguration,
    document: Option<&AuthorizationDocument>,
    live: Option<&Live>,
) -> Vec<DiagnosticCheck> {
    let Some(document) = document else {
        return Vec::new();
    };
    let intent = authorization_transaction::journal::inspect(paths).map_err(|e| e.to_string());
    let chain = crate::diagnostics::output(
        "nft",
        &[
            "list",
            "chain",
            "inet",
            "sirinvpn_handoff",
            "recovery_forward",
        ],
    )
    .await;
    // The chain may not exist yet: that also means no containment.
    let contained = match chain {
        Some(rules) => Some(rules.contains(" drop")),
        None => crate::diagnostics::output("nft", &["list", "table", "inet", "sirinvpn_handoff"])
            .await
            .map(|_| false),
    };
    let kernel =
        crate::diagnostics::output("wg", &["show", &configuration.interface_name, "peers"])
            .await
            .map(|output| {
                output
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            });
    let stored = document
        .desired_peers(unix_time())
        .into_iter()
        .map(|peer| peer.public_key)
        .collect();
    evaluate(live, intent, contained, &stored, kernel.as_ref())
}

fn evaluate(
    live: Option<&Live>,
    intent: Result<Consistency, String>,
    contained: Option<bool>,
    stored: &BTreeSet<String>,
    kernel: Option<&BTreeSet<String>>,
) -> Vec<DiagnosticCheck> {
    use DiagnosticLevel::{Fail, Pass, Warning};
    const TRANSACTION: (&str, &str) = ("authorization_transaction", "Access changes");
    const CONTAINMENT: (&str, &str) = ("authorization_containment", "Access containment");
    const INTENT: (&str, &str) = ("authorization_intent", "Access recovery record");
    const PEERS: (&str, &str) = ("authorization_peers", "Enforced devices");
    let mut checks = Vec::new();
    // Healthy is the only state in which containment must be absent.
    let healthy = match live.map(|live| &live.phase) {
        Some(Phase::Healthy { .. }) => Some(true),
        Some(_) => Some(false),
        // From the command line an unfinished intent is the only sign of a transaction.
        None => intent
            .as_ref()
            .ok()
            .map(|intent| *intent == Consistency::Absent),
    };
    if let Some(live) = live {
        let retry = live
            .retry_in
            .filter(|wait| !wait.is_zero())
            .map(|wait| format!(" Next attempt in {} s.", wait.as_secs() + 1))
            .unwrap_or_default();
        checks.push(match &live.phase {
            Phase::Healthy { .. } => check(
                TRANSACTION.0,
                TRANSACTION.1,
                Pass,
                "Every access change is fully enforced.",
            ),
            Phase::Applying { .. } => check(
                TRANSACTION.0,
                TRANSACTION.1,
                Warning,
                "An access change is being applied right now.",
            ),
            Phase::RecoveryPending { .. } => check(
                TRANSACTION.0,
                TRANSACTION.1,
                Warning,
                &format!("An interrupted access change is being restored.{retry}"),
            ),
            Phase::RecoveryFailed { .. } => check(
                TRANSACTION.0,
                TRANSACTION.1,
                Fail,
                &format!(
                    "Restoring access failed; VPN traffic stays blocked until it succeeds.{retry}"
                ),
            ),
        });
    }
    checks.push(match &intent {
        Ok(Consistency::Absent) => check(INTENT.0, INTENT.1, Pass, "No access change is unfinished."),
        Ok(Consistency::Previous | Consistency::Next) => check(
            INTENT.0,
            INTENT.1,
            Warning,
            "An access change was interrupted; the service restores it on its next attempt.",
        ),
        Ok(Consistency::Stale) => check(
            INTENT.0,
            INTENT.1,
            Warning,
            "Repair replaced the access list after an interrupted change. The service discards the old record and enforces the current list when it starts.",
        ),
        Err(_) => check(
            INTENT.0,
            INTENT.1,
            Fail,
            "The access recovery record is damaged, so the service will not start. Run server repair.",
        ),
    });
    checks.push(match (contained, healthy) {
        (None, _) | (_, None) => check(
            CONTAINMENT.0,
            CONTAINMENT.1,
            Warning,
            "The firewall state could not be read.",
        ),
        (Some(false), Some(true)) => check(
            CONTAINMENT.0,
            CONTAINMENT.1,
            Pass,
            "VPN traffic is not blocked.",
        ),
        (Some(true), Some(true)) => check(
            CONTAINMENT.0,
            CONTAINMENT.1,
            Fail,
            "VPN traffic is blocked although no access change is pending. Restart the server service.",
        ),
        (Some(true), Some(false)) => check(
            CONTAINMENT.0,
            CONTAINMENT.1,
            Warning,
            "VPN traffic is blocked while an access change is restored.",
        ),
        (Some(false), Some(false)) => check(
            CONTAINMENT.0,
            CONTAINMENT.1,
            Warning,
            "An access change is unfinished and VPN traffic is not blocked; only additions can be in flight this way.",
        ),
    });
    checks.push(match kernel {
        None => check(PEERS.0, PEERS.1, Warning, "The WireGuard peers could not be read."),
        Some(kernel) => {
            let extra = kernel.difference(stored).count();
            let missing = stored.difference(kernel).count();
            match (extra, missing) {
                (0, 0) => check(
                    PEERS.0,
                    PEERS.1,
                    Pass,
                    &format!("WireGuard enforces exactly the {} stored peers.", stored.len()),
                ),
                // Extra peers are access that should be gone: serious unless contained.
                (extra, missing) => check(
                    PEERS.0,
                    PEERS.1,
                    if extra > 0 && contained != Some(true) {
                        Fail
                    } else {
                        Warning
                    },
                    &format!(
                        "WireGuard has {extra} peers that are not stored and lacks {missing} stored peers."
                    ),
                ),
            }
        }
    });
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn level(checks: &[DiagnosticCheck], code: &str) -> DiagnosticLevel {
        checks
            .iter()
            .find(|check| check.code == code)
            .unwrap()
            .level
            .clone()
    }

    #[test]
    fn the_report_flags_contradictions_between_state_disk_and_kernel() {
        let keys = |keys: &[&str]| {
            keys.iter()
                .map(|key| key.to_string())
                .collect::<BTreeSet<_>>()
        };
        let stored = keys(&["a", "b"]);
        let healthy = Live {
            phase: Phase::Healthy { applied: None },
            retry_in: None,
        };
        let clean = evaluate(
            Some(&healthy),
            Ok(Consistency::Absent),
            Some(false),
            &stored,
            Some(&stored),
        );
        assert!(
            clean
                .iter()
                .all(|check| check.level == DiagnosticLevel::Pass)
        );
        // Containment left installed while healthy blackholes everyone.
        let stuck = evaluate(
            Some(&healthy),
            Ok(Consistency::Absent),
            Some(true),
            &stored,
            Some(&stored),
        );
        assert_eq!(
            level(&stuck, "authorization_containment"),
            DiagnosticLevel::Fail
        );
        // A kernel peer that is no longer stored is access that outlived its removal.
        let leaked = evaluate(
            Some(&healthy),
            Ok(Consistency::Absent),
            Some(false),
            &stored,
            Some(&keys(&["a", "b", "c"])),
        );
        assert_eq!(level(&leaked, "authorization_peers"), DiagnosticLevel::Fail);
        let failed = Live {
            phase: Phase::RecoveryFailed {
                contained: true,
                committed: false,
            },
            retry_in: Some(Duration::from_secs(7)),
        };
        let recovering = evaluate(
            Some(&failed),
            Ok(Consistency::Previous),
            Some(true),
            &stored,
            Some(&keys(&["a", "b", "c"])),
        );
        assert_eq!(
            level(&recovering, "authorization_transaction"),
            DiagnosticLevel::Fail
        );
        assert!(recovering[0].message.contains("Next attempt in 8 s"));
        assert_eq!(
            level(&recovering, "authorization_peers"),
            DiagnosticLevel::Warning
        );
        assert_eq!(
            level(&recovering, "authorization_containment"),
            DiagnosticLevel::Warning
        );
        // From the command line: a stale intent is explained, a damaged one blocks startup.
        let stale = evaluate(None, Ok(Consistency::Stale), Some(true), &stored, None);
        assert_eq!(
            level(&stale, "authorization_intent"),
            DiagnosticLevel::Warning
        );
        assert_eq!(
            level(&stale, "authorization_containment"),
            DiagnosticLevel::Warning
        );
        assert!(
            stale
                .iter()
                .all(|check| check.code != "authorization_transaction")
        );
        let damaged = evaluate(None, Err("invalid".into()), None, &stored, None);
        assert_eq!(
            level(&damaged, "authorization_intent"),
            DiagnosticLevel::Fail
        );
    }
}
