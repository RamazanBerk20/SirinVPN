//! Dry run: the exact remote commands and file changes a maintenance
//! transaction would make, built from the same command builders the real run
//! uses, after the same read-only inspection. Nothing on the VPS changes.

use super::*;

#[derive(Clone, Debug, Serialize)]
pub struct InstallPlan {
    /// "install", "repair", "restore" or "uninstall".
    pub operation: &'static str,
    pub host: String,
    pub nonce: String,
    pub discovery: Option<ServerDiscovery>,
    pub network_preflight: Option<NetworkPreflight>,
    /// Paths (relative to /) the transaction snapshots, replaces and restores on rollback.
    pub managed_paths: Vec<String>,
    pub steps: Vec<PlanStep>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanStep {
    /// A command as the SSH user, or as root (through sudo unless the user is root).
    Run {
        privileged: bool,
        command: String,
        /// Bytes sent on stdin that are not shown (an encrypted-backup snapshot).
        stdin_bytes: Option<usize>,
    },
    Upload {
        path: String,
        mode: String,
        size_bytes: usize,
        sha256: String,
        /// Text files (scripts, public certificates) in full; binaries by digest only.
        content: Option<String>,
    },
    /// A request whose exact text depends on what the VPS returns earlier.
    Deferred { description: String },
}

/// Where a transaction goes: executed (optionally journaled) or only planned.
pub(super) enum Sink<'a> {
    Execute(Option<&'a TransactionJournal>),
    Plan(&'a mut Option<InstallPlan>),
}

impl<'a> Sink<'a> {
    pub(super) fn journal(&self) -> Option<&'a TransactionJournal> {
        match self {
            Self::Execute(journal) => *journal,
            Self::Plan(_) => None,
        }
    }
}

/// Unwinds a planning run once its plan is recorded; never reaches a caller.
pub(super) fn planned() -> InstallerError {
    InstallerError::InvalidInput("dry run planned".to_owned())
}

/// Runs `operation` in planning mode and returns the plan it recorded.
pub(super) fn collect<T>(
    operation: impl FnOnce(Sink<'_>) -> Result<T, InstallerError>,
) -> Result<InstallPlan, InstallerError> {
    let mut plan = None;
    let result = operation(Sink::Plan(&mut plan));
    match (plan, result) {
        (Some(plan), _) => Ok(plan),
        (None, Err(error)) => Err(error),
        (None, Ok(_)) => Err(phase_error(
            "dry run",
            anyhow!("the operation finished without planning"),
        )),
    }
}

pub(super) fn managed_paths(extra: &str) -> Vec<String> {
    format!(
        "{MANAGED_SERVER_PATHS} {} {} {} {extra}",
        updates::UPDATE_MANAGED_PATHS,
        dns_blocklist::DNS_BLOCKLIST_MANAGED_PATHS,
        alerts::ALERTS_MANAGED_PATHS
    )
    .split_whitespace()
    .map(str::to_owned)
    .collect()
}

pub(super) fn run_step(privileged: bool, command: String) -> PlanStep {
    PlanStep::Run {
        privileged,
        command,
        stdin_bytes: None,
    }
}

pub(super) fn upload_step(path: &str, mode: u32, bytes: &[u8], text: bool) -> PlanStep {
    PlanStep::Upload {
        path: path.to_owned(),
        mode: format!("{mode:04o}"),
        size_bytes: bytes.len(),
        sha256: hex::encode(Sha256::digest(bytes)),
        content: text.then(|| String::from_utf8_lossy(bytes).into_owned()),
    }
}

impl InstallPlan {
    /// Human-readable form: every step in order, scripts in full.
    pub fn to_text(&self) -> String {
        let mut text = format!(
            "Dry run: {} on {} (transaction {}). Nothing was changed.\n",
            self.operation, self.host, self.nonce
        );
        if let Some(discovery) = &self.discovery {
            text.push_str(&format!(
                "VPS: {} {} {}, uplink {}\n",
                discovery.os_id,
                discovery.os_version,
                discovery.architecture,
                discovery.default_interface
            ));
        }
        if let Some(network) = &self.network_preflight {
            for port in &network.required_ports {
                text.push_str(&format!("Opens: {port:?}\n"));
            }
        }
        text.push_str(&format!(
            "Managed paths: /{}\n",
            self.managed_paths.join(" /")
        ));
        for (index, step) in self.steps.iter().enumerate() {
            let number = index + 1;
            match step {
                PlanStep::Run {
                    privileged,
                    command,
                    stdin_bytes,
                } => {
                    let user = if *privileged { "root" } else { "SSH user" };
                    text.push_str(&format!("\n# {number}. run as {user}"));
                    if let Some(bytes) = stdin_bytes {
                        text.push_str(&format!(" (with {bytes} bytes of snapshot on stdin)"));
                    }
                    text.push_str(&format!(":\n{command}\n"));
                }
                PlanStep::Upload {
                    path,
                    mode,
                    size_bytes,
                    sha256,
                    content,
                } => {
                    text.push_str(&format!(
                        "\n# {number}. upload {path} (mode {mode}, {size_bytes} bytes, sha256 {sha256})\n"
                    ));
                    if let Some(content) = content {
                        text.push_str(content);
                        if !content.ends_with('\n') {
                            text.push('\n');
                        }
                    }
                }
                PlanStep::Deferred { description } => {
                    text.push_str(&format!("\n# {number}. {description}\n"));
                }
            }
        }
        text
    }
}

impl Provisioner {
    /// Dry run of `install`: connects, verifies the pin and inspects read-only,
    /// then returns every remote command and upload without running them.
    pub fn plan_install(request: InstallRequest) -> Result<InstallPlan, InstallerError> {
        collect(|sink| Self::install_journaled(request, sink))
    }

    pub fn plan_repair(request: RepairRequest) -> Result<InstallPlan, InstallerError> {
        collect(|sink| Self::repair_journaled(request, sink))
    }

    pub fn plan_restore_server_backup(
        request: ServerRestoreRequest,
    ) -> Result<InstallPlan, InstallerError> {
        collect(|sink| Self::restore_server_backup_journaled(request, sink))
    }

    pub fn plan_uninstall(request: UninstallRequest) -> Result<InstallPlan, InstallerError> {
        collect(|sink| Self::uninstall_journaled(request, sink))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_is_returned_instead_of_the_unwinding_error_and_renders_every_step() {
        let script = b"#!/bin/sh\nset -eu\n";
        let plan = collect(|sink| -> Result<(), InstallerError> {
            let Sink::Plan(slot) = sink else {
                unreachable!("planning never executes")
            };
            *slot = Some(InstallPlan {
                operation: "uninstall",
                host: "203.0.113.9".into(),
                nonce: "n".into(),
                discovery: None,
                network_preflight: None,
                managed_paths: managed_paths("var/lib/sirinvpn-server-release"),
                steps: vec![
                    upload_step("/tmp/sirinvpn-uninstall-n.sh", 0o700, script, true),
                    upload_step("/tmp/server", 0o700, b"\x7fELF", false),
                    PlanStep::Run {
                        privileged: true,
                        command: "/bin/sh /tmp/sirinvpn-uninstall-n.sh".into(),
                        stdin_bytes: Some(12),
                    },
                    PlanStep::Deferred {
                        description: "run as root: health verification".into(),
                    },
                ],
            });
            Err(planned())
        })
        .unwrap();
        let text = plan.to_text();
        assert!(text.contains("Nothing was changed"));
        assert!(text.contains("# 1. upload /tmp/sirinvpn-uninstall-n.sh (mode 0700, 18 bytes"));
        assert!(text.contains("#!/bin/sh\nset -eu\n"));
        assert!(!text.contains("ELF"), "binaries are shown by digest only");
        assert!(text.contains("# 3. run as root (with 12 bytes of snapshot on stdin):"));
        assert!(text.contains("/var/lib/sirinvpn-server-release"));
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["steps"][2]["kind"], "run");
        assert_eq!(json["steps"][3]["kind"], "deferred");
        assert!(
            plan.managed_paths
                .contains(&"usr/local/lib/sirinvpn/sirinvpn-updater".to_owned())
        );

        // A real error before planning is returned unchanged.
        let error = collect(|_| -> Result<(), InstallerError> {
            Err(InstallerError::AuthenticationFailed)
        })
        .unwrap_err();
        assert!(matches!(error, InstallerError::AuthenticationFailed));
    }
}
