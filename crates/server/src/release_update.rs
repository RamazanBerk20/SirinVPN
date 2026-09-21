//! Root-only VPS release operations, invoked over the owner's authenticated SSH
//! session. The private management daemon never receives an update privilege.
mod files;
mod host;
mod policy;

use clap::Subcommand;
pub use policy::{AutomaticUpdateOutcome, SecurityUpdatePolicy};
use serde::{Deserialize, Serialize};
use sirinvpn_release::{
    ArtifactKind, InstallationDecisionKind, InstalledReleaseStore, ReleaseChannel,
};
use sirinvpn_release_fetch::VerifiedReleaseBundle;
use std::path::{Path, PathBuf};

pub const RELEASE_DIRECTORY: &str = "/var/lib/sirinvpn-server-release";

#[derive(Subcommand)]
pub enum ReleaseCommand {
    Capabilities,
    Status,
    Check {
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "stable")]
        channel: ReleaseChannel,
    },
    Install {
        #[arg(long)]
        manifest_sha256: String,
    },
    Rollback {
        #[arg(long)]
        confirmed: bool,
    },
    Adopt {
        #[arg(long)]
        bundle: PathBuf,
    },
    Recover {
        #[arg(long)]
        before_start: bool,
    },
    Configure {
        #[arg(long)]
        enabled: bool,
        #[arg(long)]
        source: Option<String>,
    },
    Automatic,
    /// Used by the unprivileged download worker; never installs anything.
    Fetch {
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "stable")]
        channel: ReleaseChannel,
        #[arg(long)]
        destination: PathBuf,
    },
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseCapabilities {
    server_release_transaction: u16,
    server_handoff_guard: u16,
    server_maintenance_guard: u16,
    server_security_update_policy: u16,
    trust_root_sha256: String,
}

fn release_capabilities() -> Result<ReleaseCapabilities, sirinvpn_release::ReleaseError> {
    Ok(ReleaseCapabilities {
        server_release_transaction: 1,
        server_handoff_guard: 1,
        server_maintenance_guard: 1,
        server_security_update_policy: 1,
        trust_root_sha256: sirinvpn_release::bundled_release_trust_root_id()?,
    })
}

#[derive(Serialize)]
pub struct VpsReleaseStatus {
    pub release: sirinvpn_release::ServerReleaseStatus,
    pub security_updates: SecurityUpdatePolicy,
    pub automatic_outcome: Option<AutomaticUpdateOutcome>,
    pub installed_binary_matches: bool,
}

#[derive(Serialize)]
pub struct VpsReleaseCandidate {
    pub release_version: String,
    pub release_sequence: u64,
    pub security_update: bool,
    pub channel: ReleaseChannel,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
    pub artifact_target: String,
    pub artifact_size_bytes: u64,
    pub action: InstallationDecisionKind,
    pub can_install: bool,
    pub baseline_required: bool,
}

pub async fn run(
    command: ReleaseCommand,
    paths: crate::ServerPaths,
) -> anyhow::Result<serde_json::Value> {
    if matches!(command, ReleaseCommand::Capabilities) {
        return Ok(serde_json::to_value(release_capabilities()?)?);
    }
    if let ReleaseCommand::Fetch {
        source,
        channel,
        destination,
    } = command
    {
        let fetched =
            sirinvpn_release_fetch::fetch_release(sirinvpn_release_fetch::ReleaseFetchRequest {
                source,
                expected_channel: channel,
                artifact_kind: ArtifactKind::ServerElf,
                artifact_target: target()?.to_owned(),
                destination,
            })
            .await?;
        return Ok(serde_json::to_value(fetched)?);
    }
    host::require_root()?;
    anyhow::ensure!(
        paths.state_directory == Path::new("/etc/sirinvpn"),
        "VPS release operations require the installed system state directory"
    );
    // Blocking service/process work belongs outside the async executor.
    tokio::task::spawn_blocking(move || run_root(command, paths)).await?
}

fn run_root(
    command: ReleaseCommand,
    paths: crate::ServerPaths,
) -> anyhow::Result<serde_json::Value> {
    // Acquire the global lease before opening/creating release state. This also
    // prevents a status/check from recreating that directory during uninstall.
    // The lease survives every nested library guard and SSH maintenance marker.
    let host = host::SystemServerHost::acquire(paths)?;
    let _operation_lock = files::operation_lock()?;
    match command {
        ReleaseCommand::Status => {
            let release = store().inspect_server_release()?;
            let installed_binary_matches = release.installed.as_ref().is_some_and(|receipt| {
                host::binary_digest(Path::new(host::SERVER_BINARY))
                    .ok()
                    .as_ref()
                    == Some(&receipt.active_artifact.sha256)
            });
            Ok(serde_json::to_value(VpsReleaseStatus {
                release,
                security_updates: policy::load()?,
                automatic_outcome: policy::latest()?,
                installed_binary_matches,
            })?)
        }
        ReleaseCommand::Check { source, channel } => {
            let bundle = files::fetch_unprivileged(&source, channel)?;
            let verified =
                VerifiedReleaseBundle::open(bundle.path(), ArtifactKind::ServerElf, target()?)?;
            let candidate = inspect_candidate(&host, &verified)?;
            files::publish_pending(bundle)?;
            Ok(serde_json::to_value(candidate)?)
        }
        ReleaseCommand::Install { manifest_sha256 } => {
            let verified = VerifiedReleaseBundle::open(
                &Path::new(RELEASE_DIRECTORY).join("pending"),
                ArtifactKind::ServerElf,
                target()?,
            )?;
            anyhow::ensure!(
                manifest_sha256 == verified.verified.manifest_sha256,
                "the checked release changed; check the source again"
            );
            let candidate = inspect_candidate(&host, &verified)?;
            anyhow::ensure!(
                candidate.can_install,
                "install this signed build through SSH repair to establish an authenticated VPS baseline first"
            );
            let result = if candidate.action == InstallationDecisionKind::Initialize {
                store().adopt_trusted_server(&verified.server_bundle(), &host)?
            } else {
                store().install_trusted_server(&verified.server_bundle(), &host)?
            };
            Ok(serde_json::to_value(result)?)
        }
        ReleaseCommand::Rollback { confirmed } => {
            anyhow::ensure!(
                confirmed,
                "confirm rollback to the previous signed VPS release"
            );
            Ok(serde_json::to_value(
                store().rollback_trusted_server(&host)?,
            )?)
        }
        ReleaseCommand::Adopt { bundle } => {
            let verified =
                VerifiedReleaseBundle::open(&bundle, ArtifactKind::ServerElf, target()?)?;
            let owned = files::import_bundle(&verified)?;
            let verified =
                VerifiedReleaseBundle::open(owned.path(), ArtifactKind::ServerElf, target()?)?;
            apply_trust(&verified)?;
            Ok(serde_json::to_value(
                store().adopt_trusted_server(&verified.server_bundle(), &host)?,
            )?)
        }
        ReleaseCommand::Recover { before_start } => Ok(serde_json::to_value(
            store().recover_server(&host, !before_start)?,
        )?),
        ReleaseCommand::Configure { enabled, source } => {
            Ok(serde_json::to_value(policy::configure(enabled, source)?)?)
        }
        ReleaseCommand::Automatic => Ok(serde_json::to_value(policy::automatic(&host)?)?),
        ReleaseCommand::Fetch { .. } | ReleaseCommand::Capabilities => {
            unreachable!("unprivileged commands are handled separately")
        }
    }
}

fn store() -> InstalledReleaseStore {
    InstalledReleaseStore::new(RELEASE_DIRECTORY)
}

fn target() -> anyhow::Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64-unknown-linux-gnu"),
        "aarch64" => Ok("aarch64-unknown-linux-gnu"),
        _ => anyhow::bail!("this VPS architecture has no supported signed release target"),
    }
}

fn apply_trust(bundle: &VerifiedReleaseBundle) -> anyhow::Result<()> {
    store().apply_trust_policy(&bundle.trust_policy_bytes, &bundle.trust_signature_bytes)?;
    Ok(())
}

fn inspect_candidate(
    host: &host::SystemServerHost,
    bundle: &VerifiedReleaseBundle,
) -> anyhow::Result<VpsReleaseCandidate> {
    apply_trust(bundle)?;
    host::validate_live_compatibility(&host.paths, &bundle.verified.manifest)?;
    let plan = store().plan_trusted_installation(
        &bundle.manifest_bytes,
        &bundle.signature_bytes,
        &bundle.artifact_directory,
        ArtifactKind::ServerElf,
        target()?,
        false,
    )?;
    let baseline_required = plan.action == InstallationDecisionKind::Initialize;
    let exact_installed =
        host::binary_digest(Path::new(host::SERVER_BINARY))? == bundle.verified.artifact.sha256;
    let can_install = match plan.action {
        InstallationDecisionKind::Initialize => exact_installed,
        InstallationDecisionKind::AlreadyBound | InstallationDecisionKind::Upgrade => true,
        _ => false,
    };
    Ok(VpsReleaseCandidate {
        release_version: bundle.verified.manifest.release_version.clone(),
        release_sequence: bundle.verified.manifest.release_sequence,
        security_update: bundle.verified.manifest.security_update,
        channel: bundle.verified.manifest.channel,
        manifest_sha256: bundle.verified.manifest_sha256.clone(),
        artifact_sha256: bundle.verified.artifact.sha256.clone(),
        artifact_target: bundle.verified.artifact.target.clone(),
        artifact_size_bytes: bundle.verified.artifact.size_bytes,
        action: plan.action,
        can_install,
        baseline_required,
    })
}
