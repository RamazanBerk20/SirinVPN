use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use sirinvpn_release::{
    ArtifactKind, BUNDLED_RELEASE_TRUST_ROOT_PEM, DebianRecoveryAction, InstallationDecision,
    InstalledReleaseStore, MAX_KEY_BYTES, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES,
    MAX_TRUST_POLICY_BYTES, MAX_TRUST_SIGNATURE_BYTES, ReleaseArtifact, ReleaseChannel,
    SYSTEM_RELEASE_STATE_DIRECTORY, TrustPolicyAction, build_manifest, build_trust_policy,
    bundled_release_trust_root_id, encode_manifest, encode_trust_policy, generate_signing_keypair,
    parse_compatibility_contract, plan_transition, public_key_id, sign_manifest, sign_trust_policy,
    verify_manifest, verify_release_directory, verify_release_directory_with_trust_policy,
    verify_trust_policy,
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "sirinvpn-release",
    version,
    about = "Offline SirinVPN release signing, verification, and installed-state control"
)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen(KeygenArguments),
    Create(CreateArguments),
    Verify(VerifyArguments),
    VerifyTrusted(VerifyTrustedArguments),
    Plan(PlanArguments),
    Trust(TrustArguments),
    State(StateArguments),
}

#[derive(Args)]
struct TrustArguments {
    #[command(subcommand)]
    command: TrustCommand,
}

#[derive(Subcommand)]
enum TrustCommand {
    /// Print the immutable release trust root compiled into this binary.
    Root,
    /// Create a canonical root-signed release-key policy.
    Create(TrustCreateArguments),
    /// Verify a release-key policy against the bundled root.
    Verify(TrustDocumentArguments),
}

#[derive(Args)]
struct TrustCreateArguments {
    #[arg(long)]
    sequence: u64,
    #[arg(long = "release-key", required = true)]
    release_keys: Vec<PathBuf>,
    #[arg(long = "revoke-key-id")]
    revoked_key_ids: Vec<String>,
    #[arg(long)]
    root_private_key: PathBuf,
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    signature: PathBuf,
}

#[derive(Args)]
struct TrustDocumentArguments {
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    signature: PathBuf,
}

#[derive(Args)]
struct KeygenArguments {
    #[arg(long)]
    private_key: PathBuf,
    #[arg(long)]
    public_key: PathBuf,
}

#[derive(Args)]
struct CreateArguments {
    #[arg(long)]
    version: String,
    #[arg(long)]
    sequence: u64,
    #[arg(long, default_value = "stable")]
    channel: ReleaseChannel,
    #[arg(long)]
    security_update: bool,
    #[arg(
        long,
        value_name = "KIND,TARGET,PATH",
        help = "Repeat for each artifact"
    )]
    artifact: Vec<ArtifactInput>,
    #[arg(long)]
    compatibility: PathBuf,
    #[arg(long)]
    private_key: PathBuf,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    signature: PathBuf,
}

#[derive(Args)]
struct VerifyArguments {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    trusted_public_key: PathBuf,
    #[arg(long)]
    artifact_directory: PathBuf,
}

#[derive(Args)]
struct VerifyTrustedArguments {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    trust_policy: PathBuf,
    #[arg(long)]
    trust_signature: PathBuf,
    #[arg(long)]
    artifact_directory: PathBuf,
}

#[derive(Args)]
struct PlanArguments {
    #[arg(long)]
    current_manifest: PathBuf,
    #[arg(long)]
    current_signature: PathBuf,
    #[arg(long)]
    candidate_manifest: PathBuf,
    #[arg(long)]
    candidate_signature: PathBuf,
    #[arg(long)]
    trusted_public_key: PathBuf,
    #[arg(long)]
    candidate_artifact_directory: PathBuf,
    #[arg(long)]
    allow_rollback: bool,
}

#[derive(Args)]
struct StateArguments {
    #[command(subcommand)]
    command: StateCommand,
}

#[derive(Subcommand)]
enum StateCommand {
    /// Validate a candidate against installed state without changing the receipt.
    Plan(StateCandidateArguments),
    /// Bind a successfully installed candidate and advance durable state.
    CommitInstallation(StateCandidateArguments),
    /// Transactionally install an offline signed Debian package.
    InstallDebian(DebianInstallArguments),
    /// Resolve an interrupted Debian package transaction from authenticated local state.
    RecoverDebian,
    /// Apply a newer root-signed release-key policy.
    ApplyTrust(TrustDocumentArguments),
    /// Validate and summarize the installed release-key policy.
    InspectTrust,
    /// Validate and summarize the current installed-release receipt.
    Inspect,
}

#[derive(Args)]
struct StateCandidateArguments {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    trusted_public_key: Option<PathBuf>,
    #[arg(long)]
    artifact_directory: PathBuf,
    #[arg(long)]
    artifact_kind: ArtifactKind,
    #[arg(long)]
    artifact_target: String,
    #[arg(long)]
    allow_rollback: bool,
}

#[derive(Args)]
struct DebianInstallArguments {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    trusted_public_key: Option<PathBuf>,
    #[arg(long)]
    artifact_directory: PathBuf,
    #[arg(long)]
    artifact_target: String,
    #[arg(long)]
    allow_rollback: bool,
}

#[derive(Clone, Debug)]
struct ArtifactInput {
    kind: ArtifactKind,
    target: String,
    path: PathBuf,
}

impl FromStr for ArtifactInput {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut fields = value.splitn(3, ',');
        let kind = fields
            .next()
            .ok_or_else(|| "artifact kind is missing".to_owned())?
            .parse()?;
        let target = fields
            .next()
            .filter(|field| !field.is_empty())
            .ok_or_else(|| "artifact target is missing".to_owned())?
            .to_owned();
        let path = fields
            .next()
            .filter(|field| !field.is_empty())
            .ok_or_else(|| "artifact path is missing".to_owned())?;
        Ok(Self {
            kind,
            target,
            path: PathBuf::from(path),
        })
    }
}

#[derive(Serialize)]
struct KeygenResult {
    public_key: String,
    key_id_sha256: String,
}

#[derive(Serialize)]
struct CreatedRelease {
    release_version: String,
    release_sequence: u64,
    channel: ReleaseChannel,
    security_update: bool,
    artifacts: usize,
    manifest: String,
    signature: String,
    manifest_sha256: String,
    key_id_sha256: String,
}

#[derive(Serialize)]
struct BundledTrustRoot {
    root_key_id_sha256: String,
    public_key_pem: &'static str,
}

#[derive(Serialize)]
struct CreatedTrustPolicy {
    policy_sequence: u64,
    active_release_key_ids: Vec<String>,
    revoked_release_key_ids: Vec<String>,
    root_key_id_sha256: String,
    policy_sha256: String,
    policy: String,
    signature: String,
}

#[derive(Serialize)]
struct TrustedReleaseVerification {
    root_key_id_sha256: String,
    trust_policy_sequence: u64,
    release: sirinvpn_release::VerifiedRelease,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(arguments) => keygen(arguments, cli.json),
        Command::Create(arguments) => create(arguments, cli.json),
        Command::Verify(arguments) => verify(arguments, cli.json),
        Command::VerifyTrusted(arguments) => verify_trusted(arguments, cli.json),
        Command::Plan(arguments) => plan(arguments, cli.json),
        Command::Trust(arguments) => trust(arguments, cli.json),
        Command::State(arguments) => state(arguments, cli.json),
    }
}

fn trust(arguments: TrustArguments, json: bool) -> Result<()> {
    match arguments.command {
        TrustCommand::Root => {
            let root = BundledTrustRoot {
                root_key_id_sha256: bundled_release_trust_root_id()?,
                public_key_pem: BUNDLED_RELEASE_TRUST_ROOT_PEM,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&root)?);
            } else {
                println!(
                    "Bundled SirinVPN release trust root: {}",
                    root.root_key_id_sha256
                );
            }
            Ok(())
        }
        TrustCommand::Create(arguments) => create_trust_policy(arguments, json),
        TrustCommand::Verify(arguments) => verify_trust_document(arguments, json),
    }
}

fn create_trust_policy(arguments: TrustCreateArguments, json: bool) -> Result<()> {
    ensure_distinct(&arguments.policy, &arguments.signature)?;
    let release_keys = arguments
        .release_keys
        .iter()
        .map(|path| read_public_key(path).map(|key| key.to_string()))
        .collect::<Result<Vec<_>>>()?;
    let policy = build_trust_policy(arguments.sequence, release_keys, arguments.revoked_key_ids)?;
    let policy_bytes = encode_trust_policy(&policy)?;
    let private_key_bytes = Zeroizing::new(read_private_key(&arguments.root_private_key)?);
    let private_key = std::str::from_utf8(&private_key_bytes)
        .map_err(|_| anyhow!("the release trust root private key is not UTF-8 PEM"))?;
    let signature_bytes = sign_trust_policy(&policy_bytes, private_key)?;
    let verified = verify_trust_policy(
        &policy_bytes,
        &signature_bytes,
        BUNDLED_RELEASE_TRUST_ROOT_PEM,
    )?;
    write_pair_new(
        &arguments.policy,
        &policy_bytes,
        0o644,
        &arguments.signature,
        &signature_bytes,
        0o644,
    )?;
    let result = CreatedTrustPolicy {
        policy_sequence: verified.policy.sequence,
        active_release_key_ids: verified
            .policy
            .active_release_keys
            .iter()
            .map(|key| key.key_id_sha256.clone())
            .collect(),
        revoked_release_key_ids: verified.policy.revoked_release_key_ids,
        root_key_id_sha256: verified.root_key_id_sha256,
        policy_sha256: verified.policy_sha256,
        policy: arguments.policy.display().to_string(),
        signature: arguments.signature.display().to_string(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Created release trust policy sequence {} with {} active and {} revoked key(s).\nPolicy SHA-256: {}\nRoot key ID SHA-256: {}",
            result.policy_sequence,
            result.active_release_key_ids.len(),
            result.revoked_release_key_ids.len(),
            result.policy_sha256,
            result.root_key_id_sha256
        );
    }
    Ok(())
}

fn verify_trust_document(arguments: TrustDocumentArguments, json: bool) -> Result<()> {
    let policy = read_regular_bounded(&arguments.policy, MAX_TRUST_POLICY_BYTES, "trust policy")?;
    let signature = read_regular_bounded(
        &arguments.signature,
        MAX_TRUST_SIGNATURE_BYTES,
        "trust signature envelope",
    )?;
    let verified = verify_trust_policy(&policy, &signature, BUNDLED_RELEASE_TRUST_ROOT_PEM)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&verified)?);
    } else {
        println!(
            "Verified release trust policy sequence {} with {} active and {} revoked key(s), root {}.",
            verified.policy.sequence,
            verified.policy.active_release_keys.len(),
            verified.policy.revoked_release_key_ids.len(),
            verified.root_key_id_sha256
        );
    }
    Ok(())
}

fn keygen(arguments: KeygenArguments, json: bool) -> Result<()> {
    ensure_distinct(&arguments.private_key, &arguments.public_key)?;
    let (private_key, public_key) = generate_signing_keypair()?;
    write_pair_new(
        &arguments.private_key,
        private_key.as_bytes(),
        0o600,
        &arguments.public_key,
        public_key.as_bytes(),
        0o644,
    )?;
    let result = KeygenResult {
        public_key: arguments.public_key.display().to_string(),
        key_id_sha256: public_key_id(&public_key)?,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Created an offline release key. Public key: {}\nKey ID SHA-256: {}",
            result.public_key, result.key_id_sha256
        );
    }
    Ok(())
}

fn create(arguments: CreateArguments, json: bool) -> Result<()> {
    if arguments.artifact.is_empty() {
        bail!("at least one --artifact is required");
    }
    ensure_distinct(&arguments.manifest, &arguments.signature)?;
    let compatibility_bytes = read_regular_bounded(
        &arguments.compatibility,
        MAX_MANIFEST_BYTES,
        "compatibility contract",
    )?;
    let compatibility = parse_compatibility_contract(&compatibility_bytes)?;
    let artifacts = arguments
        .artifact
        .iter()
        .map(|input| ReleaseArtifact::from_path(input.kind, &input.target, &input.path))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = build_manifest(
        arguments.version,
        arguments.sequence,
        arguments.channel,
        arguments.security_update,
        artifacts,
        compatibility.states,
    )?;
    let manifest_bytes = encode_manifest(&manifest)?;
    let private_key_bytes = Zeroizing::new(read_private_key(&arguments.private_key)?);
    let private_key = std::str::from_utf8(&private_key_bytes)
        .map_err(|_| anyhow!("the release private key is not UTF-8 PEM"))?;
    let signature_bytes = sign_manifest(&manifest_bytes, private_key)?;
    write_pair_new(
        &arguments.manifest,
        &manifest_bytes,
        0o644,
        &arguments.signature,
        &signature_bytes,
        0o644,
    )?;

    let public_key = SigningPublicKey::from_private(private_key)?;
    let verified = verify_manifest(&manifest_bytes, &signature_bytes, &public_key.pem)?;
    let result = CreatedRelease {
        release_version: manifest.release_version,
        release_sequence: manifest.release_sequence,
        channel: manifest.channel,
        security_update: manifest.security_update,
        artifacts: manifest.artifacts.len(),
        manifest: arguments.manifest.display().to_string(),
        signature: arguments.signature.display().to_string(),
        manifest_sha256: verified.manifest_sha256,
        key_id_sha256: verified.key_id_sha256,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Created signed SirinVPN {} release {} (sequence {}, security update: {}) with {} artifact(s).\nManifest SHA-256: {}\nKey ID SHA-256: {}",
            result.channel,
            result.release_version,
            result.release_sequence,
            result.security_update,
            result.artifacts,
            result.manifest_sha256,
            result.key_id_sha256
        );
    }
    Ok(())
}

fn verify(arguments: VerifyArguments, json: bool) -> Result<()> {
    let manifest = read_regular_bounded(&arguments.manifest, MAX_MANIFEST_BYTES, "manifest")?;
    let signature = read_regular_bounded(
        &arguments.signature,
        MAX_SIGNATURE_BYTES,
        "signature envelope",
    )?;
    let public_key = read_public_key(&arguments.trusted_public_key)?;
    let verified = verify_release_directory(
        &manifest,
        &signature,
        &public_key,
        &arguments.artifact_directory,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&verified)?);
    } else {
        println!(
            "Verified SirinVPN {} release {} (sequence {}), {} artifact(s), key {}.",
            verified.manifest.channel,
            verified.manifest.release_version,
            verified.manifest.release_sequence,
            verified.verified_artifacts,
            verified.key_id_sha256
        );
    }
    Ok(())
}

fn verify_trusted(arguments: VerifyTrustedArguments, json: bool) -> Result<()> {
    let manifest = read_regular_bounded(&arguments.manifest, MAX_MANIFEST_BYTES, "manifest")?;
    let signature = read_regular_bounded(
        &arguments.signature,
        MAX_SIGNATURE_BYTES,
        "signature envelope",
    )?;
    let policy = read_regular_bounded(
        &arguments.trust_policy,
        MAX_TRUST_POLICY_BYTES,
        "trust policy",
    )?;
    let trust_signature = read_regular_bounded(
        &arguments.trust_signature,
        MAX_TRUST_SIGNATURE_BYTES,
        "trust signature envelope",
    )?;
    let trust = verify_trust_policy(&policy, &trust_signature, BUNDLED_RELEASE_TRUST_ROOT_PEM)?;
    let release = verify_release_directory_with_trust_policy(
        &manifest,
        &signature,
        &trust,
        &arguments.artifact_directory,
    )?;
    let result = TrustedReleaseVerification {
        root_key_id_sha256: trust.root_key_id_sha256,
        trust_policy_sequence: trust.policy.sequence,
        release,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Verified root-authorized SirinVPN {} release {} (sequence {}) with trust policy sequence {}, root {}.",
            result.release.manifest.channel,
            result.release.manifest.release_version,
            result.release.manifest.release_sequence,
            result.trust_policy_sequence,
            result.root_key_id_sha256
        );
    }
    Ok(())
}

fn plan(arguments: PlanArguments, json: bool) -> Result<()> {
    let public_key = read_public_key(&arguments.trusted_public_key)?;
    let current_manifest = read_regular_bounded(
        &arguments.current_manifest,
        MAX_MANIFEST_BYTES,
        "current manifest",
    )?;
    let current_signature = read_regular_bounded(
        &arguments.current_signature,
        MAX_SIGNATURE_BYTES,
        "current signature envelope",
    )?;
    let candidate_manifest = read_regular_bounded(
        &arguments.candidate_manifest,
        MAX_MANIFEST_BYTES,
        "candidate manifest",
    )?;
    let candidate_signature = read_regular_bounded(
        &arguments.candidate_signature,
        MAX_SIGNATURE_BYTES,
        "candidate signature envelope",
    )?;
    let current = verify_manifest(&current_manifest, &current_signature, &public_key)?;
    let candidate = verify_release_directory(
        &candidate_manifest,
        &candidate_signature,
        &public_key,
        &arguments.candidate_artifact_directory,
    )?;
    let plan = plan_transition(
        &current.manifest,
        &candidate.manifest,
        arguments.allow_rollback,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!(
            "Verified rollback-safe {:?}: {} (sequence {}) -> {} (sequence {}, security update: {}). {} state format transition(s).",
            plan.direction,
            plan.from_version,
            plan.from_sequence,
            plan.to_version,
            plan.to_sequence,
            plan.security_update,
            plan.state_transitions.len()
        );
    }
    Ok(())
}

fn state(arguments: StateArguments, json: bool) -> Result<()> {
    require_state_root()?;
    let store = InstalledReleaseStore::system();
    match arguments.command {
        StateCommand::Plan(arguments) => {
            let decision = state_candidate(&store, arguments, false)?;
            print_state_decision(&decision, json, "Validated")
        }
        StateCommand::CommitInstallation(arguments) => {
            let decision = state_candidate(&store, arguments, true)?;
            print_state_decision(&decision, json, "Committed")
        }
        StateCommand::InstallDebian(arguments) => {
            let decision = install_debian(&store, arguments)?;
            print_state_decision(&decision, json, "Installed")
        }
        StateCommand::RecoverDebian => {
            let recovery = store.recover_debian()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&recovery)?);
            } else {
                let message = match recovery.action {
                    DebianRecoveryAction::NothingPending => {
                        "No interrupted Debian update required recovery"
                    }
                    DebianRecoveryAction::RestoredPreviousRelease => {
                        "Restored the previous authenticated Debian package"
                    }
                    DebianRecoveryAction::FinalizedCandidateRelease => {
                        "Finalized the already committed Debian package"
                    }
                };
                println!(
                    "{message}. Active SirinVPN release {} (sequence {}).",
                    recovery.state.active_release_version, recovery.state.active_release_sequence
                );
            }
            Ok(())
        }
        StateCommand::ApplyTrust(arguments) => {
            let policy =
                read_regular_bounded(&arguments.policy, MAX_TRUST_POLICY_BYTES, "trust policy")?;
            let signature = read_regular_bounded(
                &arguments.signature,
                MAX_TRUST_SIGNATURE_BYTES,
                "trust signature envelope",
            )?;
            let decision = store.apply_trust_policy(&policy, &signature)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&decision)?);
            } else {
                let verb = match decision.action {
                    TrustPolicyAction::Initialize => "Initialized",
                    TrustPolicyAction::Update => "Updated",
                    TrustPolicyAction::AlreadyCurrent => "Retained",
                };
                println!(
                    "{verb} release trust policy sequence {} with {} active and {} revoked key(s), root {}.",
                    decision.state.policy_sequence,
                    decision.state.active_release_key_ids.len(),
                    decision.state.revoked_release_key_ids.len(),
                    decision.state.root_key_id_sha256
                );
            }
            Ok(())
        }
        StateCommand::InspectTrust => {
            let summary = store.inspect_trust()?.ok_or_else(|| {
                anyhow!(
                    "no installed release trust policy exists in {SYSTEM_RELEASE_STATE_DIRECTORY}"
                )
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "Installed release trust policy sequence {} with {} active and {} revoked key(s), root {}.",
                    summary.policy_sequence,
                    summary.active_release_key_ids.len(),
                    summary.revoked_release_key_ids.len(),
                    summary.root_key_id_sha256
                );
            }
            Ok(())
        }
        StateCommand::Inspect => {
            let summary = store.inspect()?.ok_or_else(|| {
                anyhow!("no installed release receipt exists in {SYSTEM_RELEASE_STATE_DIRECTORY}")
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "Installed SirinVPN {} release {} (sequence {}, {}), highest accepted {} (sequence {}), key {}.",
                    summary.channel,
                    summary.active_release_version,
                    summary.active_release_sequence,
                    summary.active_artifact.kind,
                    summary.highest_accepted_release_version,
                    summary.highest_accepted_release_sequence,
                    summary.key_id_sha256
                );
            }
            Ok(())
        }
    }
}

fn install_debian(
    store: &InstalledReleaseStore,
    arguments: DebianInstallArguments,
) -> Result<InstallationDecision> {
    let manifest = read_regular_bounded(&arguments.manifest, MAX_MANIFEST_BYTES, "manifest")?;
    let signature = read_regular_bounded(
        &arguments.signature,
        MAX_SIGNATURE_BYTES,
        "signature envelope",
    )?;
    match arguments.trusted_public_key {
        Some(path) => {
            let public_key = read_public_key(&path)?;
            store
                .install_debian(
                    &manifest,
                    &signature,
                    &public_key,
                    &arguments.artifact_directory,
                    &arguments.artifact_target,
                    arguments.allow_rollback,
                )
                .map_err(Into::into)
        }
        None => store
            .install_trusted_debian(
                &manifest,
                &signature,
                &arguments.artifact_directory,
                &arguments.artifact_target,
                arguments.allow_rollback,
            )
            .map_err(Into::into),
    }
}

fn state_candidate(
    store: &InstalledReleaseStore,
    arguments: StateCandidateArguments,
    commit: bool,
) -> Result<InstallationDecision> {
    let manifest = read_regular_bounded(&arguments.manifest, MAX_MANIFEST_BYTES, "manifest")?;
    let signature = read_regular_bounded(
        &arguments.signature,
        MAX_SIGNATURE_BYTES,
        "signature envelope",
    )?;
    match arguments.trusted_public_key {
        Some(path) => {
            let public_key = read_public_key(&path)?;
            let operation = if commit {
                InstalledReleaseStore::commit_installation
            } else {
                InstalledReleaseStore::plan_installation
            };
            operation(
                store,
                &manifest,
                &signature,
                &public_key,
                &arguments.artifact_directory,
                arguments.artifact_kind,
                &arguments.artifact_target,
                arguments.allow_rollback,
            )
            .map_err(Into::into)
        }
        None => {
            let operation = if commit {
                InstalledReleaseStore::commit_trusted_installation
            } else {
                InstalledReleaseStore::plan_trusted_installation
            };
            operation(
                store,
                &manifest,
                &signature,
                &arguments.artifact_directory,
                arguments.artifact_kind,
                &arguments.artifact_target,
                arguments.allow_rollback,
            )
            .map_err(Into::into)
        }
    }
}

fn print_state_decision(decision: &InstallationDecision, json: bool, verb: &str) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(decision)?);
    } else {
        println!(
            "{verb} {:?}: SirinVPN {} release {} (sequence {}, {}), highest accepted sequence {}, key {}.",
            decision.action,
            decision.state.channel,
            decision.state.active_release_version,
            decision.state.active_release_sequence,
            decision.state.active_artifact.kind,
            decision.state.highest_accepted_release_sequence,
            decision.state.key_id_sha256
        );
    }
    Ok(())
}

fn require_state_root() -> Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        Ok(())
    } else {
        bail!("installed release state must be managed with root authorization")
    }
}

struct SigningPublicKey {
    pem: String,
}

impl SigningPublicKey {
    fn from_private(private_key_pem: &str) -> Result<Self> {
        use ed25519_dalek::{SigningKey, pkcs8::DecodePrivateKey};
        let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
            .map_err(|_| anyhow!("the release private key is invalid"))?;
        use ed25519_dalek::pkcs8::{EncodePublicKey, spki::der::pem::LineEnding};
        let pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| anyhow!("the release public key could not be derived"))?;
        Ok(Self { pem })
    }
}

fn read_public_key(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = Zeroizing::new(read_regular_bounded(path, MAX_KEY_BYTES, "public key")?);
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| anyhow!("the trusted release key is not UTF-8 PEM"))?;
    Ok(Zeroizing::new(text))
}

fn read_private_key(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect private key {}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("the release private key must not be accessible to group or other users");
    }
    read_regular_bounded(path, MAX_KEY_BYTES, "private key")
}

fn read_regular_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("{label} must be a non-empty regular file no larger than {maximum} bytes");
    }
    let file =
        File::open(path).with_context(|| format!("could not open {label} {}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        bail!("{label} changed size while it was being read");
    }
    Ok(bytes)
}

fn ensure_distinct(first: &Path, second: &Path) -> Result<()> {
    if first == second {
        bail!("output paths must be distinct");
    }
    Ok(())
}

fn write_pair_new(
    first_path: &Path,
    first_bytes: &[u8],
    first_mode: u32,
    second_path: &Path,
    second_bytes: &[u8],
    second_mode: u32,
) -> Result<()> {
    write_new(first_path, first_bytes, first_mode)?;
    if let Err(error) = write_new(second_path, second_bytes, second_mode) {
        let cleanup = fs::remove_file(first_path);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(error.context(format!(
                "partial output {} could not be removed: {cleanup_error}",
                first_path.display()
            ))),
        };
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("could not inspect output directory {}", parent.display()))?;
    if !parent_metadata.file_type().is_dir() {
        bail!("output parent is not a directory: {}", parent.display());
    }
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to replace existing output: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".sirinvpn-release-")
        .tempfile_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[path = "main_tests/mod.rs"]
mod tests;
