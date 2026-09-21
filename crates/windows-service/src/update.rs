//! An elevated, separately staged updater re-verifies the exact chosen manifest
//! and owns the installer until completion. The normal GUI remains unelevated.
use serde::{Deserialize, Serialize};
use sirinvpn_platform::{
    files,
    windows::{administrator_files as admin, open_protected_program, security},
};
use sirinvpn_release::{ArtifactKind, InstalledReleaseStore, ReleaseManifest};
use sirinvpn_release_fetch::{VerifiedReleaseBundle, *};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

mod native;
pub use native::{coordinator_available, launch};
const WORKER: &str = "update-worker.exe";
const PENDING: &str = "pending.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema_version: u16,
    stage: Uuid,
    install_directory: PathBuf,
    manifest_sha256: String,
    allow_rollback: bool,
}

pub fn artifact_target() -> &'static str {
    // Windows packages have a native MSVC release target even when checked with
    // a GNU cross compiler. Both use the same native Windows IPC and state ABI.
    if cfg!(target_arch = "aarch64") {
        "aarch64-pc-windows-msvc"
    } else {
        "x86_64-pc-windows-msvc"
    }
}

pub fn stage(source: &Path, expected_manifest: &str, allow_rollback: bool) -> io::Result<()> {
    crate::install::require_installed_program()?;
    if !source.is_absolute() || !valid_digest(expected_manifest) {
        return Err(invalid());
    }
    let executable = std::env::current_exe()?;
    let _program = open_protected_program(&executable)?;
    let install_directory = executable.parent().ok_or_else(invalid)?.to_path_buf();
    let root = native::machine_directory()?;
    admin::create_directory(&root)?;
    let _operation = operation_lock(&root)?;
    if let Some(pending) = read_pending(&root)? {
        if pending.install_directory != install_directory
            || pending.manifest_sha256 != expected_manifest
            || pending.allow_rollback != allow_rollback
        {
            return Err(invalid());
        }
        return start_worker(&root, &pending);
    }
    cleanup_finished_stages(&root)?;
    let pending = Pending {
        schema_version: 1,
        stage: Uuid::new_v4(),
        install_directory,
        manifest_sha256: expected_manifest.into(),
        allow_rollback,
    };
    let directory = stage_directory(&root, &pending);
    admin::create_directory(&directory)?;
    let result = (|| {
        let destination = directory.join("bundle");
        admin::create_directory(&destination)?;
        let bundle = copy_bundle(source, &destination, expected_manifest)?;
        validate_running_compatibility(&bundle.verified.manifest, allow_rollback)?;
        let store = InstalledReleaseStore::windows_machine(root.join("release"));
        store
            .apply_trust_policy(&bundle.trust_policy_bytes, &bundle.trust_signature_bytes)
            .map_err(release_error)?;
        plan(&store, &bundle, allow_rollback)?;
        copy_file(&executable, &directory.join(WORKER), 512 * 1024 * 1024)?;
        write_admin(
            &root.join(PENDING),
            &serde_json::to_vec(&pending).map_err(|_| invalid())?,
        )?;
        start_worker(&root, &pending)
    })();
    if result.is_err() && !root.join(PENDING).exists() {
        let _ = fs::remove_dir_all(directory);
    }
    result
}

pub fn apply() -> io::Result<()> {
    crate::install::require_administrator()?;
    let executable = std::env::current_exe()?;
    let _program = open_protected_program(&executable)?;
    let root = native::machine_directory()?;
    admin::validate_directory(&root)?;
    // The launching process holds this lock through publication and releases it
    // as it exits. A second worker never runs the same transaction concurrently.
    let _operation = operation_lock(&root)?;
    let pending = read_pending(&root)?.ok_or_else(invalid)?;
    let directory = stage_directory(&root, &pending);
    if fs::canonicalize(&executable)? != fs::canonicalize(directory.join(WORKER))? {
        return Err(invalid());
    }
    let bundle = VerifiedReleaseBundle::open(
        &directory.join("bundle"),
        ArtifactKind::WindowsInstaller,
        artifact_target(),
    )
    .map_err(release_error)?;
    if bundle.verified.manifest_sha256 != pending.manifest_sha256 {
        return Err(invalid());
    }
    validate_running_compatibility(&bundle.verified.manifest, pending.allow_rollback)?;
    let store = InstalledReleaseStore::windows_machine(root.join("release"));
    store
        .apply_trust_policy(&bundle.trust_policy_bytes, &bundle.trust_signature_bytes)
        .map_err(release_error)?;
    plan(&store, &bundle, pending.allow_rollback)?;
    let installer = bundle
        .artifact_directory
        .join(&bundle.verified.artifact.file_name);
    // Retain the protected source file throughout NSIS execution, including its
    // payload extraction. Neither path replacement nor a second writer is allowed.
    let _installer = open_protected_program(&installer)?;
    let install_argument = native::install_directory_argument(&pending.install_directory)?;
    let status = Command::new(&installer)
        .args(["/P", "/UPDATE", "/NS"])
        .raw_arg(install_argument)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(
            "Windows installation was interrupted; retry the same authenticated release",
        ));
    }
    crate::install::verify_installed_service(
        &pending.install_directory,
        &bundle.verified.manifest.release_version,
    )?;
    store
        .commit_trusted_installation(
            &bundle.manifest_bytes,
            &bundle.signature_bytes,
            &bundle.artifact_directory,
            ArtifactKind::WindowsInstaller,
            artifact_target(),
            pending.allow_rollback,
        )
        .map_err(release_error)?;
    fs::remove_file(root.join(PENDING))?;
    files::sync_directory(&root)?;
    drop(_installer);
    fs::remove_dir_all(directory.join("bundle"))?;
    // Windows keeps the running worker image open. The next explicit update
    // removes this one remaining binary before staging its replacement.
    Ok(())
}

fn plan(
    store: &InstalledReleaseStore,
    bundle: &VerifiedReleaseBundle,
    rollback: bool,
) -> io::Result<()> {
    store
        .plan_trusted_installation(
            &bundle.manifest_bytes,
            &bundle.signature_bytes,
            &bundle.artifact_directory,
            ArtifactKind::WindowsInstaller,
            artifact_target(),
            rollback,
        )
        .map_err(release_error)?;
    Ok(())
}

fn copy_bundle(
    source: &Path,
    destination: &Path,
    expected: &str,
) -> io::Result<VerifiedReleaseBundle> {
    for (name, maximum) in [
        (
            RELEASE_MANIFEST_FILE_NAME,
            sirinvpn_release::MAX_MANIFEST_BYTES,
        ),
        (
            RELEASE_SIGNATURE_FILE_NAME,
            sirinvpn_release::MAX_SIGNATURE_BYTES,
        ),
        (
            TRUST_POLICY_FILE_NAME,
            sirinvpn_release::MAX_TRUST_POLICY_BYTES,
        ),
        (
            TRUST_SIGNATURE_FILE_NAME,
            sirinvpn_release::MAX_TRUST_SIGNATURE_BYTES,
        ),
    ] {
        copy_file(&source.join(name), &destination.join(name), maximum)?;
    }
    let manifest = files::read_bounded(
        &destination.join(RELEASE_MANIFEST_FILE_NAME),
        sirinvpn_release::MAX_MANIFEST_BYTES as usize,
    )?;
    let signature = files::read_bounded(
        &destination.join(RELEASE_SIGNATURE_FILE_NAME),
        sirinvpn_release::MAX_SIGNATURE_BYTES as usize,
    )?;
    let policy = files::read_bounded(
        &destination.join(TRUST_POLICY_FILE_NAME),
        sirinvpn_release::MAX_TRUST_POLICY_BYTES as usize,
    )?;
    let trust_signature = files::read_bounded(
        &destination.join(TRUST_SIGNATURE_FILE_NAME),
        sirinvpn_release::MAX_TRUST_SIGNATURE_BYTES as usize,
    )?;
    let trust = sirinvpn_release::verify_trust_policy(
        &policy,
        &trust_signature,
        sirinvpn_release::BUNDLED_RELEASE_TRUST_ROOT_PEM,
    )
    .map_err(release_error)?;
    let verified =
        sirinvpn_release::verify_manifest_with_trust_policy(&manifest, &signature, &trust)
            .map_err(release_error)?;
    if verified.manifest_sha256 != expected {
        return Err(invalid());
    }
    let artifact = verified
        .manifest
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.kind == ArtifactKind::WindowsInstaller && artifact.target == artifact_target()
        })
        .ok_or_else(invalid)?;
    let artifacts = destination.join(ARTIFACT_DIRECTORY_NAME);
    admin::create_directory(&artifacts)?;
    copy_file(
        &source
            .join(ARTIFACT_DIRECTORY_NAME)
            .join(&artifact.file_name),
        &artifacts.join(&artifact.file_name),
        artifact.size_bytes,
    )?;
    VerifiedReleaseBundle::open(
        destination,
        ArtifactKind::WindowsInstaller,
        artifact_target(),
    )
    .map_err(release_error)
}

fn copy_file(source: &Path, destination: &Path, maximum: u64) -> io::Result<()> {
    let source = files::open_no_follow(source)?;
    let size = source.metadata()?.len();
    if size == 0 || size > maximum {
        return Err(invalid());
    }
    let mut file = admin::create_file(destination)?;
    let copied = io::copy(&mut source.take(maximum.saturating_add(1)), &mut file)?;
    if copied != size || copied > maximum {
        return Err(invalid());
    }
    file.sync_all()
}
fn write_admin(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut temporary = tempfile::Builder::new()
        .prefix(".update-")
        .make_in(path.parent().ok_or_else(invalid)?, admin::create_file)?;
    temporary.write_all(bytes)?;
    files::persist(temporary, path, false)?;
    Ok(())
}
fn read_pending(root: &Path) -> io::Result<Option<Pending>> {
    let path = root.join(PENDING);
    let file = match files::open_no_follow(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    admin::validate_file(&file)?;
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(invalid());
    }
    let pending: Pending = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if pending.schema_version != 1
        || pending.stage.is_nil()
        || !pending.install_directory.is_absolute()
        || !valid_digest(&pending.manifest_sha256)
    {
        return Err(invalid());
    }
    Ok(Some(pending))
}
fn stage_directory(root: &Path, pending: &Pending) -> PathBuf {
    root.join(format!("stage-{}", pending.stage))
}
fn start_worker(root: &Path, pending: &Pending) -> io::Result<()> {
    let executable = stage_directory(root, pending).join(WORKER);
    let _program = open_protected_program(&executable)?;
    Command::new(executable)
        .arg("--apply-update")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}
fn operation_lock(root: &Path) -> io::Result<File> {
    let file = admin::open_lock(&root.join("operation.lock"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(file),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn uninstall_with_cleanup(operation: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    let root = native::machine_directory()?;
    match fs::symlink_metadata(&root) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return operation(),
        Err(error) => return Err(error),
    }
    admin::validate_directory(&root)?;
    let lock = operation_lock(&root)?;
    operation()?;
    drop(lock);
    fs::remove_dir_all(&root)
}
fn cleanup_finished_stages(root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(root)?.take(128) {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(invalid)?;
        if let Some(id) = name.strip_prefix("stage-") {
            let uuid: Uuid = id.parse().map_err(|_| invalid())?;
            if uuid.to_string() != id {
                return Err(invalid());
            }
            admin::validate_directory(&entry.path())?;
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}
fn validate_running_compatibility(candidate: &ReleaseManifest, rollback: bool) -> io::Result<()> {
    let version = semver::Version::parse(&candidate.release_version).map_err(|_| invalid())?;
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| invalid())?;
    if version <= current && !rollback {
        return Err(invalid());
    }
    let contract: sirinvpn_release::CompatibilityContract =
        serde_json::from_str(include_str!("../../../release/state-compatibility.json"))
            .map_err(|_| invalid())?;
    for state in contract
        .states
        .into_iter()
        .filter(|state| relevant_state(&state.state))
    {
        let next = candidate
            .state_compatibility
            .iter()
            .find(|next| next.state == state.state)
            .ok_or_else(invalid)?;
        if next.reads.minimum > state.writes.minimum
            || next.reads.maximum < state.writes.maximum
            || state.reads.minimum > next.writes.minimum
            || state.reads.maximum < next.writes.maximum
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn relevant_state(name: &str) -> bool {
    name.starts_with("windows_")
        || name.starts_with("desktop_")
        || name.starts_with("device_")
        || name.starts_with("client_")
        || name.starts_with("owner_")
        || name.starts_with("signed_")
        || matches!(
            name,
            "linux_client_profiles"
                | "linux_identity_record"
                | "linux_key_rotation_journal"
                | "linux_network_policy"
                | "linux_release_receipt"
                | "linux_release_trust"
                | "linux_tunnel_request"
        )
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}
fn release_error(_error: impl std::fmt::Display) -> io::Error {
    invalid()
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "The Windows release or its retained update state could not be verified. Retry the same authenticated package or repair the installation.",
    )
}
