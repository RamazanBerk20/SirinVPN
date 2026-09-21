mod appimage;
use anyhow::{Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::OsString,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
};
use tauri::State;
use tempfile::{Builder as TempBuilder, TempDir};

const RELEASE_FETCH_BINARY: &str = "/usr/lib/sirinvpn/sirinvpn-release-fetch";
const RELEASE_COORDINATOR_BINARY: &str = "/usr/lib/sirinvpn/sirinvpn-release";
const DEBIAN_DESKTOP_BINARY: &str = "/usr/bin/sirinvpn-desktop";
const PKEXEC_BINARY: &str = "/usr/bin/pkexec";
const MAX_SOURCE_BYTES: usize = 2 * 1024;
const MAX_FETCH_OUTPUT_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const TRUST_POLICY_FILE_NAME: &str = "sirinvpn-release-trust.json";
const TRUST_SIGNATURE_FILE_NAME: &str = "sirinvpn-release-trust.sig.json";
const RELEASE_MANIFEST_FILE_NAME: &str = "sirinvpn-release.json";
const RELEASE_SIGNATURE_FILE_NAME: &str = "sirinvpn-release.sig.json";

#[tauri::command]
pub(crate) fn get_release_update_status(
    app: tauri::AppHandle,
    runtime: State<'_, ReleaseUpdateRuntime>,
) -> Result<crate::release_update_status::ReleaseUpdateStatus, String> {
    let state = runtime.lock()?;
    if state.busy {
        return Err("Wait for the active release operation.".into());
    }
    match appimage::Context::capture(&app)? {
        Some(context) => context.status(),
        None => Ok(crate::release_update_status::ReleaseUpdateStatus {
            installer_kind: "debian",
            rollback_version: None,
            baseline_required: false,
        }),
    }
}

#[tauri::command]
pub(crate) async fn rollback_release_update(
    app: tauri::AppHandle,
    runtime: State<'_, ReleaseUpdateRuntime>,
    input: crate::release_update_status::RollbackReleaseInput,
) -> Result<(), String> {
    if !input.confirmed {
        return Err("Confirm restoration of the displayed AppImage version first.".into());
    }
    {
        let mut state = runtime.lock()?;
        if state.busy {
            return Err("Another release operation is running.".into());
        }
        state.busy = true;
    }
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        appimage::Context::capture(&app)?
            .ok_or("AppImage rollback requires a user-owned AppImage.")?
            .rollback(&input.expected_version)
    })
    .await
    .map_err(|_| "AppImage rollback was interrupted.".to_owned())
    .and_then(|result| result);
    runtime.complete_install(outcome.is_ok())?;
    outcome
}

#[derive(Default)]
pub(crate) struct ReleaseUpdateRuntime {
    inner: Mutex<ReleaseUpdateState>,
}

#[derive(Default)]
struct ReleaseUpdateState {
    busy: bool,
    pending: Option<PendingReleaseUpdate>,
}

struct PendingReleaseUpdate {
    _temporary_directory: TempDir,
    fetched: FetchOutput,
    appimage: Option<appimage::Context>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RequestedChannel {
    Stable,
    Preview,
}

impl RequestedChannel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckReleaseUpdateInput {
    source: String,
    channel: RequestedChannel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallReleaseUpdateInput {
    confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ReleaseUpdateCandidate {
    current_version: String,
    release_version: String,
    release_sequence: String,
    channel: String,
    security_update: bool,
    trust_policy_sequence: String,
    root_key_id_sha256: String,
    release_key_id_sha256: String,
    artifact_file_name: String,
    artifact_target: String,
    artifact_size_bytes: u64,
    artifact_sha256: String,
    newer_than_running: bool,
    debian_install_available: bool,
    appimage_install_available: bool,
    baseline_bind_available: bool,
    baseline_bound: bool,
    installer_kind: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchOutput {
    release_version: String,
    release_sequence: u64,
    channel: String,
    security_update: bool,
    trust_policy_sequence: u64,
    root_key_id_sha256: String,
    release_key_id_sha256: String,
    artifact: FetchArtifact,
    bundle_directory: PathBuf,
    artifact_directory: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchArtifact {
    kind: String,
    target: String,
    file_name: String,
    size_bytes: u64,
    sha256: String,
}

struct InstallSnapshot {
    bundle_directory: PathBuf,
    artifact_directory: PathBuf,
    artifact_target: String,
    candidate: ReleaseUpdateCandidate,
    appimage: Option<appimage::Context>,
}

#[tauri::command]
pub(crate) async fn check_release_update(
    app: tauri::AppHandle,
    runtime: State<'_, ReleaseUpdateRuntime>,
    input: CheckReleaseUpdateInput,
) -> Result<ReleaseUpdateCandidate, String> {
    validate_source_input(&input.source)?;
    let fetcher = super::resolve_binary(
        "SIRINVPN_RELEASE_FETCH_PATH",
        RELEASE_FETCH_BINARY,
        "sirinvpn-release-fetch",
    )
    .map_err(|_| "The packaged release verifier is unavailable.".to_owned())?;
    let artifact_target = current_artifact_target()?.to_owned();
    let channel = input.channel.as_str().to_owned();
    let appimage = appimage::Context::capture(&app)?;
    let discarded = runtime.begin_check()?;
    drop(discarded);

    let outcome = match tauri::async_runtime::spawn_blocking(move || {
        fetch_candidate(fetcher, input.source, channel, artifact_target, appimage)
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            runtime.complete_check(None)?;
            return Err("The release check was interrupted.".to_owned());
        }
    };

    match outcome {
        Ok(pending) => match pending_summary(&pending) {
            Ok(candidate) => {
                runtime.complete_check(Some(pending))?;
                Ok(candidate)
            }
            Err(error) => {
                runtime.complete_check(None)?;
                Err(error)
            }
        },
        Err(error) => {
            runtime.complete_check(None)?;
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn install_release_update(
    runtime: State<'_, ReleaseUpdateRuntime>,
    input: InstallReleaseUpdateInput,
) -> Result<ReleaseUpdateCandidate, String> {
    if !input.confirmed {
        return Err("Confirm this exact authenticated package first.".to_owned());
    }
    let portable = runtime
        .lock()?
        .pending
        .as_ref()
        .is_some_and(|pending| pending.appimage.is_some());
    if !portable {
        let status = super::invoke_helper("status", None)
            .map_err(|_| "The local VPN state could not be verified.".to_owned())?;
        if status.state != sirinvpn_protocol::ConnectionState::Disconnected
            || status.kill_switch_enabled
            || status.auto_reconnect_enabled
        {
            return Err(
            "Disconnect SirinVPN and disable persistent protection before installing an update."
                .to_owned(),
        );
        }
    }

    let snapshot = runtime.begin_install()?;
    let operation =
        match tauri::async_runtime::spawn_blocking(move || install_candidate(&snapshot)).await {
            Ok(operation) => operation,
            Err(_) => {
                runtime.complete_install(false)?;
                return Err("The package update worker was interrupted.".to_owned());
            }
        };
    match operation {
        Ok(candidate) => {
            runtime.complete_install(true)?;
            Ok(candidate)
        }
        Err(error) => {
            runtime.complete_install(false)?;
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) fn discard_release_update(
    runtime: State<'_, ReleaseUpdateRuntime>,
) -> Result<(), String> {
    let discarded = runtime.discard()?;
    drop(discarded);
    Ok(())
}

impl ReleaseUpdateRuntime {
    fn begin_check(&self) -> Result<Option<PendingReleaseUpdate>, String> {
        let mut state = self.lock()?;
        if state.busy {
            return Err("Another release operation is already running.".to_owned());
        }
        state.busy = true;
        Ok(state.pending.take())
    }

    fn complete_check(&self, pending: Option<PendingReleaseUpdate>) -> Result<(), String> {
        let mut state = self.lock()?;
        state.pending = pending;
        state.busy = false;
        Ok(())
    }

    fn begin_install(&self) -> Result<InstallSnapshot, String> {
        let mut state = self.lock()?;
        if state.busy {
            return Err("Another release operation is already running.".to_owned());
        }
        let pending = state
            .pending
            .as_ref()
            .ok_or_else(|| "Check and authenticate a release before installing it.".to_owned())?;
        let fetched = &pending.fetched;
        let candidate = pending_summary(pending)?;
        if !candidate.newer_than_running && !candidate.baseline_bind_available {
            return Err(
                "The authenticated candidate is not newer than this running build.".to_owned(),
            );
        }
        if !candidate.debian_install_available && !candidate.appimage_install_available {
            return Err(
                "In-app installation is available only from the root-owned Debian package build."
                    .to_owned(),
            );
        }
        let snapshot = InstallSnapshot {
            bundle_directory: fetched.bundle_directory.clone(),
            artifact_directory: fetched.artifact_directory.clone(),
            artifact_target: fetched.artifact.target.clone(),
            candidate,
            appimage: pending.appimage.clone(),
        };
        state.busy = true;
        Ok(snapshot)
    }

    fn complete_install(&self, success: bool) -> Result<(), String> {
        let mut state = self.lock()?;
        if success {
            state.pending = None;
        }
        state.busy = false;
        Ok(())
    }

    fn discard(&self) -> Result<Option<PendingReleaseUpdate>, String> {
        let mut state = self.lock()?;
        if state.busy {
            return Err("The active release operation cannot be discarded.".to_owned());
        }
        Ok(state.pending.take())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ReleaseUpdateState>, String> {
        self.inner
            .lock()
            .map_err(|_| "The in-memory release state is unavailable.".to_owned())
    }
}

fn validate_source_input(source: &str) -> Result<(), String> {
    if source.is_empty()
        || source.len() > MAX_SOURCE_BYTES
        || source.trim() != source
        || source.chars().any(char::is_control)
        || !source.ends_with('/')
    {
        return Err("Enter a valid HTTPS release directory ending in '/'.".to_owned());
    }
    Ok(())
}

fn current_artifact_target() -> Result<&'static str, String> {
    match env::consts::ARCH {
        "x86_64" => Ok("x86_64-unknown-linux-gnu"),
        "aarch64" => Ok("aarch64-unknown-linux-gnu"),
        _ => Err("This Linux architecture has no signed update target.".to_owned()),
    }
}

fn fetch_candidate(
    fetcher: PathBuf,
    source: String,
    channel: String,
    artifact_target: String,
    appimage: Option<appimage::Context>,
) -> Result<PendingReleaseUpdate, String> {
    let temporary_directory = TempBuilder::new()
        .prefix("sirinvpn-desktop-release.")
        .tempdir()
        .map_err(|_| "A private release staging directory could not be created.".to_owned())?;
    fs::set_permissions(
        temporary_directory.path(),
        fs::Permissions::from_mode(0o700),
    )
    .map_err(|_| "The release staging directory could not be made private.".to_owned())?;
    let real_staging = fs::canonicalize(temporary_directory.path())
        .map_err(|_| "The release staging directory could not be verified.".to_owned())?;
    let destination = real_staging.join("candidate");
    let mut command = Command::new(fetcher);
    command
        .arg("--json")
        .arg("--source")
        .arg(source)
        .arg("--channel")
        .arg(&channel)
        .arg("--artifact-kind")
        .arg(if appimage.is_some() {
            "linux_appimage"
        } else {
            "linux_deb"
        })
        .arg("--artifact-target")
        .arg(&artifact_target)
        .arg("--output")
        .arg(&destination)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = successful_bounded_output(
        command,
        "The release source did not provide an authenticated compatible Debian candidate.",
    )?;
    let fetched = parse_fetch_output_kind(
        &output,
        &destination,
        &channel,
        &artifact_target,
        if appimage.is_some() {
            "linux_appimage"
        } else {
            "linux_deb"
        },
    )?;
    validate_fetched_layout(&fetched)?;
    Ok(PendingReleaseUpdate {
        _temporary_directory: temporary_directory,
        fetched,
        appimage,
    })
}

fn successful_bounded_output(mut command: Command, failure: &str) -> Result<Vec<u8>, String> {
    let mut child = command.spawn().map_err(|_| failure.to_owned())?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(failure.to_owned());
    };
    let mut output = Vec::new();
    if stdout
        .take(MAX_FETCH_OUTPUT_BYTES + 1)
        .read_to_end(&mut output)
        .is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(failure.to_owned());
    }
    if output.len() as u64 > MAX_FETCH_OUTPUT_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(failure.to_owned());
    }
    let status = child.wait().map_err(|_| failure.to_owned())?;
    if !status.success() {
        return Err(failure.to_owned());
    }
    Ok(output)
}

#[cfg(test)]
fn parse_fetch_output(
    output: &[u8],
    destination: &Path,
    expected_channel: &str,
    expected_target: &str,
) -> Result<FetchOutput, String> {
    parse_fetch_output_kind(
        output,
        destination,
        expected_channel,
        expected_target,
        "linux_deb",
    )
}

fn parse_fetch_output_kind(
    output: &[u8],
    destination: &Path,
    expected_channel: &str,
    expected_target: &str,
    expected_kind: &str,
) -> Result<FetchOutput, String> {
    let fetched: FetchOutput = serde_json::from_slice(output)
        .map_err(|_| "The packaged release verifier returned invalid data.".to_owned())?;
    if fetched.bundle_directory != destination
        || fetched.artifact_directory != destination.join("artifact")
        || fetched.channel != expected_channel
        || fetched.artifact.kind != expected_kind
        || fetched.artifact.target != expected_target
        || fetched.release_sequence == 0
        || fetched.trust_policy_sequence == 0
        || fetched.artifact.size_bytes == 0
        || fetched.artifact.size_bytes > MAX_ARTIFACT_BYTES
        || !valid_sha256(&fetched.root_key_id_sha256)
        || !valid_sha256(&fetched.release_key_id_sha256)
        || !valid_sha256(&fetched.artifact.sha256)
        || !valid_file_name(&fetched.artifact.file_name)
        || Version::parse(&fetched.release_version).is_err()
    {
        return Err("The packaged release verifier returned inconsistent data.".to_owned());
    }
    Ok(fetched)
}

fn validate_fetched_layout(fetched: &FetchOutput) -> Result<(), String> {
    let uid = nix::unistd::Uid::effective().as_raw();
    require_private_directory(&fetched.bundle_directory, uid)?;
    require_private_directory(&fetched.artifact_directory, uid)?;
    for file_name in [
        TRUST_POLICY_FILE_NAME,
        TRUST_SIGNATURE_FILE_NAME,
        RELEASE_MANIFEST_FILE_NAME,
        RELEASE_SIGNATURE_FILE_NAME,
    ] {
        require_private_file(&fetched.bundle_directory.join(file_name), uid)?;
    }
    require_private_file(
        &fetched.artifact_directory.join(&fetched.artifact.file_name),
        uid,
    )
}

fn require_private_directory(path: &Path, uid: u32) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "The verified release directory is unavailable.".to_owned())?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("The verified release directory is not private.".to_owned());
    }
    Ok(())
}

fn require_private_file(path: &Path, uid: u32) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "A verified release file is unavailable.".to_owned())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("A verified release file has unsafe local permissions.".to_owned());
    }
    Ok(())
}

fn candidate_summary(fetched: &FetchOutput) -> Result<ReleaseUpdateCandidate, String> {
    let current = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|_| "The running application version is invalid.".to_owned())?;
    let candidate = Version::parse(&fetched.release_version)
        .map_err(|_| "The authenticated release version is invalid.".to_owned())?;
    Ok(ReleaseUpdateCandidate {
        current_version: current.to_string(),
        release_version: candidate.to_string(),
        release_sequence: fetched.release_sequence.to_string(),
        channel: fetched.channel.clone(),
        security_update: fetched.security_update,
        trust_policy_sequence: fetched.trust_policy_sequence.to_string(),
        root_key_id_sha256: fetched.root_key_id_sha256.clone(),
        release_key_id_sha256: fetched.release_key_id_sha256.clone(),
        artifact_file_name: fetched.artifact.file_name.clone(),
        artifact_target: fetched.artifact.target.clone(),
        artifact_size_bytes: fetched.artifact.size_bytes,
        artifact_sha256: fetched.artifact.sha256.clone(),
        newer_than_running: candidate > current,
        debian_install_available: installed_debian_release_coordinator().is_ok(),
        appimage_install_available: false,
        baseline_bind_available: false,
        baseline_bound: false,
        installer_kind: "debian",
    })
}

fn pending_summary(pending: &PendingReleaseUpdate) -> Result<ReleaseUpdateCandidate, String> {
    let mut candidate = candidate_summary(&pending.fetched)?;
    if let Some(context) = &pending.appimage {
        context.summarize(&mut candidate)?;
    }
    Ok(candidate)
}

fn installed_debian_release_coordinator() -> Result<PathBuf> {
    let current = env::current_exe()?.canonicalize()?;
    if current != Path::new(DEBIAN_DESKTOP_BINARY) || env::var_os("APPIMAGE").is_some() {
        bail!("the running application is not the installed Debian package");
    }
    let coordinator = PathBuf::from(RELEASE_COORDINATOR_BINARY);
    let metadata = fs::symlink_metadata(&coordinator)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o755
    {
        bail!("the installed release coordinator is not a safe root executable");
    }
    Ok(coordinator)
}

fn install_candidate(snapshot: &InstallSnapshot) -> Result<ReleaseUpdateCandidate, String> {
    if let Some(context) = &snapshot.appimage {
        return context.install(snapshot);
    }
    let coordinator = installed_debian_release_coordinator().map_err(|_| {
        "The root-owned Debian release coordinator is unavailable or unsafe.".to_owned()
    })?;
    let policy = snapshot.bundle_directory.join(TRUST_POLICY_FILE_NAME);
    let trust_signature = snapshot.bundle_directory.join(TRUST_SIGNATURE_FILE_NAME);
    run_privileged_release(
        &coordinator,
        [
            OsString::from("--json"),
            OsString::from("state"),
            OsString::from("apply-trust"),
            OsString::from("--policy"),
            policy.into_os_string(),
            OsString::from("--signature"),
            trust_signature.into_os_string(),
        ],
        "The root-signed trust policy could not be confirmed. The installed package was not changed.",
    )?;

    let manifest = snapshot.bundle_directory.join(RELEASE_MANIFEST_FILE_NAME);
    let signature = snapshot.bundle_directory.join(RELEASE_SIGNATURE_FILE_NAME);
    run_privileged_release(
        &coordinator,
        [
            OsString::from("--json"),
            OsString::from("state"),
            OsString::from("install-debian"),
            OsString::from("--manifest"),
            manifest.into_os_string(),
            OsString::from("--signature"),
            signature.into_os_string(),
            OsString::from("--artifact-directory"),
            snapshot.artifact_directory.clone().into_os_string(),
            OsString::from("--artifact-target"),
            OsString::from(&snapshot.artifact_target),
        ],
        "The authenticated package update did not complete. The coordinator attempted rollback and retained recovery state if it could not prove completion; a root-authenticated trust-policy update may remain active.",
    )?;
    Ok(snapshot.candidate.clone())
}

fn run_privileged_release<const N: usize>(
    coordinator: &Path,
    arguments: [OsString; N],
    failure: &str,
) -> Result<(), String> {
    let mut command = if nix::unistd::Uid::effective().is_root() {
        Command::new(coordinator)
    } else {
        let mut command = Command::new(PKEXEC_BINARY);
        command.arg(coordinator);
        command
    };
    let status = command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| failure.to_owned())?;
    if !status.success() {
        return Err(failure.to_owned());
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_file_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
        && Path::new(value).components().count() == 1
        && matches!(
            Path::new(value).components().next(),
            Some(Component::Normal(_))
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn test_source(path: &str) -> String {
        format!("{}://updates.invalid/{path}", "https")
    }

    fn fetched_fixture() -> (TempDir, PathBuf, Vec<u8>) {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("candidate");
        let artifact_directory = destination.join("artifact");
        fs::create_dir(&destination).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&artifact_directory).unwrap();
        fs::set_permissions(&artifact_directory, fs::Permissions::from_mode(0o700)).unwrap();
        for name in [
            TRUST_POLICY_FILE_NAME,
            TRUST_SIGNATURE_FILE_NAME,
            RELEASE_MANIFEST_FILE_NAME,
            RELEASE_SIGNATURE_FILE_NAME,
        ] {
            private_file(&destination.join(name), b"fixture");
        }
        private_file(
            &artifact_directory.join("SirinVPN_0.2.0_amd64.deb"),
            b"package",
        );
        let output = serde_json::to_vec(&json!({
            "release_version": "0.2.0",
            "release_sequence": 2,
            "channel": "stable",
            "security_update": true,
            "trust_policy_sequence": 3,
            "root_key_id_sha256": "a".repeat(64),
            "release_key_id_sha256": "b".repeat(64),
            "artifact": {
                "kind": "linux_deb",
                "target": "x86_64-unknown-linux-gnu",
                "file_name": "SirinVPN_0.2.0_amd64.deb",
                "size_bytes": 7,
                "sha256": "c".repeat(64),
            },
            "bundle_directory": destination,
            "artifact_directory": artifact_directory,
        }))
        .unwrap();
        (parent, destination, output)
    }

    #[test]
    fn verifier_output_is_bound_to_the_requested_private_bundle() {
        let (_parent, destination, output) = fetched_fixture();
        let fetched =
            parse_fetch_output(&output, &destination, "stable", "x86_64-unknown-linux-gnu")
                .unwrap();
        validate_fetched_layout(&fetched).unwrap();
        let summary = candidate_summary(&fetched).unwrap();
        assert_eq!(summary.release_version, "0.2.0");
        assert_eq!(summary.release_sequence, "2");
        assert_eq!(summary.trust_policy_sequence, "3");
        assert_eq!(summary.artifact_target, "x86_64-unknown-linux-gnu");
        assert_eq!(summary.root_key_id_sha256, "a".repeat(64));
        assert!(summary.newer_than_running);
        assert!(!summary.debian_install_available);
    }

    #[test]
    fn verifier_output_cannot_redirect_installation_to_another_path_or_slot() {
        let (_parent, destination, output) = fetched_fixture();
        assert!(
            parse_fetch_output(
                &output,
                &destination.join("other"),
                "stable",
                "x86_64-unknown-linux-gnu"
            )
            .is_err()
        );
        assert!(
            parse_fetch_output(&output, &destination, "preview", "x86_64-unknown-linux-gnu")
                .is_err()
        );
        assert!(
            parse_fetch_output(&output, &destination, "stable", "aarch64-unknown-linux-gnu")
                .is_err()
        );
    }

    #[test]
    fn source_input_is_bounded_and_not_normalized_implicitly() {
        assert!(validate_source_input(&test_source("stable/")).is_ok());
        assert!(validate_source_input(&format!(" {}", test_source("stable/"))).is_err());
        assert!(validate_source_input(&test_source("stable")).is_err());
        assert!(validate_source_input(&"x".repeat(MAX_SOURCE_BYTES + 1)).is_err());
    }

    #[test]
    fn runtime_serializes_operations_and_discards_only_while_idle() {
        let runtime = ReleaseUpdateRuntime::default();
        assert!(runtime.begin_check().unwrap().is_none());
        assert!(runtime.begin_check().is_err());
        assert!(runtime.discard().is_err());
        runtime.complete_check(None).unwrap();
        assert!(runtime.discard().unwrap().is_none());
    }

    #[test]
    fn fetch_output_rejects_unknown_fields() {
        let (_parent, destination, output) = fetched_fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        value["unexpected"] = json!(true);
        let output = serde_json::to_vec(&value).unwrap();
        assert!(
            parse_fetch_output(&output, &destination, "stable", "x86_64-unknown-linux-gnu")
                .is_err()
        );
    }
}
