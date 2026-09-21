use serde::{Deserialize, Serialize};
use sirinvpn_release::{ArtifactKind, ReleaseChannel};
use sirinvpn_release_fetch::{FetchedRelease, ReleaseFetchRequest, VerifiedReleaseBundle};
use std::sync::{Mutex, MutexGuard};
use tauri::State;

#[tauri::command]
pub(crate) fn get_release_update_status() -> crate::release_update_status::ReleaseUpdateStatus {
    crate::release_update_status::ReleaseUpdateStatus {
        installer_kind: "windows",
        rollback_version: None,
        baseline_required: false,
    }
}

#[tauri::command]
pub(crate) fn rollback_release_update(
    input: crate::release_update_status::RollbackReleaseInput,
) -> Result<(), String> {
    let _ = (input.confirmed, input.expected_version);
    Err("Use the Windows signed-release coordinator for an explicit compatible rollback.".into())
}

#[derive(Default)]
pub(crate) struct ReleaseUpdateRuntime {
    inner: Mutex<Runtime>,
}
#[derive(Default)]
struct Runtime {
    busy: bool,
    pending: Option<Pending>,
}
struct Pending {
    _temporary: tempfile::TempDir,
    fetched: FetchedRelease,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckReleaseUpdateInput {
    source: String,
    channel: ReleaseChannel,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallReleaseUpdateInput {
    confirmed: bool,
}

#[derive(Clone, Serialize)]
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
    windows_install_available: bool,
    installer_kind: &'static str,
}

impl ReleaseUpdateRuntime {
    fn lock(&self) -> Result<MutexGuard<'_, Runtime>, String> {
        self.inner
            .lock()
            .map_err(|_| "The current release check is unavailable. Reopen SirinVPN.".into())
    }
}

#[tauri::command]
pub(crate) async fn check_release_update(
    runtime: State<'_, ReleaseUpdateRuntime>,
    input: CheckReleaseUpdateInput,
) -> Result<ReleaseUpdateCandidate, String> {
    sirinvpn_release_fetch::validate_source_url(&input.source)
        .map_err(|_| "Enter an HTTPS release directory ending in '/'.".to_owned())?;
    {
        let mut state = runtime.lock()?;
        if state.busy {
            return Err("Another release operation is running.".into());
        }
        state.busy = true;
        state.pending = None;
    }
    let outcome = async {
        let temporary = tempfile::Builder::new()
            .prefix("sirinvpn-release-")
            .tempdir()
            .map_err(|_| "A private release directory could not be created.".to_owned())?;
        sirinvpn_platform::files::restrict_temporary_directory(&temporary)
            .map_err(|_| "The release directory could not be secured.".to_owned())?;
        let fetched = sirinvpn_release_fetch::fetch_release(ReleaseFetchRequest {
            source: input.source,
            expected_channel: input.channel,
            artifact_kind: ArtifactKind::WindowsInstaller,
            artifact_target: sirinvpn_windows_service::update::artifact_target().into(),
            destination: temporary.path().join("bundle"),
        })
        .await
        .map_err(|_| {
            "The source did not provide an authenticated Windows release for this computer."
                .to_owned()
        })?;
        let candidate = summary(&fetched)?;
        Ok::<_, String>((
            Pending {
                _temporary: temporary,
                fetched,
            },
            candidate,
        ))
    }
    .await;
    let mut state = runtime.lock()?;
    state.busy = false;
    let (pending, candidate) = outcome?;
    state.pending = Some(pending);
    Ok(candidate)
}

#[tauri::command]
pub(crate) async fn install_release_update(
    app: tauri::AppHandle,
    runtime: State<'_, ReleaseUpdateRuntime>,
    input: InstallReleaseUpdateInput,
) -> Result<ReleaseUpdateCandidate, String> {
    if !input.confirmed {
        return Err("Confirm this authenticated Windows update first.".into());
    }
    let (directory, candidate, digest) = {
        let mut state = runtime.lock()?;
        if state.busy {
            return Err("Another release operation is running.".into());
        }
        let pending = state
            .pending
            .as_ref()
            .ok_or("Check an authenticated release first.")?;
        let candidate = summary(&pending.fetched)?;
        if !candidate.newer_than_running || !candidate.windows_install_available {
            return Err("This candidate cannot update the installed Windows application.".into());
        }
        let bundle = VerifiedReleaseBundle::open(
            &pending.fetched.bundle_directory,
            ArtifactKind::WindowsInstaller,
            sirinvpn_windows_service::update::artifact_target(),
        )
        .map_err(|_| "The downloaded release changed. Check it again.")?;
        if bundle.verified.artifact != pending.fetched.artifact {
            return Err("The downloaded release changed. Check it again.".into());
        }
        let directory = pending.fetched.bundle_directory.clone();
        state.busy = true;
        (directory, candidate, bundle.verified.manifest_sha256)
    };
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        sirinvpn_windows_service::update::launch(&directory, &digest, false)
    })
    .await;
    let discarded = {
        let mut state = runtime.lock()?;
        state.busy = false;
        outcome.map_err(|_| "The Windows update was interrupted.".to_owned())?
            .map_err(|_| "Windows did not authorize or finish staging the update. Retry the same authenticated release.".to_owned())?;
        state.pending.take()
    };
    // The privileged worker now owns its own verified copy. Remove the user's
    // temporary download before exiting; the installer can replace the desktop.
    drop(discarded);
    app.exit(0);
    Ok(candidate)
}

#[tauri::command]
pub(crate) fn discard_release_update(
    runtime: State<'_, ReleaseUpdateRuntime>,
) -> Result<(), String> {
    let mut state = runtime.lock()?;
    if state.busy {
        return Err("Wait for the current release operation to finish.".into());
    }
    state.pending = None;
    Ok(())
}

fn summary(fetched: &FetchedRelease) -> Result<ReleaseUpdateCandidate, String> {
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|_| "The running version is invalid.")?;
    let candidate = semver::Version::parse(&fetched.release_version)
        .map_err(|_| "The release version is invalid.")?;
    Ok(ReleaseUpdateCandidate {
        current_version: current.to_string(),
        release_version: candidate.to_string(),
        release_sequence: fetched.release_sequence.to_string(),
        channel: fetched.channel.to_string(),
        security_update: fetched.security_update,
        trust_policy_sequence: fetched.trust_policy_sequence.to_string(),
        root_key_id_sha256: fetched.root_key_id_sha256.clone(),
        release_key_id_sha256: fetched.release_key_id_sha256.clone(),
        artifact_file_name: fetched.artifact.file_name.clone(),
        artifact_target: fetched.artifact.target.clone(),
        artifact_size_bytes: fetched.artifact.size_bytes,
        artifact_sha256: fetched.artifact.sha256.clone(),
        newer_than_running: candidate > current,
        debian_install_available: false,
        windows_install_available: sirinvpn_windows_service::update::coordinator_available()
            .is_ok(),
        installer_kind: "windows",
    })
}
