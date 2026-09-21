use serde::Deserialize;
use sirinvpn_core::{ClientPaths, SecretStore};
use sirinvpn_installer::{
    Provisioner, ServerReleaseAction, ServerReleaseRequest, SignedBaselineCandidate,
    SignedServerBundle,
};
use sirinvpn_protocol::{ConnectionState, ServerRole};
use std::sync::{Arc, Mutex};
use tauri::State;

struct Pending {
    server_id: String,
    host_key: String,
    bundle: Arc<SignedServerBundle>,
}
#[derive(Default)]
pub(crate) struct BaselineRuntime(Mutex<BaselineState>);
#[derive(Default)]
struct BaselineState {
    generation: u64,
    server_id: Option<String>,
    pending: Option<Pending>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrepareBaselineInput {
    server_id: String,
    ssh: crate::ssh_login::SshLoginInput,
    source: String,
    channel: sirinvpn_release::ReleaseChannel,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallBaselineInput {
    server_id: String,
    ssh: crate::ssh_login::SshLoginInput,
    manifest_sha256: String,
}

fn request(
    paths: &ClientPaths,
    server_id: &str,
    ssh: crate::ssh_login::SshLoginInput,
) -> Result<ServerReleaseRequest, String> {
    let profile = crate::find_profile(paths, server_id)?;
    if profile.role != ServerRole::Owner {
        return Err("Only the Owner can establish a signed VPS baseline.".to_owned());
    }
    let secret = paths
        .secret_store()
        .get(&profile.identity_reference)
        .map_err(crate::safe_error)?;
    let identity = secret
        .public_identity(&profile.client_management_certificate_pem)
        .map_err(crate::safe_error)?;
    let target = crate::ssh_login::resolve_target(ssh)?;
    Ok(ServerReleaseRequest {
        profile,
        identity,
        target,
        action: ServerReleaseAction::Status,
    })
}

#[tauri::command]
pub(crate) async fn prepare_vps_baseline(
    state: State<'_, crate::AppState>,
    runtime: State<'_, BaselineRuntime>,
    input: PrepareBaselineInput,
) -> Result<SignedBaselineCandidate, String> {
    sirinvpn_release_fetch::validate_source_url(&input.source)
        .map_err(|error| error.to_string())?;
    let generation = {
        let mut current = runtime
            .0
            .lock()
            .map_err(|_| "The baseline state is unavailable.".to_owned())?;
        current.generation = current.generation.wrapping_add(1);
        current.server_id = Some(input.server_id.clone());
        current.pending = None;
        current.generation
    };
    let paths = state.paths.clone();
    let server_id = input.server_id.clone();
    let host_key = input.ssh.host_key_sha256.clone();
    let discovery = tauri::async_runtime::spawn_blocking(move || {
        let request = request(&paths, &server_id, input.ssh)?;
        Provisioner::inspect_signed_baseline_target(&request).map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "The signed baseline preflight was interrupted.".to_owned())??;
    if runtime
        .0
        .lock()
        .map_err(|_| "The baseline state is unavailable.".to_owned())?
        .generation
        != generation
    {
        return Err("The baseline preparation was cancelled.".to_owned());
    }
    let temporary = tempfile::tempdir().map_err(crate::safe_error)?;
    let destination = temporary.path().join("bundle");
    sirinvpn_release_fetch::fetch_release(sirinvpn_release_fetch::ReleaseFetchRequest {
        source: input.source,
        expected_channel: input.channel,
        artifact_kind: sirinvpn_release::ArtifactKind::ServerElf,
        artifact_target: sirinvpn_installer::release_target(&discovery.architecture)
            .map_err(|error| error.to_string())?
            .to_owned(),
        destination: destination.clone(),
    })
    .await
    .map_err(|error| error.to_string())?;
    let bundle = Arc::new(
        SignedServerBundle::open(&destination, &discovery.architecture)
            .map_err(|error| error.to_string())?,
    );
    let summary = bundle.summary().clone();
    let mut current = runtime
        .0
        .lock()
        .map_err(|_| "The signed baseline state is unavailable.".to_owned())?;
    if current.generation != generation {
        return Err("The baseline preparation was cancelled.".to_owned());
    }
    current.pending = Some(Pending {
        server_id: input.server_id,
        host_key,
        bundle,
    });
    Ok(summary)
}

#[tauri::command]
pub(crate) async fn install_vps_baseline(
    state: State<'_, crate::AppState>,
    runtime: State<'_, BaselineRuntime>,
    input: InstallBaselineInput,
) -> Result<serde_json::Value, String> {
    let (bundle, generation) = {
        let pending = runtime
            .0
            .lock()
            .map_err(|_| "The signed baseline state is unavailable.".to_owned())?;
        let generation = pending.generation;
        let pending = pending
            .pending
            .as_ref()
            .ok_or_else(|| "Check the signed baseline release first.".to_owned())?;
        if pending.server_id != input.server_id
            || pending.host_key != input.ssh.host_key_sha256
            || pending.bundle.summary().manifest_sha256 != input.manifest_sha256
        {
            return Err("The VPS or checked baseline changed. Check the release again.".to_owned());
        }
        (pending.bundle.clone(), generation)
    };
    let paths = state.paths.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let status = crate::invoke_helper("status", None).map_err(crate::safe_error)?;
        if status.state != ConnectionState::Disconnected || status.kill_switch_enabled || status.auto_reconnect_enabled {
            return Err("Disconnect this computer before installing the signed VPS baseline.".to_owned());
        }
        let request = request(&paths, &input.server_id, input.ssh)?;
        if sirinvpn_core::has_pending_key_rotation(&paths, request.profile.id).map_err(crate::safe_error)? {
            return Err("Finish this device's pending key rotation first.".to_owned());
        }
        let profile = request.profile.clone();
        let outcome = Provisioner::install_signed_baseline(request, bundle).map_err(|error| error.to_string())?;
        paths.profile_store().upsert(outcome.repair.updated_profile(&profile))
            .map_err(|_| "The signed baseline is installed, but the local profile could not be saved. Refresh the profile before connecting.".to_owned())?;
        Ok(outcome.release)
    }).await.map_err(|_| "The guarded baseline installation was interrupted.".to_owned())?;
    if result.is_ok() {
        let mut current = runtime
            .0
            .lock()
            .map_err(|_| "The baseline state could not be cleared.".to_owned())?;
        if current.generation == generation {
            current.pending = None;
            current.server_id = None;
        }
    }
    result
}

#[tauri::command]
pub(crate) fn discard_vps_baseline(
    runtime: State<'_, BaselineRuntime>,
    server_id: String,
) -> Result<(), String> {
    let mut pending = runtime
        .0
        .lock()
        .map_err(|_| "The baseline state could not be cleared.".to_owned())?;
    if pending.server_id.as_ref() == Some(&server_id) {
        pending.generation = pending.generation.wrapping_add(1);
        pending.pending = None;
        pending.server_id = None;
    }
    Ok(())
}
