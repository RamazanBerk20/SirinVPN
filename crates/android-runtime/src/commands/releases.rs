use super::*;
use sirinvpn_installer::{
    Provisioner, ServerReleaseAction, ServerReleaseRequest, SignedServerBundle,
};
use sirinvpn_release::{ArtifactKind, ClientReleaseBundle, InstalledReleaseStore};
use sirinvpn_release_fetch::{ReleaseFetchRequest, VerifiedReleaseBundle, fetch_release};
use std::sync::{Arc, Mutex};

struct Baseline {
    id: ServerId,
    pin: String,
    bundle: Arc<SignedServerBundle>,
}
static BASELINE: Mutex<Option<Baseline>> = Mutex::new(None);
static CANDIDATE: Mutex<Option<Value>> = Mutex::new(None);
fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-linux-android"
    } else {
        "x86_64-linux-android"
    }
}
fn store(runtime: &Runtime) -> InstalledReleaseStore {
    InstalledReleaseStore::new(runtime.paths.configuration_directory.join("apk-releases"))
}
fn request(runtime: &Runtime, input: &Value) -> Result<ServerReleaseRequest> {
    let p = profile(runtime, text(input, "server_id")?)?;
    ensure!(
        p.role == ServerRole::Owner,
        "Only the Owner may manage VPS software"
    );
    let secret = runtime.paths.secret_store().get(&p.identity_reference)?;
    let identity = secret.public_identity(&p.client_management_certificate_pem)?;
    let ssh = &input["ssh"];
    let target = maintenance::target(runtime, ssh, text(ssh, "host")?)?;
    Ok(ServerReleaseRequest {
        profile: p,
        target,
        identity,
        action: ServerReleaseAction::Status,
    })
}
pub async fn dispatch(runtime: &Runtime, command: &str, input: &Value) -> Result<Value> {
    let directory = runtime.paths.configuration_directory.join("checked-apk");
    match command {
        "get_release_update_status" => {
            store(runtime).finish_client_release(&runtime.platform.installed_apk()?)?;
            let state = store(runtime).inspect_client_release()?;
            Ok(
                json!({"installer_kind":"android","rollback_version":null,"baseline_required":state.installed.is_none(),"pending_version":state.pending_version}),
            )
        }
        "check_release_update" => {
            ensure!(
                store(runtime)
                    .inspect_client_release()?
                    .pending_version
                    .is_none(),
                "Finish or cancel the existing Android installation first"
            );
            if directory.exists() {
                std::fs::remove_dir_all(&directory)?;
            }
            let fetched = fetch_release(ReleaseFetchRequest {
                source: text(input, "source")?.to_owned(),
                expected_channel: serde_json::from_value(input["channel"].clone())?,
                artifact_kind: ArtifactKind::AndroidApk,
                artifact_target: arch().to_owned(),
                destination: directory,
            })
            .await?;
            let current = env!("CARGO_PKG_VERSION");
            let baseline = store(runtime).inspect_client_release()?.installed.is_none();
            let value = json!({"current_version":current,"release_version":fetched.release_version,"release_sequence":fetched.release_sequence.to_string(),
                "channel":fetched.channel,"security_update":fetched.security_update,"trust_policy_sequence":fetched.trust_policy_sequence.to_string(),
                "root_key_id_sha256":fetched.root_key_id_sha256,"release_key_id_sha256":fetched.release_key_id_sha256,
                "artifact_file_name":fetched.artifact.file_name,"artifact_target":fetched.artifact.target,"artifact_size_bytes":fetched.artifact.size_bytes,
                "artifact_sha256":fetched.artifact.sha256,"newer_than_running":semver::Version::parse(&fetched.release_version)? > semver::Version::parse(current)?,
                "debian_install_available":false,"appimage_install_available":false,"android_install_available":true,
                "baseline_bind_available":baseline && current==fetched.release_version,"baseline_bound":false,"installer_kind":"android"});
            *CANDIDATE
                .lock()
                .map_err(|_| anyhow::anyhow!("Release state unavailable"))? = Some(value.clone());
            Ok(value)
        }
        "install_release_update" => {
            confirmed(input)?;
            let mut candidate = CANDIDATE
                .lock()
                .map_err(|_| anyhow::anyhow!("Release state unavailable"))?
                .clone()
                .context("Check the release first")?;
            let bundle = VerifiedReleaseBundle::open(&directory, ArtifactKind::AndroidApk, arch())?;
            ensure!(
                candidate["artifact_sha256"] == bundle.verified.artifact.sha256,
                "The reviewed artifact changed"
            );
            let store = store(runtime);
            let installed = runtime.platform.installed_apk()?;
            store.apply_trust_policy(&bundle.trust_policy_bytes, &bundle.trust_signature_bytes)?;
            let prepared = store.prepare_client_release(
                &ClientReleaseBundle {
                    manifest: &bundle.manifest_bytes,
                    signature: &bundle.signature_bytes,
                    artifact_directory: &bundle.artifact_directory,
                    kind: ArtifactKind::AndroidApk,
                    target: arch(),
                },
                &installed,
                env!("CARGO_PKG_VERSION"),
            )?;
            candidate["baseline_bound"] = json!(prepared.baseline_bound);
            if !prepared.baseline_bound {
                store.verify_pending_client_artifact(
                    &installed,
                    &prepared.artifact,
                    ArtifactKind::AndroidApk,
                    arch(),
                )?;
                runtime.platform.install_apk(&prepared.artifact)?;
            }
            Ok(candidate)
        }
        "discard_release_update" => {
            runtime.platform.abandon_apk()?;
            store(runtime).cancel_client_release(&runtime.platform.installed_apk()?)?;
            *CANDIDATE
                .lock()
                .map_err(|_| anyhow::anyhow!("Release state unavailable"))? = None;
            if directory.exists() {
                std::fs::remove_dir_all(directory)?;
            }
            Ok(Value::Null)
        }
        "rollback_release_update" => {
            bail!("Android does not permit an ordinary app to silently downgrade its installed APK")
        }
        "discard_vps_baseline" => {
            *BASELINE
                .lock()
                .map_err(|_| anyhow::anyhow!("Baseline unavailable"))? = None;
            Ok(Value::Null)
        }
        "prepare_vps_baseline" => {
            let request = request(runtime, input)?;
            let discovery = Provisioner::inspect_signed_baseline_target(&request)?;
            let directory = tempfile::tempdir_in(&runtime.paths.configuration_directory)?;
            let destination = directory.path().join("bundle");
            fetch_release(ReleaseFetchRequest {
                source: text(input, "source")?.to_owned(),
                expected_channel: serde_json::from_value(input["channel"].clone())?,
                artifact_kind: ArtifactKind::ServerElf,
                artifact_target: sirinvpn_installer::release_target(&discovery.architecture)?
                    .to_owned(),
                destination: destination.clone(),
            })
            .await?;
            let bundle = Arc::new(SignedServerBundle::open(
                &destination,
                &discovery.architecture,
            )?);
            let value = encode(bundle.summary())?;
            *BASELINE
                .lock()
                .map_err(|_| anyhow::anyhow!("Baseline unavailable"))? = Some(Baseline {
                id: request.profile.id,
                pin: text(&input["ssh"], "host_key_sha256")?.to_owned(),
                bundle,
            });
            Ok(value)
        }
        "install_vps_baseline" => {
            runtime.platform.require_idle()?;
            let request = request(runtime, input)?;
            ensure!(
                !sirinvpn_core::has_pending_key_rotation(&runtime.paths, request.profile.id)?,
                "Finish key rotation first"
            );
            let bundle = {
                let pending = BASELINE
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Baseline unavailable"))?;
                let pending = pending
                    .as_ref()
                    .context("Review the signed baseline first")?;
                ensure!(
                    pending.id == request.profile.id
                        && pending.pin == text(&input["ssh"], "host_key_sha256")?
                        && pending.bundle.summary().manifest_sha256
                            == text(input, "manifest_sha256")?,
                    "Baseline identity changed"
                );
                pending.bundle.clone()
            };
            let p = request.profile.clone();
            let outcome = Provisioner::install_signed_baseline(request, bundle)?;
            runtime
                .paths
                .profile_store()
                .upsert(outcome.repair.updated_profile(&p))?;
            *BASELINE
                .lock()
                .map_err(|_| anyhow::anyhow!("Baseline unavailable"))? = None;
            Ok(outcome.release)
        }
        "manage_vps_release" => {
            let mut request = request(runtime, input)?;
            request.action = serde_json::from_value(input["operation"].clone())?;
            if matches!(
                request.action,
                ServerReleaseAction::Install { .. }
                    | ServerReleaseAction::Rollback { .. }
                    | ServerReleaseAction::Recover
            ) {
                runtime.platform.require_idle()?;
                ensure!(
                    !sirinvpn_core::has_pending_key_rotation(&runtime.paths, request.profile.id)?,
                    "Finish key rotation first"
                );
            }
            let mut output = Provisioner::manage_server_release(request)?;
            sequences(&mut output);
            Ok(output)
        }
        _ => bail!("Unknown signed release operation"),
    }
}
fn sequences(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if (key == "release_sequence" || key.ends_with("_release_sequence"))
                    && value.is_u64()
                {
                    *value = Value::String(value.to_string());
                } else {
                    sequences(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                sequences(value);
            }
        }
        _ => {}
    }
}
