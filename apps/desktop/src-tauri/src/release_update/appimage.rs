use super::{InstallSnapshot, ReleaseUpdateCandidate, current_artifact_target};
use sirinvpn_release::{AppImageFile, ArtifactKind, ClientReleaseBundle, InstalledReleaseStore};
use sirinvpn_release_fetch::VerifiedReleaseBundle;
use std::path::PathBuf;
use tauri::Manager;

#[derive(Clone)]
pub(super) struct Context {
    path: PathBuf,
    state: PathBuf,
}

impl Context {
    pub(super) fn status(
        &self,
    ) -> Result<crate::release_update_status::ReleaseUpdateStatus, String> {
        let status = self
            .store()
            .inspect_client_release()
            .map_err(|error| error.to_string())?;
        Ok(crate::release_update_status::ReleaseUpdateStatus {
            installer_kind: "appimage",
            rollback_version: status.rollback_version,
            baseline_required: status.installed.is_none(),
        })
    }

    pub(super) fn rollback(&self, expected: &str) -> Result<(), String> {
        let file = AppImageFile::inspect(&self.path, current_artifact_target()?)
            .map_err(|error| error.to_string())?;
        let store = self.store();
        if self.status()?.rollback_version.as_deref() != Some(expected) {
            return Err(
                "The previous version changed. Reopen app updates and review it again.".into(),
            );
        }
        let prepared = store
            .prepare_appimage_rollback(file.path())
            .map_err(|error| error.to_string())?;
        if prepared.state.active_release_version != expected {
            store
                .cancel_client_release(file.path())
                .map_err(|error| error.to_string())?;
            return Err(
                "The previous version changed. Reopen app updates and review it again.".into(),
            );
        }
        store
            .replace_prepared_appimage(file.path(), |candidate, artifact| {
                file.replace(candidate, artifact)
            })
            .map_err(|error| error.to_string())
    }

    pub(super) fn capture(app: &tauri::AppHandle) -> Result<Option<Self>, String> {
        let Some(path) = app.env().appimage.map(PathBuf::from) else {
            return Ok(None);
        };
        let file = AppImageFile::inspect(&path, current_artifact_target()?).map_err(|_| {
            "Move the AppImage into a folder you own, with no symlinks or shared write permissions, before updating it.".to_owned()
        })?;
        let state = app
            .path()
            .app_local_data_dir()
            .map_err(|_| "The private app-update folder is unavailable.")?
            .join("appimage-releases")
            .join(file.state_key());
        let context = Self { path, state };
        let store = context.store();
        store
            .finish_client_release(&context.path)
            .map_err(|error| error.to_string())?;
        if store
            .inspect_client_release()
            .map_err(|error| error.to_string())?
            .pending_version
            .is_some()
        {
            // AppImage rename is synchronous. If its old bytes remain after a
            // process restart, no external installer can still complete it.
            store
                .cancel_client_release(&context.path)
                .map_err(|error| error.to_string())?;
        }
        Ok(Some(context))
    }

    fn store(&self) -> InstalledReleaseStore {
        InstalledReleaseStore::new(&self.state)
    }

    pub(super) fn summarize(&self, candidate: &mut ReleaseUpdateCandidate) -> Result<(), String> {
        let status = self
            .store()
            .inspect_client_release()
            .map_err(|error| error.to_string())?;
        candidate.installer_kind = "appimage";
        candidate.debian_install_available = false;
        candidate.appimage_install_available = true;
        candidate.baseline_bind_available =
            status.installed.is_none() && candidate.current_version == candidate.release_version;
        Ok(())
    }

    pub(super) fn install(
        &self,
        snapshot: &InstallSnapshot,
    ) -> Result<ReleaseUpdateCandidate, String> {
        let file = AppImageFile::inspect(&self.path, &snapshot.artifact_target)
            .map_err(|error| error.to_string())?;
        let bundle = VerifiedReleaseBundle::open(
            &snapshot.bundle_directory,
            ArtifactKind::LinuxAppImage,
            &snapshot.artifact_target,
        )
        .map_err(|_| "The verified download changed. Check this release again.")?;
        if bundle.verified.artifact.sha256 != snapshot.candidate.artifact_sha256
            || bundle.verified.artifact.size_bytes != snapshot.candidate.artifact_size_bytes
            || bundle.verified.manifest.release_version != snapshot.candidate.release_version
        {
            return Err("The checked AppImage changed. Check this release again.".into());
        }
        let store = self.store();
        store
            .apply_trust_policy(&bundle.trust_policy_bytes, &bundle.trust_signature_bytes)
            .map_err(|error| error.to_string())?;
        let prepared = store
            .prepare_client_release(
                &ClientReleaseBundle {
                    manifest: &bundle.manifest_bytes,
                    signature: &bundle.signature_bytes,
                    artifact_directory: &bundle.artifact_directory,
                    kind: ArtifactKind::LinuxAppImage,
                    target: &snapshot.artifact_target,
                },
                file.path(),
                env!("CARGO_PKG_VERSION"),
            )
            .map_err(|error| error.to_string())?;
        if !prepared.baseline_bound {
            store
                .replace_prepared_appimage(file.path(), |candidate, artifact| {
                    file.replace(candidate, artifact)
                })
                .map_err(|error| error.to_string())?;
        }
        let mut result = snapshot.candidate.clone();
        result.baseline_bound = prepared.baseline_bound;
        Ok(result)
    }
}
