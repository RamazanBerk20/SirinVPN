use super::*;
use sirinvpn_core::PendingEnrollment;
use sirinvpn_core::{DecodedRecoveryKey, RecoveryKeyDraft, RecoveryKeyPreview};
use sirinvpn_protocol::{RecoveryId, RecoveryPolicy, RecoverySettings};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryCreateInput {
    server_id: String,
    replace_recovery_id: Option<String>,
    confirmed: bool,
}

#[derive(Serialize)]
pub(super) struct RecoveryKeyOutput {
    key: String,
    qr_svg: String,
    recovery_id: sirinvpn_protocol::RecoveryId,
}
impl Drop for RecoveryKeyOutput {
    fn drop(&mut self) {
        self.key.zeroize();
        self.qr_svg.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryKeyInput {
    key: String,
}
impl Drop for RecoveryKeyInput {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoverOwnerInput {
    key: String,
    device_name: String,
    confirmed: bool,
    replace_existing: bool,
}
impl Drop for RecoverOwnerInput {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryPackageInput {
    #[serde(default)]
    key: String,
    path: String,
    password: String,
    #[serde(default)]
    confirmed: bool,
}
impl Drop for RecoveryPackageInput {
    fn drop(&mut self) {
        self.key.zeroize();
        self.password.zeroize();
    }
}

#[derive(Serialize)]
pub(super) struct RecoveryPreviewOutput {
    preview: RecoveryKeyPreview,
    existing_profile: bool,
}

async fn client(
    app: &tauri::AppHandle,
    server_id: &str,
) -> Result<crate::management_session::ManagementSession, String> {
    let client = crate::management_session::connected(app, server_id).await?;
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .recovery_keys_enabled
    {
        return Err("Update this VPS before configuring offline recovery keys.".into());
    }
    Ok(client)
}

#[tauri::command]
pub(super) async fn recovery_settings(
    app: tauri::AppHandle,
    server_id: String,
) -> Result<RecoverySettings, String> {
    client(&app, &server_id)
        .await?
        .recovery_settings()
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn update_recovery_policy(
    app: tauri::AppHandle,
    server_id: String,
    administrator_member_ids: Vec<String>,
) -> Result<RecoverySettings, String> {
    let ids = administrator_member_ids
        .iter()
        .map(|id| {
            id.parse::<MemberId>()
                .map_err(|_| "An administrator ID is invalid.".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    client(&app, &server_id)
        .await?
        .update_recovery_policy(&RecoveryPolicy {
            administrator_member_ids: ids,
        })
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn create_recovery_key(
    app: tauri::AppHandle,
    input: RecoveryCreateInput,
) -> Result<RecoveryKeyOutput, String> {
    if !input.confirmed {
        return Err(
            "Confirm that this key can replace all Owner devices before creating it.".into(),
        );
    }
    let client = client(&app, &input.server_id).await?;
    let replace = input
        .replace_recovery_id
        .as_deref()
        .map(str::parse::<RecoveryId>)
        .transpose()
        .map_err(|_| "The recovery ID is invalid.".to_owned())?;
    let draft = RecoveryKeyDraft::new(&client.profile, replace).map_err(safe_error)?;
    let response = client
        .create_recovery_key(draft.request())
        .await
        .map_err(safe_error)?;
    let key = draft.finish(response).map_err(safe_error)?;
    Ok(RecoveryKeyOutput {
        qr_svg: render_invitation_qr(&key)?,
        recovery_id: DecodedRecoveryKey::decode(&key)
            .map_err(|error| error.to_string())?
            .recovery_id(),
        key: key.to_string(),
    })
}

#[tauri::command]
pub(super) async fn revoke_recovery_key(
    app: tauri::AppHandle,
    server_id: String,
    recovery_id: String,
) -> Result<RecoverySettings, String> {
    let id = recovery_id
        .parse::<RecoveryId>()
        .map_err(|_| "The recovery ID is invalid.".to_owned())?;
    client(&app, &server_id)
        .await?
        .revoke_recovery_key(id)
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn preview_recovery_key(
    app: tauri::AppHandle,
    input: RecoveryKeyInput,
) -> Result<RecoveryPreviewOutput, String> {
    let preview = DecodedRecoveryKey::decode(&input.key)
        .and_then(|key| key.preview())
        .map_err(safe_error)?;
    let existing_profile = {
        use tauri::Manager;
        app.state::<AppState>()
            .paths
            .profile_store()
            .load()
            .map_err(safe_error)?
            .iter()
            .any(|profile| profile.id == preview.server_id)
    };
    Ok(RecoveryPreviewOutput {
        preview,
        existing_profile,
    })
}

#[tauri::command]
pub(super) async fn recover_owner_access(
    state: State<'_, AppState>,
    input: RecoverOwnerInput,
) -> Result<ServerProfile, String> {
    if !input.confirmed {
        return Err(
            "Confirm revoking all old Owner device identities and consuming the recovery key."
                .into(),
        );
    }
    let _operation = crate::connection_controller::acquire()?;
    let recovery = DecodedRecoveryKey::decode(&input.key).map_err(safe_error)?;
    let bootstrap = recovery.bootstrap_profile();
    let old_profile = state
        .paths
        .profile_store()
        .load()
        .map_err(safe_error)?
        .into_iter()
        .find(|profile| profile.id == bootstrap.id);
    if old_profile.is_some() && !input.replace_existing {
        return Err("Review and confirm replacing the saved profile for this server.".into());
    }
    if invoke_helper("status", None).map_err(safe_error)?.state != ConnectionState::Disconnected {
        return Err("Disconnect the current VPN before recovering Owner access.".into());
    }
    if has_pending_key_rotation(&state.paths, bootstrap.id).map_err(safe_error)? {
        return Err(
            "Resolve the pending device key rotation before recovering this server.".into(),
        );
    }
    let secrets = state.paths.secret_store();
    let mut pending = PendingEnrollment::open(
        &state.paths,
        &secrets,
        bootstrap.id,
        &format!("recovery-{}", recovery.recovery_id()),
        &input.device_name,
    )
    .map_err(safe_error)?;
    let outcome = async {
        let profile = if let Some(profile) = pending.completed_profile() {
            profile
        } else {
            let bootstrap = recovery.current_bootstrap_profile().await?;
            connect_candidate_automatically(bootstrap.clone(), recovery.secret().clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let client = ManagementClient::new(&bootstrap, recovery.secret())?;
            let request = recovery.request(&pending.identity.public, input.device_name.clone());
            let result = match client.recover_owner(&request).await {
                Err(ManagementError::ConnectionFailed) => client.recover_owner(&request).await?,
                result => result?,
            };
            recovery.permanent_profile(
                &result,
                &pending.identity.public,
                pending.identity_reference.clone(),
            )?
        };
        pending.commit_profile(&state.paths, profile.clone(), input.replace_existing)?;
        if let Some(old) = &old_profile
            && old.identity_reference != profile.identity_reference
        {
            secrets.delete(&old.identity_reference).map_err(|_| anyhow!(
                "Owner recovery committed; old credential cleanup is incomplete. Unlock the secure store and retry credential cleanup."
            ))?;
        }
        disconnect_candidate(profile.id).map_err(anyhow::Error::msg)?;
        connect_candidate_automatically(profile.clone(), pending.identity.secret.clone())
            .await
            .map_err(anyhow::Error::msg)?;
        Ok::<_, anyhow::Error>(profile)
    }
    .await;
    if outcome.is_err() {
        let _ = disconnect_candidate(bootstrap.id);
    }
    outcome.map_err(safe_error)
}

#[tauri::command]
pub(super) async fn export_recovery_package(
    _app: tauri::AppHandle,
    input: RecoveryPackageInput,
) -> Result<(), String> {
    if !input.confirmed {
        return Err("Confirm exporting this Owner recovery credential.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        {
            sirinvpn_core::write_recovery_package(
                Path::new(&input.path),
                &input.key,
                &input.password,
            )
            .map_err(safe_error)
        }
    })
    .await
    .map_err(|_| "The recovery export was interrupted.".to_owned())?
}

#[tauri::command]
pub(super) async fn import_recovery_package(
    _app: tauri::AppHandle,
    input: RecoveryPackageInput,
) -> Result<RecoveryKeyOutput, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let key = sirinvpn_core::read_recovery_package(Path::new(&input.path), &input.password)
            .map_err(safe_error)?;
        Ok(RecoveryKeyOutput {
            qr_svg: String::new(),
            recovery_id: DecodedRecoveryKey::decode(&key)
                .map_err(|error| error.to_string())?
                .recovery_id(),
            key: key.to_string(),
        })
    })
    .await
    .map_err(|_| "The recovery import was interrupted.".to_owned())?
}
