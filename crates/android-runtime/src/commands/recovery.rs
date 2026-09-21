use super::*;
use sirinvpn_core::{DecodedRecoveryKey, RecoveryKeyDraft};

pub async fn dispatch(
    runtime: &Runtime,
    command: &str,
    input: &Value,
    generation: i64,
) -> Result<Value> {
    match command {
        "preview_recovery_key" => {
            let preview = DecodedRecoveryKey::decode(text(input, "key")?)?.preview()?;
            let existing = runtime
                .paths
                .profile_store()
                .load()?
                .iter()
                .any(|p| p.id == preview.server_id);
            Ok(json!({"preview":preview,"existing_profile":existing}))
        }
        "export_recovery_package" => {
            confirmed(input)?;
            let bytes = sirinvpn_core::encrypt_recovery_package(
                text(input, "key")?,
                text(input, "password")?,
            )?;
            runtime
                .platform
                .write_document(text(input, "path")?, &bytes)?;
            Ok(Value::Null)
        }
        "import_recovery_package" => {
            let bytes = runtime.platform.document(text(input, "path")?)?;
            let key = sirinvpn_core::decrypt_recovery_package(&bytes, text(input, "password")?)?;
            Ok(
                json!({"key":key.as_str(),"qr_svg":"","qr_modules":membership::qr_modules(&key).ok(),"recovery_id":DecodedRecoveryKey::decode(&key)?.recovery_id()}),
            )
        }
        "create_recovery_key" => {
            confirmed(input)?;
            let p = profile(runtime, text(input, "server_id")?)?;
            runtime.platform.require_active(&p.id.to_string())?;
            let client = ManagementClient::new(
                &p,
                &runtime.paths.secret_store().get(&p.identity_reference)?,
            )?;
            ensure!(
                client.configuration().await?.recovery_keys_enabled,
                "Update the VPS for recovery support"
            );
            let replace = input["replace_recovery_id"]
                .as_str()
                .map(str::parse)
                .transpose()?;
            let draft = RecoveryKeyDraft::new(&p, replace)?;
            let response = client.create_recovery_key(draft.request()).await?;
            let key = draft.finish(response)?;
            Ok(
                json!({"key":key.as_str(),"qr_svg":"","qr_modules":membership::qr_modules(&key).ok(),"recovery_id":DecodedRecoveryKey::decode(&key)?.recovery_id()}),
            )
        }
        "recover_owner_access" => {
            confirmed(input)?;
            runtime.platform.require_idle()?;
            let key = DecodedRecoveryKey::decode(text(input, "key")?)?;
            let id = key.bootstrap_profile().id;
            let old = runtime
                .paths
                .profile_store()
                .load()?
                .into_iter()
                .find(|p| p.id == id);
            let replace = input["replace_existing"] == true;
            ensure!(
                old.is_none() || replace,
                "Confirm replacing the existing profile"
            );
            ensure!(
                !sirinvpn_core::has_pending_key_rotation(&runtime.paths, id)?,
                "Finish key rotation first"
            );
            let secrets = runtime.paths.secret_store();
            let mut pending = PendingEnrollment::open(
                &runtime.paths,
                &secrets,
                id,
                &format!("recovery-{}", key.recovery_id()),
                text(input, "device_name")?,
            )?;
            let outcome = async {
                let profile = if let Some(profile) = pending.completed_profile() {
                    profile
                } else {
                    let bootstrap = key.current_bootstrap_profile().await?;
                    crate::tunnel::connect(
                        runtime,
                        &bootstrap,
                        key.secret(),
                        &ConnectionPreferences::default(),
                        generation,
                    )
                    .await?;
                    let client = ManagementClient::new(&bootstrap, key.secret())?;
                    let request = key.request(
                        &pending.identity.public,
                        text(input, "device_name")?.to_owned(),
                    );
                    let response = match client.recover_owner(&request).await {
                        Err(sirinvpn_core::ManagementError::ConnectionFailed) => {
                            client.recover_owner(&request).await?
                        }
                        other => other?,
                    };
                    key.permanent_profile(
                        &response,
                        &pending.identity.public,
                        pending.identity_reference.clone(),
                    )?
                };
                pending.commit_profile(&runtime.paths, profile.clone(), replace)?;
                if let Some(old) = old
                    && old.identity_reference != profile.identity_reference
                {
                    secrets.delete(&old.identity_reference)?;
                }
                runtime.platform.deactivate(generation)?;
                let prefs = preferences(runtime).get(id).map_err(anyhow::Error::msg)?;
                crate::tunnel::connect(
                    runtime,
                    &profile,
                    &pending.identity.secret,
                    &prefs,
                    generation,
                )
                .await?;
                encode(profile)
            }
            .await;
            if outcome.is_err() {
                let _ = runtime.platform.deactivate(generation);
            }
            outcome
        }
        _ => bail!("Unknown recovery operation"),
    }
}
