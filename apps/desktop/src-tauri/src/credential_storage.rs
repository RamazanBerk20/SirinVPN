//! No credential values, key references, or storage paths cross this API.
use super::*;

#[tauri::command]
pub(super) async fn credential_storage(
    state: State<'_, AppState>,
    action: Option<String>,
    server_id: Option<String>,
) -> Result<serde_json::Value, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        operate(&paths, action.as_deref(), server_id.as_deref())
    })
    .await
    .map_err(|_| "Credential storage worker was interrupted.".to_owned())?
}

fn operate(
    paths: &ClientPaths,
    action: Option<&str>,
    server_id: Option<&str>,
) -> Result<serde_json::Value, String> {
    #[cfg(not(windows))]
    {
        use sirinvpn_core::StoragePolicy;
        let store = paths.secret_store();
        match action {
            None => {}
            Some("require_secure") => store
                .set_policy(StoragePolicy::SecureStoreRequired)
                .map_err(safe_error)?,
            Some("allow_private_file") => store
                .set_policy(StoragePolicy::AllowPrivateFile)
                .map_err(safe_error)?,
            Some("migrate") => {
                let profile = paths
                    .profile_store()
                    .load()
                    .map_err(safe_error)?
                    .into_iter()
                    .find(|p| Some(p.id.to_string()).as_deref() == server_id)
                    .ok_or_else(|| "Choose an existing profile.".to_owned())?;
                store
                    .migrate(
                        &profile.identity_reference,
                        &profile.client_management_certificate_pem,
                    )
                    .map_err(safe_error)?;
            }
            Some("retry_cleanup") => {
                let mut failed = false;
                for reference in store.pending_cleanup().map_err(safe_error)? {
                    failed |= store.delete(&reference).is_err();
                }
                if failed {
                    return Err(
                        "Credential cleanup is incomplete. Unlock the system keyring and retry."
                            .into(),
                    );
                }
            }
            _ => return Err("Unknown credential storage action.".into()),
        }
        let profiles = paths.profile_store().load().map_err(safe_error)?.into_iter().map(|p| {
            store.status(&p.identity_reference).map(|status| serde_json::json!({"server_id":p.id,"name":p.name,"storage":status})).map_err(safe_error)
        }).collect::<Result<Vec<_>, String>>()?;
        Ok(
            serde_json::json!({"supported":true,"policy":store.policy().map_err(safe_error)?,
            "profiles":profiles,"pending_cleanup":store.pending_cleanup().map_err(safe_error)?.len()}),
        )
    }
    #[cfg(windows)]
    {
        let _ = paths;
        if action.is_some() || server_id.is_some() {
            return Err("Windows uses DPAPI; Linux storage policy does not apply.".into());
        }
        Ok(serde_json::json!({"supported":false,"protection":"windows_dpapi"}))
    }
}
