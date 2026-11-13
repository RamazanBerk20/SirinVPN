use serde::Deserialize;
use sirinvpn_installer::{OwnerMaintenance, Provisioner, ServerReleaseAction, ServerReleaseRequest};
use sirinvpn_protocol::ServerRole;
use tauri::State;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VpsReleaseInput {
    server_id: String,
    ssh: crate::ssh_login::SshLoginInput,
    operation: ServerReleaseAction,
}

#[tauri::command]
pub(crate) async fn manage_vps_release(
    state: State<'_, crate::AppState>,
    input: VpsReleaseInput,
) -> Result<serde_json::Value, crate::CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<_, crate::CommandError> {
        let profile = crate::find_profile(&paths, &input.server_id)?;
        if profile.role != ServerRole::Owner { return Err("Only the Owner can update this VPS.".into()); }
        if matches!(input.operation, ServerReleaseAction::Install { .. } | ServerReleaseAction::Rollback { .. } | ServerReleaseAction::Recover) {
            crate::vps_transaction::ensure_owner_maintenance_ready(&paths, &profile, OwnerMaintenance::ReleaseInstall)?;
        }
        let secret = crate::explicit_secret(&paths, &profile.identity_reference)?;
        let identity = secret.public_identity(&profile.client_management_certificate_pem).map_err(crate::safe_error)?;
        let target = crate::ssh_login::resolve_target(input.ssh)?;
        let mut value = Provisioner::manage_server_release(ServerReleaseRequest { profile, target, identity, action: input.operation })
            .map_err(crate::command_error)?;
        preserve_sequence_precision(&mut value);
        Ok(value)
    }).await.map_err(|_| crate::CommandError::from("The VPS update was interrupted. Its recovery data stays on the VPS; check its status before trying again."))?
}

fn preserve_sequence_precision(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if (key == "release_sequence" || key.ends_with("_release_sequence"))
                    && value.is_u64()
                {
                    *value = serde_json::Value::String(value.to_string());
                } else {
                    preserve_sequence_precision(value);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                preserve_sequence_precision(value);
            }
        }
        _ => {}
    }
}
