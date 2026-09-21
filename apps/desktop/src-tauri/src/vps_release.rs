use serde::Deserialize;
use sirinvpn_core::SecretStore;
use sirinvpn_installer::{Provisioner, ServerReleaseAction, ServerReleaseRequest};
use sirinvpn_protocol::{ConnectionState, ServerRole};
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
) -> Result<serde_json::Value, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let profile = crate::find_profile(&paths, &input.server_id)?;
        if profile.role != ServerRole::Owner { return Err("Only the Owner can manage VPS software releases.".to_owned()); }
        if matches!(input.operation, ServerReleaseAction::Install { .. } | ServerReleaseAction::Rollback { .. } | ServerReleaseAction::Recover) {
            let status = crate::invoke_helper("status", None).map_err(crate::safe_error)?;
            if status.state != ConnectionState::Disconnected || status.kill_switch_enabled || status.auto_reconnect_enabled {
                return Err("Disconnect this computer before restarting the VPS services.".to_owned());
            }
            if sirinvpn_core::has_pending_key_rotation(&paths, profile.id).map_err(crate::safe_error)? {
                return Err("Finish this device's pending key rotation before updating its VPS.".to_owned());
            }
        }
        let secret = paths.secret_store().get(&profile.identity_reference).map_err(crate::safe_error)?;
        let identity = secret.public_identity(&profile.client_management_certificate_pem).map_err(crate::safe_error)?;
        let target = crate::ssh_login::resolve_target(input.ssh)?;
        let mut value = Provisioner::manage_server_release(ServerReleaseRequest { profile, target, identity, action: input.operation })
            .map_err(|error| error.to_string())?;
        preserve_sequence_precision(&mut value);
        Ok(value)
    }).await.map_err(|_| "The VPS release operation was interrupted. Its recovery transaction is retained on the VPS.".to_owned())?
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
