//! Shared native operation gate. Window visibility has no role in VPN lifetime.
use crate::{helper::invoke_helper, *};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static OPERATION: AtomicBool = AtomicBool::new(false);
static CANCELLING: AtomicBool = AtomicBool::new(false);
static CONNECTING: AtomicBool = AtomicBool::new(false);
static EPOCH: AtomicU64 = AtomicU64::new(0);

pub fn epoch() -> u64 {
    EPOCH.load(Ordering::Acquire)
}
pub fn require_current(expected: u64) -> Result<(), String> {
    if expected != epoch() || CANCELLING.load(Ordering::Acquire) {
        Err("The connection was cancelled.".into())
    } else {
        Ok(())
    }
}
pub struct CancellationGuard;
impl Drop for CancellationGuard {
    fn drop(&mut self) {
        CANCELLING.store(false, Ordering::Release);
        crate::local_status_stream::changed();
    }
}
pub fn cancel() -> Result<CancellationGuard, String> {
    CANCELLING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .map_err(|_| "Disconnect is already in progress.".to_owned())?;
    if is_busy() && !CONNECTING.load(Ordering::Acquire) {
        CANCELLING.store(false, Ordering::Release);
        return Err("Finish the current protected device operation before disconnecting.".into());
    }
    EPOCH.fetch_add(1, Ordering::AcqRel);
    crate::management_session::invalidate();
    crate::local_status_stream::changed();
    Ok(CancellationGuard)
}

pub struct OperationGuard;
impl Drop for OperationGuard {
    fn drop(&mut self) {
        CONNECTING.store(false, Ordering::Release);
        OPERATION.store(false, Ordering::Release);
        crate::local_status_stream::changed();
    }
}

pub fn acquire_connection() -> Result<OperationGuard, String> {
    let guard = acquire()?;
    CONNECTING.store(true, Ordering::Release);
    Ok(guard)
}

pub fn is_busy() -> bool {
    OPERATION.load(Ordering::Acquire)
}

pub fn require_finished_rotation(paths: &ClientPaths, id: ServerId) -> Result<(), String> {
    if has_pending_key_rotation(paths, id).map_err(safe_error)? {
        return Err("Finish this device's pending key rotation in Keys & recovery before reconnecting or switching servers.".into());
    }
    Ok(())
}

pub fn acquire() -> Result<OperationGuard, String> {
    if CANCELLING.load(Ordering::Acquire) {
        return Err("Wait for Disconnect to finish.".into());
    }
    OPERATION
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .and_then(|_| {
            let guard = OperationGuard;
            if CANCELLING.load(Ordering::Acquire) {
                drop(guard);
                return Err(true);
            }
            crate::management_session::invalidate();
            Ok(guard)
        })
        .map_err(|_| {
            "Another connection operation is in progress. Finish it before trying again.".into()
        })
}

pub fn session_action(command: &str, expected: ServerId) -> Result<LocalTunnelStatus, String> {
    let current = invoke_helper("status", None).map_err(safe_error)?;
    if current.server_id != Some(expected) {
        return Err("The active connection changed. Check its status before trying again.".into());
    }
    if !current.connection_control_supported {
        return Err(
            "Update the local VPN component in Settings before using this connection control."
                .into(),
        );
    }
    let input = serde_json::to_vec(&expected).map_err(safe_error)?;
    invoke_helper(command, Some(&input)).map_err(safe_error)
}

pub fn confirmed_disconnected(status: &LocalTunnelStatus) -> bool {
    status.state == ConnectionState::Disconnected
        && status.server_id.is_none()
        && !status.kill_switch_enabled
        && !status.auto_reconnect_enabled
        && status.kill_switch_state == Some(sirinvpn_tunnel_model::KillSwitchState::Off)
}

#[tauri::command]
pub async fn reconnect_server(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<LocalTunnelStatus, String> {
    let paths = state.paths.clone();
    let id = server_id
        .parse::<ServerId>()
        .map_err(|_| "The local server ID is invalid.")?;
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = acquire()?;
        require_finished_rotation(&paths, id)?;
        session_action("reconnect-session", id)
    })
    .await
    .map_err(|_| "The network worker was interrupted.".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_invalidates_connect_but_preserves_protected_operation_guards() {
        let operation = acquire_connection().unwrap();
        let started = epoch();
        let stop = cancel().unwrap();
        assert!(require_current(started).is_err());
        assert!(acquire_connection().is_err());
        drop(operation);
        assert!(acquire_connection().is_err());
        drop(stop);
        let protected = acquire().unwrap();
        let before = epoch();
        assert!(cancel().is_err());
        assert_eq!(before, epoch());
        drop(protected);
    }
    #[test]
    fn failed_or_retained_protection_is_never_a_successful_disconnect() {
        let mut status: LocalTunnelStatus = serde_json::from_value(serde_json::json!({
            "state":"disconnected", "interface_name":"sirin0", "server_id":null,
            "rx_bytes":0,"tx_bytes":0,"ipv6_blocked":false,"ipv6_tunneled":false,
            "kill_switch_enabled":false,"auto_reconnect_enabled":false,
            "transport_fallback_enabled":false,"routing_mode":"full_tunnel","allow_lan":false,
            "kill_switch_state":"off"
        }))
        .unwrap();
        assert!(confirmed_disconnected(&status));
        for state in [
            None,
            Some(sirinvpn_tunnel_model::KillSwitchState::Unknown),
            Some(sirinvpn_tunnel_model::KillSwitchState::Blocking),
        ] {
            status.kill_switch_state = state;
            assert!(!confirmed_disconnected(&status));
        }
    }
}
