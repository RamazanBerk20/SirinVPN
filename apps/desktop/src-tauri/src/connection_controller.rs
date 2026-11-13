//! Shared native operation gate. Window visibility has no role in VPN lifetime.
use crate::{helper::invoke_helper, *};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// The one native operation slot. Tray and window read the same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Gate {
    Idle,
    /// A connect that a Disconnect may still cancel.
    Connecting,
    /// Any other operation; Disconnect waits for it.
    Protected,
    /// A Disconnect is running while a cancelled connect is still unwinding.
    CancellingConnect,
    /// A Disconnect is running and nothing else is.
    Cancelling,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateEvent {
    AcquireConnect,
    AcquireProtected,
    Cancel,
    /// The connect or protected operation released its guard.
    OperationDone,
    /// The Disconnect released its guard.
    CancelDone,
}

impl Gate {
    const ALL: [Gate; 5] = [
        Gate::Idle,
        Gate::Connecting,
        Gate::Protected,
        Gate::CancellingConnect,
        Gate::Cancelling,
    ];

    /// The only transition function; an `Err` is the message for the refused request.
    pub fn next(self, event: GateEvent) -> Result<Gate, &'static str> {
        use {Gate::*, GateEvent::*};
        match (self, event) {
            (Idle, AcquireConnect) => Ok(Connecting),
            (Idle, AcquireProtected) => Ok(Protected),
            (Idle, Cancel) => Ok(Cancelling),
            (Connecting, Cancel) => Ok(CancellingConnect),
            (Connecting | Protected, OperationDone) => Ok(Idle),
            (CancellingConnect, OperationDone) => Ok(Cancelling),
            (Cancelling, CancelDone) => Ok(Idle),
            // A Disconnect abandoned early leaves the cancelled connect to unwind;
            // the advanced epoch still refuses its result.
            (CancellingConnect, CancelDone) => Ok(Connecting),
            (Protected, Cancel) => {
                Err("Wait for the current operation to finish before disconnecting.")
            }
            (CancellingConnect | Cancelling, Cancel) => Err("Disconnect is already in progress."),
            (CancellingConnect | Cancelling, AcquireConnect | AcquireProtected) => {
                Err("Wait for Disconnect to finish.")
            }
            (Connecting | Protected, AcquireConnect | AcquireProtected) => {
                Err("Another VPN operation is running. Try again when it finishes.")
            }
            // Guards make these unreachable; refusing keeps the state intact.
            (Idle, OperationDone | CancelDone)
            | (Connecting | Protected, CancelDone)
            | (Cancelling, OperationDone) => Err("The VPN operation state is inconsistent."),
        }
    }

    fn cancelling(self) -> bool {
        matches!(self, Gate::CancellingConnect | Gate::Cancelling)
    }
}

static GATE: AtomicU8 = AtomicU8::new(Gate::Idle as u8);
static EPOCH: AtomicU64 = AtomicU64::new(0);

pub fn gate() -> Gate {
    Gate::ALL[usize::from(GATE.load(Ordering::Acquire))]
}

/// One compare-and-swap per transition, so no observer sees a half-made change.
fn transition(event: GateEvent) -> Result<Gate, String> {
    let mut current = gate();
    loop {
        let next = current.next(event)?;
        match GATE.compare_exchange(
            current as u8,
            next as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                if event == GateEvent::Cancel {
                    // Inside the transition's success: no connect can pass
                    // `require_current` with the old epoch after this returns.
                    EPOCH.fetch_add(1, Ordering::AcqRel);
                }
                crate::local_status_stream::changed();
                return Ok(next);
            }
            Err(actual) => current = Gate::ALL[usize::from(actual)],
        }
    }
}

pub fn epoch() -> u64 {
    EPOCH.load(Ordering::Acquire)
}
pub fn require_current(expected: u64) -> Result<(), String> {
    if expected != epoch() || gate().cancelling() {
        Err("The connection was cancelled.".into())
    } else {
        Ok(())
    }
}
pub struct CancellationGuard;
impl CancellationGuard {
    /// Disconnect completes only after the cancelled connect has unwound.
    pub fn wait_for_connect(&self) {
        while gate() == Gate::CancellingConnect {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}
impl Drop for CancellationGuard {
    fn drop(&mut self) {
        let _ = transition(GateEvent::CancelDone);
    }
}
/// Honoured while a connect is starting: it is cancelled instead of refused.
pub fn cancel() -> Result<CancellationGuard, String> {
    transition(GateEvent::Cancel)?;
    crate::management_session::invalidate();
    Ok(CancellationGuard)
}

pub struct OperationGuard;
impl Drop for OperationGuard {
    fn drop(&mut self) {
        let _ = transition(GateEvent::OperationDone);
    }
}

/// A connect stays cancellable by Disconnect; other operations are protected.
pub fn acquire_connection() -> Result<OperationGuard, String> {
    transition(GateEvent::AcquireConnect)?;
    crate::management_session::invalidate();
    Ok(OperationGuard)
}

pub fn require_finished_rotation(paths: &ClientPaths, id: ServerId) -> Result<(), String> {
    if has_pending_key_rotation(paths, id).map_err(safe_error)? {
        return Err("Finish this device’s key rotation in Keys & recovery first.".into());
    }
    Ok(())
}

pub fn acquire() -> Result<OperationGuard, String> {
    transition(GateEvent::AcquireProtected)?;
    crate::management_session::invalidate();
    Ok(OperationGuard)
}

pub fn session_action(command: &str, expected: ServerId) -> Result<LocalTunnelStatus, String> {
    let current = invoke_helper("status", None).map_err(safe_error)?;
    if current.server_id != Some(expected) {
        return Err("The active connection changed. Check its status before trying again.".into());
    }
    if !current.connection_control_supported {
        return Err(
            "Update the VPN component in Settings first."
                .into(),
        );
    }
    let input = serde_json::to_vec(&expected).map_err(safe_error)?;
    invoke_helper(command, Some(&input)).map_err(safe_error)
}

pub fn confirmed_disconnected(status: &LocalTunnelStatus) -> bool {
    status.phase() == Some(sirinvpn_tunnel_model::TunnelPhase::Idle)
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
    .map_err(|_| "Reconnecting was interrupted. Check the connection status.".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_gate_transition_is_listed_and_a_starting_connect_is_cancellable() {
        use {Gate::*, GateEvent::*};
        let events = [AcquireConnect, AcquireProtected, Cancel, OperationDone, CancelDone];
        let allowed: Vec<_> = Gate::ALL
            .iter()
            .flat_map(|&gate| events.iter().map(move |&event| (gate, event)))
            .filter_map(|(gate, event)| gate.next(event).ok().map(|next| (gate, event, next)))
            .collect();
        assert_eq!(
            allowed,
            [
                (Idle, AcquireConnect, Connecting),
                (Idle, AcquireProtected, Protected),
                (Idle, Cancel, Cancelling),
                (Connecting, Cancel, CancellingConnect),
                (Connecting, OperationDone, Idle),
                (Protected, OperationDone, Idle),
                (CancellingConnect, OperationDone, Cancelling),
                (CancellingConnect, CancelDone, Connecting),
                (Cancelling, CancelDone, Idle),
            ]
        );
        assert!(Protected.next(Cancel).unwrap_err().contains("current operation"));
        for gate in Gate::ALL {
            assert_eq!(Gate::ALL[gate as usize], gate);
        }
    }
    #[test]
    fn cancellation_invalidates_connect_but_preserves_protected_operation_guards() {
        let operation = acquire_connection().unwrap();
        let started = epoch();
        let stop = cancel().unwrap();
        assert_eq!(gate(), Gate::CancellingConnect);
        assert!(require_current(started).is_err());
        assert!(acquire_connection().is_err());
        drop(operation);
        assert_eq!(gate(), Gate::Cancelling);
        stop.wait_for_connect();
        assert!(acquire_connection().is_err());
        drop(stop);
        let protected = acquire().unwrap();
        let before = epoch();
        assert!(cancel().is_err());
        assert_eq!(before, epoch());
        drop(protected);
        assert_eq!(gate(), Gate::Idle);
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
