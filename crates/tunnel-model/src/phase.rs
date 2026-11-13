//! The local tunnel lifecycle as one explicit state. `LocalTunnelStatus` keeps its
//! legacy lifecycle flags for older peers; they are a projection of this phase, and
//! a snapshot whose flags no phase produces has no phase at all.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TunnelPhase {
    /// No session: nothing is routed or held for any server.
    Idle,
    /// The first attempts to reach the server since connect or resume.
    Connecting { server_id: ServerId },
    /// The tunnel is up and its handshake is current.
    Connected { server_id: ServerId },
    /// The tunnel was up, the path was lost, and the policy is reconnecting.
    Recovering { server_id: ServerId },
    /// Attempts stopped until Resume or Disconnect (the legacy `waiting_for_user`). The
    /// phase does not say whether traffic is blocked: saved intent after a reboot with
    /// connect-on-startup off has no guard. Read `kill_switch_state` for that.
    Paused { server_id: ServerId },
    /// The service cannot vouch for the session (a stale observation or failed
    /// enforcement); `recovering` says whether a reconnect is also running.
    Unhealthy {
        server_id: ServerId,
        recovering: bool,
    },
}

/// What a producer observed or was asked to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelEvent {
    Connect { server_id: ServerId },
    HandshakeConfirmed,
    PathLost,
    AttemptsExhausted,
    Pause,
    Resume,
    ObservationLost,
    ObservationRestored,
    Disconnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("the tunnel cannot handle {event:?} while {from:?}")]
pub struct IllegalTransition {
    pub from: TunnelPhase,
    pub event: TunnelEvent,
}

/// The lifecycle fields of `LocalTunnelStatus` that older clients and services read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyLifecycle {
    pub state: ConnectionState,
    pub server_id: Option<ServerId>,
    pub waiting_for_user: bool,
    pub recovery_in_progress: bool,
}

impl TunnelPhase {
    pub fn server_id(self) -> Option<ServerId> {
        match self {
            Self::Idle => None,
            Self::Connecting { server_id }
            | Self::Connected { server_id }
            | Self::Recovering { server_id }
            | Self::Paused { server_id }
            | Self::Unhealthy { server_id, .. } => Some(server_id),
        }
    }

    /// The only transition function. Pure: producers feed it what they observed and
    /// publish the result; anything not listed here is a bug in the producer.
    pub fn next(self, event: TunnelEvent) -> Result<Self, IllegalTransition> {
        use TunnelEvent as E;
        let illegal = Err(IllegalTransition { from: self, event });
        let Some(server_id) = self.server_id() else {
            return match event {
                E::Connect { server_id } => Ok(Self::Connecting { server_id }),
                E::Disconnect | E::ObservationLost | E::ObservationRestored => Ok(self),
                _ => illegal,
            };
        };
        let to_connecting = Self::Connecting { server_id };
        let to_connected = Self::Connected { server_id };
        let to_recovering = Self::Recovering { server_id };
        let to_paused = Self::Paused { server_id };
        Ok(match (self, event) {
            (_, E::Disconnect) => Self::Idle,
            // Switching servers is an explicit Disconnect followed by Connect.
            (_, E::Connect { server_id: other }) if other != server_id => return illegal,
            (Self::Paused { .. }, E::Connect { .. } | E::Resume) => to_connecting,
            (Self::Paused { .. }, E::HandshakeConfirmed) => return illegal,
            // A held block stays held whatever the path or supervisor does.
            (Self::Paused { .. }, _) => to_paused,
            (_, E::Connect { .. }) => self,
            (_, E::Resume) => return illegal,
            (_, E::Pause) => to_paused,
            (_, E::HandshakeConfirmed) => to_connected,
            (Self::Connected { .. }, E::AttemptsExhausted) => return illegal,
            (_, E::AttemptsExhausted) => to_paused,
            (Self::Connected { .. } | Self::Recovering { .. }, E::PathLost) => to_recovering,
            (Self::Connecting { .. }, E::PathLost) => to_connecting,
            (Self::Unhealthy { .. }, E::PathLost) => Self::Unhealthy {
                server_id,
                recovering: true,
            },
            (Self::Connected { .. }, E::ObservationLost) => Self::Unhealthy {
                server_id,
                recovering: false,
            },
            (Self::Connecting { .. } | Self::Recovering { .. }, E::ObservationLost) => {
                Self::Unhealthy {
                    server_id,
                    recovering: true,
                }
            }
            (Self::Unhealthy { recovering, .. }, E::ObservationRestored) => {
                if recovering {
                    to_recovering
                } else {
                    to_connected
                }
            }
            (_, E::ObservationLost | E::ObservationRestored) => self,
            (Self::Idle, E::PathLost) => return illegal,
        })
    }

    pub fn legacy(self) -> LegacyLifecycle {
        let (state, waiting_for_user, recovery_in_progress) = match self {
            Self::Idle => (ConnectionState::Disconnected, false, false),
            Self::Connecting { .. } => (ConnectionState::Connecting, false, false),
            Self::Connected { .. } => (ConnectionState::Connected, false, false),
            Self::Recovering { .. } => (ConnectionState::Connecting, false, true),
            Self::Paused { .. } => (ConnectionState::Degraded, true, false),
            Self::Unhealthy { recovering, .. } => (ConnectionState::Degraded, false, recovering),
        };
        LegacyLifecycle {
            state,
            server_id: self.server_id(),
            waiting_for_user,
            recovery_in_progress,
        }
    }

    /// The inverse of [`TunnelPhase::legacy`], for snapshots from services that do not
    /// publish a phase yet. Flag combinations no phase produces return `None`.
    pub fn from_legacy(legacy: &LegacyLifecycle) -> Option<Self> {
        let phase = match (&legacy.state, legacy.server_id) {
            (ConnectionState::Disconnected, None) => Self::Idle,
            (ConnectionState::Disconnected, Some(_)) | (_, None) => return None,
            (ConnectionState::Connecting, Some(server_id)) if legacy.recovery_in_progress => {
                Self::Recovering { server_id }
            }
            (ConnectionState::Connecting, Some(server_id)) => Self::Connecting { server_id },
            (ConnectionState::Connected, Some(server_id)) => Self::Connected { server_id },
            (ConnectionState::Degraded, Some(server_id)) if legacy.waiting_for_user => {
                Self::Paused { server_id }
            }
            (ConnectionState::Degraded, Some(server_id)) => Self::Unhealthy {
                server_id,
                recovering: legacy.recovery_in_progress,
            },
        };
        (phase.legacy() == *legacy).then_some(phase)
    }
}

impl LocalTunnelStatus {
    /// The lifecycle phase of this snapshot, or `None` when an older or faulty service
    /// sent lifecycle flags that contradict each other.
    pub fn phase(&self) -> Option<TunnelPhase> {
        TunnelPhase::from_legacy(&self.legacy_lifecycle())
    }

    /// Producers set the lifecycle only here, so the legacy flags always agree.
    pub fn set_phase(&mut self, phase: TunnelPhase) {
        let legacy = phase.legacy();
        self.state = legacy.state;
        self.server_id = legacy.server_id;
        self.waiting_for_user = legacy.waiting_for_user;
        self.recovery_in_progress = legacy.recovery_in_progress;
    }

    fn legacy_lifecycle(&self) -> LegacyLifecycle {
        LegacyLifecycle {
            state: self.state.clone(),
            server_id: self.server_id,
            waiting_for_user: self.waiting_for_user,
            recovery_in_progress: self.recovery_in_progress,
        }
    }
}

#[cfg(test)]
mod tests;
