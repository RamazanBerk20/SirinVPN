//! The helper's device-wide session as one explicit state.
//!
//! The runtime file keeps its four lifecycle fields (`has_connected`, `reconnecting`,
//! `waiting_for_user`, `initial_attempts`) so files written by older helpers stay
//! readable and older helpers can read ours. They are a projection of [`Session`]:
//! production code changes them only through the transitions below, and status
//! derives the published [`TunnelPhase`] from the session in one exhaustive match.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Session {
    /// No saved intent and no runtime state.
    Idle,
    /// Saved intent without runtime state: /run was wiped by a reboot and the session
    /// did not restart. Paused until Resume, Connect or Disconnect; a guard is held only
    /// when kill switch and connect-on-startup were both on.
    SavedIntent {
        server_id: ServerId,
    },
    /// Initial selection across the carrier/address plan; `attempt` counts tries.
    Selecting {
        server_id: ServerId,
        attempt: u8,
    },
    Connected {
        server_id: ServerId,
    },
    /// The tunnel was up and is being rebuilt.
    Recovering {
        server_id: ServerId,
        attempt: u8,
    },
    /// Attempts stopped; the policy's guard is held.
    Paused {
        server_id: ServerId,
        after_connect: bool,
    },
}

impl RuntimeState {
    /// The one place the lifecycle fields are interpreted. A paused flag wins over a
    /// reconnecting one, the only contradiction older files can hold.
    pub(super) fn session(&self) -> Session {
        let server_id = self.server_id;
        let attempt = self.initial_attempts;
        match (self.waiting_for_user, self.reconnecting, self.has_connected) {
            (true, _, after_connect) => Session::Paused {
                server_id,
                after_connect,
            },
            (false, true, false) => Session::Selecting { server_id, attempt },
            (false, true, true) => Session::Recovering { server_id, attempt },
            // Sessions without a policy never set `has_connected`: applied is connected.
            (false, false, _) => Session::Connected { server_id },
        }
    }

    fn enter(&mut self, session: Session) {
        let (waiting, reconnecting, connected, attempts) = match session {
            Session::Idle | Session::SavedIntent { .. } => {
                unreachable!("runtime state always belongs to a session")
            }
            Session::Selecting { attempt, .. } => (false, true, false, attempt),
            Session::Connected { .. } => (false, false, true, self.initial_attempts),
            Session::Recovering { attempt, .. } => (false, true, true, attempt),
            Session::Paused { after_connect, .. } => {
                (true, false, after_connect, self.initial_attempts)
            }
        };
        self.waiting_for_user = waiting;
        self.reconnecting = reconnecting;
        self.has_connected = connected;
        self.initial_attempts = attempts;
    }

    pub(super) fn confirm_handshake(&mut self) {
        let server_id = self.server_id;
        self.enter(Session::Connected { server_id });
    }

    /// The path is gone or being replaced; a pause is never lifted by it.
    pub(super) fn lose_path(&mut self) {
        let server_id = self.server_id;
        let attempt = self.initial_attempts;
        match self.session() {
            Session::Paused { .. } => {}
            Session::Selecting { .. } => self.enter(Session::Selecting { server_id, attempt }),
            _ => self.enter(Session::Recovering { server_id, attempt }),
        }
    }

    /// One more try from the plan, as part of selection or recovery.
    pub(super) fn begin_attempt(&mut self) {
        let attempt = self.initial_attempts.saturating_add(1);
        let server_id = self.server_id;
        match self.session() {
            Session::Connected { .. } | Session::Recovering { .. } => {
                self.enter(Session::Recovering { server_id, attempt })
            }
            _ => self.enter(Session::Selecting { server_id, attempt }),
        }
    }

    /// A new endpoint restarts the plan's count; a paused session stays paused.
    pub(super) fn restart_plan(&mut self) {
        self.initial_attempts = 1;
        if !matches!(self.session(), Session::Paused { .. }) {
            self.lose_path();
        }
    }

    pub(super) fn pause(&mut self) {
        let server_id = self.server_id;
        let after_connect = self.has_connected;
        self.enter(Session::Paused {
            server_id,
            after_connect,
        });
    }

    /// A legacy bundle adopted into a versioned policy keeps what it had reached.
    pub(super) fn adopt_legacy(&mut self) {
        let connected = !self.reconnecting;
        self.has_connected = connected;
        self.initial_attempts = 1;
    }
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    /// The session including what only the files say: saved intent without state.
    pub(super) fn session(&self) -> Session {
        if let Ok(state) = self.read_state() {
            return state.session();
        }
        match self.read_guard_spec() {
            Some(spec) if self.persistent_path().exists() => Session::SavedIntent {
                server_id: spec.server_id,
            },
            _ => Session::Idle,
        }
    }
}

impl Session {
    /// What status publishes. `vouched` is false when the helper cannot stand behind
    /// the session: a stale supervisor observation, or a missing interface.
    pub(super) fn phase(self, vouched: bool) -> TunnelPhase {
        match self {
            Self::Idle => TunnelPhase::Idle,
            Self::SavedIntent { server_id } | Self::Paused { server_id, .. } => {
                TunnelPhase::Paused { server_id }
            }
            Self::Selecting { server_id, .. } if vouched => TunnelPhase::Connecting { server_id },
            Self::Connected { server_id } if vouched => TunnelPhase::Connected { server_id },
            Self::Recovering { server_id, .. } if vouched => TunnelPhase::Recovering { server_id },
            Self::Selecting { server_id, .. } => TunnelPhase::Unhealthy {
                server_id,
                recovering: false,
            },
            Self::Connected { server_id } => TunnelPhase::Unhealthy {
                server_id,
                recovering: false,
            },
            Self::Recovering { server_id, .. } => TunnelPhase::Unhealthy {
                server_id,
                recovering: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> RuntimeState {
        RuntimeState::for_policy(&crate::tests::request())
    }

    #[test]
    fn every_flag_combination_is_one_session_and_round_trips() {
        for waiting in [false, true] {
            for reconnecting in [false, true] {
                for connected in [false, true] {
                    let mut state = state();
                    state.waiting_for_user = waiting;
                    state.reconnecting = reconnecting;
                    state.has_connected = connected;
                    state.initial_attempts = 2;
                    let session = state.session();
                    let mut projected = state.clone();
                    projected.enter(session);
                    assert_eq!(projected.session(), session);
                    // Writing a session never produces the contradictory pair.
                    assert!(!(projected.waiting_for_user && projected.reconnecting));
                }
            }
        }
    }

    #[test]
    fn transitions_follow_the_session_and_never_lift_a_pause() {
        let mut state = state();
        let server_id = state.server_id;
        // `for_policy` is fresh intent: the first selection pass.
        assert_eq!(
            state.session(),
            Session::Selecting {
                server_id,
                attempt: 0
            }
        );
        state.begin_attempt();
        assert_eq!(
            state.session(),
            Session::Selecting {
                server_id,
                attempt: 1
            }
        );
        state.confirm_handshake();
        assert_eq!(state.session(), Session::Connected { server_id });
        state.lose_path();
        assert_eq!(
            state.session(),
            Session::Recovering {
                server_id,
                attempt: 1
            }
        );
        state.begin_attempt();
        assert_eq!(
            state.session(),
            Session::Recovering {
                server_id,
                attempt: 2
            }
        );
        state.pause();
        let paused = Session::Paused {
            server_id,
            after_connect: true,
        };
        assert_eq!(state.session(), paused);
        state.lose_path();
        state.restart_plan();
        assert_eq!(state.session(), paused);
    }

    #[test]
    fn published_phases_agree_with_the_session() {
        let server_id = ServerId::new();
        let cases = [
            (Session::Idle, true, TunnelPhase::Idle),
            (
                Session::SavedIntent { server_id },
                true,
                TunnelPhase::Paused { server_id },
            ),
            (
                Session::Selecting {
                    server_id,
                    attempt: 0,
                },
                true,
                TunnelPhase::Connecting { server_id },
            ),
            (
                Session::Recovering {
                    server_id,
                    attempt: 1,
                },
                false,
                TunnelPhase::Unhealthy {
                    server_id,
                    recovering: true,
                },
            ),
            (
                Session::Paused {
                    server_id,
                    after_connect: true,
                },
                false,
                TunnelPhase::Paused { server_id },
            ),
        ];
        for (session, vouched, phase) in cases {
            assert_eq!(session.phase(vouched), phase);
            let mut status = disconnected_status();
            status.set_phase(phase);
            assert_eq!(status.phase(), Some(phase));
        }
    }

    /// Only this module writes the lifecycle fields, so they cannot drift from `Session`.
    #[test]
    fn production_code_changes_the_lifecycle_only_through_session_transitions() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![source];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                for entry in fs::read_dir(&path).unwrap() {
                    stack.push(entry.unwrap().path());
                }
                continue;
            }
            let name = path.to_string_lossy();
            if !name.ends_with(".rs") || name.ends_with("session.rs") || name.contains("test") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            for field in [
                "has_connected",
                "reconnecting",
                "waiting_for_user",
                "initial_attempts",
            ] {
                assert!(
                    !text
                        .match_indices(&format!(".{field} ="))
                        .any(|(at, found)| text[at + found.len()..].starts_with(' ')),
                    "{name} writes `{field}` directly"
                );
            }
        }
    }
}
