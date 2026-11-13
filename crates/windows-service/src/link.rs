//! The controller's runtime connection state, beside the persisted `SessionPhase`.
//! Each variant carries only what is true in it, so an adapter without a running
//! attempt, or a failed enforcement with a live adapter, cannot be represented.
//! `A` is the live adapter payload; tests use `()`.
use crate::state::SessionPhase;
use sirinvpn_protocol::ServerId;
use sirinvpn_tunnel_model::TunnelPhase;
use std::time::{Duration, Instant};

pub(crate) const RETRY_DELAY: Duration = Duration::from_secs(1);
pub(crate) const PASS_WINDOW: Duration = Duration::from_secs(90);

/// Position in the endpoint x transport candidate list and the pass backoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Attempts {
    pub index: usize,
    pub retry_passes: u32,
    pub next_attempt: Instant,
    pub pass_started: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Link<A> {
    /// No adapter and no attempts: no session, Held, or a pending Disconnect.
    Stopped { enforcement_failed: bool },
    /// Attempts run; `trial` is the adapter of the current one, if started.
    /// `recovering` once an established tunnel lost its path.
    Connecting {
        attempts: Attempts,
        recovering: bool,
        trial: Option<A>,
    },
    /// A handshake confirmed the trial of candidate `attempt`.
    Connected { attempt: usize, active: A },
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Event<A> {
    /// Connect, Resume, Reconnect or a new endpoint: fresh attempts.
    Start,
    /// Held, Disconnecting, or an enforcement/storage failure.
    Stop {
        enforcement_failed: bool,
    },
    TrialStarted(A),
    /// The current trial could not start or missed its handshake window.
    TrialFailed,
    Handshake,
    /// An established tunnel failed; its own candidate is retried first.
    PathLost,
    /// Every candidate of this pass failed; back off and start a new pass.
    PassExhausted,
    /// Quality optimization moves to another transport of the same endpoint.
    Select {
        index: usize,
    },
}

impl<A> Link<A> {
    /// The only transition function. Returns the new state and the adapter it
    /// displaced, which the caller must stop. An event that does not apply leaves
    /// the state unchanged (and hands back any adapter the event carried).
    pub(crate) fn next(self, event: Event<A>, now: Instant) -> (Self, Option<A>) {
        use Event as E;
        match (self, event) {
            (link, E::Start) => (Self::connecting(fresh(now, 0), false), link.into_active()),
            (link, E::Stop { enforcement_failed }) => {
                (Self::Stopped { enforcement_failed }, link.into_active())
            }
            (
                Self::Connecting {
                    attempts,
                    recovering,
                    trial,
                },
                E::TrialStarted(active),
            ) => (
                Self::Connecting {
                    attempts,
                    recovering,
                    trial: Some(active),
                },
                trial,
            ),
            (
                Self::Connecting {
                    attempts,
                    trial: Some(active),
                    ..
                },
                E::Handshake,
            ) => (
                Self::Connected {
                    attempt: attempts.index,
                    active,
                },
                None,
            ),
            (
                Self::Connecting {
                    mut attempts,
                    recovering,
                    trial,
                },
                E::TrialFailed,
            ) => {
                attempts.index += 1;
                attempts.next_attempt = now + RETRY_DELAY;
                (Self::connecting(attempts, recovering), trial)
            }
            (Self::Connected { attempt, active }, E::PathLost) => {
                let mut attempts = fresh(now, attempt);
                attempts.next_attempt = now + RETRY_DELAY;
                (Self::connecting(attempts, true), Some(active))
            }
            (
                Self::Connecting {
                    mut attempts,
                    recovering,
                    trial: None,
                },
                E::PassExhausted,
            ) => {
                attempts.retry_passes = attempts.retry_passes.saturating_add(1);
                let delay = 5u64
                    .saturating_mul(1u64 << attempts.retry_passes.min(4).saturating_sub(1))
                    .min(60);
                attempts.next_attempt = now + Duration::from_secs(delay);
                attempts.pass_started = attempts.next_attempt;
                attempts.index = 0;
                (Self::connecting(attempts, recovering), None)
            }
            (Self::Connected { active, .. }, E::Select { index }) => {
                (Self::connecting(fresh(now, index), true), Some(active))
            }
            (
                Self::Connecting {
                    attempts,
                    recovering,
                    trial,
                },
                E::Select { index },
            ) => (
                Self::connecting(
                    Attempts {
                        index,
                        next_attempt: now,
                        pass_started: now,
                        ..attempts
                    },
                    recovering,
                ),
                trial,
            ),
            (link, E::TrialStarted(active)) => (link, Some(active)),
            (link, _) => (link, None),
        }
    }

    fn connecting(attempts: Attempts, recovering: bool) -> Self {
        Self::Connecting {
            attempts,
            recovering,
            trial: None,
        }
    }

    fn into_active(self) -> Option<A> {
        match self {
            Self::Stopped { .. } => None,
            Self::Connecting { trial, .. } => trial,
            Self::Connected { active, .. } => Some(active),
        }
    }

    pub(crate) fn active(&self) -> Option<&A> {
        match self {
            Self::Stopped { .. } => None,
            Self::Connecting { trial, .. } => trial.as_ref(),
            Self::Connected { active, .. } => Some(active),
        }
    }

    pub(crate) fn active_mut(&mut self) -> Option<&mut A> {
        match self {
            Self::Stopped { .. } => None,
            Self::Connecting { trial, .. } => trial.as_mut(),
            Self::Connected { active, .. } => Some(active),
        }
    }

    pub(crate) fn connected(&self) -> Option<&A> {
        match self {
            Self::Connected { active, .. } => Some(active),
            _ => None,
        }
    }

    pub(crate) fn enforcement_failed(&self) -> bool {
        matches!(
            self,
            Self::Stopped {
                enforcement_failed: true
            }
        )
    }

    /// The candidate in use or being tried.
    pub(crate) fn attempt(&self) -> usize {
        match self {
            Self::Stopped { .. } => 0,
            Self::Connecting { attempts, .. } => attempts.index,
            Self::Connected { attempt, .. } => *attempt,
        }
    }

    /// Whether this session already used up a first attempt, so a policy without
    /// automatic reconnect does not start background endpoint discovery.
    pub(crate) fn tried(&self) -> bool {
        match self {
            Self::Stopped { .. } => false,
            Self::Connecting {
                attempts,
                recovering,
                ..
            } => *recovering || attempts.index > 0,
            Self::Connected { .. } => true,
        }
    }

    /// Attempts waiting for their next start, if one is due now.
    pub(crate) fn due(&self, now: Instant) -> Option<Attempts> {
        match self {
            Self::Connecting {
                attempts,
                trial: None,
                ..
            } if now >= attempts.next_attempt => Some(*attempts),
            _ => None,
        }
    }
}

impl Attempts {
    pub(crate) fn exhausted(&self, count: usize, now: Instant) -> bool {
        count == 0
            || self.index >= count
            || now.saturating_duration_since(self.pass_started) >= PASS_WINDOW
    }
}

fn fresh(now: Instant, index: usize) -> Attempts {
    Attempts {
        index,
        retry_passes: 0,
        next_attempt: now,
        pass_started: now,
    }
}

/// Health facts the published phase needs beyond the state itself.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Observation {
    /// The owned filters match the plan (or are absent when they should be).
    pub verified: bool,
    /// The connected adapter still reports statistics and its carrier runs.
    pub carrying: bool,
}

/// The published lifecycle of a saved session. Only a session that was up and
/// lost its path is `Recovering`; first attempts are `Connecting`.
pub(crate) fn tunnel_phase<A>(
    server_id: ServerId,
    saved: SessionPhase,
    link: &Link<A>,
    observed: Observation,
) -> TunnelPhase {
    let recovering = matches!(
        link,
        Link::Connecting {
            recovering: true,
            ..
        } | Link::Connected { .. }
    );
    match (saved, link) {
        (SessionPhase::Held, _) => TunnelPhase::Paused { server_id },
        // A Disconnect that could not finish yet is retried on every tick.
        (SessionPhase::Disconnecting, _) => TunnelPhase::Unhealthy {
            server_id,
            recovering: false,
        },
        (_, Link::Stopped { .. }) => TunnelPhase::Unhealthy {
            server_id,
            recovering: false,
        },
        _ if !observed.verified => TunnelPhase::Unhealthy {
            server_id,
            recovering,
        },
        (_, Link::Connected { .. }) if observed.carrying => TunnelPhase::Connected { server_id },
        _ if recovering => TunnelPhase::Recovering { server_id },
        _ => TunnelPhase::Connecting { server_id },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64, base: Instant) -> Instant {
        base + Duration::from_secs(seconds)
    }

    fn start(now: Instant) -> Link<u8> {
        Link::Stopped {
            enforcement_failed: false,
        }
        .next(Event::Start, now)
        .0
    }

    #[test]
    fn first_attempts_advance_and_a_handshake_connects_the_tried_candidate() {
        let now = Instant::now();
        let link = start(now);
        assert_eq!(link.due(now).unwrap().index, 0);
        let (link, displaced) = link.next(Event::TrialStarted(7), now);
        assert_eq!(displaced, None);
        assert!(link.due(now).is_none(), "a running trial is not restarted");
        let (link, displaced) = link.next(Event::TrialFailed, now);
        assert_eq!(
            displaced,
            Some(7),
            "the failed trial's adapter is handed back"
        );
        assert!(link.due(now).is_none());
        let attempts = link.due(at(1, now)).unwrap();
        assert_eq!(attempts.index, 1);
        let (link, _) = link.next(Event::TrialStarted(8), now);
        let (link, displaced) = link.next(Event::Handshake, now);
        assert_eq!(displaced, None);
        assert_eq!(
            link,
            Link::Connected {
                attempt: 1,
                active: 8
            }
        );
        assert!(link.tried());
    }

    #[test]
    fn a_lost_path_retries_the_working_candidate_and_is_recovering() {
        let now = Instant::now();
        let (link, _) = start(now).next(Event::TrialFailed, now);
        let (link, _) = link.next(Event::TrialStarted(1), now);
        let (link, _) = link.next(Event::Handshake, now);
        let (link, displaced) = link.next(Event::PathLost, at(5, now));
        assert_eq!(displaced, Some(1));
        let Link::Connecting {
            attempts,
            recovering: true,
            trial: None,
        } = link
        else {
            panic!("{link:?}")
        };
        assert_eq!(attempts.index, 1);
        assert_eq!(attempts.retry_passes, 0);
        assert_eq!(attempts.next_attempt, at(6, now));
        // Further failures keep the recovering cause until a handshake.
        let (link, _) = link.next(Event::TrialFailed, at(6, now));
        assert!(matches!(
            link,
            Link::Connecting {
                recovering: true,
                ..
            }
        ));
    }

    #[test]
    fn exhausted_passes_back_off_and_restart_the_candidate_list() {
        let now = Instant::now();
        let mut link = start(now);
        let mut delays = Vec::new();
        for pass in 0..6 {
            let (next, _) = link.next(Event::PassExhausted, at(pass * 100, now));
            let Link::Connecting { attempts, .. } = &next else {
                panic!()
            };
            assert_eq!(attempts.index, 0);
            assert_eq!(attempts.pass_started, attempts.next_attempt);
            delays.push(
                attempts
                    .next_attempt
                    .duration_since(at(pass * 100, now))
                    .as_secs(),
            );
            link = next;
        }
        assert_eq!(delays, [5, 10, 20, 40, 40, 40]);
        let attempts = Attempts {
            index: 2,
            retry_passes: 0,
            next_attempt: now,
            pass_started: now,
        };
        assert!(attempts.exhausted(2, now));
        assert!(attempts.exhausted(0, now));
        assert!(!attempts.exhausted(3, now));
        assert!(attempts.exhausted(3, now + PASS_WINDOW));
    }

    #[test]
    fn stopping_releases_any_adapter_and_failure_is_only_representable_while_stopped() {
        let now = Instant::now();
        let (link, _) = start(now).next(Event::TrialStarted(3), now);
        let (link, displaced) = link.next(
            Event::Stop {
                enforcement_failed: true,
            },
            now,
        );
        assert_eq!(displaced, Some(3));
        assert!(link.enforcement_failed());
        assert!(link.active().is_none());
        // Starting again clears the failure.
        let (link, _) = link.next(Event::Start, now);
        assert!(!link.enforcement_failed());
        assert!(!link.tried());
    }

    #[test]
    fn events_that_do_not_apply_leave_the_state_and_return_carried_adapters() {
        let now = Instant::now();
        let stopped = Link::<u8>::Stopped {
            enforcement_failed: false,
        };
        let (link, displaced) = stopped.next(Event::TrialStarted(9), now);
        assert_eq!(displaced, Some(9));
        assert!(matches!(link, Link::Stopped { .. }));
        for event in [
            Event::Handshake,
            Event::PathLost,
            Event::TrialFailed,
            Event::PassExhausted,
        ] {
            let (same, displaced) = Link::<u8>::Stopped {
                enforcement_failed: false,
            }
            .next(event, now);
            assert!(matches!(same, Link::Stopped { .. }) && displaced.is_none());
        }
        // A handshake needs a trial; a pass cannot end while a trial runs.
        let (link, _) = start(now).next(Event::Handshake, now);
        assert!(matches!(link, Link::Connecting { trial: None, .. }));
        let (link, _) = link.next(Event::TrialStarted(1), now);
        let (link, displaced) = link.next(Event::PassExhausted, now);
        assert!(displaced.is_none() && link.active() == Some(&1));
    }

    #[test]
    fn quality_selection_moves_to_the_chosen_candidate_now() {
        let now = Instant::now();
        let (link, _) = start(now).next(Event::TrialStarted(1), now);
        let (link, _) = link.next(Event::Handshake, now);
        let (link, displaced) = link.next(Event::Select { index: 3 }, at(9, now));
        assert_eq!(displaced, Some(1));
        assert_eq!(link.due(at(9, now)).unwrap().index, 3);
        assert_eq!(link.attempt(), 3);
    }

    #[test]
    fn published_phase_distinguishes_first_attempts_from_recovery() {
        let id = ServerId::new();
        let now = Instant::now();
        let good = Observation {
            verified: true,
            carrying: true,
        };
        let first = start(now);
        assert_eq!(
            tunnel_phase(id, SessionPhase::Connecting, &first, good),
            TunnelPhase::Connecting { server_id: id }
        );
        let (trial, _) = first.clone().next(Event::TrialStarted(1), now);
        assert_eq!(
            tunnel_phase(id, SessionPhase::Connecting, &trial, good),
            TunnelPhase::Connecting { server_id: id }
        );
        let (up, _) = trial.next(Event::Handshake, now);
        assert_eq!(
            tunnel_phase(id, SessionPhase::Active, &up, good),
            TunnelPhase::Connected { server_id: id }
        );
        // The carrier ended between ticks: the tunnel was up, so this is recovery.
        let stale = Observation {
            verified: true,
            carrying: false,
        };
        assert_eq!(
            tunnel_phase(id, SessionPhase::Active, &up, stale),
            TunnelPhase::Recovering { server_id: id }
        );
        let (lost, _) = up.next(Event::PathLost, now);
        assert_eq!(
            tunnel_phase(id, SessionPhase::Connecting, &lost, good),
            TunnelPhase::Recovering { server_id: id }
        );
        let broken = Observation {
            verified: false,
            carrying: false,
        };
        assert_eq!(
            tunnel_phase(id, SessionPhase::Connecting, &lost, broken),
            TunnelPhase::Unhealthy {
                server_id: id,
                recovering: true
            }
        );
        assert_eq!(
            tunnel_phase(id, SessionPhase::Connecting, &first, broken),
            TunnelPhase::Unhealthy {
                server_id: id,
                recovering: false
            }
        );
        let (held, _) = lost.clone().next(
            Event::Stop {
                enforcement_failed: true,
            },
            now,
        );
        assert_eq!(
            tunnel_phase(id, SessionPhase::Held, &held, broken),
            TunnelPhase::Paused { server_id: id }
        );
        assert_eq!(
            tunnel_phase(id, SessionPhase::Disconnecting, &held, good),
            TunnelPhase::Unhealthy {
                server_id: id,
                recovering: false
            }
        );
        // Every derived phase projects to flags the shared model reads back.
        for phase in [
            tunnel_phase(id, SessionPhase::Connecting, &lost, good),
            tunnel_phase(id, SessionPhase::Held, &held, good),
        ] {
            let mut status = crate::tests::idle_status();
            status.set_phase(phase);
            assert_eq!(status.phase(), Some(phase));
        }
    }
}
