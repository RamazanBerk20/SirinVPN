//! The rotation driver as a pure step function. The executor in `key_rotation.rs`
//! performs each step and reports what it observed; only this table decides what
//! happens next, so every crash and uncertain-commit path is enumerable without a VPS.
use super::RotationPhase;

/// Where a run stands: the persisted phase plus what this run already did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Progress {
    pub phase: RotationPhase,
    /// The journal existed before this run, so the tunnel may use either identity.
    pub resumed: bool,
    /// This run sent a commit; a lost response then means "outcome unknown".
    pub commit_sent: bool,
}

/// What the executor learned from its last step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Observation {
    Started,
    NewIdentityConfirmed,
    NewIdentityUnconfirmed,
    OldIdentityConfirmed,
    OldIdentityUnconfirmed,
    RotationSupported,
    RotationUnsupported,
    Prepared,
    PrepareUncertain,
    PrepareRejected,
    CommitSent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    /// Reconnect with the final identity and verify it with the VPS.
    ConnectNew,
    /// Reconnect with the original identity and verify it with the VPS.
    ConnectOld,
    /// A fresh rotation: the verified original identity is still connected.
    UseOld,
    /// Ask the VPS, through the original identity, whether it still rotates keys.
    CheckSupport,
    Prepare,
    /// Persist `Committing`, then commit through the transition identity.
    Commit,
    /// The final identity works: save it, delete the old secrets, drop the journal.
    Activate,
    /// The VPS refused preparation: delete the staged secrets and the journal.
    Abandon,
    /// The VPS kept the original identity: restore it locally and go back to `Prepared`.
    KeepOld,
    /// Stop and return the error the last step produced; the journal stays.
    Stop,
    Fail(Failure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    NeitherIdentityConfirmed,
    RotationUnsupported,
    PrepareUncertain,
    CommitUncertain,
    InvalidState,
}

impl Failure {
    /// Whether the profile goes back to the original identity, which the VPS may
    /// still accept, rather than keep a candidate that was never confirmed.
    pub(super) fn restores_original_identity(self) -> bool {
        matches!(self, Self::NeitherIdentityConfirmed | Self::CommitUncertain)
    }

    pub(super) fn message(self) -> Option<&'static str> {
        Some(match self {
            Self::NeitherIdentityConfirmed => {
                "neither the old nor new device identity could be confirmed; restore network access and run key rotation again"
            }
            Self::RotationUnsupported => {
                "the VPS no longer exposes the safe rotation protocol; repair/update the server, reconnect the old identity, and resume"
            }
            Self::PrepareUncertain => {
                "preparation may have reached the VPS; keep the local journal and run key rotation again"
            }
            Self::CommitUncertain => {
                "the commit result is uncertain and neither identity can currently reach the VPS; restore network access and run key rotation again"
            }
            Self::InvalidState => return None,
        })
    }
}

pub(super) fn next(progress: Progress, observation: Observation) -> Step {
    use Observation as O;
    use RotationPhase as P;
    let reach_old = || {
        if progress.resumed {
            Step::ConnectOld
        } else {
            Step::UseOld
        }
    };
    match observation {
        O::Started => match progress.phase {
            P::Committing | P::Activated => Step::ConnectNew,
            P::Staged | P::Prepared => reach_old(),
        },
        O::NewIdentityConfirmed => Step::Activate,
        O::NewIdentityUnconfirmed => match progress.phase {
            // The VPS already confirmed the new identity once; never fall back to the old one.
            P::Activated => Step::Stop,
            _ if progress.commit_sent => Step::ConnectOld,
            P::Staged | P::Prepared | P::Committing => reach_old(),
        },
        O::OldIdentityConfirmed if progress.commit_sent => Step::KeepOld,
        O::OldIdentityConfirmed => Step::CheckSupport,
        O::OldIdentityUnconfirmed if progress.commit_sent => Step::Fail(Failure::CommitUncertain),
        O::OldIdentityUnconfirmed => Step::Fail(Failure::NeitherIdentityConfirmed),
        O::RotationUnsupported => Step::Fail(Failure::RotationUnsupported),
        O::RotationSupported => match progress.phase {
            P::Staged | P::Prepared => Step::Prepare,
            // A resumed commit retries the same idempotent request.
            P::Committing => Step::Commit,
            P::Activated => Step::Fail(Failure::InvalidState),
        },
        O::Prepared => Step::Commit,
        O::PrepareUncertain => Step::Fail(Failure::PrepareUncertain),
        // Staged secrets are deleted only while no commit can have reached the VPS.
        O::PrepareRejected
            if progress.commit_sent || matches!(progress.phase, P::Committing | P::Activated) =>
        {
            Step::Fail(Failure::InvalidState)
        }
        O::PrepareRejected => Step::Abandon,
        O::CommitSent => Step::ConnectNew,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Observation as O;
    use RotationPhase as P;

    const PHASES: [RotationPhase; 4] = [P::Staged, P::Prepared, P::Committing, P::Activated];
    const OBSERVATIONS: [Observation; 11] = [
        O::Started,
        O::NewIdentityConfirmed,
        O::NewIdentityUnconfirmed,
        O::OldIdentityConfirmed,
        O::OldIdentityUnconfirmed,
        O::RotationSupported,
        O::RotationUnsupported,
        O::Prepared,
        O::PrepareUncertain,
        O::PrepareRejected,
        O::CommitSent,
    ];

    fn at(phase: RotationPhase, resumed: bool, commit_sent: bool) -> Progress {
        Progress {
            phase,
            resumed,
            commit_sent,
        }
    }

    #[test]
    fn every_state_and_observation_has_one_defined_step() {
        for phase in PHASES {
            for resumed in [false, true] {
                for commit_sent in [false, true] {
                    // Sending a commit always persists `Committing` first.
                    if commit_sent && phase != P::Committing {
                        continue;
                    }
                    for observation in OBSERVATIONS {
                        let step = next(at(phase, resumed, commit_sent), observation);
                        // Activation is only ever reached through a confirmed final identity.
                        assert_eq!(
                            step == Step::Activate,
                            observation == O::NewIdentityConfirmed,
                            "{phase:?} {resumed} {commit_sent} {observation:?}"
                        );
                        // After a commit may have reached the VPS, nothing deletes staged
                        // secrets; after one was sent, nothing skips verification.
                        if phase == P::Committing || phase == P::Activated {
                            assert_ne!(step, Step::Abandon);
                        }
                        if commit_sent {
                            assert!(!matches!(
                                step,
                                Step::Abandon | Step::UseOld | Step::CheckSupport
                            ));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn fresh_rotation_prepares_commits_and_verifies_the_new_identity() {
        let mut progress = at(P::Staged, false, false);
        assert_eq!(next(progress, O::Started), Step::UseOld);
        assert_eq!(next(progress, O::OldIdentityConfirmed), Step::CheckSupport);
        assert_eq!(next(progress, O::RotationSupported), Step::Prepare);
        progress.phase = P::Prepared;
        assert_eq!(next(progress, O::Prepared), Step::Commit);
        progress = at(P::Committing, false, true);
        assert_eq!(next(progress, O::CommitSent), Step::ConnectNew);
        assert_eq!(next(progress, O::NewIdentityConfirmed), Step::Activate);
    }

    #[test]
    fn commit_in_doubt_paths_never_lose_both_identities() {
        // Response lost, new identity unreachable: the old identity decides.
        let sent = at(P::Committing, false, true);
        assert_eq!(next(sent, O::NewIdentityUnconfirmed), Step::ConnectOld);
        // The VPS kept the old identity: restore it and retry the commit later.
        assert_eq!(next(sent, O::OldIdentityConfirmed), Step::KeepOld);
        // Neither answers: keep both candidates and restore the original locally.
        let failure = next(sent, O::OldIdentityUnconfirmed);
        assert_eq!(failure, Step::Fail(Failure::CommitUncertain));
        assert!(Failure::CommitUncertain.restores_original_identity());

        // A resumed Committing journal tries the new identity before anything else,
        let resumed = at(P::Committing, true, false);
        assert_eq!(next(resumed, O::Started), Step::ConnectNew);
        // then the old one, and re-sends the same idempotent commit.
        assert_eq!(next(resumed, O::NewIdentityUnconfirmed), Step::ConnectOld);
        assert_eq!(next(resumed, O::OldIdentityConfirmed), Step::CheckSupport);
        assert_eq!(next(resumed, O::RotationSupported), Step::Commit);
        assert_eq!(
            next(resumed, O::OldIdentityUnconfirmed),
            Step::Fail(Failure::NeitherIdentityConfirmed)
        );

        // Once activated, the old identity is never used again.
        let activated = at(P::Activated, true, false);
        assert_eq!(next(activated, O::Started), Step::ConnectNew);
        assert_eq!(next(activated, O::NewIdentityUnconfirmed), Step::Stop);
        assert_eq!(
            next(activated, O::RotationSupported),
            Step::Fail(Failure::InvalidState)
        );
    }

    #[test]
    fn preparation_outcomes_keep_or_abandon_the_stage_explicitly() {
        let progress = at(P::Staged, true, false);
        assert_eq!(next(progress, O::Started), Step::ConnectOld);
        assert_eq!(
            next(progress, O::PrepareUncertain),
            Step::Fail(Failure::PrepareUncertain)
        );
        assert!(!Failure::PrepareUncertain.restores_original_identity());
        assert_eq!(next(progress, O::PrepareRejected), Step::Abandon);
        assert_eq!(
            next(progress, O::RotationUnsupported),
            Step::Fail(Failure::RotationUnsupported)
        );
    }
}
