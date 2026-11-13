//! The current status snapshot shared by the controller and pipe readers.
//! Readers never block the controller: the watch value is replaced, never
//! borrowed across an await, and `changed()` wakes status waiters.
use crate::{MAX_WAIT_MS, Operation, ServiceError, StatusWait, state::authorize};
use sirinvpn_tunnel_model::LocalTunnelStatus;
use std::time::Duration;
use tokio::sync::watch;

pub(crate) type SharedStatus = watch::Receiver<PublishedStatus>;

pub(crate) struct PublishedStatus {
    pub owner: Option<String>,
    pub status: LocalTunnelStatus,
    /// Advances whenever owner or status changes; a random start keeps a token
    /// from an earlier service process from matching this one.
    pub sequence: u64,
}

impl PublishedStatus {
    pub(crate) fn channel(status: LocalTunnelStatus) -> watch::Sender<Self> {
        watch::Sender::new(Self {
            owner: None,
            status,
            sequence: uuid::Uuid::new_v4().as_u64_pair().0,
        })
    }

    /// The status, if `caller` may run `operation` on this session. Checked before the
    /// service cancels anything, so a non-owner Administrator cannot interrupt the owner's
    /// in-flight operation with a request it is then refused.
    pub(crate) fn for_user(
        &self,
        caller: &str,
        administrator: bool,
        operation: &Operation,
    ) -> Result<LocalTunnelStatus, ServiceError> {
        authorize(self.owner.as_deref(), caller, administrator, operation)?;
        Ok(self.status.clone())
    }
}

/// Only a real change wakes status waiters and advances their token.
pub(crate) fn publish(
    sender: &watch::Sender<PublishedStatus>,
    owner: Option<String>,
    status: LocalTunnelStatus,
) {
    sender.send_if_modified(|current| {
        if current.owner == owner && current.status == status {
            return false;
        }
        current.owner = owner;
        current.status = status;
        current.sequence = current.sequence.wrapping_add(1);
        true
    });
}

/// Answers once the published status is not the one numbered `after`, or at the
/// deadline with the current one. Ownership is checked again on every wake.
pub(crate) async fn wait_for_change(
    caller: &str,
    administrator: bool,
    wait: StatusWait,
    mut status: SharedStatus,
) -> Result<(u64, LocalTunnelStatus), ServiceError> {
    let deadline = tokio::time::Instant::now() + wait_limit(wait.timeout_ms);
    loop {
        let current = {
            let published = status.borrow_and_update();
            (
                published.sequence,
                published.for_user(caller, administrator, &Operation::Status)?,
            )
        };
        if wait.after != Some(current.0) {
            return Ok(current);
        }
        match tokio::time::timeout_at(deadline, status.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(ServiceError::Unavailable),
            Err(_) => return Ok(current),
        }
    }
}

fn wait_limit(timeout_ms: u32) -> Duration {
    Duration::from_millis(u64::from(timeout_ms.min(MAX_WAIT_MS)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::idle_status;

    const OWNER: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";

    fn wait(after: Option<u64>, timeout_ms: u32) -> StatusWait {
        StatusWait { after, timeout_ms }
    }

    #[test]
    fn a_non_owner_administrator_is_refused_before_anything_is_cancelled() {
        let sender = PublishedStatus::channel(idle_status());
        publish(&sender, Some(OWNER.to_owned()), idle_status());
        let published = sender.borrow();
        for allowed in [Operation::Status, Operation::Disconnect] {
            assert!(published.for_user(OTHER, true, &allowed).is_ok());
        }
        let id = sirinvpn_protocol::ServerId::new();
        for refused in [Operation::Resume(id), Operation::ReconnectSession(id)] {
            assert!(matches!(
                published.for_user(OTHER, true, &refused),
                Err(ServiceError::OwnedByAnotherUser)
            ));
        }
        assert!(
            published
                .for_user(OTHER, false, &Operation::Disconnect)
                .is_err()
        );
        assert!(
            published
                .for_user(OWNER, false, &Operation::Resume(id))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn waiters_wake_on_a_real_change_and_otherwise_time_out() {
        let sender = PublishedStatus::channel(idle_status());
        let (first, _) = wait_for_change(OWNER, false, wait(None, 0), sender.subscribe())
            .await
            .unwrap();
        // An unchanged publish does not advance the token or wake anyone.
        publish(&sender, None, idle_status());
        let (same, _) = wait_for_change(OWNER, false, wait(Some(first), 50), sender.subscribe())
            .await
            .unwrap();
        assert_eq!(same, first);
        // A stale token answers at once.
        let (now, _) = wait_for_change(
            OWNER,
            false,
            wait(Some(first ^ 1), 1000),
            sender.subscribe(),
        )
        .await
        .unwrap();
        assert_eq!(now, first);
        let waiter = tokio::spawn(wait_for_change(
            OWNER,
            false,
            wait(Some(first), 30_000),
            sender.subscribe(),
        ));
        tokio::task::yield_now().await;
        let mut changed = idle_status();
        changed.rx_bytes = 1;
        publish(&sender, Some(OWNER.into()), changed.clone());
        let (next, status) = waiter.await.unwrap().unwrap();
        assert_eq!(next, first.wrapping_add(1));
        assert_eq!(status, changed);
    }

    #[tokio::test]
    async fn waiters_follow_status_ownership_and_never_exceed_the_cap() {
        let sender = PublishedStatus::channel(idle_status());
        let token = sender.borrow().sequence;
        let other = tokio::spawn(wait_for_change(
            OTHER,
            false,
            wait(Some(token), u32::MAX),
            sender.subscribe(),
        ));
        let admin = tokio::spawn(wait_for_change(
            OTHER,
            true,
            wait(Some(token), u32::MAX),
            sender.subscribe(),
        ));
        tokio::task::yield_now().await;
        publish(&sender, Some(OWNER.into()), idle_status());
        // Another user's session ends the wait with the same error Status gives.
        assert!(matches!(
            other.await.unwrap(),
            Err(ServiceError::OwnedByAnotherUser)
        ));
        assert!(admin.await.unwrap().is_ok());
        assert_eq!(wait_limit(u32::MAX), Duration::from_secs(30));
        assert_eq!(wait_limit(250), Duration::from_millis(250));
    }
}
