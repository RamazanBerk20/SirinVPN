//! Applied runtime policy uses the shared platform contract.
use super::*;

impl RuntimeState {
    pub(super) fn connection_policy(&self) -> ConnectionPolicy {
        self.policy
            .unwrap_or_else(|| ConnectionPolicy::legacy(self.persistent_protection))
    }
}
