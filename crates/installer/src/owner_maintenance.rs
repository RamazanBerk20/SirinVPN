//! One rule set for when an Owner device may run VPS maintenance, so every
//! command and app blocks for the same reasons with the same words.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerMaintenance {
    Repair,
    Uninstall,
    Backup,
    Restore,
    ReleaseInstall,
    SignedBaseline,
}

/// What this device knows about itself and the selected profile.
#[derive(Clone, Copy, Debug)]
pub struct OwnerDeviceState {
    pub role: ServerRole,
    pub disconnected: bool,
    pub kill_switch_enabled: bool,
    pub auto_reconnect_enabled: bool,
    pub pending_key_rotation: bool,
    /// The transaction journal still names an unresolved transaction.
    pub unresolved_transaction: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceBlocker {
    NotOwner,
    Connected,
    /// The kill switch or auto-reconnect would fight services the VPS restarts.
    PersistentPolicy,
    PendingKeyRotation,
    UnresolvedTransaction,
}

impl MaintenanceBlocker {
    pub fn message(self) -> &'static str {
        match self {
            Self::NotOwner => "only the Owner device can maintain this VPS",
            Self::Connected => "disconnect from this VPS first",
            Self::PersistentPolicy => "turn off the kill switch and auto-reconnect first",
            Self::PendingKeyRotation => {
                "complete or recover this device's pending key rotation first"
            }
            Self::UnresolvedTransaction => {
                "resolve the interrupted VPS maintenance transaction first"
            }
        }
    }
}

/// Every blocker for `operation`, in the order the Owner should clear them.
pub fn owner_maintenance_ready(
    operation: OwnerMaintenance,
    state: &OwnerDeviceState,
) -> Result<(), Vec<MaintenanceBlocker>> {
    // A backup only reads VPS state; everything else restarts VPS services.
    let restarts_services = operation != OwnerMaintenance::Backup;
    let blockers = [
        (
            state.role != ServerRole::Owner,
            MaintenanceBlocker::NotOwner,
        ),
        (!state.disconnected, MaintenanceBlocker::Connected),
        (
            restarts_services && (state.kill_switch_enabled || state.auto_reconnect_enabled),
            MaintenanceBlocker::PersistentPolicy,
        ),
        (
            state.pending_key_rotation,
            MaintenanceBlocker::PendingKeyRotation,
        ),
        (
            state.unresolved_transaction,
            MaintenanceBlocker::UnresolvedTransaction,
        ),
    ]
    .into_iter()
    .filter_map(|(blocked, blocker)| blocked.then_some(blocker))
    .collect::<Vec<_>>();
    if blockers.is_empty() {
        Ok(())
    } else {
        Err(blockers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use MaintenanceBlocker::*;
    use OwnerMaintenance::*;

    const READY: OwnerDeviceState = OwnerDeviceState {
        role: ServerRole::Owner,
        disconnected: true,
        kill_switch_enabled: false,
        auto_reconnect_enabled: false,
        pending_key_rotation: false,
        unresolved_transaction: false,
    };

    #[test]
    fn every_operation_blocks_for_the_same_reasons() {
        let all = [
            Repair,
            Uninstall,
            Backup,
            Restore,
            ReleaseInstall,
            SignedBaseline,
        ];
        for operation in all {
            assert_eq!(owner_maintenance_ready(operation, &READY), Ok(()));
            for (state, blocker) in [
                (
                    OwnerDeviceState {
                        role: ServerRole::Member,
                        ..READY
                    },
                    NotOwner,
                ),
                (
                    OwnerDeviceState {
                        disconnected: false,
                        ..READY
                    },
                    Connected,
                ),
                (
                    OwnerDeviceState {
                        pending_key_rotation: true,
                        ..READY
                    },
                    PendingKeyRotation,
                ),
                (
                    OwnerDeviceState {
                        unresolved_transaction: true,
                        ..READY
                    },
                    UnresolvedTransaction,
                ),
            ] {
                assert_eq!(
                    owner_maintenance_ready(operation, &state),
                    Err(vec![blocker])
                );
            }
        }
        // Repair restarts services just as a release install does.
        let persistent = OwnerDeviceState {
            auto_reconnect_enabled: true,
            ..READY
        };
        assert_eq!(
            owner_maintenance_ready(Repair, &persistent),
            Err(vec![PersistentPolicy])
        );
        assert_eq!(owner_maintenance_ready(Backup, &persistent), Ok(()));
        let everything = OwnerDeviceState {
            role: ServerRole::Member,
            disconnected: false,
            kill_switch_enabled: true,
            auto_reconnect_enabled: false,
            pending_key_rotation: true,
            unresolved_transaction: true,
        };
        assert_eq!(
            owner_maintenance_ready(Uninstall, &everything)
                .unwrap_err()
                .len(),
            5
        );
        assert!(PendingKeyRotation.message().contains("key rotation"));
    }
}
