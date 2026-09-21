//! Current authorization policy. Times are UTC; no activity history is recorded.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemberPolicy {
    pub device_limit: Option<u16>,
    pub expires_at_unix: Option<u64>,
    /// Half-open intervals in a UTC week, starting Monday 00:00.
    pub weekly_access: Vec<WeeklyAccessWindow>,
    pub invite_members: bool,
    pub add_own_devices: bool,
    pub manage_own_peer_communication: bool,
    pub manage_own_port_forwards: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_windows_and_expiration_are_half_open_and_wrap_at_monday() {
        let policy = MemberPolicy {
            weekly_access: vec![WeeklyAccessWindow {
                start_minute: 9 * 60,
                end_minute: 17 * 60,
            }],
            expires_at_unix: Some(345_600 + 16 * 3600),
            ..Default::default()
        };
        assert!(!policy.permits_access_at(345_600 + 9 * 3600 - 1));
        assert!(policy.permits_access_at(345_600 + 9 * 3600));
        assert!(policy.permits_access_at(345_600 + 16 * 3600 - 1));
        assert!(!policy.permits_access_at(345_600 + 16 * 3600));
        let mut recurring = policy;
        recurring.expires_at_unix = None;
        assert!(!recurring.permits_access_at(345_600 + 17 * 3600));
        assert!(recurring.permits_access_at(345_600 + 7 * 86_400 + 10 * 3600));
    }
    #[test]
    fn delegated_scope_cannot_amplify_limits_times_or_permissions() {
        let issuer = MemberPolicy {
            device_limit: Some(2),
            expires_at_unix: Some(900),
            invite_members: true,
            weekly_access: vec![WeeklyAccessWindow {
                start_minute: 60,
                end_minute: 180,
            }],
            ..Default::default()
        };
        let mut grant = issuer.clone();
        grant.invite_members = false;
        assert!(grant.is_subset_of(&issuer));
        grant.device_limit = None;
        assert!(!grant.is_subset_of(&issuer));
        grant.device_limit = Some(1);
        grant.weekly_access.clear();
        assert!(!grant.is_subset_of(&issuer));
        grant.weekly_access = issuer.weekly_access.clone();
        grant.manage_own_port_forwards = true;
        assert!(!grant.is_subset_of(&issuer));
        grant.manage_own_port_forwards = false;
        grant.expires_at_unix = Some(901);
        assert!(!grant.is_subset_of(&issuer));
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeeklyAccessWindow {
    pub start_minute: u16,
    pub end_minute: u16,
}

impl MemberPolicy {
    /// Delegated invitations cannot amplify the issuer's current policy.
    pub fn is_subset_of(&self, issuer: &Self) -> bool {
        !self.invite_members
            && (!self.add_own_devices || issuer.add_own_devices)
            && (!self.manage_own_peer_communication || issuer.manage_own_peer_communication)
            && (!self.manage_own_port_forwards || issuer.manage_own_port_forwards)
            && issuer
                .device_limit
                .is_none_or(|limit| self.device_limit.is_some_and(|own| own <= limit))
            && issuer
                .expires_at_unix
                .is_none_or(|expiry| self.expires_at_unix.is_some_and(|own| own <= expiry))
            && (issuer.weekly_access.is_empty()
                || (!self.weekly_access.is_empty()
                    && self.weekly_access.iter().all(|own| {
                        issuer.weekly_access.iter().any(|window| {
                            window.start_minute <= own.start_minute
                                && own.end_minute <= window.end_minute
                        })
                    })))
    }

    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self
            .device_limit
            .is_some_and(|limit| !(1..=222).contains(&limit))
        {
            return Err("device limit must be between 1 and 222");
        }
        if self
            .expires_at_unix
            .is_some_and(|expiry| !(1..=253_402_300_799).contains(&expiry))
            || self.weekly_access.len() > 28
        {
            return Err("access expiration or schedule is invalid");
        }
        let mut end = 0;
        for window in &self.weekly_access {
            if window.start_minute < end
                || window.start_minute >= window.end_minute
                || window.end_minute > 7 * 24 * 60
            {
                return Err(
                    "UTC access windows must be ordered, non-overlapping intervals within a week",
                );
            }
            end = window.end_minute;
        }
        Ok(())
    }

    pub fn permits_access_at(&self, now: u64) -> bool {
        if self.expires_at_unix.is_some_and(|expires| now >= expires) {
            return false;
        }
        let minute = ((((now / 86_400) + 3) % 7) * 1_440 + (now % 86_400) / 60) as u16;
        self.weekly_access.is_empty()
            || self
                .weekly_access
                .iter()
                .any(|window| window.start_minute <= minute && minute < window.end_minute)
    }
}
