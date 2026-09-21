//! Current member access and its dependent authorizations; no event history.
use super::*;

impl AuthorizationDocument {
    pub(crate) fn required_schema_version(&self) -> u16 {
        if self.endpoint_observed_address.is_some()
            || self
                .endpoint_transition
                .as_ref()
                .is_some_and(|head| head.claims.schema_version >= 2)
        {
            5
        } else {
            self.authorization_policy_schema_version()
        }
    }

    pub(crate) fn authorization_policy_schema_version(&self) -> u16 {
        if self.recovery_key.is_some()
            || self.recovery_receipt.is_some()
            || !self.recovery_policy.is_default()
        {
            4
        } else if self
            .members
            .iter()
            .any(|member| !member.policy.is_default())
            || self.invitations.iter().any(|invitation| {
                invitation.claims.schema_version >= 2 || invitation.issued_by.is_some()
            })
            || self
                .enrollment_receipts
                .iter()
                .any(|receipt| receipt.claims.schema_version >= 2)
        {
            POLICY_AUTHORIZATION_SCHEMA_VERSION
        } else if self.members.iter().any(|member| member.suspended) {
            SUSPENDED_AUTHORIZATION_SCHEMA_VERSION
        } else {
            AUTHORIZATION_SCHEMA_VERSION
        }
    }

    pub(crate) fn set_member_suspended(
        &mut self,
        member_id: MemberId,
        suspended: bool,
    ) -> Result<()> {
        let member = self
            .members
            .iter_mut()
            .find(|member| member.id == member_id)
            .context("member was not found")?;
        if member.role == ServerRole::Owner {
            bail!("the owner cannot be suspended; transfer ownership first");
        }
        member.suspended = suspended;
        if suspended {
            self.remove_member_pending_access(member_id);
        }
        // An old daemon rejects schema 2 instead of ignoring the suspension.
        // Once no member is suspended, the current state needs only schema 1.
        self.schema_version = self.required_schema_version();
        self.validate()
    }

    pub(crate) fn revoke_member_devices(&mut self, member_id: MemberId) -> Result<()> {
        let member = self
            .members
            .iter()
            .find(|member| member.id == member_id)
            .context("member was not found")?;
        if member.role == ServerRole::Owner {
            bail!("the owner's devices cannot all be revoked; transfer ownership first");
        }
        self.remove_member_pending_access(member_id);
        let devices: HashSet<_> = self
            .devices
            .iter()
            .filter(|device| device.member_id == member_id)
            .map(|device| device.id)
            .collect();
        self.port_forwards
            .retain(|forward| !devices.contains(&forward.device_id));
        self.devices.retain(|device| device.member_id != member_id);
        self.members.retain(|member| member.id != member_id);
        self.recovery_policy
            .administrator_member_ids
            .retain(|id| *id != member_id);
        self.schema_version = self.required_schema_version();
        self.validate()
    }

    pub(super) fn remove_member_pending_access(&mut self, member_id: MemberId) {
        if self
            .recovery_key
            .as_ref()
            .is_some_and(|key| key.claims.issuer_member_id == member_id)
        {
            self.recovery_key = None;
        }
        self.invitations.retain(|invitation| {
            invitation.claims.target_member_id != Some(member_id)
                && invitation.claims.member_id != member_id
                && invitation.issued_by != Some(member_id)
        });
        self.enrollment_receipts
            .retain(|receipt| receipt.result.member_id != member_id);
        let devices: HashSet<_> = self
            .devices
            .iter()
            .filter(|device| device.member_id == member_id)
            .map(|device| device.id)
            .collect();
        self.key_rotations
            .retain(|rotation| !devices.contains(&rotation.device_id));
    }
}
