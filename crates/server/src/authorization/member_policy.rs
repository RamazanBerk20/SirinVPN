use super::*;

impl AuthorizationDocument {
    pub(crate) fn set_member_policy(
        &mut self,
        member_id: MemberId,
        policy: MemberPolicy,
    ) -> Result<()> {
        policy.validate().map_err(anyhow::Error::msg)?;
        if policy.device_limit.is_some_and(|limit| {
            self.devices
                .iter()
                .filter(|device| device.member_id == member_id)
                .count()
                > usize::from(limit)
        }) {
            bail!("revoke excess devices before reducing this member's device limit");
        }
        let member = self
            .members
            .iter_mut()
            .find(|member| member.id == member_id)
            .context("member was not found")?;
        if member.role == ServerRole::Owner {
            bail!("transfer ownership before restricting the owner's access");
        }
        member.policy = policy;
        // Pending grants must be reissued under the updated policy.
        self.remove_member_pending_access(member_id);
        self.schema_version = self.required_schema_version();
        self.validate()
    }

    pub(crate) fn ensure_device_capacity(&self, member_id: MemberId) -> Result<()> {
        let member = self
            .members
            .iter()
            .find(|member| member.id == member_id)
            .context("member was not found")?;
        if member.suspended || !member.policy.permits_access_at(super::super::unix_time()) {
            bail!("this member's access is currently unavailable");
        }
        if member.policy.device_limit.is_some_and(|limit| {
            self.devices
                .iter()
                .filter(|device| device.member_id == member_id)
                .count()
                >= usize::from(limit)
        }) {
            bail!("this member has reached the device limit");
        }
        Ok(())
    }
}
