use super::*;

impl AuthorizationDocument {
    pub(super) fn validate_enrollment_receipts(
        &self,
        addresses: &mut HashSet<IpAddr>,
        wireguard_keys: &mut HashSet<String>,
        certificate_fingerprints: &mut HashSet<String>,
        invitation_ids: &HashSet<InvitationId>,
    ) -> Result<()> {
        let mut receipt_ids = HashSet::new();
        let mut reusable_bootstraps: std::collections::HashMap<_, _> = self
            .invitations
            .iter()
            .filter(|invitation| invitation.claims.max_uses > 1)
            .map(|invitation| {
                (
                    invitation.claims.invitation_id,
                    (&invitation.claims, &invitation.signature),
                )
            })
            .collect();
        for receipt in &self.enrollment_receipts {
            validate_claims(self.server_id, &receipt.claims)?;
            let resolved_member_id = receipt
                .claims
                .target_member_id
                .unwrap_or(receipt.claims.member_id);
            let resolved_role = receipt.claims.target_role.unwrap_or(receipt.claims.role);
            if receipt.invitation_id != receipt.claims.invitation_id
                || receipt.token_hash != receipt.claims.token_hash
                || receipt.bootstrap_tunnel_address != receipt.claims.bootstrap_tunnel_address
                || receipt.bootstrap_wireguard_public_key
                    != receipt.claims.bootstrap_wireguard_public_key
                || receipt.bootstrap_management_certificate_pem
                    != receipt.claims.bootstrap_management_certificate_pem
                || receipt.result.server_id != receipt.claims.server_id
                || ((receipt.claims.max_uses == 1 || receipt.claims.target_member_id.is_some())
                    && receipt.result.member_id != resolved_member_id)
                || (receipt.claims.max_uses == 1
                    && receipt.result.device_id != receipt.claims.device_id)
                || (receipt.claims.max_uses == 1
                    && receipt.result.client_tunnel_address != receipt.claims.client_tunnel_address)
                || receipt.result.role != resolved_role
                || receipt.result.administrator != receipt.claims.administrator
            {
                bail!("authorization state contains an inconsistent enrollment receipt");
            }
            if !receipt_ids.insert((receipt.invitation_id, receipt.result.device_id))
                || (receipt.claims.max_uses == 1 && invitation_ids.contains(&receipt.invitation_id))
            {
                bail!("authorization state contains duplicate enrollment receipts");
            }
            let bootstrap_fingerprint =
                certificate_fingerprint(&receipt.bootstrap_management_certificate_pem)?;
            let shared = if receipt.claims.max_uses > 1 {
                if let Some((claims, signature)) = reusable_bootstraps.get(&receipt.invitation_id) {
                    if *claims != &receipt.claims || *signature != &receipt.signature {
                        bail!("reusable invitation receipts disagree on their signed grant");
                    }
                    true
                } else {
                    reusable_bootstraps
                        .insert(receipt.invitation_id, (&receipt.claims, &receipt.signature));
                    false
                }
            } else {
                false
            };
            if bootstrap_fingerprint != receipt.bootstrap_certificate_fingerprint
                || (!shared
                    && (!addresses.insert(receipt.bootstrap_tunnel_address)
                        || !wireguard_keys.insert(receipt.bootstrap_wireguard_public_key.clone())
                        || !certificate_fingerprints.insert(bootstrap_fingerprint)))
            {
                bail!("authorization state contains duplicate receipt identity material");
            }
            let enrolled_device = self
                .devices
                .iter()
                .find(|device| device.id == receipt.result.device_id)
                .context("enrollment receipt refers to a missing device")?;
            if self.structural_access_for_device(enrolled_device).is_none()
                || enrolled_device.member_id != receipt.result.member_id
                || enrolled_device.client_tunnel_address != receipt.result.client_tunnel_address
                || enrolled_device.wireguard_public_key != receipt.device_wireguard_public_key
                || enrolled_device.management_certificate_pem
                    != receipt.device_management_certificate_pem
            {
                bail!("enrollment receipt does not match its enrolled device");
            }
        }

        Ok(())
    }
}
