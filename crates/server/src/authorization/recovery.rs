use super::*;
use sirinvpn_protocol::{RecoveryKeyResponse, RecoveryKeySummary, RecoverySettings};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RecoveryReceipt {
    pub response: RecoveryKeyResponse,
    pub device_wireguard_public_key: String,
    pub device_management_certificate_pem: String,
    pub result: EnrollmentResult,
    pub expires_at_unix: u64,
}

impl AuthorizationDocument {
    pub(crate) fn recovery_authorization(&self, now: u64) -> Option<&RecoveryKeyResponse> {
        self.recovery_key
            .as_ref()
            .filter(|key| {
                self.members
                    .iter()
                    .find(|member| member.id == key.claims.issuer_member_id)
                    .is_some_and(|member| self.can_issue_recovery(member))
            })
            .or_else(|| {
                self.recovery_receipt
                    .as_ref()
                    .filter(|receipt| receipt.expires_at_unix > now)
                    .map(|receipt| &receipt.response)
            })
    }

    pub(crate) fn can_issue_recovery(&self, member: &MemberRecord) -> bool {
        !member.suspended
            && member.policy.permits_access_at(super::super::unix_time())
            && (member.role == ServerRole::Owner
                || (member.administrator
                    && self
                        .recovery_policy
                        .administrator_member_ids
                        .contains(&member.id)))
    }

    pub(crate) fn recovery_settings(&self, member: &MemberRecord) -> Result<RecoverySettings> {
        Ok(RecoverySettings {
            policy: self.recovery_policy.clone(),
            key: self
                .recovery_key
                .as_ref()
                .map(|response| {
                    Ok::<_, anyhow::Error>(RecoveryKeySummary {
                        recovery_id: response.claims.recovery_id,
                        identity_fingerprint: certificate_fingerprint(
                            &response.claims.recovery_management_certificate_pem,
                        )?,
                    })
                })
                .transpose()?,
            enrollment_finishing: self
                .recovery_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.expires_at_unix > super::super::unix_time()),
            can_issue_key: self.can_issue_recovery(member),
        })
    }

    pub(super) fn validate_recovery(
        &self,
        addresses: &mut HashSet<IpAddr>,
        keys: &mut HashSet<String>,
        certificates: &mut HashSet<String>,
    ) -> Result<()> {
        let ids = &self.recovery_policy.administrator_member_ids;
        if ids.len() > 32
            || ids.iter().collect::<HashSet<_>>().len() != ids.len()
            || ids.iter().any(|id| {
                !self.members.iter().any(|member| {
                    member.id == *id && member.role == ServerRole::Member && member.administrator
                })
            })
        {
            bail!("recovery policy must name unique current administrators");
        }
        if self.recovery_key.is_some() && self.recovery_receipt.is_some() {
            bail!("a recovery enrollment is still finishing");
        }
        let response = self.recovery_key.as_ref().or_else(|| {
            self.recovery_receipt
                .as_ref()
                .map(|receipt| &receipt.response)
        });
        let Some(response) = response else {
            return Ok(());
        };
        let c = &response.claims;
        if c.schema_version != c.required_schema_version()
            || !sirinvpn_protocol::valid_alternate_endpoint_hosts(
                &c.endpoint.host,
                &c.alternate_endpoint_hosts,
            )
            || c.endpoint_discovery_port
                .is_some_and(|port| port == 0 || c.tls_like.is_none())
            || c.recovery_id.0.is_nil()
            || c.server_id != self.server_id
            || !self
                .members
                .iter()
                .any(|member| member.id == c.owner_member_id && member.role == ServerRole::Owner)
            || c.recovery_tunnel_address != IpAddr::V4(Ipv4Addr::new(10, 77, 0, 254))
            || c.server_tunnel_address != SERVER_TUNNEL_ADDRESS.parse::<IpAddr>()?
            || c.management_port != DEFAULT_MANAGEMENT_PORT
            || c.endpoint.wireguard_port == 0
        {
            bail!("the recovery authorization is inconsistent with this server");
        }
        if self.recovery_key.is_some()
            && c.issuer_member_id != c.owner_member_id
            && !self
                .recovery_policy
                .administrator_member_ids
                .contains(&c.issuer_member_id)
        {
            bail!("the administrator's recovery authority has been revoked");
        }
        validate_host(&c.endpoint.host)?;
        validate_display_name(&c.server_name)?;
        validate_wireguard_public_key(&c.recovery_wireguard_public_key)?;
        validate_wireguard_public_key(&c.server_wireguard_public_key)?;
        certificate_fingerprint(&c.pinned_server_certificate_pem)?;
        let fingerprint = certificate_fingerprint(&c.recovery_management_certificate_pem)?;
        if !addresses.insert(c.recovery_tunnel_address)
            || !keys.insert(c.recovery_wireguard_public_key.clone())
            || !certificates.insert(fingerprint)
        {
            bail!("recovery identity material is already in use");
        }
        Signature::from_slice(&STANDARD.decode(&response.signature)?)?;
        if let Some(receipt) = &self.recovery_receipt {
            let device = self
                .devices
                .iter()
                .find(|device| device.id == receipt.result.device_id)
                .context("recovery receipt device is missing")?;
            if device.member_id != c.owner_member_id
                || receipt.result.member_id != c.owner_member_id
                || receipt.result.server_id != self.server_id
                || receipt.result.role != ServerRole::Owner
                || receipt.result.administrator
                || device.client_tunnel_address != receipt.result.client_tunnel_address
                || device.wireguard_public_key != receipt.device_wireguard_public_key
                || device.management_certificate_pem != receipt.device_management_certificate_pem
            {
                bail!("the recovery receipt does not match its new Owner device");
            }
        }
        Ok(())
    }
}
