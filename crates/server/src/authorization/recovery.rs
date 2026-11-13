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

/// The Owner recovery grant. Persisted as the historical `recovery_key` / `recovery_receipt`
/// fields; a document carrying both no longer loads.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "StoredOwnerRecovery", into = "StoredOwnerRecovery")]
pub(crate) enum OwnerRecovery {
    #[default]
    Unarmed,
    /// A signed key waits for the recovering device.
    Armed(Box<RecoveryKeyResponse>),
    /// The key was redeemed; the receipt answers an exact retry until it expires.
    Finishing(Box<RecoveryReceipt>),
}

impl OwnerRecovery {
    pub(crate) fn key(&self) -> Option<&RecoveryKeyResponse> {
        match self {
            Self::Armed(key) => Some(key),
            _ => None,
        }
    }

    pub(crate) fn receipt(&self) -> Option<&RecoveryReceipt> {
        match self {
            Self::Finishing(receipt) => Some(receipt),
            _ => None,
        }
    }

    /// The signed authorization either state carries.
    pub(crate) fn response(&self) -> Option<&RecoveryKeyResponse> {
        match self {
            Self::Unarmed => None,
            Self::Armed(key) => Some(key),
            Self::Finishing(receipt) => Some(&receipt.response),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredOwnerRecovery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_key: Option<RecoveryKeyResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_receipt: Option<RecoveryReceipt>,
}

impl TryFrom<StoredOwnerRecovery> for OwnerRecovery {
    type Error = &'static str;
    fn try_from(stored: StoredOwnerRecovery) -> Result<Self, Self::Error> {
        match (stored.recovery_key, stored.recovery_receipt) {
            (None, None) => Ok(Self::Unarmed),
            (Some(key), None) => Ok(Self::Armed(Box::new(key))),
            (None, Some(receipt)) => Ok(Self::Finishing(Box::new(receipt))),
            (Some(_), Some(_)) => Err("a recovery enrollment is still finishing"),
        }
    }
}

impl From<OwnerRecovery> for StoredOwnerRecovery {
    fn from(recovery: OwnerRecovery) -> Self {
        match recovery {
            OwnerRecovery::Unarmed => Self {
                recovery_key: None,
                recovery_receipt: None,
            },
            OwnerRecovery::Armed(key) => Self {
                recovery_key: Some(*key),
                recovery_receipt: None,
            },
            OwnerRecovery::Finishing(receipt) => Self {
                recovery_key: None,
                recovery_receipt: Some(*receipt),
            },
        }
    }
}

impl AuthorizationDocument {
    pub(crate) fn recovery_authorization(&self, now: u64) -> Option<&RecoveryKeyResponse> {
        self.owner_recovery
            .key()
            .filter(|key| {
                self.members
                    .iter()
                    .find(|member| member.id == key.claims.issuer_member_id)
                    .is_some_and(|member| self.can_issue_recovery(member))
            })
            .or_else(|| {
                self.owner_recovery
                    .receipt()
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
                .owner_recovery
                .key()
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
                .owner_recovery
                .receipt()
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
        let Some(response) = self.owner_recovery.response() else {
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
        if self.owner_recovery.key().is_some()
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
        if let Some(receipt) = self.owner_recovery.receipt() {
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
