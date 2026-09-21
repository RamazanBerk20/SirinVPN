use super::*;

impl AuthorizationDocument {
    pub(crate) fn invitation_for_fingerprint(
        &self,
        fingerprint: &str,
        now: u64,
    ) -> Option<&InvitationRecord> {
        self.invitations.iter().find(|invitation| {
            invitation.claims.expires_at_unix > now
                && certificate_fingerprint(&invitation.claims.bootstrap_management_certificate_pem)
                    .is_ok_and(|candidate| candidate == fingerprint)
        })
    }

    pub(crate) fn receipt_for_fingerprint(
        &self,
        fingerprint: &str,
        now: u64,
    ) -> Option<&EnrollmentReceipt> {
        self.enrollment_receipts.iter().find(|receipt| {
            receipt.expires_at_unix > now
                && receipt.bootstrap_certificate_fingerprint == fingerprint
        })
    }

    pub(crate) fn client_certificates(&self, now: u64) -> Vec<String> {
        let mut certificates: Vec<_> = self
            .devices
            .iter()
            .filter(|device| self.access_for_device(device).is_some())
            .map(|device| device.management_certificate_pem.clone())
            .collect();
        certificates.extend(
            self.invitations
                .iter()
                .filter(|invitation| invitation.claims.expires_at_unix > now)
                .map(|invitation| {
                    invitation
                        .claims
                        .bootstrap_management_certificate_pem
                        .clone()
                }),
        );
        certificates.extend(
            self.enrollment_receipts
                .iter()
                .filter(|receipt| receipt.expires_at_unix > now)
                .map(|receipt| receipt.bootstrap_management_certificate_pem.clone()),
        );
        certificates.extend(
            self.key_rotations
                .iter()
                .filter(|rotation| rotation.expires_at_unix > now)
                .map(|rotation| rotation.new_management_certificate_pem.clone()),
        );
        if let Some(response) = self.recovery_authorization(now) {
            certificates.push(response.claims.recovery_management_certificate_pem.clone());
        }
        certificates
    }

    pub(crate) fn desired_peers(&self, now: u64) -> Vec<DesiredPeer> {
        let mut peers: BTreeMap<String, IpAddr> = self
            .devices
            .iter()
            .filter(|device| self.access_for_device(device).is_some())
            .map(|device| {
                (
                    device.wireguard_public_key.clone(),
                    device.client_tunnel_address,
                )
            })
            .collect();
        for invitation in self
            .invitations
            .iter()
            .filter(|invitation| invitation.claims.expires_at_unix > now)
        {
            peers.insert(
                invitation.claims.bootstrap_wireguard_public_key.clone(),
                invitation.claims.bootstrap_tunnel_address,
            );
        }
        for receipt in self
            .enrollment_receipts
            .iter()
            .filter(|receipt| receipt.expires_at_unix > now)
        {
            peers.insert(
                receipt.bootstrap_wireguard_public_key.clone(),
                receipt.bootstrap_tunnel_address,
            );
        }
        if let Some(response) = self.recovery_authorization(now) {
            peers.insert(
                response.claims.recovery_wireguard_public_key.clone(),
                response.claims.recovery_tunnel_address,
            );
        }
        for lease in self
            .measurement_leases
            .iter()
            .filter(|lease| lease.active(self, now))
        {
            peers
                .entry(lease.public_key.clone())
                .or_insert(IpAddr::V4(lease.address));
        }
        peers
            .into_iter()
            .map(|(public_key, address)| DesiredPeer {
                public_key,
                address,
            })
            .collect()
    }

    pub(crate) fn prune_expired(&mut self, now: u64) -> bool {
        let recovery_expired = self
            .recovery_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.expires_at_unix <= now);
        if recovery_expired {
            self.recovery_receipt = None;
        }
        let invitation_count = self.invitations.len();
        let receipt_count = self.enrollment_receipts.len();
        let rotation_count = self.key_rotations.len();
        self.invitations
            .retain(|invitation| invitation.claims.expires_at_unix > now);
        self.enrollment_receipts
            .retain(|receipt| receipt.expires_at_unix > now);
        self.key_rotations
            .retain(|rotation| rotation.expires_at_unix > now);
        self.schema_version = self.required_schema_version();
        recovery_expired
            || invitation_count != self.invitations.len()
            || receipt_count != self.enrollment_receipts.len()
            || rotation_count != self.key_rotations.len()
    }

    pub(crate) fn allocate_member_address(&self) -> Result<IpAddr> {
        self.allocate_address(FIRST_MEMBER_ADDRESS, LAST_MEMBER_ADDRESS)
    }

    pub(crate) fn allocate_bootstrap_address(&self) -> Result<IpAddr> {
        self.allocate_address(FIRST_BOOTSTRAP_ADDRESS, LAST_BOOTSTRAP_ADDRESS - 1)
    }

    fn allocate_address(&self, first: u8, last: u8) -> Result<IpAddr> {
        let used: HashSet<_> = self
            .devices
            .iter()
            .map(|device| device.client_tunnel_address)
            .chain(self.invitations.iter().flat_map(|invitation| {
                [
                    invitation.claims.client_tunnel_address,
                    invitation.claims.bootstrap_tunnel_address,
                ]
            }))
            .chain(self.enrollment_receipts.iter().flat_map(|receipt| {
                [
                    receipt.result.client_tunnel_address,
                    receipt.bootstrap_tunnel_address,
                ]
            }))
            .collect();
        (first..=last)
            .map(|host| IpAddr::V4(Ipv4Addr::new(10, 77, 0, host)))
            .find(|address| !used.contains(address))
            .context("the SirinVPN address pool is exhausted")
    }

    pub(crate) fn snapshot(&self, now: u64) -> MembershipSnapshot {
        let mut members: Vec<_> = self
            .members
            .iter()
            .map(|member| {
                let mut devices: Vec<_> = self
                    .devices
                    .iter()
                    .filter(|device| device.member_id == member.id)
                    .map(|device| DeviceSummary {
                        id: device.id,
                        member_id: device.member_id,
                        name: device.name.clone(),
                        client_tunnel_address: device.client_tunnel_address,
                        identity_fingerprint: device.certificate_fingerprint.clone(),
                        peer_communication_enabled: device.peer_communication_enabled,
                        recent_handshake: None,
                    })
                    .collect();
                devices.sort_by(|left, right| left.name.cmp(&right.name));
                MemberSummary {
                    id: member.id,
                    name: member.name.clone(),
                    role: member.role,
                    administrator: member.administrator,
                    suspended: member.suspended,
                    policy: member.policy.clone(),
                    devices,
                }
            })
            .collect();
        members.sort_by_key(|member| match member.role {
            ServerRole::Owner => (0, member.name.clone()),
            ServerRole::Member if member.administrator => (1, member.name.clone()),
            ServerRole::Member => (2, member.name.clone()),
        });
        let mut active_invitations: Vec<_> = self
            .invitations
            .iter()
            .filter(|invitation| invitation.claims.expires_at_unix > now)
            .map(|invitation| ActiveInvitationSummary {
                recipient_names: invitation.claims.recipient_names,
                id: invitation.claims.invitation_id,
                member_name: invitation.claims.member_name.clone(),
                device_name: invitation.claims.device_name.clone(),
                target_member_id: invitation.claims.target_member_id,
                administrator: invitation.claims.administrator,
                expires_at_unix: invitation.claims.expires_at_unix,
                uses_remaining: invitation.claims.max_uses - invitation.uses_consumed,
                max_uses: invitation.claims.max_uses,
                member_policy: invitation.claims.member_policy.clone(),
            })
            .collect();
        active_invitations.sort_by_key(|invitation| invitation.expires_at_unix);
        let mut port_forwards = self.port_forwards.clone();
        port_forwards.sort_by_key(|forward| (forward.protocol, forward.public_port));
        MembershipSnapshot {
            members,
            active_invitations,
            port_forwards,
        }
    }
}
