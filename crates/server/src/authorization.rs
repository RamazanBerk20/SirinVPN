mod enrollment_receipts;
mod enrollment_state;
mod member_lifecycle;
mod member_policy;
mod recovery;
pub(crate) use recovery::RecoveryReceipt;
mod validation;
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, pkcs8::DecodePrivateKey};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sirinvpn_protocol::{
    ActiveInvitationSummary, DEFAULT_MANAGEMENT_PORT, DeviceId, DeviceSummary,
    EndpointTransitionClaims, EndpointTransitionResponse, EnrollmentResult, InvitationClaims,
    InvitationId, KeyRotationCommitResponse, KeyRotationId, KeyRotationPrepareRequest,
    KeyRotationPrepareResponse, MAX_PORT_FORWARDS, MIN_PORT_FORWARD_PUBLIC_PORT, MemberId,
    MemberPolicy, MemberSummary, MembershipSnapshot, PortForward, PortForwardProtocol,
    SERVER_TUNNEL_ADDRESS, ServerId, ServerRole, validate_host,
};
use std::{
    collections::{BTreeMap, HashSet},
    fs, io,
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use validation::*;
pub(crate) use validation::{
    certificate_fingerprint, load_authorization, sign_claims, sign_endpoint_transition,
    validate_display_name, validate_endpoint_descriptor, validate_wireguard_public_key,
    verify_endpoint_transition_signature, verify_endpoint_transition_signature_with_key,
    write_authorization,
};

pub(crate) fn sign_recovery_claims(
    path: &Path,
    claims: &sirinvpn_protocol::RecoveryKeyClaims,
) -> Result<String> {
    validation::sign_serialized(path, claims)
}

pub(crate) const AUTHORIZATION_SCHEMA_VERSION: u16 = 1;
pub(crate) const SUSPENDED_AUTHORIZATION_SCHEMA_VERSION: u16 = 2;
pub(crate) const POLICY_AUTHORIZATION_SCHEMA_VERSION: u16 = 3;
pub(crate) const ENROLLMENT_HANDOFF_SECONDS: u64 = 60;
pub(crate) const KEY_ROTATION_LIFETIME_SECONDS: u64 = 10 * 60;
const FIRST_MEMBER_ADDRESS: u8 = 3;
const LAST_MEMBER_ADDRESS: u8 = 223;
const FIRST_BOOTSTRAP_ADDRESS: u8 = 224;
const LAST_BOOTSTRAP_ADDRESS: u8 = 254;

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AuthorizationDocument {
    // Leases disappear on restart; sync removes their kernel peers before serving.
    #[serde(skip)]
    pub measurement_leases: Vec<crate::measurement::Lease>,
    pub schema_version: u16,
    pub server_id: ServerId,
    pub members: Vec<MemberRecord>,
    pub devices: Vec<DeviceRecord>,
    pub invitations: Vec<InvitationRecord>,
    pub enrollment_receipts: Vec<EnrollmentReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_rotations: Vec<KeyRotationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_transition: Option<EndpointTransitionResponse>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub endpoint_transition_source: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_observed_address: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<PortForward>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<sirinvpn_protocol::RecoveryKeyResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_receipt: Option<RecoveryReceipt>,
    #[serde(
        default,
        skip_serializing_if = "sirinvpn_protocol::RecoveryPolicy::is_default"
    )]
    pub recovery_policy: sirinvpn_protocol::RecoveryPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct MemberRecord {
    pub id: MemberId,
    pub name: String,
    pub role: ServerRole,
    #[serde(default, skip_serializing_if = "is_false")]
    pub administrator: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub suspended: bool,
    #[serde(default, skip_serializing_if = "MemberPolicy::is_default")]
    pub policy: MemberPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemberAccess {
    pub role: ServerRole,
    pub administrator: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct DeviceRecord {
    pub id: DeviceId,
    pub member_id: MemberId,
    pub name: String,
    pub client_tunnel_address: IpAddr,
    pub wireguard_public_key: String,
    pub management_certificate_pem: String,
    pub certificate_fingerprint: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub peer_communication_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct InvitationRecord {
    pub claims: InvitationClaims,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_by: Option<MemberId>,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub uses_consumed: u16,
}

fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct EnrollmentReceipt {
    pub invitation_id: InvitationId,
    pub claims: InvitationClaims,
    pub signature: String,
    pub token_hash: String,
    pub bootstrap_tunnel_address: IpAddr,
    pub bootstrap_wireguard_public_key: String,
    pub bootstrap_management_certificate_pem: String,
    pub bootstrap_certificate_fingerprint: String,
    pub device_wireguard_public_key: String,
    pub device_management_certificate_pem: String,
    pub result: EnrollmentResult,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct KeyRotationRecord {
    pub rotation_id: KeyRotationId,
    pub device_id: DeviceId,
    pub previous_certificate_fingerprint: String,
    pub new_wireguard_public_key: String,
    pub new_management_certificate_pem: String,
    pub new_certificate_fingerprint: String,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DesiredPeer {
    pub public_key: String,
    pub address: IpAddr,
}

#[derive(Serialize)]
struct EndpointAuthorizationBinding<'a> {
    schema_version: u16,
    server_id: ServerId,
    members: &'a [MemberRecord],
    devices: &'a [DeviceRecord],
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_key: &'a Option<sirinvpn_protocol::RecoveryKeyResponse>,
    #[serde(skip_serializing_if = "sirinvpn_protocol::RecoveryPolicy::is_default")]
    recovery_policy: &'a sirinvpn_protocol::RecoveryPolicy,
}

impl AuthorizationDocument {
    pub(crate) fn new_owner(
        server_id: ServerId,
        owner_wireguard_public_key: String,
        owner_certificate_pem: String,
    ) -> Result<Self> {
        validate_wireguard_public_key(&owner_wireguard_public_key)?;
        let certificate_fingerprint = certificate_fingerprint(&owner_certificate_pem)?;
        let member_id = MemberId::new();
        Ok(Self {
            measurement_leases: Vec::new(),
            schema_version: AUTHORIZATION_SCHEMA_VERSION,
            server_id,
            members: vec![MemberRecord {
                id: member_id,
                name: "Owner".to_owned(),
                role: ServerRole::Owner,
                administrator: false,
                suspended: false,
                policy: MemberPolicy::default(),
            }],
            devices: vec![DeviceRecord {
                id: DeviceId::new(),
                member_id,
                name: "Owner device".to_owned(),
                client_tunnel_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
                wireguard_public_key: owner_wireguard_public_key,
                management_certificate_pem: owner_certificate_pem,
                certificate_fingerprint,
                peer_communication_enabled: false,
            }],
            invitations: Vec::new(),
            enrollment_receipts: Vec::new(),
            key_rotations: Vec::new(),
            endpoint_transition: None,
            endpoint_transition_source: false,
            endpoint_observed_address: None,
            port_forwards: Vec::new(),
            recovery_key: None,
            recovery_receipt: None,
            recovery_policy: Default::default(),
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != self.required_schema_version() {
            bail!("authorization state version is unsupported");
        }
        if self
            .members
            .iter()
            .filter(|member| member.role == ServerRole::Owner)
            .count()
            != 1
        {
            bail!("authorization state must contain exactly one owner");
        }

        let member_ids: HashSet<_> = self.members.iter().map(|member| member.id).collect();
        if member_ids.len() != self.members.len() {
            bail!("authorization state contains duplicate members");
        }
        let device_ids: HashSet<_> = self.devices.iter().map(|device| device.id).collect();
        if device_ids.len() != self.devices.len() {
            bail!("authorization state contains duplicate devices");
        }

        let mut addresses = HashSet::new();
        let mut wireguard_keys = HashSet::new();
        let mut certificate_fingerprints = HashSet::new();
        for member in &self.members {
            validate_display_name(&member.name)?;
            member.policy.validate().map_err(anyhow::Error::msg)?;
            if member.role == ServerRole::Owner && !member.policy.is_default() {
                bail!("the owner cannot have a restricted member policy");
            }
            if member.role == ServerRole::Owner && member.administrator {
                bail!("the owner cannot carry the administrator compatibility flag");
            }
            if member.role == ServerRole::Owner && member.suspended {
                bail!("the owner cannot be suspended");
            }
        }
        for device in &self.devices {
            if !member_ids.contains(&device.member_id) {
                bail!("authorization state contains an orphaned device");
            }
            validate_device_address(device.client_tunnel_address)?;
            validate_wireguard_public_key(&device.wireguard_public_key)?;
            let fingerprint = certificate_fingerprint(&device.management_certificate_pem)?;
            if fingerprint != device.certificate_fingerprint {
                bail!("authorization state contains a mismatched device certificate");
            }
            if !addresses.insert(device.client_tunnel_address)
                || !wireguard_keys.insert(device.wireguard_public_key.clone())
                || !certificate_fingerprints.insert(fingerprint)
            {
                bail!("authorization state contains duplicate device identity material");
            }
        }

        if self.port_forwards.len() > MAX_PORT_FORWARDS {
            bail!("authorization state contains too many port forwards");
        }
        let mut public_ports = HashSet::new();
        for forward in &self.port_forwards {
            if forward.public_port < MIN_PORT_FORWARD_PUBLIC_PORT || forward.device_port == 0 {
                bail!("authorization state contains an invalid port forward");
            }
            if !device_ids.contains(&forward.device_id) {
                bail!("authorization state contains an orphaned port forward");
            }
            if !public_ports.insert((forward.protocol, forward.public_port)) {
                bail!("authorization state contains a duplicate public port forward");
            }
        }

        let mut invitation_ids = HashSet::new();
        let mut reserved_member_ids = HashSet::new();
        let mut reserved_device_ids = HashSet::new();
        for invitation in &self.invitations {
            let claims = &invitation.claims;
            validate_claims(self.server_id, claims)?;
            if invitation.uses_consumed >= claims.max_uses
                || invitation
                    .issued_by
                    .is_some_and(|id| !member_ids.contains(&id))
            {
                bail!("invitation authority is unavailable or exhausted");
            }
            if let Some(target_member_id) = claims.target_member_id {
                let target = self
                    .members
                    .iter()
                    .find(|member| member.id == target_member_id)
                    .context("invitation target member is missing")?;
                if target.suspended
                    || claims.target_role != Some(target.role)
                    || claims.member_name != target.name
                    || claims.administrator != target.administrator
                {
                    bail!("invitation target no longer matches current authorization");
                }
            }
            if !invitation_ids.insert(claims.invitation_id)
                || !reserved_member_ids.insert(claims.member_id)
                || !reserved_device_ids.insert(claims.device_id)
                || member_ids.contains(&claims.member_id)
                || device_ids.contains(&claims.device_id)
            {
                bail!("authorization state contains duplicate invitation identifiers");
            }
            let fingerprint =
                certificate_fingerprint(&claims.bootstrap_management_certificate_pem)?;
            if !addresses.insert(claims.client_tunnel_address)
                || !addresses.insert(claims.bootstrap_tunnel_address)
                || !wireguard_keys.insert(claims.bootstrap_wireguard_public_key.clone())
                || !certificate_fingerprints.insert(fingerprint)
            {
                bail!("authorization state contains duplicate invitation identity material");
            }
        }

        self.validate_enrollment_receipts(
            &mut addresses,
            &mut wireguard_keys,
            &mut certificate_fingerprints,
            &invitation_ids,
        )?;

        self.validate_recovery(
            &mut addresses,
            &mut wireguard_keys,
            &mut certificate_fingerprints,
        )?;
        let mut rotation_ids = HashSet::new();
        let mut rotating_device_ids = HashSet::new();
        for rotation in &self.key_rotations {
            let device = self
                .devices
                .iter()
                .find(|device| device.id == rotation.device_id)
                .context("key rotation refers to a missing device")?;
            if self.structural_access_for_device(device).is_none()
                || device.certificate_fingerprint != rotation.previous_certificate_fingerprint
                || rotation.expires_at_unix == 0
                || !rotation_ids.insert(rotation.rotation_id)
                || !rotating_device_ids.insert(rotation.device_id)
            {
                bail!("authorization state contains an inconsistent key rotation");
            }
            validate_wireguard_public_key(&rotation.new_wireguard_public_key)?;
            let fingerprint = certificate_fingerprint(&rotation.new_management_certificate_pem)?;
            if fingerprint != rotation.new_certificate_fingerprint
                || !wireguard_keys.insert(rotation.new_wireguard_public_key.clone())
                || !certificate_fingerprints.insert(fingerprint)
            {
                bail!("authorization state contains duplicate key rotation identity material");
            }
        }
        if let Some(transition) = &self.endpoint_transition {
            validate_endpoint_transition(self.server_id, &transition.claims)?;
            if self.endpoint_transition_source
                && transition.claims.authorization_fingerprint
                    != self.endpoint_authorization_fingerprint()?
            {
                bail!("endpoint handoff source authorization fingerprint is stale");
            }
            let signature = STANDARD
                .decode(&transition.signature)
                .context("endpoint transition signature is invalid")?;
            if Signature::from_slice(&signature).is_err() {
                bail!("endpoint transition signature is invalid");
            }
        } else if self.endpoint_transition_source {
            bail!("an endpoint handoff source must retain its signed transition");
        }
        if let Some(observed) = self.endpoint_observed_address
            && (self.endpoint_transition_source
                || !crate::endpoint_observation::automatic_address(observed)
                || self.endpoint_transition.as_ref().is_none_or(|head| {
                    head.claims.endpoint.host.parse::<IpAddr>().ok() != Some(observed)
                }))
        {
            bail!("current endpoint address observation is inconsistent");
        }
        Ok(())
    }

    pub(crate) fn endpoint_generation(&self) -> u64 {
        self.endpoint_transition
            .as_ref()
            .map_or(0, |transition| transition.claims.generation)
    }

    pub(crate) fn endpoint_authorization_fingerprint(&self) -> Result<String> {
        let binding = EndpointAuthorizationBinding {
            schema_version: self.authorization_policy_schema_version(),
            server_id: self.server_id,
            members: &self.members,
            devices: &self.devices,
            recovery_key: &self.recovery_key,
            recovery_policy: &self.recovery_policy,
        };
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(&binding)?)))
    }

    pub(crate) fn accept_endpoint_transition(
        &mut self,
        response: EndpointTransitionResponse,
    ) -> Result<()> {
        validate_endpoint_transition(self.server_id, &response.claims)?;
        if let Some(existing) = &self.endpoint_transition {
            if existing == &response {
                return Ok(());
            }
            if response.claims.generation == existing.claims.generation {
                bail!("endpoint generation is already bound to another transition");
            }
            if response.claims.generation <= existing.claims.generation
                || (response.claims.schema_version == 1
                    && (existing
                        .claims
                        .generation
                        .checked_add(1)
                        .is_none_or(|expected| response.claims.generation != expected)
                        || response.claims.previous_endpoint != existing.claims.endpoint))
            {
                bail!("endpoint transition is stale or breaks the current endpoint chain");
            }
        }
        let mut next = self.clone();
        next.endpoint_observed_address = None;
        next.endpoint_transition = Some(response);
        next.schema_version = next.required_schema_version();
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn device_for_fingerprint(&self, fingerprint: &str) -> Option<&DeviceRecord> {
        self.devices.iter().find(|device| {
            device.certificate_fingerprint == fingerprint
                && self.access_for_device(device).is_some()
        })
    }

    pub(crate) fn role_for_device(&self, device: &DeviceRecord) -> Option<ServerRole> {
        self.members
            .iter()
            .find(|member| member.id == device.member_id)
            .map(|member| member.role)
    }

    pub(crate) fn access_for_device(&self, device: &DeviceRecord) -> Option<MemberAccess> {
        let now = super::unix_time();
        self.members
            .iter()
            .find(|member| member.id == device.member_id)
            .filter(|member| member.policy.permits_access_at(now))?;
        self.structural_access_for_device(device)
    }

    fn structural_access_for_device(&self, device: &DeviceRecord) -> Option<MemberAccess> {
        self.members
            .iter()
            .find(|member| member.id == device.member_id && !member.suspended)
            .map(|member| MemberAccess {
                role: member.role,
                administrator: member.administrator,
            })
    }

    pub(crate) fn set_device_peer_communication(
        &mut self,
        device_id: DeviceId,
        enabled: bool,
    ) -> Result<()> {
        let device = self
            .devices
            .iter_mut()
            .find(|device| device.id == device_id)
            .context("device was not found")?;
        device.peer_communication_enabled = enabled;
        self.validate()
    }

    pub(crate) fn add_port_forward(&mut self, forward: PortForward) -> Result<()> {
        if self.port_forwards.len() >= MAX_PORT_FORWARDS {
            bail!("the port-forward limit has been reached");
        }
        if forward.public_port < MIN_PORT_FORWARD_PUBLIC_PORT || forward.device_port == 0 {
            bail!("the port forward is invalid");
        }
        if self.port_forwards.iter().any(|existing| {
            existing.protocol == forward.protocol && existing.public_port == forward.public_port
        }) {
            bail!("that public protocol and port is already forwarded");
        }
        if !self
            .devices
            .iter()
            .any(|device| device.id == forward.device_id)
        {
            bail!("the port-forward device was not found");
        }
        self.port_forwards.push(forward);
        self.validate()
    }

    pub(crate) fn remove_port_forward(
        &mut self,
        protocol: PortForwardProtocol,
        public_port: u16,
    ) -> Result<()> {
        let previous_len = self.port_forwards.len();
        self.port_forwards
            .retain(|forward| forward.protocol != protocol || forward.public_port != public_port);
        if self.port_forwards.len() == previous_len {
            bail!("the port forward was not found");
        }
        self.validate()
    }

    pub(crate) fn transfer_ownership(&mut self, destination_device_id: DeviceId) -> Result<()> {
        let current_owner_id = self
            .members
            .iter()
            .find(|member| member.role == ServerRole::Owner)
            .map(|member| member.id)
            .context("authorization state has no owner")?;
        let destination_member_id = self
            .devices
            .iter()
            .find(|device| {
                device.id == destination_device_id && self.access_for_device(device).is_some()
            })
            .map(|device| device.member_id)
            .context("destination device was not found")?;
        if destination_member_id == current_owner_id {
            bail!("the destination device already belongs to the owner");
        }

        let enrollment_is_pending = |member_id| {
            self.recovery_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.result.member_id == member_id)
                || self
                    .invitations
                    .iter()
                    .any(|invitation| invitation.claims.target_member_id == Some(member_id))
                || self
                    .enrollment_receipts
                    .iter()
                    .any(|receipt| receipt.result.member_id == member_id)
        };
        if enrollment_is_pending(current_owner_id) || enrollment_is_pending(destination_member_id) {
            bail!(
                "wait for recent enrollment handoffs and cancel active device invitations before transferring ownership"
            );
        }

        let previous_owner = self
            .members
            .iter_mut()
            .find(|member| member.id == current_owner_id)
            .context("authorization state has no owner")?;
        previous_owner.role = ServerRole::Member;
        previous_owner.administrator = true;

        let destination = self
            .members
            .iter_mut()
            .find(|member| member.id == destination_member_id)
            .context("destination member was not found")?;
        destination.role = ServerRole::Owner;
        destination.administrator = false;
        destination.policy = MemberPolicy::default();
        self.recovery_key = None;
        self.recovery_receipt = None;
        self.recovery_policy = Default::default();
        self.invitations.retain(|invitation| {
            invitation.issued_by != Some(current_owner_id)
                && invitation.issued_by != Some(destination_member_id)
        });
        self.schema_version = self.required_schema_version();
        self.validate()
    }

    pub(crate) fn prepare_key_rotation(
        &mut self,
        caller_fingerprint: &str,
        request: &KeyRotationPrepareRequest,
        now: u64,
    ) -> Result<KeyRotationPrepareResponse> {
        if request.server_id != self.server_id {
            bail!("key rotation belongs to a different server");
        }
        validate_wireguard_public_key(&request.new_wireguard_public_key)?;
        let new_certificate_fingerprint =
            certificate_fingerprint(&request.new_management_certificate_pem)?;
        let device = self
            .device_for_fingerprint(caller_fingerprint)
            .context("the current device is not authorized")?
            .clone();
        if self
            .enrollment_receipts
            .iter()
            .any(|receipt| receipt.result.device_id == device.id)
            || self
                .recovery_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.result.device_id == device.id)
        {
            bail!("wait for the recent device enrollment handoff before rotating keys");
        }
        if let Some(existing) = self
            .key_rotations
            .iter()
            .find(|rotation| rotation.rotation_id == request.rotation_id)
        {
            if existing.device_id == device.id
                && existing.previous_certificate_fingerprint == caller_fingerprint
                && existing.new_wireguard_public_key == request.new_wireguard_public_key
                && existing.new_certificate_fingerprint == new_certificate_fingerprint
                && existing.new_management_certificate_pem == request.new_management_certificate_pem
            {
                return Ok(KeyRotationPrepareResponse {
                    rotation_id: existing.rotation_id,
                    expires_at_unix: existing.expires_at_unix,
                });
            }
            bail!("key rotation identifier is already in use");
        }
        if self
            .key_rotations
            .iter()
            .any(|rotation| rotation.device_id == device.id)
        {
            bail!("this device already has a pending key rotation");
        }
        let expires_at_unix = now
            .checked_add(KEY_ROTATION_LIFETIME_SECONDS)
            .context("key rotation expiry overflowed")?;
        let mut next = self.clone();
        next.key_rotations.push(KeyRotationRecord {
            rotation_id: request.rotation_id,
            device_id: device.id,
            previous_certificate_fingerprint: device.certificate_fingerprint,
            new_wireguard_public_key: request.new_wireguard_public_key.clone(),
            new_management_certificate_pem: request.new_management_certificate_pem.clone(),
            new_certificate_fingerprint,
            expires_at_unix,
        });
        next.validate()?;
        *self = next;
        Ok(KeyRotationPrepareResponse {
            rotation_id: request.rotation_id,
            expires_at_unix,
        })
    }

    pub(crate) fn commit_key_rotation(
        &mut self,
        rotation_id: KeyRotationId,
        caller_fingerprint: &str,
        now: u64,
    ) -> Result<KeyRotationCommitResponse> {
        let rotation = self
            .key_rotations
            .iter()
            .find(|rotation| rotation.rotation_id == rotation_id)
            .context("pending key rotation was not found")?
            .clone();
        if rotation.expires_at_unix <= now
            || rotation.new_certificate_fingerprint != caller_fingerprint
        {
            bail!("pending key rotation is expired or unauthorized");
        }
        let mut next = self.clone();
        let device_id = {
            let device = next
                .devices
                .iter_mut()
                .find(|device| device.id == rotation.device_id)
                .context("key rotation device was not found")?;
            if device.certificate_fingerprint != rotation.previous_certificate_fingerprint {
                bail!("the device identity changed during key rotation");
            }
            device.wireguard_public_key = rotation.new_wireguard_public_key;
            device.management_certificate_pem = rotation.new_management_certificate_pem;
            device.certificate_fingerprint = rotation.new_certificate_fingerprint.clone();
            device.id
        };
        next.key_rotations
            .retain(|candidate| candidate.rotation_id != rotation_id);
        next.validate()?;
        *self = next;
        Ok(KeyRotationCommitResponse {
            server_id: self.server_id,
            device_id,
            identity_fingerprint: rotation.new_certificate_fingerprint,
        })
    }

    pub(crate) fn cancel_key_rotation(
        &mut self,
        rotation_id: KeyRotationId,
        caller_fingerprint: &str,
    ) -> Result<()> {
        let rotation = self
            .key_rotations
            .iter()
            .find(|rotation| rotation.rotation_id == rotation_id)
            .context("pending key rotation was not found")?;
        if rotation.previous_certificate_fingerprint != caller_fingerprint
            && rotation.new_certificate_fingerprint != caller_fingerprint
        {
            bail!("pending key rotation is unauthorized");
        }
        let mut next = self.clone();
        next.key_rotations
            .retain(|rotation| rotation.rotation_id != rotation_id);
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn remove_device_and_dependents(
        &mut self,
        device_id: DeviceId,
        member_id: MemberId,
    ) {
        self.devices.retain(|device| device.id != device_id);
        if self
            .recovery_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.result.device_id == device_id)
        {
            self.recovery_receipt = None;
        }
        self.enrollment_receipts
            .retain(|receipt| receipt.result.device_id != device_id);
        self.key_rotations
            .retain(|rotation| rotation.device_id != device_id);
        self.port_forwards
            .retain(|forward| forward.device_id != device_id);
        if !self
            .devices
            .iter()
            .any(|device| device.member_id == member_id)
        {
            self.invitations.retain(|invitation| {
                invitation.claims.target_member_id != Some(member_id)
                    && invitation.issued_by != Some(member_id)
            });
            self.members.retain(|member| member.id != member_id);
            self.recovery_policy
                .administrator_member_ids
                .retain(|id| *id != member_id);
            if self
                .recovery_key
                .as_ref()
                .is_some_and(|key| key.claims.issuer_member_id == member_id)
            {
                self.recovery_key = None;
            }
        }
        self.schema_version = self.required_schema_version();
    }
}

#[cfg(test)]
mod tests;
