use crate::SecretIdentity;
use reqwest::{Certificate, Client, Identity};
use sirinvpn_protocol::DiagnosticReport;
use sirinvpn_protocol::{
    API_VERSION, ApiEnvelope, ApiErrorBody, CurrentConfiguration, DeviceId,
    DevicePeerCommunicationUpdateRequest, EndpointTransitionCreateRequest,
    EndpointTransitionResponse, EnrollmentRequest, EnrollmentResult, ErrorCode,
    InvitationCreateRequest, InvitationCreateResponse, InvitationId, KeyRotationCommitResponse,
    KeyRotationId, KeyRotationPrepareRequest, KeyRotationPrepareResponse,
    MemberAccessUpdateRequest, MemberDevicesRevokeRequest, MemberId, MemberSuspensionUpdateRequest,
    MembershipSnapshot, OwnershipTransferRequest, PortForwardCreateRequest, PortForwardProtocol,
    RenameDeviceRequest, ServerProfile, ServerStatus,
};
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

mod status_stream;
pub use status_stream::ManagementStatusStream;

#[derive(Debug, Error)]
pub enum ManagementError {
    #[error("the pinned server identity is invalid")]
    InvalidServerIdentity,
    #[error("the local device identity is invalid")]
    InvalidClientIdentity,
    #[error("the private management connection failed")]
    ConnectionFailed,
    #[error("the current diagnostic management request timed out")]
    DiagnosticTimedOut,
    #[error("TLS authentication or negotiation failed during the current diagnostic request")]
    DiagnosticTlsFailed,
    #[error("the server returned an incompatible protocol version")]
    ProtocolMismatch,
    #[error("this server does not support live status streaming")]
    StatusStreamingUnsupported,
    #[error("the server rejected the request ({code:?}): {message}")]
    RequestRejected { code: ErrorCode, message: String },
}

#[derive(Clone)]
pub struct ManagementClient {
    client: Client,
    base_url: String,
}

impl ManagementClient {
    /// Provisioned legacy Owner profiles have no membership IDs. Fill both from
    /// the authenticated directory before recording a newly verified device.
    pub async fn refresh_membership_ids(
        &self,
        profile: &mut ServerProfile,
        device: DeviceId,
    ) -> Result<(), ManagementError> {
        if profile.member_id.is_none() {
            let membership = self.membership().await?;
            let member = membership
                .members
                .iter()
                .find(|member| member.devices.iter().any(|item| item.id == device))
                .ok_or(ManagementError::ProtocolMismatch)?;
            profile.member_id = Some(member.id);
        }
        profile.device_id = Some(device);
        Ok(())
    }
    pub async fn recovery_settings(
        &self,
    ) -> Result<sirinvpn_protocol::RecoverySettings, ManagementError> {
        let response = self
            .client
            .get(format!("{}/v1/recovery", self.base_url))
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }
    pub async fn update_recovery_policy(
        &self,
        policy: &sirinvpn_protocol::RecoveryPolicy,
    ) -> Result<sirinvpn_protocol::RecoverySettings, ManagementError> {
        let response = self
            .client
            .patch(format!("{}/v1/recovery", self.base_url))
            .json(policy)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }
    pub async fn create_recovery_key(
        &self,
        request: &sirinvpn_protocol::RecoveryKeyCreateRequest,
    ) -> Result<sirinvpn_protocol::RecoveryKeyResponse, ManagementError> {
        let response = self
            .client
            .put(format!("{}/v1/recovery/key", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }
    pub async fn revoke_recovery_key(
        &self,
        id: sirinvpn_protocol::RecoveryId,
    ) -> Result<sirinvpn_protocol::RecoverySettings, ManagementError> {
        let response = self
            .client
            .delete(format!("{}/v1/recovery/key/{id}", self.base_url))
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }
    pub async fn recover_owner(
        &self,
        request: &sirinvpn_protocol::RecoveryRedeemRequest,
    ) -> Result<EnrollmentResult, ManagementError> {
        let response = self
            .client
            .post(format!("{}/v1/recovery/enrollment", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }
    pub fn new(profile: &ServerProfile, secret: &SecretIdentity) -> Result<Self, ManagementError> {
        Self::with_timeout(profile, secret, Some(Duration::from_secs(8)))
    }

    fn with_timeout(
        profile: &ServerProfile,
        secret: &SecretIdentity,
        timeout: Option<Duration>,
    ) -> Result<Self, ManagementError> {
        Self::with_options(profile, secret, timeout, false)
    }

    pub(crate) fn for_diagnostics(
        profile: &ServerProfile,
        secret: &SecretIdentity,
    ) -> Result<Self, ManagementError> {
        Self::with_options(profile, secret, Some(Duration::from_secs(8)), true)
    }

    fn with_options(
        profile: &ServerProfile,
        secret: &SecretIdentity,
        timeout: Option<Duration>,
        bind_tunnel: bool,
    ) -> Result<Self, ManagementError> {
        let server_certificate =
            Certificate::from_pem(profile.pinned_server_certificate_pem.as_bytes())
                .map_err(|_| ManagementError::InvalidServerIdentity)?;
        let mut identity_pem = Zeroizing::new(String::new());
        identity_pem.push_str(&profile.client_management_certificate_pem);
        identity_pem.push_str(&secret.management_private_key_pem);
        let identity = Identity::from_pem(identity_pem.as_bytes())
            .map_err(|_| ManagementError::InvalidClientIdentity)?;
        let builder = Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(server_certificate)
            .identity(identity)
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .retry(reqwest::retry::never())
            // Access polling runs every 10 seconds, the same as the VPS's HTTP/1
            // header deadline. Retire idle sockets first to avoid racing a 408
            // or EOF on the next poll, while still reusing them for active work.
            .pool_idle_timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(8))
            .user_agent("SirinVPN local management");
        let builder = if bind_tunnel {
            builder.local_address(profile.client_tunnel_address)
        } else {
            builder
        };
        let builder = match timeout {
            Some(timeout) => builder.timeout(timeout),
            None => builder,
        };
        let client = builder
            .build()
            .map_err(|_| ManagementError::InvalidClientIdentity)?;
        Ok(Self {
            client,
            base_url: format!("https://{}:8443", profile.server_tunnel_address),
        })
    }

    pub async fn measurement_lease(
        &self,
        public_key: String,
    ) -> Result<sirinvpn_protocol::MeasurementLease, ManagementError> {
        let response = self
            .client
            .post(format!("{}/v1/measurements", self.base_url))
            .json(&sirinvpn_protocol::MeasurementLeaseRequest { public_key })
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn remove_measurement_lease(
        &self,
        public_key: String,
    ) -> Result<(), ManagementError> {
        let response = self
            .client
            .delete(format!("{}/v1/measurements", self.base_url))
            .json(&sirinvpn_protocol::MeasurementLeaseRequest { public_key })
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn status(&self) -> Result<ServerStatus, ManagementError> {
        self.get("/v1/status").await
    }

    pub async fn diagnostics(&self) -> Result<DiagnosticReport, ManagementError> {
        let response = self
            .client
            .get(format!("{}/v1/diagnostics", self.base_url))
            .send()
            .await
            .map_err(crate::diagnostics::request_failure)?;
        let report: DiagnosticReport = self.decode(response).await?;
        if report.api_version != API_VERSION {
            return Err(ManagementError::ProtocolMismatch);
        }
        Ok(crate::diagnostics::sanitize(report))
    }

    pub async fn configuration(&self) -> Result<CurrentConfiguration, ManagementError> {
        self.get("/v1/configuration").await
    }

    pub async fn endpoint_transition(
        &self,
    ) -> Result<Option<EndpointTransitionResponse>, ManagementError> {
        self.get("/v1/endpoint-transition").await
    }

    pub async fn create_endpoint_transition(
        &self,
        request: &EndpointTransitionCreateRequest,
    ) -> Result<EndpointTransitionResponse, ManagementError> {
        let response = self
            .client
            .post(format!("{}/v1/endpoint-transition", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn publish_endpoint_transition(
        &self,
        transition: &EndpointTransitionResponse,
    ) -> Result<EndpointTransitionResponse, ManagementError> {
        let response = self
            .client
            .put(format!("{}/v1/endpoint-transition", self.base_url))
            .json(transition)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn create_invitation(
        &self,
        request: &InvitationCreateRequest,
    ) -> Result<InvitationCreateResponse, ManagementError> {
        let response = self
            .client
            .post(format!("{}/v1/invitations", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn cancel_invitation(
        &self,
        invitation_id: InvitationId,
    ) -> Result<(), ManagementError> {
        let response = self
            .client
            .delete(format!("{}/v1/invitations/{invitation_id}", self.base_url))
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn membership(&self) -> Result<MembershipSnapshot, ManagementError> {
        self.get("/v1/membership").await
    }

    pub async fn rename_device(
        &self,
        device_id: DeviceId,
        name: String,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .patch(format!("{}/v1/devices/{device_id}", self.base_url))
            .json(&RenameDeviceRequest { name })
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn revoke_device(
        &self,
        device_id: DeviceId,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .delete(format!("{}/v1/devices/{device_id}", self.base_url))
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn update_device_peer_communication(
        &self,
        device_id: DeviceId,
        enabled: bool,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .patch(format!(
                "{}/v1/devices/{device_id}/peer-communication",
                self.base_url
            ))
            .json(&DevicePeerCommunicationUpdateRequest { enabled })
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn create_port_forward(
        &self,
        request: &PortForwardCreateRequest,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .post(format!("{}/v1/port-forwards", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn remove_port_forward(
        &self,
        protocol: PortForwardProtocol,
        public_port: u16,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .delete(format!(
                "{}/v1/port-forwards/{protocol}/{public_port}",
                self.base_url
            ))
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn update_member_access(
        &self,
        member_id: MemberId,
        administrator: bool,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .patch(format!("{}/v1/members/{member_id}/access", self.base_url))
            .json(&MemberAccessUpdateRequest { administrator })
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn update_member_policy(
        &self,
        member_id: MemberId,
        policy: &sirinvpn_protocol::MemberPolicy,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .patch(format!("{}/v1/members/{member_id}/policy", self.base_url))
            .json(policy)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn update_member_suspension(
        &self,
        member_id: MemberId,
        suspended: bool,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .patch(format!(
                "{}/v1/members/{member_id}/suspension",
                self.base_url
            ))
            .json(&MemberSuspensionUpdateRequest { suspended })
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn revoke_member_devices(
        &self,
        member_id: MemberId,
        confirmed: bool,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .delete(format!("{}/v1/members/{member_id}/devices", self.base_url))
            .json(&MemberDevicesRevokeRequest { confirmed })
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn transfer_ownership(
        &self,
        destination_device_id: DeviceId,
    ) -> Result<MembershipSnapshot, ManagementError> {
        let response = self
            .client
            .patch(format!("{}/v1/ownership", self.base_url))
            .json(&OwnershipTransferRequest {
                destination_device_id,
            })
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn prepare_key_rotation(
        &self,
        request: &KeyRotationPrepareRequest,
    ) -> Result<KeyRotationPrepareResponse, ManagementError> {
        let response = self
            .client
            .post(format!("{}/v1/key-rotations", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn commit_key_rotation(
        &self,
        rotation_id: KeyRotationId,
    ) -> Result<KeyRotationCommitResponse, ManagementError> {
        let response = self
            .client
            .patch(format!("{}/v1/key-rotations/{rotation_id}", self.base_url))
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn cancel_key_rotation(
        &self,
        rotation_id: KeyRotationId,
    ) -> Result<(), ManagementError> {
        let response = self
            .client
            .delete(format!("{}/v1/key-rotations/{rotation_id}", self.base_url))
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    pub async fn enroll(
        &self,
        request: &EnrollmentRequest,
    ) -> Result<EnrollmentResult, ManagementError> {
        let response = self
            .client
            .post(format!("{}/v1/enrollment", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ManagementError> {
        let response = self
            .client
            .get(format!("{}{path}", self.base_url))
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        self.decode(response).await
    }

    async fn decode<T: serde::de::DeserializeOwned>(
        &self,
        mut response: reqwest::Response,
    ) -> Result<T, ManagementError> {
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_MANAGEMENT_RESPONSE_BYTES as u64)
        {
            return Err(ManagementError::ConnectionFailed);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_MANAGEMENT_RESPONSE_BYTES {
                return Err(ManagementError::ConnectionFailed);
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let error: ApiErrorBody =
                serde_json::from_slice(&bytes).map_err(|_| ManagementError::ConnectionFailed)?;
            if error.api_version != API_VERSION {
                return Err(ManagementError::ProtocolMismatch);
            }
            return Err(ManagementError::RequestRejected {
                code: error.code,
                message: error.message,
            });
        }
        let envelope: ApiEnvelope<T> =
            serde_json::from_slice(&bytes).map_err(|_| ManagementError::ConnectionFailed)?;
        if envelope.api_version != API_VERSION {
            return Err(ManagementError::ProtocolMismatch);
        }
        Ok(envelope.payload)
    }
}

const MAX_MANAGEMENT_RESPONSE_BYTES: usize = 1024 * 1024;

#[cfg(test)]
mod tests;
