//! The management calls rotation makes, behind a seam so the driver can run against
//! an in-memory VPS that loses responses or refuses identities at every step.
use crate::{ManagementClient, ManagementError, SecretIdentity};
use sirinvpn_protocol::{
    DeviceId, KeyRotationCommitResponse, KeyRotationId, KeyRotationPrepareRequest,
    KeyRotationPrepareResponse, ServerProfile, ServerStatus,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RotationCapabilities {
    pub key_rotation: bool,
    pub preshared_keys: bool,
}

pub(super) trait RotationRemote {
    type Client: RotationClient;
    fn client(
        &self,
        profile: &ServerProfile,
        secret: &SecretIdentity,
    ) -> Result<Self::Client, ManagementError>;
}

pub(super) trait RotationClient {
    async fn capabilities(&self) -> Result<RotationCapabilities, ManagementError>;
    async fn status(&self) -> Result<ServerStatus, ManagementError>;
    async fn prepare(
        &self,
        request: &KeyRotationPrepareRequest,
    ) -> Result<KeyRotationPrepareResponse, ManagementError>;
    async fn commit(
        &self,
        rotation_id: KeyRotationId,
    ) -> Result<KeyRotationCommitResponse, ManagementError>;
    async fn refresh_membership_ids(
        &self,
        profile: &mut ServerProfile,
        device: DeviceId,
    ) -> Result<(), ManagementError>;
}

pub(super) struct LiveRemote;

impl RotationRemote for LiveRemote {
    type Client = ManagementClient;
    fn client(
        &self,
        profile: &ServerProfile,
        secret: &SecretIdentity,
    ) -> Result<ManagementClient, ManagementError> {
        ManagementClient::new(profile, secret)
    }
}

impl RotationClient for ManagementClient {
    async fn capabilities(&self) -> Result<RotationCapabilities, ManagementError> {
        let configuration = self.configuration().await?;
        Ok(RotationCapabilities {
            key_rotation: configuration.key_rotation_enabled,
            preshared_keys: configuration.preshared_keys_enabled,
        })
    }
    async fn status(&self) -> Result<ServerStatus, ManagementError> {
        ManagementClient::status(self).await
    }
    async fn prepare(
        &self,
        request: &KeyRotationPrepareRequest,
    ) -> Result<KeyRotationPrepareResponse, ManagementError> {
        self.prepare_key_rotation(request).await
    }
    async fn commit(
        &self,
        rotation_id: KeyRotationId,
    ) -> Result<KeyRotationCommitResponse, ManagementError> {
        self.commit_key_rotation(rotation_id).await
    }
    async fn refresh_membership_ids(
        &self,
        profile: &mut ServerProfile,
        device: DeviceId,
    ) -> Result<(), ManagementError> {
        ManagementClient::refresh_membership_ids(self, profile, device).await
    }
}
