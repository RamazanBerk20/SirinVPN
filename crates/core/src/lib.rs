#![forbid(unsafe_code)]

mod backup;
pub mod diagnostics;
mod encrypted_backup;
mod endpoint_discovery;
mod endpoint_transition;
pub use endpoint_discovery::{
    current_checkpoint_matches, discover_endpoint_checkpoint, discover_endpoint_checkpoint_at,
    endpoint_connection_candidates, offer_endpoint_checkpoint_at, validate_endpoint_identity,
    verify_endpoint_checkpoint,
};
mod identity;
mod invitation;
mod key_rotation;
mod management;
mod network_policy;
mod pending_enrollment;
mod recovery;
pub use pending_enrollment::PendingEnrollment;
pub use recovery::{
    DecodedRecoveryKey, MAX_RECOVERY_PACKAGE_BYTES, RecoveryKeyDraft, RecoveryKeyPreview,
    decrypt_recovery_package, encrypt_recovery_package, read_recovery_package,
    validate_recovery_response, write_recovery_package,
};
mod secrets;
mod server_backup;
mod store;

use directories::ProjectDirs;
use std::path::PathBuf;

pub use backup::{
    BackupError, DecryptedDeviceBackup, DeviceBackupRecoveryMetadata, MAX_DEVICE_BACKUP_BYTES,
    decrypt_device_backup, encrypt_device_backup,
};
pub use endpoint_transition::{
    DecodedEndpointTransition, EndpointTransitionCode, EndpointTransitionError,
    EndpointTransitionResult, apply_endpoint_transition, create_endpoint_transition,
    publish_endpoint_transition,
};
pub use identity::{
    LocalIdentity, PublicIdentity, SecretIdentity, management_certificate_fingerprint,
    management_identity_fingerprint, wireguard_public_key_from_private,
};
pub use invitation::{
    DecodedInvitation, InvitationDraft, InvitationEnrollmentBinding, InvitationError,
    InvitationTarget, SecretInvitationCode,
};
pub use key_rotation::{
    KeyRotationError, KeyRotationResult, RotationConnectionPolicy, has_pending_key_rotation,
    rotate_current_device_keys, rotate_current_device_keys_with_policy,
};
pub use management::{ManagementClient, ManagementError, ManagementStatusStream};
pub use network_policy::{
    NetworkContext, NetworkPolicyError, NetworkPolicyStore, TrustedWifiNetwork,
    WifiAutomationPolicy, WifiNetworkStatus, WifiPolicySnapshot,
};
#[cfg(target_os = "android")]
pub use secrets::install_android_secret_store;
pub use secrets::{HybridSecretStore, SecretStore, SecretStoreError};
#[cfg(not(any(windows, target_os = "android")))]
pub use secrets::{StoragePolicy, StorageStatus};
pub use server_backup::{
    DecryptedServerBackup, ServerBackupError, ServerBackupMetadata, read_encrypted_server_backup,
    validate_server_backup_password, write_encrypted_server_backup,
};
pub use store::{ProfileStore, ProfileStoreError};

#[derive(Clone, Debug)]
pub struct ClientPaths {
    pub configuration_directory: PathBuf,
    pub profiles_file: PathBuf,
    pub fallback_secrets_directory: PathBuf,
    pub key_rotations_directory: PathBuf,
    pub network_policy_file: PathBuf,
}

impl ClientPaths {
    pub fn discover() -> anyhow::Result<Self> {
        let directories = ProjectDirs::from("org", "SirinVPN", "SirinVPN")
            .ok_or_else(|| anyhow::anyhow!("local application directories are unavailable"))?;
        Ok(Self::under(directories.config_dir().to_path_buf()))
    }

    pub fn under(configuration_directory: PathBuf) -> Self {
        Self {
            profiles_file: configuration_directory.join("servers.json"),
            fallback_secrets_directory: configuration_directory.join("secrets"),
            key_rotations_directory: configuration_directory.join("key-rotations"),
            network_policy_file: configuration_directory.join("network-policy.json"),
            configuration_directory,
        }
    }

    pub fn profile_store(&self) -> ProfileStore {
        ProfileStore::new(self.profiles_file.clone())
    }

    pub fn secret_store(&self) -> HybridSecretStore {
        HybridSecretStore::new(self.fallback_secrets_directory.clone())
    }

    pub fn network_policy_store(&self) -> NetworkPolicyStore {
        NetworkPolicyStore::new(self.network_policy_file.clone())
    }
}
