use crate::{
    ClientPaths, ProfileStore, ProfileStoreError, SecretIdentity, SecretStore, SecretStoreError,
    encrypted_backup::{self, EncryptedBackupError},
    identity::{
        extract_ed25519_public_key, management_identity_fingerprint, validate_secret_identity,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{
    SERVER_TUNNEL_ADDRESS, ServerId, ServerProfile, ServerRole, validate_host, validate_server_name,
};
use std::{io, net::IpAddr, path::Path};
use thiserror::Error;
use zeroize::Zeroizing;

const BACKUP_FORMAT: &str = "sirinvpn-device-backup";
const LEGACY_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const RECOVERY_METADATA_PAYLOAD_SCHEMA_VERSION: u16 = 2;
pub const MAX_DEVICE_BACKUP_BYTES: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("the local server profile was not found")]
    ProfileNotFound,
    #[error("the backup password must contain at least 12 characters")]
    WeakPassword,
    #[error("the backup password is invalid")]
    InvalidPassword,
    #[error("the backup destination already exists")]
    DestinationExists,
    #[error("the backup file is too large")]
    FileTooLarge,
    #[error("the backup format is invalid")]
    InvalidFormat,
    #[error("the backup format version is not supported")]
    IncompatibleVersion,
    #[error("the backup password is incorrect or the file was modified")]
    AuthenticationFailed,
    #[error("the backup contains an invalid device identity")]
    InvalidIdentity,
    #[error("this device identity is already present locally")]
    DuplicateIdentity,
    #[error("a different local profile already uses this server ID")]
    ServerConflict,
    #[error("an existing local profile is invalid; repair it before importing a backup")]
    InvalidLocalProfile,
    #[error("complete or recover the pending device key rotation before exporting a backup")]
    KeyRotationPending,
    #[error("the backup file operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("the local profile store operation failed: {0}")]
    ProfileStore(#[from] ProfileStoreError),
    #[error("the local secret store operation failed: {0}")]
    SecretStore(#[from] SecretStoreError),
    #[error("the profile restore failed and its staged device key could not be removed")]
    RestoreRollbackFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBackupRecoveryMetadata {
    pub owner_ssh_port: u16,
}

pub struct DecryptedDeviceBackup {
    pub profile: ServerProfile,
    pub identity: SecretIdentity,
    pub recovery_metadata: Option<DeviceBackupRecoveryMetadata>,
}

impl std::fmt::Debug for DecryptedDeviceBackup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecryptedDeviceBackup")
            .field("profile", &self.profile)
            .field("identity", &"[REDACTED]")
            .field("recovery_metadata", &self.recovery_metadata)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupPayload {
    schema_version: u16,
    profile: ServerProfile,
    identity: SecretIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_metadata: Option<DeviceBackupRecoveryMetadata>,
}

impl ClientPaths {
    pub fn export_device_backup(
        &self,
        server_id: ServerId,
        destination: &Path,
        password: &str,
    ) -> Result<ServerProfile, BackupError> {
        if crate::has_pending_key_rotation(self, server_id)
            .map_err(|_| BackupError::InvalidLocalProfile)?
        {
            return Err(BackupError::KeyRotationPending);
        }
        let profile_store = self.profile_store();
        let secret_store = self.secret_store();
        export_device_backup(
            &profile_store,
            &secret_store,
            server_id,
            destination,
            password,
        )
    }

    pub fn import_device_backup(
        &self,
        source: &Path,
        password: &str,
    ) -> Result<ServerProfile, BackupError> {
        let profile_store = self.profile_store();
        let secret_store = self.secret_store();
        import_device_backup(&profile_store, &secret_store, source, password)
    }
}

fn export_device_backup(
    profiles: &ProfileStore,
    secrets: &dyn SecretStore,
    server_id: ServerId,
    destination: &Path,
    password: &str,
) -> Result<ServerProfile, BackupError> {
    validate_export_password(password)?;
    let profile = profiles
        .load()?
        .into_iter()
        .find(|profile| profile.id == server_id)
        .ok_or(BackupError::ProfileNotFound)?;
    let identity = secrets.get(&profile.identity_reference)?;
    validate_profile_and_identity(&profile, &identity)?;
    let bytes = encrypt_device_backup(&profile, &identity, None, password)?;
    write_backup_file(destination, &bytes)?;
    Ok(profile)
}

fn import_device_backup(
    profiles: &ProfileStore,
    secrets: &dyn SecretStore,
    source: &Path,
    password: &str,
) -> Result<ServerProfile, BackupError> {
    validate_import_password(password)?;
    let bytes = read_backup_file(source)?;
    let payload = decrypt_device_backup(&bytes, password)?;
    let incoming_fingerprint =
        management_identity_fingerprint(&payload.profile.client_management_certificate_pem)
            .map_err(|_| BackupError::InvalidIdentity)?;

    for existing in profiles.load()? {
        let existing_fingerprint =
            management_identity_fingerprint(&existing.client_management_certificate_pem)
                .map_err(|_| BackupError::InvalidLocalProfile)?;
        if existing.id == payload.profile.id {
            return if existing_fingerprint == incoming_fingerprint {
                Err(BackupError::DuplicateIdentity)
            } else {
                Err(BackupError::ServerConflict)
            };
        }
        if existing_fingerprint == incoming_fingerprint {
            return Err(BackupError::DuplicateIdentity);
        }
    }

    let identity_reference = unused_identity_reference(secrets)?;
    let DecryptedDeviceBackup {
        mut profile,
        identity,
        ..
    } = payload;
    profile.identity_reference = identity_reference.clone();
    secrets.put(&identity_reference, &identity)?;
    if let Err(error) = profiles.insert(profile.clone()) {
        if secrets.delete(&identity_reference).is_err() {
            return Err(BackupError::RestoreRollbackFailed);
        }
        return Err(match error {
            ProfileStoreError::AlreadyExists => BackupError::ServerConflict,
            other => BackupError::ProfileStore(other),
        });
    }
    Ok(profile)
}

fn unused_identity_reference(secrets: &dyn SecretStore) -> Result<String, BackupError> {
    for _ in 0..8 {
        let reference = format!("restored-{}", ServerId::new());
        match secrets.get(&reference) {
            Err(SecretStoreError::NotFound) => return Ok(reference),
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(BackupError::DuplicateIdentity)
}

fn validate_export_password(password: &str) -> Result<(), BackupError> {
    encrypted_backup::validate_export_password(password).map_err(map_encrypted_backup_error)
}

fn validate_import_password(password: &str) -> Result<(), BackupError> {
    encrypted_backup::validate_import_password(password).map_err(map_encrypted_backup_error)
}

pub fn encrypt_device_backup(
    profile: &ServerProfile,
    identity: &SecretIdentity,
    recovery_metadata: Option<DeviceBackupRecoveryMetadata>,
    password: &str,
) -> Result<Vec<u8>, BackupError> {
    validate_export_password(password)?;
    validate_profile_and_identity(profile, identity)?;
    validate_recovery_metadata(profile, recovery_metadata.as_ref())?;
    let payload = BackupPayload {
        schema_version: if recovery_metadata.is_some() {
            RECOVERY_METADATA_PAYLOAD_SCHEMA_VERSION
        } else {
            LEGACY_PAYLOAD_SCHEMA_VERSION
        },
        profile: profile.clone(),
        identity: identity.clone(),
        recovery_metadata,
    };
    let plaintext =
        Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| BackupError::InvalidIdentity)?);
    encrypted_backup::encrypt(BACKUP_FORMAT, plaintext.as_slice(), password)
        .map_err(map_encrypted_backup_error)
}

pub fn decrypt_device_backup(
    bytes: &[u8],
    password: &str,
) -> Result<DecryptedDeviceBackup, BackupError> {
    validate_import_password(password)?;
    if bytes.len() > MAX_DEVICE_BACKUP_BYTES {
        return Err(BackupError::FileTooLarge);
    }
    let plaintext = encrypted_backup::decrypt(BACKUP_FORMAT, bytes, password)
        .map_err(map_encrypted_backup_error)?;
    let payload: BackupPayload =
        serde_json::from_slice(&plaintext).map_err(|_| BackupError::InvalidFormat)?;
    match payload.schema_version {
        LEGACY_PAYLOAD_SCHEMA_VERSION if payload.recovery_metadata.is_none() => {}
        RECOVERY_METADATA_PAYLOAD_SCHEMA_VERSION if payload.recovery_metadata.is_some() => {}
        LEGACY_PAYLOAD_SCHEMA_VERSION | RECOVERY_METADATA_PAYLOAD_SCHEMA_VERSION => {
            return Err(BackupError::InvalidFormat);
        }
        _ => return Err(BackupError::IncompatibleVersion),
    }
    validate_profile_and_identity(&payload.profile, &payload.identity)?;
    validate_recovery_metadata(&payload.profile, payload.recovery_metadata.as_ref())?;
    Ok(DecryptedDeviceBackup {
        profile: payload.profile,
        identity: payload.identity,
        recovery_metadata: payload.recovery_metadata,
    })
}

fn validate_recovery_metadata(
    profile: &ServerProfile,
    recovery_metadata: Option<&DeviceBackupRecoveryMetadata>,
) -> Result<(), BackupError> {
    if let Some(metadata) = recovery_metadata
        && (profile.role != ServerRole::Owner || metadata.owner_ssh_port == 0)
    {
        return Err(BackupError::InvalidIdentity);
    }
    Ok(())
}

fn validate_profile_and_identity(
    profile: &ServerProfile,
    identity: &SecretIdentity,
) -> Result<(), BackupError> {
    let valid_membership_ids = matches!(
        (profile.member_id, profile.device_id),
        (None, None) | (Some(_), Some(_))
    );
    let valid_client_address = match profile.client_tunnel_address {
        IpAddr::V4(address) => {
            address.octets()[..3] == [10, 77, 0] && (2..=223).contains(&address.octets()[3])
        }
        IpAddr::V6(_) => false,
    };
    let expected_server_address: IpAddr = SERVER_TUNNEL_ADDRESS
        .parse()
        .map_err(|_| BackupError::InvalidIdentity)?;
    if profile.schema_version != 1
        || validate_server_name(&profile.name).is_err()
        || validate_host(&profile.endpoint.host).is_err()
        || profile.endpoint.wireguard_port == 0
        || profile
            .pending_previous_endpoint
            .as_ref()
            .is_some_and(|endpoint| {
                validate_host(&endpoint.host).is_err()
                    || endpoint.wireguard_port == 0
                    || endpoint == &profile.endpoint
                    || profile.role != ServerRole::Owner
            })
        || !valid_client_address
        || profile.server_tunnel_address != expected_server_address
        || !valid_membership_ids
        || (profile.role == ServerRole::Owner && profile.administrator)
        || profile.identity_reference.is_empty()
        || profile.identity_reference.len() > 128
        || !profile
            .identity_reference
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err(BackupError::InvalidIdentity);
    }
    validate_wireguard_public_key(&profile.server_wireguard_public_key)?;
    extract_ed25519_public_key(&profile.pinned_server_certificate_pem)
        .map_err(|_| BackupError::InvalidIdentity)?;
    validate_secret_identity(identity, &profile.client_management_certificate_pem)
        .map_err(|_| BackupError::InvalidIdentity)
}

fn validate_wireguard_public_key(public_key: &str) -> Result<(), BackupError> {
    let decoded = STANDARD
        .decode(public_key)
        .map_err(|_| BackupError::InvalidIdentity)?;
    if decoded.len() != 32 || STANDARD.encode(&decoded) != public_key {
        return Err(BackupError::InvalidIdentity);
    }
    Ok(())
}

fn read_backup_file(source: &Path) -> Result<Vec<u8>, BackupError> {
    encrypted_backup::read_file(source, MAX_DEVICE_BACKUP_BYTES).map_err(map_encrypted_backup_error)
}

fn write_backup_file(destination: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    encrypted_backup::write_file(destination, bytes, ".sirinvpn-backup-")
        .map_err(map_encrypted_backup_error)
}

fn map_encrypted_backup_error(error: EncryptedBackupError) -> BackupError {
    match error {
        EncryptedBackupError::WeakPassword => BackupError::WeakPassword,
        EncryptedBackupError::InvalidPassword => BackupError::InvalidPassword,
        EncryptedBackupError::DestinationExists => BackupError::DestinationExists,
        EncryptedBackupError::FileTooLarge => BackupError::FileTooLarge,
        EncryptedBackupError::InvalidFormat => BackupError::InvalidFormat,
        EncryptedBackupError::IncompatibleVersion => BackupError::IncompatibleVersion,
        EncryptedBackupError::AuthenticationFailed => BackupError::AuthenticationFailed,
        EncryptedBackupError::Io(error) => BackupError::Io(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LocalIdentity,
        encrypted_backup::{BackupEnvelope, ENVELOPE_SCHEMA_VERSION},
    };
    use std::{collections::HashMap, fs, net::Ipv4Addr, os::unix::fs::PermissionsExt, sync::Mutex};

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<HashMap<String, SecretIdentity>>,
    }

    impl SecretStore for MemorySecretStore {
        fn put(&self, reference: &str, secret: &SecretIdentity) -> Result<(), SecretStoreError> {
            self.values
                .lock()
                .unwrap()
                .insert(reference.to_owned(), secret.clone());
            Ok(())
        }

        fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError> {
            self.values
                .lock()
                .unwrap()
                .get(reference)
                .cloned()
                .ok_or(SecretStoreError::NotFound)
        }

        fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
            self.values.lock().unwrap().remove(reference);
            Ok(())
        }
    }

    fn profile_and_secret(name: &str) -> (ServerProfile, SecretIdentity) {
        let server = LocalIdentity::generate("backup test server").unwrap();
        let client = LocalIdentity::generate("backup test client").unwrap();
        let id = ServerId::new();
        (
            ServerProfile {
                favorite: false,
                schema_version: 1,
                id,
                name: name.to_owned(),
                endpoint: sirinvpn_protocol::ServerEndpoint {
                    host: "203.0.113.40".to_owned(),
                    wireguard_port: 51_820,
                },
                endpoint_generation: 0,
                pending_previous_endpoint: None,
                pending_previous_transports: None,
                endpoint_discovery_port: None,
                alternate_endpoint_hosts: Vec::new(),
                client_tunnel_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
                server_tunnel_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1)),
                ipv6_tunnel_enabled: false,
                server_wireguard_public_key: server.public.wireguard_public_key,
                pinned_server_certificate_pem: server.public.management_certificate_pem,
                client_management_certificate_pem: client.public.management_certificate_pem,
                identity_reference: id.to_string(),
                role: ServerRole::Owner,
                administrator: false,
                member_id: None,
                device_id: None,
                obfuscated_udp: None,
                tcp_fallback: None,
                tls_like: None,
            },
            client.secret,
        )
    }

    fn export_fixture(
        directory: &tempfile::TempDir,
    ) -> (std::path::PathBuf, ServerProfile, SecretIdentity) {
        let profile_store = ProfileStore::new(directory.path().join("source/servers.json"));
        let secrets = MemorySecretStore::default();
        let (profile, secret) = profile_and_secret("Recovery source");
        profile_store.insert(profile.clone()).unwrap();
        secrets.put(&profile.identity_reference, &secret).unwrap();
        let backup = directory.path().join("device.sirinvpn-backup");
        export_device_backup(
            &profile_store,
            &secrets,
            profile.id,
            &backup,
            "correct horse battery staple",
        )
        .unwrap();
        (backup, profile, secret)
    }

    #[test]
    fn encrypted_round_trip_restores_without_exposing_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let (backup, original, secret) = export_fixture(&directory);
        let bytes = fs::read(&backup).unwrap();
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !bytes
                .windows(original.name.len())
                .any(|part| part == original.name.as_bytes())
        );
        assert!(
            !bytes
                .windows(secret.wireguard_private_key.len())
                .any(|part| { part == secret.wireguard_private_key.as_bytes() })
        );

        let target_store = ProfileStore::new(directory.path().join("target/servers.json"));
        let target_secrets = MemorySecretStore::default();
        let restored = import_device_backup(
            &target_store,
            &target_secrets,
            &backup,
            "correct horse battery staple",
        )
        .unwrap();
        assert_eq!(restored.id, original.id);
        assert_eq!(restored.name, original.name);
        assert_ne!(restored.identity_reference, original.identity_reference);
        let restored_secret = target_secrets.get(&restored.identity_reference).unwrap();
        assert_eq!(
            restored_secret.wireguard_private_key,
            secret.wireguard_private_key
        );
        assert_eq!(
            restored_secret.management_private_key_pem,
            secret.management_private_key_pem
        );
    }

    #[test]
    fn wrong_password_tampering_and_unknown_versions_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let (backup, _, _) = export_fixture(&directory);
        let target_store = ProfileStore::new(directory.path().join("target/servers.json"));
        let target_secrets = MemorySecretStore::default();
        assert!(matches!(
            import_device_backup(&target_store, &target_secrets, &backup, "wrong password"),
            Err(BackupError::AuthenticationFailed)
        ));

        let mut envelope: BackupEnvelope =
            serde_json::from_slice(&fs::read(&backup).unwrap()).unwrap();
        let mut ciphertext = STANDARD.decode(&envelope.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        envelope.ciphertext = STANDARD.encode(ciphertext);
        let tampered = directory.path().join("tampered.sirinvpn-backup");
        fs::write(&tampered, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(matches!(
            import_device_backup(
                &target_store,
                &target_secrets,
                &tampered,
                "correct horse battery staple"
            ),
            Err(BackupError::AuthenticationFailed)
        ));

        envelope.schema_version += 1;
        let future = directory.path().join("future.sirinvpn-backup");
        fs::write(&future, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(matches!(
            import_device_backup(
                &target_store,
                &target_secrets,
                &future,
                "correct horse battery staple"
            ),
            Err(BackupError::IncompatibleVersion)
        ));

        envelope.schema_version = ENVELOPE_SCHEMA_VERSION;
        envelope.kdf.memory_kib = u32::MAX;
        let unbounded = directory.path().join("unbounded.sirinvpn-backup");
        fs::write(&unbounded, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(matches!(
            import_device_backup(
                &target_store,
                &target_secrets,
                &unbounded,
                "correct horse battery staple"
            ),
            Err(BackupError::IncompatibleVersion)
        ));

        let oversized = directory.path().join("oversized.sirinvpn-backup");
        fs::write(&oversized, vec![b'x'; MAX_DEVICE_BACKUP_BYTES + 1]).unwrap();
        assert!(matches!(
            import_device_backup(
                &target_store,
                &target_secrets,
                &oversized,
                "correct horse battery staple"
            ),
            Err(BackupError::FileTooLarge)
        ));
    }

    #[test]
    fn restore_detects_duplicates_conflicts_and_existing_destinations() {
        let directory = tempfile::tempdir().unwrap();
        let (backup, original, _) = export_fixture(&directory);
        assert!(matches!(
            write_backup_file(&backup, b"replacement"),
            Err(BackupError::DestinationExists)
        ));

        let duplicate_store = ProfileStore::new(directory.path().join("duplicate/servers.json"));
        let duplicate_secrets = MemorySecretStore::default();
        import_device_backup(
            &duplicate_store,
            &duplicate_secrets,
            &backup,
            "correct horse battery staple",
        )
        .unwrap();
        assert!(matches!(
            import_device_backup(
                &duplicate_store,
                &duplicate_secrets,
                &backup,
                "correct horse battery staple"
            ),
            Err(BackupError::DuplicateIdentity)
        ));

        let conflict_store = ProfileStore::new(directory.path().join("conflict/servers.json"));
        let conflict_secrets = MemorySecretStore::default();
        let (mut conflict, conflict_secret) = profile_and_secret("Conflict");
        conflict.id = original.id;
        conflict.identity_reference = original.id.to_string();
        conflict_store.insert(conflict.clone()).unwrap();
        conflict_secrets
            .put(&conflict.identity_reference, &conflict_secret)
            .unwrap();
        assert!(matches!(
            import_device_backup(
                &conflict_store,
                &conflict_secrets,
                &backup,
                "correct horse battery staple"
            ),
            Err(BackupError::ServerConflict)
        ));

        let copied_identity_store =
            ProfileStore::new(directory.path().join("copied-identity/servers.json"));
        let copied_identity_secrets = MemorySecretStore::default();
        let mut copied_identity = original.clone();
        copied_identity.id = ServerId::new();
        copied_identity.identity_reference = copied_identity.id.to_string();
        copied_identity_store.insert(copied_identity).unwrap();
        assert!(matches!(
            import_device_backup(
                &copied_identity_store,
                &copied_identity_secrets,
                &backup,
                "correct horse battery staple"
            ),
            Err(BackupError::DuplicateIdentity)
        ));
    }

    #[test]
    fn export_rejects_weak_passwords_and_mismatched_private_keys() {
        let directory = tempfile::tempdir().unwrap();
        let profile_store = ProfileStore::new(directory.path().join("source/servers.json"));
        let secrets = MemorySecretStore::default();
        let (profile, _) = profile_and_secret("Mismatched identity");
        let (_, wrong_secret) = profile_and_secret("Other identity");
        profile_store.insert(profile.clone()).unwrap();
        secrets
            .put(&profile.identity_reference, &wrong_secret)
            .unwrap();
        let backup = directory.path().join("invalid.sirinvpn-backup");
        assert!(matches!(
            export_device_backup(&profile_store, &secrets, profile.id, &backup, "short"),
            Err(BackupError::WeakPassword)
        ));
        assert!(matches!(
            export_device_backup(
                &profile_store,
                &secrets,
                profile.id,
                &backup,
                "correct horse battery staple"
            ),
            Err(BackupError::InvalidIdentity)
        ));
        assert!(!backup.exists());
    }

    #[test]
    fn recovery_metadata_expands_the_payload_without_breaking_legacy_import() {
        let directory = tempfile::tempdir().unwrap();
        let (profile, identity) = profile_and_secret("Portable recovery");
        let password = "correct horse battery staple";

        let legacy = encrypt_device_backup(&profile, &identity, None, password).unwrap();
        let legacy = decrypt_device_backup(&legacy, password).unwrap();
        assert_eq!(legacy.profile, profile);
        assert!(legacy.recovery_metadata.is_none());

        let metadata = DeviceBackupRecoveryMetadata {
            owner_ssh_port: 2_222,
        };
        let extended =
            encrypt_device_backup(&profile, &identity, Some(metadata.clone()), password).unwrap();
        let decrypted = decrypt_device_backup(&extended, password).unwrap();
        assert_eq!(decrypted.profile, profile);
        assert_eq!(decrypted.recovery_metadata, Some(metadata));

        let source = directory.path().join("android.sirinvpn-backup");
        fs::write(&source, extended).unwrap();
        let target_store = ProfileStore::new(directory.path().join("target/servers.json"));
        let target_secrets = MemorySecretStore::default();
        let imported = import_device_backup(&target_store, &target_secrets, &source, password)
            .expect("updated desktop reader should accept an Android backup");
        assert_eq!(imported.id, profile.id);
    }

    #[test]
    fn recovery_metadata_is_bound_to_an_owner_profile() {
        let (mut profile, identity) = profile_and_secret("Member recovery");
        profile.role = ServerRole::Member;
        assert!(matches!(
            encrypt_device_backup(
                &profile,
                &identity,
                Some(DeviceBackupRecoveryMetadata { owner_ssh_port: 22 }),
                "correct horse battery staple",
            ),
            Err(BackupError::InvalidIdentity)
        ));
        assert!(matches!(
            encrypt_device_backup(
                &profile,
                &identity,
                Some(DeviceBackupRecoveryMetadata { owner_ssh_port: 0 }),
                "correct horse battery staple",
            ),
            Err(BackupError::InvalidIdentity)
        ));
    }
}
