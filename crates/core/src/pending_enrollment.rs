//! Retain the same locally generated permanent keys when enrollment is retried.
use crate::{ClientPaths, LocalIdentity, PublicIdentity, SecretStore};
use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{ServerId, ServerProfile};
use std::{fs, path::PathBuf};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentJournal {
    schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invitation_names: Option<sirinvpn_protocol::EnrollmentNames>,
    server_id: ServerId,
    authority: String,
    public_identity: PublicIdentity,
    identity_reference: String,
    profile: Option<ServerProfile>,
}

/// Where an enrollment stands; each step accepts only its legal predecessors. On disk
/// it stays the schema-1 journal (names and profile), so journals written by earlier
/// versions resume unchanged. Key confirmation is not persisted: a resumed enrollment
/// re-sends the same request and confirms the VPS answer again before committing.
#[derive(Clone, Debug, Eq, PartialEq)]
// Short-lived values read once per operation; boxing would only complicate matching.
#[allow(clippy::large_enum_variant)]
pub enum EnrollmentStage {
    /// The permanent identity is generated and stored.
    Staged,
    /// The invitation's recipient names are bound to this journal.
    Named(sirinvpn_protocol::EnrollmentNames),
    /// The VPS answered; `preshared_key` says whether the identity keeps its key.
    KeyConfirmed { preshared_key: bool },
    /// The profile is saved in the journal and committed to the profile store.
    Committed(ServerProfile),
}

pub struct PendingEnrollment {
    pub identity: LocalIdentity,
    pub identity_reference: String,
    stage: EnrollmentStage,
    journal: EnrollmentJournal,
    path: PathBuf,
    _lock: fs::File,
}

impl PendingEnrollment {
    pub fn open(
        paths: &ClientPaths,
        secrets: &dyn SecretStore,
        server_id: ServerId,
        authority: &str,
        device_label: &str,
    ) -> Result<Self> {
        sirinvpn_protocol::validate_server_name(device_label)?;
        if authority.is_empty()
            || authority.len() > 96
            || !authority
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("enrollment authority is invalid");
        }
        let directory = paths.configuration_directory.join("pending-enrollment");
        sirinvpn_platform::files::create_private_directory(&directory)?;
        let lock_path = directory.join(format!("{server_id}.lock"));
        if fs::symlink_metadata(&lock_path)
            .is_ok_and(|metadata| !metadata.is_file() || metadata.file_type().is_symlink())
        {
            bail!("enrollment lock is invalid");
        }
        let lock = sirinvpn_platform::files::open_private_lock(&lock_path)?;
        lock.try_lock_exclusive()
            .context("another enrollment for this server is already running")?;
        let path = directory.join(format!("{authority}.json"));
        let (journal, identity) = if path.try_exists()? {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 32768 {
                bail!("pending enrollment is invalid");
            }
            let journal: EnrollmentJournal = serde_json::from_slice(&fs::read(&path)?)?;
            if journal.schema_version != 1
                || journal.server_id != server_id
                || journal.authority != authority
            {
                bail!("pending enrollment belongs to a different authority");
            }
            let secret = secrets.get(&journal.identity_reference)?;
            let public =
                secret.public_identity(&journal.public_identity.management_certificate_pem)?;
            if public != journal.public_identity {
                bail!("pending enrollment identity does not match its secret");
            }
            (journal, LocalIdentity { public, secret })
        } else {
            let mut identity = LocalIdentity::generate(device_label)?;
            // Recovery requests reject unknown fields on older servers, so only
            // invitation enrollment offers a preshared key.
            if authority.starts_with("invitation-") {
                identity.secret.wireguard_preshared_key = Some(crate::generate_preshared_key());
            }
            let identity_reference = format!("enrollment-{}", sirinvpn_protocol::DeviceId::new());
            secrets.put(&identity_reference, &identity.secret)?;
            let journal = EnrollmentJournal {
                schema_version: 1,
                invitation_names: None,
                server_id,
                authority: authority.into(),
                public_identity: identity.public.clone(),
                identity_reference,
                profile: None,
            };
            (journal, identity)
        };
        let stage = match (&journal.profile, &journal.invitation_names) {
            (Some(profile), _) => EnrollmentStage::Committed(profile.clone()),
            (None, Some(names)) => EnrollmentStage::Named(names.clone()),
            (None, None) => EnrollmentStage::Staged,
        };
        let staged = Self {
            identity_reference: journal.identity_reference.clone(),
            identity,
            stage,
            journal,
            path,
            _lock: lock,
        };
        if let Some(profile) = &staged.journal.profile {
            staged.validate_profile(profile)?;
        }
        staged.persist()?;
        Ok(staged)
    }

    pub fn bind_invitation_names(
        &mut self,
        names: Option<sirinvpn_protocol::EnrollmentNames>,
    ) -> Result<()> {
        if !matches!(
            self.stage,
            EnrollmentStage::Staged | EnrollmentStage::Named(_)
        ) {
            bail!("recipient names can only be bound before the VPS answers");
        }
        if self.journal.invitation_names.is_some() && self.journal.invitation_names != names {
            bail!("retry this invitation with the same member and device names");
        }
        self.journal.invitation_names = names.clone();
        self.persist()?;
        if let Some(names) = names {
            self.stage = EnrollmentStage::Named(names);
        }
        Ok(())
    }

    pub fn stage(&self) -> &EnrollmentStage {
        &self.stage
    }

    /// Keeps the offered preshared key only when the VPS reports storing it; an
    /// older VPS ignores the field and would never complete a handshake with it.
    pub fn confirm_preshared_key(
        &mut self,
        secrets: &dyn SecretStore,
        stored_by_server: bool,
    ) -> Result<()> {
        if matches!(self.stage, EnrollmentStage::Committed(_)) {
            bail!("this enrollment is already committed");
        }
        self.confirm_preshared_key_answer(secrets, stored_by_server)?;
        self.stage = EnrollmentStage::KeyConfirmed {
            preshared_key: self.identity.secret.wireguard_preshared_key.is_some(),
        };
        Ok(())
    }

    fn confirm_preshared_key_answer(
        &mut self,
        secrets: &dyn SecretStore,
        stored_by_server: bool,
    ) -> Result<()> {
        match (
            stored_by_server,
            &self.identity.secret.wireguard_preshared_key,
        ) {
            (true, Some(_)) | (false, None) => return Ok(()),
            (true, None) => bail!("the VPS confirmed a preshared key this device did not offer"),
            (false, Some(_)) => {}
        }
        // Stored secret references are immutable; the key-less copy needs its own.
        let mut secret = self.identity.secret.clone();
        secret.wireguard_preshared_key = None;
        let reference = format!("enrollment-{}", sirinvpn_protocol::DeviceId::new());
        secrets.put(&reference, &secret)?;
        let previous = std::mem::replace(&mut self.journal.identity_reference, reference.clone());
        self.persist()?;
        self.identity_reference = reference;
        self.identity.secret = secret;
        secrets.delete(&previous)?;
        Ok(())
    }

    pub fn completed_profile(&self) -> Option<ServerProfile> {
        self.journal.profile.clone()
    }

    pub fn commit_profile(
        &mut self,
        paths: &ClientPaths,
        profile: ServerProfile,
        replace_existing: bool,
    ) -> Result<()> {
        // A key the VPS never confirmed must not reach a saved profile: an older VPS
        // ignores it and the device could never complete a handshake.
        let legal = match &self.stage {
            EnrollmentStage::KeyConfirmed { .. } => true,
            EnrollmentStage::Committed(committed) => committed == &profile,
            EnrollmentStage::Staged | EnrollmentStage::Named(_) => {
                self.identity.secret.wireguard_preshared_key.is_none()
            }
        };
        if !legal {
            bail!("confirm the VPS answer for this device's preshared key before committing");
        }
        self.validate_profile(&profile)?;
        self.journal.profile = Some(profile.clone());
        self.persist()?;
        if replace_existing
            || paths
                .profile_store()
                .load()?
                .iter()
                .any(|existing| existing == &profile)
        {
            paths.profile_store().upsert(profile.clone())?;
        } else {
            paths.profile_store().insert(profile.clone())?;
        }
        fs::remove_file(&self.path)?;
        sirinvpn_platform::files::sync_directory(
            self.path
                .parent()
                .context("enrollment directory is unavailable")?,
        )?;
        self.stage = EnrollmentStage::Committed(profile);
        Ok(())
    }

    fn validate_profile(&self, profile: &ServerProfile) -> Result<()> {
        if profile.id != self.journal.server_id
            || profile.identity_reference != self.identity_reference
            || profile.client_management_certificate_pem
                != self.identity.public.management_certificate_pem
        {
            bail!("completed enrollment does not match the staged identity");
        }
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        sirinvpn_platform::files::atomic_write(
            &self.path,
            &serde_json::to_vec(&self.journal)?,
            true,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecretIdentity, SecretStoreError};
    #[derive(Default)]
    struct MemorySecrets(std::sync::Mutex<std::collections::HashMap<String, SecretIdentity>>);
    impl SecretStore for MemorySecrets {
        fn put(&self, reference: &str, secret: &SecretIdentity) -> Result<(), SecretStoreError> {
            self.0
                .lock()
                .unwrap()
                .insert(reference.into(), secret.clone());
            Ok(())
        }
        fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError> {
            self.0
                .lock()
                .unwrap()
                .get(reference)
                .cloned()
                .ok_or(SecretStoreError::NotFound)
        }
        fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
            self.0.lock().unwrap().remove(reference);
            Ok(())
        }
    }
    #[test]
    fn retries_retain_keys_and_concurrent_enrollment_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().into());
        let secrets = MemorySecrets::default();
        let server = ServerId::new();
        let mut first =
            PendingEnrollment::open(&paths, &secrets, server, "invitation-test", "Phone").unwrap();
        let names = Some(sirinvpn_protocol::EnrollmentNames {
            member_name: Some("Nickname".into()),
            device_name: "My phone".into(),
        });
        first.bind_invitation_names(names.clone()).unwrap();
        let public = first.identity.public.clone();
        let reference = first.identity_reference.clone();
        assert!(
            PendingEnrollment::open(&paths, &secrets, server, "invitation-test", "Phone").is_err()
        );
        let journal = fs::read_to_string(&first.path).unwrap();
        assert!(!journal.contains("PRIVATE KEY"));
        assert!(!journal.contains(&first.identity.secret.wireguard_private_key));
        drop(first);
        let mut resumed =
            PendingEnrollment::open(&paths, &secrets, server, "invitation-test", "Phone").unwrap();
        resumed.bind_invitation_names(names).unwrap();
        assert!(resumed.bind_invitation_names(None).is_err());
        assert_eq!(resumed.identity.public, public);
        assert_eq!(resumed.identity_reference, reference);
        drop(resumed);
        assert!(
            PendingEnrollment::open(
                &paths,
                &secrets,
                ServerId::new(),
                "invitation-test",
                "Phone"
            )
            .is_err()
        );
    }

    #[test]
    fn invitation_preshared_keys_survive_retries_and_follow_the_server_answer() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().into());
        let secrets = MemorySecrets::default();
        let server = ServerId::new();
        let first =
            PendingEnrollment::open(&paths, &secrets, server, "invitation-psk", "Phone").unwrap();
        let key = first
            .identity
            .secret
            .wireguard_preshared_key
            .clone()
            .unwrap();
        crate::validate_preshared_key(&key).unwrap();
        assert!(!fs::read_to_string(&first.path).unwrap().contains(&key));
        drop(first);

        // A retry after a lost response offers the same key, as the receipt requires.
        let mut kept =
            PendingEnrollment::open(&paths, &secrets, server, "invitation-psk", "Phone").unwrap();
        assert_eq!(
            kept.identity.secret.wireguard_preshared_key.as_deref(),
            Some(key.as_str())
        );
        let reference = kept.identity_reference.clone();
        kept.confirm_preshared_key(&secrets, true).unwrap();
        assert_eq!(kept.identity_reference, reference);
        drop(kept);

        // An older VPS ignored the key: continue with a key-less identity under a new reference.
        let mut ignored =
            PendingEnrollment::open(&paths, &secrets, server, "invitation-psk", "Phone").unwrap();
        let public = ignored.identity.public.clone();
        ignored.confirm_preshared_key(&secrets, false).unwrap();
        assert_ne!(ignored.identity_reference, reference);
        assert!(ignored.identity.secret.wireguard_preshared_key.is_none());
        assert!(matches!(
            secrets.get(&reference),
            Err(SecretStoreError::NotFound)
        ));
        let stored = secrets.get(&ignored.identity_reference).unwrap();
        assert!(stored.wireguard_preshared_key.is_none());
        assert!(ignored.confirm_preshared_key(&secrets, true).is_err());
        drop(ignored);
        let resumed =
            PendingEnrollment::open(&paths, &secrets, server, "invitation-psk", "Phone").unwrap();
        assert_eq!(resumed.identity.public, public);
        assert!(resumed.identity.secret.wireguard_preshared_key.is_none());
        drop(resumed);

        let recovery =
            PendingEnrollment::open(&paths, &secrets, ServerId::new(), "recovery-psk", "Laptop")
                .unwrap();
        assert!(recovery.identity.secret.wireguard_preshared_key.is_none());
    }

    fn profile_for(pending: &PendingEnrollment, server: ServerId) -> ServerProfile {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "id": server,
            "name": "Joined VPS",
            "endpoint": {"host": "203.0.113.30", "wireguard_port": 51820},
            "client_tunnel_address": "10.77.0.3",
            "server_tunnel_address": "10.77.0.1",
            "server_wireguard_public_key": "public",
            "pinned_server_certificate_pem": "certificate",
            "client_management_certificate_pem": pending.identity.public.management_certificate_pem,
            "identity_reference": pending.identity_reference,
            "role": "member"
        }))
        .unwrap()
    }

    #[test]
    fn a_journal_written_by_an_earlier_version_resumes_at_its_stage() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().into());
        let secrets = MemorySecrets::default();
        let server = ServerId::new();
        let mut identity = LocalIdentity::generate("Phone").unwrap();
        identity.secret.wireguard_preshared_key = Some(crate::generate_preshared_key());
        secrets.put("enrollment-legacy", &identity.secret).unwrap();
        let journal_directory = paths.configuration_directory.join("pending-enrollment");
        sirinvpn_platform::files::create_private_directory(&journal_directory).unwrap();
        // The schema-1 shape every earlier version wrote: names bound, no profile yet.
        let legacy = serde_json::json!({
            "schema_version": 1,
            "invitation_names": {"member_name": "Nickname", "device_name": "My phone"},
            "server_id": server,
            "authority": "invitation-legacy",
            "public_identity": identity.public,
            "identity_reference": "enrollment-legacy",
            "profile": null
        });
        sirinvpn_platform::files::atomic_write(
            &journal_directory.join("invitation-legacy.json"),
            &serde_json::to_vec(&legacy).unwrap(),
            false,
        )
        .unwrap();
        let mut pending =
            PendingEnrollment::open(&paths, &secrets, server, "invitation-legacy", "Phone")
                .unwrap();
        let EnrollmentStage::Named(names) = pending.stage() else {
            panic!("legacy journal did not resume named: {:?}", pending.stage());
        };
        assert_eq!(names.device_name, "My phone");
        assert_eq!(pending.identity.public, identity.public);
        // Resuming never skips the key confirmation for a key-bearing identity.
        let profile = profile_for(&pending, server);
        assert!(
            pending
                .commit_profile(&paths, profile.clone(), false)
                .is_err()
        );
        assert!(paths.profile_store().load().unwrap().is_empty());
        pending.confirm_preshared_key(&secrets, true).unwrap();
        assert_eq!(
            pending.stage(),
            &EnrollmentStage::KeyConfirmed {
                preshared_key: true
            }
        );
        // Names cannot change once the VPS answered.
        assert!(pending.bind_invitation_names(None).is_err());
        pending
            .commit_profile(&paths, profile.clone(), false)
            .unwrap();
        assert_eq!(
            pending.stage(),
            &EnrollmentStage::Committed(profile.clone())
        );
        assert_eq!(paths.profile_store().load().unwrap(), vec![profile]);
        assert!(pending.confirm_preshared_key(&secrets, true).is_err());
    }

    #[test]
    fn recovery_without_a_preshared_key_commits_without_confirmation() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().into());
        let secrets = MemorySecrets::default();
        let server = ServerId::new();
        let mut pending =
            PendingEnrollment::open(&paths, &secrets, server, "recovery-test", "Laptop").unwrap();
        assert_eq!(pending.stage(), &EnrollmentStage::Staged);
        let profile = profile_for(&pending, server);
        pending.commit_profile(&paths, profile, false).unwrap();
    }
}
