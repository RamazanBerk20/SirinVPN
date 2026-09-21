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

pub struct PendingEnrollment {
    pub identity: LocalIdentity,
    pub identity_reference: String,
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
            let identity = LocalIdentity::generate(device_label)?;
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
        let staged = Self {
            identity_reference: journal.identity_reference.clone(),
            identity,
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
        if self.journal.invitation_names.is_some() && self.journal.invitation_names != names {
            bail!("retry this invitation with the same member and device names");
        }
        self.journal.invitation_names = names;
        self.persist()
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
            paths.profile_store().upsert(profile)?;
        } else {
            paths.profile_store().insert(profile)?;
        }
        fs::remove_file(&self.path)?;
        sirinvpn_platform::files::sync_directory(
            self.path
                .parent()
                .context("enrollment directory is unavailable")?,
        )?;
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
}
