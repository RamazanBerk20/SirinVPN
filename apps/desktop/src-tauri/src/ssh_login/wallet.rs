//! Secret Service access for saved SSH logins. keyring-rs unlocks locked items
//! and waits indefinitely for the system prompt; an automatic lookup must not.
use dbus_secret_service::{EncryptionType, Error, SecretService};
use keyring::credential::CredentialApi;
use std::collections::HashMap;

#[derive(Debug)]
pub(super) struct Wallet {
    service: &'static str,
    account: String,
    /// Zero refuses locked items before any system prompt appears.
    prompt_seconds: u64,
}

impl Wallet {
    pub(super) fn new(service: &'static str, account: String, prompt: bool) -> Self {
        Self {
            service,
            account,
            prompt_seconds: if prompt { 60 } else { 0 },
        }
    }

    fn connect(&self) -> keyring::Result<SecretService> {
        SecretService::connect_with_max_prompt_timeout(EncryptionType::Plain, self.prompt_seconds)
            .map_err(failure)
    }

    /// Matches items written by keyring-rs, with or without its target attribute.
    fn query(&self) -> HashMap<&str, &str> {
        HashMap::from([
            ("service", self.service),
            ("username", self.account.as_str()),
        ])
    }

    /// keyring-rs also cached a copy in the kernel keyring. Nothing reads it
    /// now, so a replaced or forgotten login must not linger there.
    fn forget_cached_copy(&self) {
        if let Ok(cached) = keyring::keyutils::KeyutilsCredential::new_with_target(
            None,
            self.service,
            &self.account,
        ) {
            let _ = cached.delete_credential();
        }
    }
}

fn failure(error: Error) -> keyring::Error {
    match error {
        Error::Locked | Error::Prompt | Error::NoResult => {
            keyring::Error::NoStorageAccess(Box::new(error))
        }
        error => keyring::Error::PlatformFailure(Box::new(error)),
    }
}

impl CredentialApi for Wallet {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        let service = self.connect()?;
        let collection = service.get_default_collection().map_err(failure)?;
        if collection.is_locked().map_err(failure)? {
            collection.unlock().map_err(failure)?;
        }
        // Same attributes as keyring-rs, so the existing item is replaced.
        let mut attributes = self.query();
        attributes.extend([("target", "default"), ("application", "rust-keyring")]);
        collection
            .create_item(
                &format!("{}@{}:default", self.account, self.service),
                attributes,
                secret,
                true,
                "text/plain",
            )
            .map_err(failure)?;
        self.forget_cached_copy();
        Ok(())
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        let service = self.connect()?;
        let found = service.search_items(self.query()).map_err(failure)?;
        if found.locked.len() + found.unlocked.len() > 1 {
            return Err(keyring::Error::Invalid(
                "entry".into(),
                "matches several items".into(),
            ));
        }
        if let Some(item) = found.locked.first() {
            if self.prompt_seconds == 0 {
                return Err(failure(Error::Locked));
            }
            item.unlock().map_err(failure)?;
            return item.get_secret().map_err(failure);
        }
        found
            .unlocked
            .first()
            .ok_or(keyring::Error::NoEntry)?
            .get_secret()
            .map_err(failure)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        self.forget_cached_copy();
        let service = self.connect()?;
        let found = service.search_items(self.query()).map_err(failure)?;
        if found.locked.is_empty() && found.unlocked.is_empty() {
            return Err(keyring::Error::NoEntry);
        }
        for item in found.unlocked.iter().chain(&found.locked) {
            item.delete().map_err(failure)?;
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
