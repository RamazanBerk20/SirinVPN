//! Preserve keyring-rs attributes. Background reads never prompt; explicit
//! user actions can request a bounded system unlock prompt.
use super::*;
use dbus_secret_service::{EncryptionType, Item, SecretService};
use std::collections::HashMap;

fn unavailable(error: dbus_secret_service::Error) -> SecretStoreError {
    let message = match error {
        dbus_secret_service::Error::Locked | dbus_secret_service::Error::Prompt => {
            "the system keyring is locked or its unlock prompt was cancelled; unlock your desktop keyring (or retry the action to be prompted) and try again"
        }
        _ => {
            "the system keyring service could not be reached; check that your desktop wallet is running and retry"
        }
    };
    SecretStoreError::Unavailable(message.into())
}
fn attributes(reference: &str) -> HashMap<&str, &str> {
    HashMap::from([
        ("service", "org.sirinvpn.client"),
        ("username", reference),
        ("target", "default"),
    ])
}
fn service() -> Result<SecretService, SecretStoreError> {
    SecretService::connect_with_max_prompt_timeout(EncryptionType::Plain, 0).map_err(unavailable)
}
fn owned_attributes(reference: &str) -> HashMap<&str, &str> {
    // Both legacy entries and current entries belong to this app/reference.
    let mut values = attributes(reference);
    values.remove("target");
    values
}
fn lookup<'a>(
    service: &'a SecretService,
    reference: &str,
) -> Result<Option<Item<'a>>, SecretStoreError> {
    let found = service
        .search_items(owned_attributes(reference))
        .map_err(unavailable)?;
    if found.locked.len() + found.unlocked.len() > 1 {
        return Err(SecretStoreError::InvalidData);
    }
    if !found.locked.is_empty() {
        return Err(SecretStoreError::Unavailable(
            "unlock the system keyring and retry".into(),
        ));
    }
    if let Some(item) = found.unlocked.into_iter().next() {
        return Ok(Some(item));
    }
    Ok(None)
}
impl KeyringBackend for SystemKeyring {
    fn unlock(&self, reference: &str) -> Result<(), SecretStoreError> {
        let service = SecretService::connect_with_max_prompt_timeout(EncryptionType::Plain, 60)
            .map_err(unavailable)?;
        let found = service
            .search_items(owned_attributes(reference))
            .map_err(unavailable)?;
        if found.locked.len() + found.unlocked.len() > 1 {
            return Err(SecretStoreError::InvalidData);
        }
        for item in found.locked {
            item.unlock().map_err(unavailable)?;
            if item.is_locked().map_err(unavailable)? {
                return Err(unavailable(dbus_secret_service::Error::Locked));
            }
        }
        Ok(())
    }

    fn put(&self, reference: &str, bytes: &[u8]) -> Result<(), SecretStoreError> {
        let service = service()?;
        if let Some(item) = lookup(&service, reference)? {
            let existing = Zeroizing::new(item.get_secret().map_err(unavailable)?);
            if existing.len() > 73728 || identity(&existing)?.1 != identity(bytes)?.1 {
                return Err(SecretStoreError::InvalidData);
            }
            return item
                .set_secret(bytes, "application/octet-stream")
                .map_err(unavailable);
        }
        let collection = service.get_default_collection().map_err(unavailable)?;
        if collection.is_locked().map_err(unavailable)? {
            return Err(SecretStoreError::Unavailable(
                "unlock the system keyring and retry".into(),
            ));
        }
        collection
            .create_item(
                "SirinVPN device identity",
                attributes(reference),
                bytes,
                false,
                "application/octet-stream",
            )
            .map_err(unavailable)?;
        Ok(())
    }
    fn get(&self, reference: &str) -> Result<Vec<u8>, SecretStoreError> {
        let service = service()?;
        let item = lookup(&service, reference)?.ok_or(SecretStoreError::NotFound)?;
        let bytes = item.get_secret().map_err(unavailable)?;
        if bytes.len() > 73728 {
            return Err(SecretStoreError::InvalidData);
        }
        Ok(bytes)
    }
    fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
        let service = service()?;
        let found = service
            .search_items(owned_attributes(reference))
            .map_err(unavailable)?;
        let mut failed = false;
        for item in found.unlocked.into_iter().chain(found.locked) {
            failed |= item.delete().is_err();
        }
        let remaining = service
            .search_items(owned_attributes(reference))
            .map_err(unavailable)?;
        if failed || !remaining.unlocked.is_empty() || !remaining.locked.is_empty() {
            return Err(SecretStoreError::CleanupPending);
        }
        Ok(())
    }
}
