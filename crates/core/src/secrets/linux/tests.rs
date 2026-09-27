use super::*;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires scripts/test-keyring.sh disposable Secret Service session"]
fn real_secret_service_interop_migration_duplicates_and_lock() {
    use dbus_secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;
    assert!(std::path::Path::new("/run/sirinvpn-keyring-fixture").is_file());
    let directory = tempfile::tempdir().unwrap();
    let store = HybridSecretStore::new(directory.path().join("secrets"));
    let generated = crate::LocalIdentity::generate("synthetic keyring acceptance").unwrap();
    let reference = format!("acceptance-{}", sirinvpn_protocol::ServerId::new());
    store.put(&reference, &generated.secret).unwrap();
    let entry = keyring::Entry::new("org.sirinvpn.client", &reference).unwrap();
    assert_eq!(
        identity(&entry.get_secret().unwrap()).unwrap().1,
        identity(&serde_json::to_vec(&store.get(&reference).unwrap()).unwrap())
            .unwrap()
            .1
    );
    let service = SecretService::connect_with_max_prompt_timeout(EncryptionType::Plain, 0).unwrap();
    let collection = service.get_default_collection().unwrap();
    collection
        .create_item(
            "synthetic legacy duplicate",
            HashMap::from([
                ("service", "org.sirinvpn.client"),
                ("username", reference.as_str()),
            ]),
            &serde_json::to_vec(&generated.secret).unwrap(),
            false,
            "application/octet-stream",
        )
        .unwrap();
    assert!(matches!(
        store.get(&reference),
        Err(SecretStoreError::InvalidData)
    ));
    store.delete(&reference).unwrap();
    assert!(matches!(entry.get_secret(), Err(keyring::Error::NoEntry)));
    assert!(store.pending_cleanup().unwrap().is_empty());

    let legacy = format!("acceptance-{}", sirinvpn_protocol::ServerId::new());
    files::atomic_write(
        &store.fallback_path(&legacy).unwrap(),
        &serde_json::to_vec(&generated.secret).unwrap(),
        true,
    )
    .unwrap();
    store
        .migrate(&legacy, &generated.public.management_certificate_pem)
        .unwrap();
    assert!(!store.fallback_path(&legacy).unwrap().exists());
    assert_eq!(store.status(&legacy).unwrap().backend, "keyring");
    collection.lock().unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(
        store.get(&legacy),
        Err(SecretStoreError::Unavailable(_))
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    // The entire session/keyring is destroyed by the container after this test.
}

#[derive(Default)]
struct Memory {
    value: Option<Vec<u8>>,
    unavailable: bool,
    invalid_put: bool,
    calls: usize,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Memory>>);
impl KeyringBackend for Fake {
    fn put(&self, _: &str, bytes: &[u8]) -> Result<(), SecretStoreError> {
        let mut m = self.0.lock().unwrap();
        m.calls += 1;
        if m.invalid_put {
            return Err(SecretStoreError::InvalidData);
        }
        if m.unavailable {
            return Err(SecretStoreError::Unavailable("fixture".into()));
        }
        m.value = Some(bytes.to_vec());
        Ok(())
    }
    fn get(&self, _: &str) -> Result<Vec<u8>, SecretStoreError> {
        let mut m = self.0.lock().unwrap();
        m.calls += 1;
        if m.unavailable {
            return Err(SecretStoreError::Unavailable("fixture".into()));
        }
        m.value.clone().ok_or(SecretStoreError::NotFound)
    }
    fn delete(&self, _: &str) -> Result<(), SecretStoreError> {
        let mut m = self.0.lock().unwrap();
        m.calls += 1;
        if m.unavailable {
            return Err(SecretStoreError::Unavailable("fixture".into()));
        }
        m.value = None;
        Ok(())
    }
}
fn fixture() -> (tempfile::TempDir, HybridSecretStore, Fake) {
    let dir = tempfile::tempdir().unwrap();
    let backend = Fake::default();
    let store = HybridSecretStore {
        fallback_directory: dir.path().join("secrets"),
        backend: Box::new(backend.clone()),
    };
    (dir, store, backend)
}

#[test]
fn unavailable_keyring_without_file_never_acknowledges_deletion() {
    let (_dir, store, backend) = fixture();
    backend.0.lock().unwrap().unavailable = true;
    assert!(matches!(
        store.delete("fixture"),
        Err(SecretStoreError::CleanupPending)
    ));
    assert_eq!(store.pending_cleanup().unwrap(), ["fixture"]);
    assert!(matches!(
        store.get("fixture"),
        Err(SecretStoreError::Deleted)
    ));
    backend.0.lock().unwrap().unavailable = false;
    store.delete("fixture").unwrap();
    store.delete("fixture").unwrap();
    assert!(store.pending_cleanup().unwrap().is_empty());
    let secret = crate::LocalIdentity::generate("fixture").unwrap().secret;
    assert!(matches!(
        store.put("fixture", &secret),
        Err(SecretStoreError::Deleted)
    ));
}

#[test]
fn deletion_matrix_attempts_both_backends_and_retains_retry() {
    for unavailable in [false, true] {
        for file in ["absent", "present", "unremovable"] {
            let (_dir, store, backend) = fixture();
            let _lock = store.lock("setup").unwrap();
            let path = store.fallback_path("fixture").unwrap();
            if file == "present" {
                fs::write(&path, b"fixture").unwrap();
            }
            if file == "unremovable" {
                fs::create_dir(&path).unwrap();
            }
            backend.0.lock().unwrap().unavailable = unavailable;
            assert_eq!(
                store.delete("fixture").is_ok(),
                !unavailable && file != "unremovable"
            );
            assert_eq!(backend.0.lock().unwrap().calls, 1);
            if file == "present" {
                assert!(!path.exists());
            }
            if file == "unremovable" {
                fs::remove_dir(&path).unwrap();
            }
            backend.0.lock().unwrap().unavailable = false;
            store.delete("fixture").unwrap();
        }
    }
}

#[test]
fn invalid_references_have_no_backend_or_filesystem_effects() {
    let (dir, store, backend) = fixture();
    let secret = crate::LocalIdentity::generate("fixture").unwrap().secret;
    for reference in ["", "../escape", "a/b", "a.b", &"x".repeat(129)] {
        assert!(store.put(reference, &secret).is_err());
        assert!(store.get(reference).is_err());
        assert!(store.delete(reference).is_err());
    }
    assert_eq!(backend.0.lock().unwrap().calls, 0);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn strict_is_default_and_fallback_requires_explicit_policy() {
    let (_dir, store, backend) = fixture();
    let secret = crate::LocalIdentity::generate("fixture").unwrap().secret;
    backend.0.lock().unwrap().unavailable = true;
    assert!(store.new_reference_available("fixture").is_err());
    assert!(matches!(
        store.put("fixture", &secret),
        Err(SecretStoreError::SecureStoreRequired)
    ));
    assert!(!store.fallback_path("fixture").unwrap().exists());
    store.set_policy(StoragePolicy::AllowPrivateFile).unwrap();
    assert!(!store.new_reference_available("fixture").unwrap()); // Interrupted write owns it.
    assert!(store.new_reference_available("another").unwrap());
    assert!(matches!(
        store.get("another"),
        Err(SecretStoreError::Unavailable(_))
    ));
    store.put("fixture", &secret).unwrap();
    assert!(!store.new_reference_available("fixture").unwrap());
    assert_eq!(
        store.status("fixture").unwrap().protection,
        "permissions_only"
    );
    assert_eq!(
        store.get("fixture").unwrap().wireguard_private_key,
        secret.wireguard_private_key
    );
    let mut memory = backend.0.lock().unwrap();
    memory.unavailable = false;
    memory.invalid_put = true;
    drop(memory);
    assert!(matches!(
        store.put("another", &secret),
        Err(SecretStoreError::InvalidData)
    ));
    assert!(!store.fallback_path("another").unwrap().exists());
}

#[test]
fn migration_commits_authority_before_cleanup_and_never_falls_back_afterward() {
    let (_dir, store, backend) = fixture();
    let id = crate::LocalIdentity::generate("fixture").unwrap();
    store.set_policy(StoragePolicy::AllowPrivateFile).unwrap();
    backend.0.lock().unwrap().unavailable = true;
    store.put("fixture", &id.secret).unwrap();
    backend.0.lock().unwrap().unavailable = false;
    store
        .migrate("fixture", &id.public.management_certificate_pem)
        .unwrap();
    assert!(!store.fallback_path("fixture").unwrap().exists());
    store
        .migrate("fixture", &id.public.management_certificate_pem)
        .unwrap();
    files::atomic_write(
        &store.fallback_path("fixture").unwrap(),
        &serde_json::to_vec(&id.secret).unwrap(),
        true,
    )
    .unwrap();
    backend.0.lock().unwrap().unavailable = true;
    assert!(matches!(
        store.get("fixture"),
        Err(SecretStoreError::Unavailable(_))
    ));
    assert!(store.status("fixture").unwrap().cleanup_pending);
}

#[test]
fn conflicting_legacy_copies_and_corruption_are_not_hidden() {
    let (_dir, store, backend) = fixture();
    let first = crate::LocalIdentity::generate("first").unwrap();
    let second = crate::LocalIdentity::generate("second").unwrap();
    let _lock = store.lock("setup").unwrap();
    files::atomic_write(
        &store.fallback_path("fixture").unwrap(),
        &serde_json::to_vec(&first.secret).unwrap(),
        true,
    )
    .unwrap();
    backend.0.lock().unwrap().value = Some(serde_json::to_vec(&second.secret).unwrap());
    assert!(matches!(
        store.get("fixture"),
        Err(SecretStoreError::InvalidData)
    ));
    backend.0.lock().unwrap().value = Some(b"corrupt".to_vec());
    assert!(matches!(
        store.get("fixture"),
        Err(SecretStoreError::InvalidData)
    ));
}

#[test]
fn concurrent_identity_read_waits_for_the_existing_operation_without_file_fallback() {
    let (_dir, store, backend) = fixture();
    let secret = crate::LocalIdentity::generate("fixture").unwrap().secret;
    store.put("fixture", &secret).unwrap();
    let second = HybridSecretStore {
        fallback_directory: store.fallback_directory.clone(),
        backend: Box::new(backend),
    };
    let lock = store.lock("fixture").unwrap();
    let (started, ready) = std::sync::mpsc::channel();
    let (completed, result) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        started.send(()).unwrap();
        completed.send(second.get("fixture")).unwrap();
    });
    ready.recv().unwrap();
    let early = result.recv_timeout(std::time::Duration::from_millis(100));
    drop(lock);
    let read = match early {
        Ok(value) => value,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => result
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap(),
        Err(error) => panic!("credential reader stopped: {error}"),
    };
    reader.join().unwrap();
    assert!(read.unwrap().wireguard_private_key == secret.wireguard_private_key);
    assert_eq!(store.policy().unwrap(), StoragePolicy::SecureStoreRequired);
    assert_eq!(store.status("fixture").unwrap().backend, "keyring");
    assert!(!store.fallback_path("fixture").unwrap().exists());
}

#[test]
fn shared_reference_lock_rejects_concurrent_operations() {
    let (_dir, store, backend) = fixture();
    let second = HybridSecretStore {
        fallback_directory: store.fallback_directory.clone(),
        backend: Box::new(backend.clone()),
    };
    let lock = store.lock("fixture").unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(
        second.delete("fixture"),
        Err(SecretStoreError::Unavailable(_))
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
    assert_eq!(backend.0.lock().unwrap().calls, 0);
    drop(lock);
    second.delete("fixture").unwrap();
}

#[test]
fn unsafe_fallback_files_and_future_metadata_are_rejected() {
    use std::os::unix::fs::symlink;
    let (dir, store, _backend) = fixture();
    let _lock = store.lock("setup").unwrap();
    let target = dir.path().join("other");
    fs::write(&target, "unrelated").unwrap();
    symlink(&target, store.fallback_path("fixture").unwrap()).unwrap();
    assert!(store.get("fixture").is_err());
    store.delete("fixture").unwrap();
    assert_eq!(fs::read_to_string(target).unwrap(), "unrelated");
    files::atomic_write(
        &store.fallback_directory.join("future.state.json"),
        br#"{"schema_version":99,"backend":"keyring","binding":""}"#,
        true,
    )
    .unwrap();
    assert!(matches!(
        store.get("future"),
        Err(SecretStoreError::InvalidData)
    ));
}

#[test]
fn interrupted_file_install_resumes_and_existing_identity_cannot_be_overwritten() {
    let (_dir, store, backend) = fixture();
    let first = crate::LocalIdentity::generate("first").unwrap();
    let other = crate::LocalIdentity::generate("other").unwrap();
    store.set_policy(StoragePolicy::AllowPrivateFile).unwrap();
    let bytes = serde_json::to_vec(&first.secret).unwrap();
    let binding = identity(&bytes).unwrap().1;
    store
        .save_record("fixture", Backend::Writing, &binding)
        .unwrap();
    files::atomic_write(&store.fallback_path("fixture").unwrap(), &bytes, false).unwrap();
    backend.0.lock().unwrap().unavailable = true;
    store.put("fixture", &first.secret).unwrap();
    assert_eq!(store.status("fixture").unwrap().backend, "private_file");
    assert!(store.put("fixture", &other.secret).is_err());
    backend.0.lock().unwrap().unavailable = false;
    backend.0.lock().unwrap().value = Some(bytes.clone());
    assert!(store.put("legacy-keyring", &other.secret).is_err());
    assert_eq!(backend.0.lock().unwrap().value.as_ref(), Some(&bytes));
    store.delete("fixture").unwrap();
    backend.0.lock().unwrap().unavailable = true;
    store.delete("fixture").unwrap(); // Completed, sealed deletion needs no live backend.
}

#[test]
fn policy_names_do_not_collide_with_valid_references() {
    let (_dir, store, _backend) = fixture();
    let secret = crate::LocalIdentity::generate("fixture").unwrap().secret;
    store.put("storage-policy", &secret).unwrap();
    assert_eq!(store.policy().unwrap(), StoragePolicy::SecureStoreRequired);
}
