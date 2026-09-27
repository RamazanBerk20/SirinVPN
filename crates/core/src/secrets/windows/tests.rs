use super::*;
use std::{
    os::windows::fs::OpenOptionsExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn windows_secrets_never_have_a_plaintext_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let store = HybridSecretStore::new(directory.path().join("secrets"));
    let identity = crate::LocalIdentity::generate("Windows device").unwrap();
    assert!(store.new_reference_available("test-device").unwrap());
    store.put("test-device", &identity.secret).unwrap();
    let saved = fs::read(store.fallback_path("test-device").unwrap()).unwrap();
    assert!(!String::from_utf8_lossy(&saved).contains("PRIVATE KEY"));
    assert!(!directory.path().join("secrets/test-device.json").exists());
    // Existing DPAPI records have no metadata. They remain readable on upgrade.
    assert!(!store.deletion_path("test-device").exists());
    assert_eq!(
        store
            .get("test-device")
            .unwrap()
            .public_identity(&identity.public.management_certificate_pem)
            .unwrap(),
        identity.public
    );
    store.delete("test-device").unwrap();
    store.delete("test-device").unwrap();
    assert!(matches!(
        store.get("test-device"),
        Err(SecretStoreError::Deleted)
    ));
    assert!(matches!(
        store.put("test-device", &identity.secret),
        Err(SecretStoreError::Deleted)
    ));
    assert!(!store.new_reference_available("test-device").unwrap());
    assert!(!store.fallback_path("test-device").unwrap().exists());
}

#[test]
fn failed_removal_stays_sealed_until_cleanup_retry_succeeds() {
    let directory = tempfile::tempdir().unwrap();
    let store = HybridSecretStore::new(directory.path().join("secrets"));
    let identity = crate::LocalIdentity::generate("Cleanup fixture").unwrap();
    store.put("fixture", &identity.secret).unwrap();
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(store.fallback_path("fixture").unwrap())
        .unwrap();
    assert!(matches!(
        store.delete("fixture"),
        Err(SecretStoreError::CleanupPending)
    ));
    assert!(matches!(
        store.get("fixture"),
        Err(SecretStoreError::Deleted)
    ));
    assert!(matches!(
        store.put("fixture", &identity.secret),
        Err(SecretStoreError::Deleted)
    ));
    drop(held);
    store.delete("fixture").unwrap();
    assert!(!store.fallback_path("fixture").unwrap().exists());
}

#[test]
fn invalid_references_and_malformed_deletion_records_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let store = HybridSecretStore::new(directory.path().join("secrets"));
    let identity = crate::LocalIdentity::generate("Validation fixture").unwrap();
    for reference in ["", "../outside", "device/key", "device:key"] {
        assert!(matches!(
            store.put(reference, &identity.secret),
            Err(SecretStoreError::InvalidData)
        ));
        assert!(matches!(
            store.get(reference),
            Err(SecretStoreError::InvalidData)
        ));
        assert!(matches!(
            store.delete(reference),
            Err(SecretStoreError::InvalidData)
        ));
        assert!(!store.fallback_directory.exists());
    }
    store.put("fixture", &identity.secret).unwrap();
    files::atomic_write(&store.deletion_path("fixture"), b"{}", false).unwrap();
    assert!(matches!(
        store.get("fixture"),
        Err(SecretStoreError::InvalidData)
    ));
    assert!(matches!(
        store.put("fixture", &identity.secret),
        Err(SecretStoreError::InvalidData)
    ));
    assert!(matches!(
        store.delete("fixture"),
        Err(SecretStoreError::InvalidData)
    ));
}

struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(store: &HybridSecretStore, mode: &str, stage: &str) -> Worker {
    Worker(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "secrets::windows::tests::deletion_worker",
            ])
            .env("SIRINVPN_SECRET_TEST_DIRECTORY", &store.fallback_directory)
            .env("SIRINVPN_SECRET_TEST_MODE", mode)
            .env("SIRINVPN_SECRET_TEST_STAGE", stage)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn wait_for(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "test worker did not reach its checkpoint"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn checkpoint(store: &HybridSecretStore, stage: &str) {
    if std::env::var("SIRINVPN_SECRET_TEST_STAGE").ok().as_deref() != Some(stage)
        || std::env::var_os("SIRINVPN_SECRET_TEST_DIRECTORY").as_deref()
            != Some(store.fallback_directory.as_os_str())
    {
        return;
    }
    assert_eq!(
        fs::read(store.fallback_directory.join("owned-test")).unwrap(),
        b"synthetic-secrets"
    );
    fs::write(store.fallback_directory.join("checkpoint"), stage).unwrap();
    wait_for(&store.fallback_directory.join("release-worker"));
}

#[test]
#[ignore = "child worker for the process termination and lock regression"]
fn deletion_worker() {
    let Some(directory) = std::env::var_os("SIRINVPN_SECRET_TEST_DIRECTORY") else {
        return;
    };
    let store = HybridSecretStore::new(directory.into());
    assert_eq!(
        fs::read(store.fallback_directory.join("owned-test")).unwrap(),
        b"synthetic-secrets"
    );
    if std::env::var("SIRINVPN_SECRET_TEST_MODE").unwrap() == "delete" {
        store.delete("fixture").unwrap();
    } else {
        let identity = crate::LocalIdentity::generate("Waiting writer").unwrap();
        fs::write(store.fallback_directory.join("writer-started"), b"ready").unwrap();
        assert!(matches!(
            store.put("fixture", &identity.secret),
            Err(SecretStoreError::Deleted)
        ));
    }
}

fn fixture(directory: &std::path::Path) -> HybridSecretStore {
    let store = HybridSecretStore::new(directory.join("secrets"));
    let identity = crate::LocalIdentity::generate("Process fixture").unwrap();
    store.put("fixture", &identity.secret).unwrap();
    fs::write(
        store.fallback_directory.join("owned-test"),
        b"synthetic-secrets",
    )
    .unwrap();
    store
}

#[test]
fn process_termination_at_each_deletion_boundary_remains_retryable_and_sealed() {
    for stage in ["intent", "removed", "complete"] {
        let directory = tempfile::tempdir().unwrap();
        let store = fixture(directory.path());
        let mut worker = spawn(&store, "delete", stage);
        wait_for(&store.fallback_directory.join("checkpoint"));
        worker.0.kill().unwrap();
        worker.0.wait().unwrap();
        let reopened = HybridSecretStore::new(store.fallback_directory.clone());
        assert!(matches!(
            reopened.get("fixture"),
            Err(SecretStoreError::Deleted)
        ));
        assert!(!reopened.new_reference_available("fixture").unwrap());
        let identity = crate::LocalIdentity::generate("Stale write").unwrap();
        assert!(matches!(
            reopened.put("fixture", &identity.secret),
            Err(SecretStoreError::Deleted)
        ));
        reopened.delete("fixture").unwrap();
        assert!(!reopened.fallback_path("fixture").unwrap().exists());
    }
}

#[test]
fn a_writer_in_another_process_cannot_restore_a_reference_after_delete() {
    let directory = tempfile::tempdir().unwrap();
    let store = fixture(directory.path());
    let mut deleter = spawn(&store, "delete", "intent");
    wait_for(&store.fallback_directory.join("checkpoint"));
    let mut writer = spawn(&store, "put", "");
    wait_for(&store.fallback_directory.join("writer-started"));
    assert!(writer.0.try_wait().unwrap().is_none());
    fs::write(store.fallback_directory.join("release-worker"), b"continue").unwrap();
    assert!(deleter.0.wait().unwrap().success());
    assert!(writer.0.wait().unwrap().success());
    assert!(matches!(
        store.get("fixture"),
        Err(SecretStoreError::Deleted)
    ));
    assert!(!store.fallback_path("fixture").unwrap().exists());
}
