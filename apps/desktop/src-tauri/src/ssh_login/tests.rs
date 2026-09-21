use super::*;
use sirinvpn_installer::SshAuthentication;

fn login() -> SshLoginInput {
    SshLoginInput {
        host: "vps.example".into(),
        ssh_port: 2222,
        username: "admin".into(),
        authentication: "password".into(),
        password: Some("test-password".into()),
        private_key_path: None,
        private_key_passphrase: None,
        sudo_password: Some("test-sudo".into()),
        host_key_sha256: format!("SHA256:{}", "A".repeat(43)),
    }
}
fn store() -> Entry {
    Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default()))
}

#[test]
fn saved_login_retains_credentials_but_ui_summary_contains_no_secrets() {
    let store = store();
    let saved = save_entry(login(), &store, |target| {
        assert!(matches!(&target.authentication, SshAuthentication::Password(value) if value.as_str() == "test-password"));
        assert_eq!(target.expected_host_key_sha256, Some(login().host_key_sha256.clone()));
        Ok(())
    }).unwrap();
    let summary = serde_json::to_value(saved).unwrap();
    assert_eq!(summary.as_object().unwrap().len(), 4);
    assert!(summary.get("password").is_none());
    assert!(summary.get("sudo_password").is_none());
    assert!(!summary.to_string().contains("test-password"));
    let restored = read_entry("VPS.EXAMPLE", &store).unwrap().unwrap();
    assert_eq!(restored.password.as_deref(), Some("test-password"));
    assert_eq!(restored.sudo_password.as_deref(), Some("test-sudo"));
}

#[test]
fn failed_authentication_does_not_overwrite_an_existing_login() {
    let store = store();
    save_entry(login(), &store, |_| Ok(())).unwrap();
    let mut replacement = login();
    replacement.password = Some("wrong-password".into());
    assert!(
        save_entry(replacement, &store, |_| Err(
            "SSH authentication failed.".into()
        ))
        .is_err()
    );
    assert_eq!(
        read_entry("vps.example", &store)
            .unwrap()
            .unwrap()
            .password
            .as_deref(),
        Some("test-password")
    );
}

#[test]
fn saved_credentials_cannot_move_to_another_host_port_or_key() {
    let store = store();
    save_entry(login(), &store, |_| Ok(())).unwrap();
    assert!(read_entry("other.example", &store).is_err());
    assert!(bound_target(login(), 22, &login().host_key_sha256).is_err());
    assert!(bound_target(login(), 2222, &format!("SHA256:{}", "B".repeat(43))).is_err());
    assert!(bound_target(login(), 2222, &login().host_key_sha256).is_ok());
}

#[test]
fn locked_or_corrupt_store_does_not_become_a_missing_login() {
    let store = store();
    assert!(read_entry("vps.example", &store).unwrap().is_none());
    store.set_secret(b"not a saved login").unwrap();
    assert!(read_entry("vps.example", &store).is_err());
    store.set_secret(&vec![b'x'; MAX_LOGIN_BYTES + 1]).unwrap();
    assert!(read_entry("vps.example", &store).is_err());
    let mock: &keyring::mock::MockCredential = store.get_credential().downcast_ref().unwrap();
    mock.set_error(keyring::Error::Invalid("wallet".into(), "locked".into()));
    assert!(
        read_entry("vps.example", &store)
            .err()
            .unwrap()
            .contains("Unlock")
    );
}

#[test]
fn failed_wallet_write_never_reports_success() {
    let store = store();
    let mock: &keyring::mock::MockCredential = store.get_credential().downcast_ref().unwrap();
    mock.set_error(keyring::Error::Invalid("wallet".into(), "locked".into()));
    assert!(
        save_entry(login(), &store, |_| Ok(()))
            .err()
            .unwrap()
            .contains("could not be saved")
    );
    assert!(read_entry("vps.example", &store).unwrap().is_none());
}
