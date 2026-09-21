use super::*;
use sirinvpn_platform::files;
use std::fs;

fn fingerprint(letter: &str) -> String {
    format!("SHA256:{}", letter.repeat(43))
}

#[test]
fn inspection_never_learns_an_unknown_or_changed_key() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hosts.json");
    let first = fingerprint("A");
    let next = fingerprint("B");
    assert_eq!(
        inspect_at(&path, "vps.example", 22, first.clone())
            .unwrap()
            .status,
        TrustStatus::Unknown
    );
    assert!(!path.exists());
    remember_at(&path, "vps.example", 22, &first).unwrap();
    let before = fs::read(&path).unwrap();
    assert_eq!(
        inspect_at(&path, "vps.example", 22, next).unwrap().status,
        TrustStatus::Changed
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        inspect_at(&path, "vps.example", 22, first).unwrap().status,
        TrustStatus::Trusted
    );
}

#[test]
fn saved_trust_survives_reopening_and_is_scoped_to_host_and_port() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config/hosts.json");
    let first = fingerprint("A");
    remember_at(&path, "VPS.Example.", 22, &first).unwrap();
    assert_eq!(
        inspect_at(&path, "vps.example", 22, first.clone())
            .unwrap()
            .status,
        TrustStatus::Trusted
    );
    assert_eq!(
        inspect_at(&path, "vps.example", 2222, first.clone())
            .unwrap()
            .status,
        TrustStatus::Unknown
    );
    assert_eq!(
        inspect_at(&path, "other.example", 22, first.clone())
            .unwrap()
            .status,
        TrustStatus::Unknown
    );
    remember_at(&path, "[2001:0db8::1]", 22, &first).unwrap();
    assert_eq!(
        inspect_at(&path, "2001:db8::1", 22, first).unwrap().status,
        TrustStatus::Trusted
    );
    files::validate_private_file(&files::open_no_follow(&path).unwrap()).unwrap();
    files::validate_private_directory(path.parent().unwrap()).unwrap();
}

#[test]
fn explicit_verification_can_replace_only_the_selected_endpoint() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hosts.json");
    let first = fingerprint("A");
    let next = fingerprint("B");
    remember_at(&path, "vps.example", 22, &first).unwrap();
    remember_at(&path, "vps.example", 2222, &first).unwrap();
    remember_at(&path, "vps.example", 22, &next).unwrap();
    assert_eq!(
        inspect_at(&path, "vps.example", 22, next).unwrap().status,
        TrustStatus::Trusted
    );
    assert_eq!(
        inspect_at(&path, "vps.example", 2222, first)
            .unwrap()
            .status,
        TrustStatus::Trusted
    );
}

#[test]
fn corrupt_or_unsupported_data_is_preserved_and_never_treated_as_trusted() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hosts.json");
    for bytes in [
        "broken".into(),
        " ".repeat(MAX_STORE_BYTES + 1),
        r#"{"schema_version":2,"hosts":{}}"#.into(),
        r#"{"schema_version":1,"hosts":{"[vps.example]:22":"bad"}}"#.into(),
    ] {
        fs::write(&path, &bytes).unwrap();
        assert!(inspect_at(&path, "vps.example", 22, fingerprint("A")).is_err());
        assert!(remember_at(&path, "vps.example", 22, &fingerprint("A")).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), bytes);
    }
}

#[test]
fn invalid_input_does_not_create_a_trust_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hosts.json");
    for (host, port, fp) in [
        ("vps.example", 0, fingerprint("A")),
        ("vps example", 22, fingerprint("A")),
        ("", 22, fingerprint("A")),
        ("vps.example", 22, "SHA256:bad".into()),
    ] {
        assert!(remember_at(&path, host, port, &fp).is_err());
    }
    assert!(!path.exists());
}
