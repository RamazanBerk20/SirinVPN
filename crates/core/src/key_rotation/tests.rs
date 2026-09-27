use super::*;
use sirinvpn_protocol::{ServerEndpoint, ServerRole};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Mutex,
};

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

fn profile(identity: &LocalIdentity, server_id: ServerId) -> ServerProfile {
    ServerProfile {
        favorite: false,
        schema_version: 1,
        id: server_id,
        name: "Rotation test".to_owned(),
        endpoint: ServerEndpoint {
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
        server_wireguard_public_key: "server-key".to_owned(),
        pinned_server_certificate_pem: "server-certificate".to_owned(),
        client_management_certificate_pem: identity.public.management_certificate_pem.clone(),
        identity_reference: "original-identity".to_owned(),
        role: ServerRole::Owner,
        administrator: false,
        member_id: None,
        device_id: None,
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
    }
}

#[test]
fn staged_rotation_journal_contains_no_private_key_and_cleanup_is_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().join("client"));
    let journals = RotationJournalStore::new(&paths);
    let secrets = MemorySecretStore::default();
    let original = LocalIdentity::generate("Original").unwrap();
    let server_id = ServerId::new();
    let profile = profile(&original, server_id);
    paths.profile_store().insert(profile.clone()).unwrap();
    secrets
        .put(&profile.identity_reference, &original.secret)
        .unwrap();

    let mut journal = stage_rotation(
        &journals,
        &secrets,
        profile.clone(),
        &original.secret,
        true,
        TransportKind::DirectUdp,
        true,
        None,
    )
    .unwrap();
    assert!(has_pending_key_rotation(&paths, server_id).unwrap());
    sirinvpn_platform::files::validate_private_file(
        &fs::File::open(journals.path(server_id)).unwrap(),
    )
    .unwrap();
    sirinvpn_platform::files::validate_private_directory(&paths.key_rotations_directory).unwrap();
    let journal_bytes = fs::read(journals.path(server_id)).unwrap();
    let journal_shape: serde_json::Value = serde_json::from_slice(&journal_bytes).unwrap();
    assert!(journal_shape.get("transport").is_none());
    assert_eq!(journal_shape["transport_fallback_enabled"], true);
    let mut legacy_shape = journal_shape.clone();
    legacy_shape
        .as_object_mut()
        .unwrap()
        .remove("transport_fallback_enabled");
    let legacy: RotationJournal = serde_json::from_value(legacy_shape).unwrap();
    assert!(!legacy.transport_fallback_enabled);
    legacy.validate(server_id).unwrap();
    assert!(
        !journal_bytes
            .windows(b"PRIVATE KEY".len())
            .any(|window| window == b"PRIVATE KEY")
    );
    assert!(
        !journal_bytes
            .windows(original.secret.wireguard_private_key.len())
            .any(|window| window == original.secret.wireguard_private_key.as_bytes())
    );
    let transition = secrets.get(&journal.transition_identity_reference).unwrap();
    let final_identity = secrets.get(&journal.final_identity_reference).unwrap();
    validate_staged_identities(&journal, &original.secret, &transition, &final_identity).unwrap();

    journal.phase = RotationPhase::Activated;
    journal.activated_device_id = Some(DeviceId::new());
    journals.update(&journal).unwrap();
    let result =
        finish_activation(&paths.profile_store(), &secrets, &journals, &journal, false).unwrap();
    assert_eq!(result.server_id, server_id);
    assert!(matches!(
        secrets.get(&profile.identity_reference),
        Err(SecretStoreError::NotFound)
    ));
    assert!(matches!(
        secrets.get(&journal.transition_identity_reference),
        Err(SecretStoreError::NotFound)
    ));
    assert!(secrets.get(&journal.final_identity_reference).is_ok());
    assert!(!has_pending_key_rotation(&paths, server_id).unwrap());
    let stored = paths.profile_store().load().unwrap().remove(0);
    assert_eq!(stored.identity_reference, journal.final_identity_reference);
    assert_eq!(
        stored.client_management_certificate_pem,
        journal.new_public_identity.management_certificate_pem
    );
    assert_eq!(stored.device_id, journal.activated_device_id);
}

#[test]
fn corrupt_journal_fails_closed_without_deleting_staged_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().join("client"));
    let journals = RotationJournalStore::new(&paths);
    let secrets = MemorySecretStore::default();
    let original = LocalIdentity::generate("Original").unwrap();
    let server_id = ServerId::new();
    let profile = profile(&original, server_id);
    secrets
        .put(&profile.identity_reference, &original.secret)
        .unwrap();
    let journal = stage_rotation(
        &journals,
        &secrets,
        profile,
        &original.secret,
        false,
        TransportKind::DirectUdp,
        false,
        None,
    )
    .unwrap();
    fs::write(journals.path(server_id), b"{\"schema_version\":2}").unwrap();

    assert!(matches!(
        journals.load(server_id),
        Err(KeyRotationError::InvalidState)
    ));
    assert!(secrets.get(&journal.transition_identity_reference).is_ok());
    assert!(secrets.get(&journal.final_identity_reference).is_ok());
    assert!(
        secrets
            .get(&journal.original_profile.identity_reference)
            .is_ok()
    );
}

#[test]
fn abandoning_an_unaccepted_stage_keeps_the_original_identity() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().join("client"));
    let journals = RotationJournalStore::new(&paths);
    let secrets = MemorySecretStore::default();
    let original = LocalIdentity::generate("Original").unwrap();
    let profile = profile(&original, ServerId::new());
    secrets
        .put(&profile.identity_reference, &original.secret)
        .unwrap();
    let journal = stage_rotation(
        &journals,
        &secrets,
        profile.clone(),
        &original.secret,
        false,
        TransportKind::DirectUdp,
        false,
        None,
    )
    .unwrap();

    abandon_staged_rotation(&secrets, &journals, &journal).unwrap();
    assert!(secrets.get(&profile.identity_reference).is_ok());
    assert!(matches!(
        secrets.get(&journal.transition_identity_reference),
        Err(SecretStoreError::NotFound)
    ));
    assert!(matches!(
        secrets.get(&journal.final_identity_reference),
        Err(SecretStoreError::NotFound)
    ));
    assert!(!has_pending_key_rotation(&paths, profile.id).unwrap());
}

#[test]
fn independent_rotation_policy_survives_journal_reload_and_old_schema_stays_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().join("client"));
    let secrets = MemorySecretStore::default();
    let original = LocalIdentity::generate("Original").unwrap();
    let server_id = ServerId::new();
    let profile = profile(&original, server_id);
    let journals = RotationJournalStore::new(&paths);
    let policy = RotationConnectionPolicy {
        mtu_policy: Some(sirinvpn_protocol::MtuPolicy::Manual { value: 1300 }),
        kill_switch: true,
        automatic_reconnect: false,
        connect_on_startup: false,
        selected_applications: false,
        selected_routes: Some(vec!["198.51.100.0/24".into()]),
        allow_lan: false,
    };
    let journal = stage_rotation(
        &journals,
        &secrets,
        profile,
        &original.secret,
        false,
        TransportKind::TlsLike,
        true,
        Some(policy.clone()),
    )
    .unwrap();
    assert_eq!(journal.schema_version, 3);
    journal.validate(server_id).unwrap();
    let restored = journals.load(server_id).unwrap().unwrap();
    assert_eq!(restored.connection_policy, Some(policy));
    assert!(restored.transport_fallback_enabled);
    assert!(!restored.persistent_protection);
    let mut unsupported = restored.clone();
    unsupported.schema_version = 2;
    assert!(unsupported.validate(server_id).is_err());
    let mut application = restored;
    let policy = application.connection_policy.as_mut().unwrap();
    policy.selected_applications = true;
    policy.selected_routes = None;
    assert!(application.validate(server_id).is_err());
    application.schema_version = 4;
    application.validate(server_id).unwrap();
    application
        .connection_policy
        .as_mut()
        .unwrap()
        .selected_routes = Some(vec!["198.51.100.0/24".into()]);
    assert!(application.validate(server_id).is_err());
}
