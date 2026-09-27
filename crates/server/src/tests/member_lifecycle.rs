use super::*;
mod policy_enrollment;
mod recovery;

fn fixture() -> (tempfile::TempDir, AppState) {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Lifecycle owner").unwrap();
    initialize(
        &paths,
        "Lifecycle",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51820,
    )
    .unwrap();
    let mut document = load_authorization(&paths.authorization).unwrap();
    for (name, admin, count) in [
        ("Admin", true, 1),
        ("Family", false, 2),
        ("Other", false, 1),
    ] {
        let member_id = MemberId::new();
        document.members.push(MemberRecord {
            policy: Default::default(),
            id: member_id,
            name: name.into(),
            role: ServerRole::Member,
            administrator: admin,
            suspended: false,
        });
        for index in 0..count {
            let identity = LocalIdentity::generate(name).unwrap();
            let id = DeviceId::new();
            write_private(
                &directory.path().join(format!("{id}.key")),
                identity.secret.wireguard_private_key.as_bytes(),
            )
            .unwrap();
            document.devices.push(DeviceRecord {
                id,
                member_id,
                name: format!("{name} {index}"),
                client_tunnel_address: document.allocate_member_address().unwrap(),
                certificate_fingerprint: certificate_fingerprint(
                    &identity.public.management_certificate_pem,
                )
                .unwrap(),
                wireguard_public_key: identity.public.wireguard_public_key,
                management_certificate_pem: identity.public.management_certificate_pem,
                peer_communication_enabled: true,
            });
        }
    }
    document.port_forwards.push(PortForward {
        protocol: PortForwardProtocol::Tcp,
        public_port: 18080,
        device_port: 8080,
        device_id: document.devices[2].id,
    });
    write_authorization(&paths.authorization, &document).unwrap();
    let transport_peers = AuthorizedPeers::default();
    transport_peers.replace(decoded_transport_peers(&document).unwrap());
    let state = AppState {
        recovery: Default::default(),
        measurement_ready: false,
        configuration: load_configuration(&paths).unwrap(),
        operational_configuration: Some(OperationalConfiguration {
            schema_version: 1,
            external_interface: "eth-test".into(),
            ssh_port: 22,
        }),
        paths,
        authorization: Some(Arc::new(RwLock::new(document))),
        redemption_failures: Arc::new(Mutex::new(HashMap::new())),
        live_metrics: Arc::new(Mutex::new(LiveMetricSampler::default())),
        transport_peers,
        transport_activity: ActiveTransportRegistry::default(),
    };
    (directory, state)
}

fn identity(device: &DeviceRecord) -> CallerIdentity {
    CallerIdentity {
        certificate_fingerprint: device.certificate_fingerprint.clone(),
    }
}

#[tokio::test]
async fn lifecycle_handler_permissions_and_confirmation_fail_without_mutation() {
    let (_directory, state) = fixture();
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    for (caller_index, permissions) in [
        (0, [false, true, true, true]),
        (1, [false, false, true, true]),
        (2, [false; 4]),
    ] {
        for (target, allowed) in before.members.iter().zip(permissions) {
            // Reactivating an already-active member checks authorization without touching networking.
            let result = update_member_suspension_handler(
                State(state.clone()),
                Extension(identity(&before.devices[caller_index])),
                AxumPath(target.id.to_string()),
                Json(MemberSuspensionUpdateRequest { suspended: false }),
            )
            .await;
            assert_eq!(result.is_ok(), allowed);
            if !allowed {
                assert_eq!(result.err().unwrap().status, StatusCode::FORBIDDEN);
            }
        }
    }
    let owner = || Extension(identity(&before.devices[0]));
    let target = before.members[2].id.to_string();
    let unconfirmed = revoke_member_devices_handler(
        State(state.clone()),
        owner(),
        AxumPath(target),
        Json(MemberDevicesRevokeRequest { confirmed: false }),
    )
    .await;
    assert_eq!(unconfirmed.err().unwrap().status, StatusCode::BAD_REQUEST);
    let owner_revoke = revoke_member_devices_handler(
        State(state.clone()),
        owner(),
        AxumPath(before.members[0].id.to_string()),
        Json(MemberDevicesRevokeRequest { confirmed: true }),
    )
    .await;
    assert_eq!(owner_revoke.err().unwrap().status, StatusCode::FORBIDDEN);
    let retry = revoke_member_devices_handler(
        State(state.clone()),
        owner(),
        AxumPath(MemberId::new().to_string()),
        Json(MemberDevicesRevokeRequest { confirmed: true }),
    )
    .await;
    assert!(retry.is_ok());
    assert_eq!(*state.authorization.as_ref().unwrap().read().await, before);
    assert_eq!(
        load_authorization(&state.paths.authorization).unwrap(),
        before
    );
}

#[tokio::test]
async fn request_waiting_on_state_cannot_use_an_administrator_suspended_before_its_turn() {
    let (_directory, state) = fixture();
    let authorization = state.authorization.as_ref().unwrap();
    let mut locked = authorization.write().await;
    let caller = identity(&locked.devices[1]);
    let admin_id = locked.members[1].id;
    let target = locked.members[2].id.to_string();
    let pending_state = state.clone();
    let pending = tokio::spawn(async move {
        update_member_suspension_handler(
            State(pending_state),
            Extension(caller),
            AxumPath(target),
            Json(MemberSuspensionUpdateRequest { suspended: false }),
        )
        .await
    });
    tokio::task::yield_now().await;
    locked.set_member_suspended(admin_id, true).unwrap();
    drop(locked);
    assert_eq!(
        pending.await.unwrap().err().unwrap().status,
        StatusCode::FORBIDDEN
    );
    let current = authorization.read().await;
    assert!(authorize_current(&current, &identity(&current.devices[1]), false).is_err());
    assert!(
        !current
            .client_certificates(unix_time())
            .contains(&current.devices[1].management_certificate_pem)
    );
}

#[tokio::test]
async fn suspended_administrator_status_stream_closes_and_cannot_be_reopened() {
    use futures_util::StreamExt;
    let (_directory, state) = fixture();
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    let response = crate::status_stream::status_stream_handler(
        State(state.clone()),
        Extension(identity(&before.devices[1])),
    )
    .await
    .unwrap_or_else(|_| panic!("active admin denied"));
    let mut stream = axum::body::Body::into_data_stream(response.into_body());
    assert!(
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .is_some()
    );
    state
        .authorization
        .as_ref()
        .unwrap()
        .write()
        .await
        .set_member_suspended(before.members[1].id, true)
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .is_none()
    );
    let denied = crate::status_stream::status_stream_handler(
        State(state),
        Extension(identity(&before.devices[1])),
    )
    .await;
    assert_eq!(denied.err().unwrap().status, StatusCode::FORBIDDEN);
}

mod kernel;

#[tokio::test]
async fn encrypted_vps_backup_restores_suspended_members_without_restoring_access() {
    let (directory, state) = fixture();
    let mut document = state.authorization.as_ref().unwrap().read().await.clone();
    document
        .set_member_suspended(document.members[2].id, true)
        .unwrap();
    write_authorization(&state.paths.authorization, &document).unwrap();
    let certificate = &state.configuration.owner_certificate_pem;
    let snapshot = export_backup_state(&state.paths, document.server_id, certificate).unwrap();
    let backup = directory.path().join("suspended.sirinvpn-server-backup");
    write_encrypted_server_backup(&backup, snapshot.as_slice(), "correct horse battery staple")
        .unwrap();
    let decrypted = read_encrypted_server_backup(&backup, "correct horse battery staple").unwrap();
    let destination = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(destination.path());
    restore_backup_state(
        &paths,
        document.server_id,
        certificate,
        decrypted.snapshot(),
    )
    .unwrap();
    let restored = load_authorization(&paths.authorization).unwrap();
    assert_eq!(restored, document);
    assert_eq!(restored.desired_peers(unix_time()).len(), 3);
    assert!(
        restored
            .device_for_fingerprint(&restored.devices[2].certificate_fingerprint)
            .is_none()
    );
}

#[tokio::test]
async fn handoff_source_rejects_even_idempotent_member_changes() {
    let (_directory, state) = fixture();
    let mut document = state.authorization.as_ref().unwrap().write().await;
    let owner = identity(&document.devices[0]);
    let target = document.members[2].id.to_string();
    // This guard is intentionally independent of the handoff signature checks at load time.
    document.endpoint_transition_source = true;
    drop(document);
    let result = update_member_suspension_handler(
        State(state.clone()),
        Extension(owner.clone()),
        AxumPath(target.clone()),
        Json(MemberSuspensionUpdateRequest { suspended: false }),
    )
    .await;
    assert_eq!(result.err().unwrap().status, StatusCode::CONFLICT);
    let result = revoke_member_devices_handler(
        State(state),
        Extension(owner),
        AxumPath(target),
        Json(MemberDevicesRevokeRequest { confirmed: true }),
    )
    .await;
    assert_eq!(result.err().unwrap().status, StatusCode::CONFLICT);
}
