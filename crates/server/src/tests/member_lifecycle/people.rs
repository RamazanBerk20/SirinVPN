//! Named join codes, person rename, Admin own devices and invitation issuers.
//! Allowed cases stop before the commit (which needs disposable networking); refusals go
//! through the handlers and must leave state untouched.
use super::*;
use crate::authorization_transaction::{footprint, narrows};
use crate::wireguard_device::prepare_wireguard_device;
use sirinvpn_protocol::{
    EnrollmentNames, InvitationCreateRequest, MemberPolicy, WireGuardDeviceCreateRequest,
};

const TOKEN: &str = "people-test-token";

fn invitation(
    document: &AuthorizationDocument,
    bootstrap: &LocalIdentity,
    target: Option<&MemberRecord>,
    fixed_member_name: bool,
) -> InvitationCreateBody {
    InvitationCreateBody {
        request: InvitationCreateRequest {
            recipient_names: true,
            server_id: document.server_id,
            endpoint: ServerEndpoint {
                host: "203.0.113.4".into(),
                wireguard_port: 51820,
            },
            member_name: target.map_or_else(|| "Ayşe".into(), |member| member.name.clone()),
            device_name: "Phone".into(),
            target_member_id: target.map(|member| member.id),
            administrator: target.is_some_and(|member| member.administrator),
            max_uses: 1,
            member_policy: MemberPolicy::default(),
            expires_in_seconds: 600,
            token_hash: hex::encode(Sha256::digest(TOKEN.as_bytes())),
            bootstrap_wireguard_public_key: bootstrap.public.wireguard_public_key.clone(),
            bootstrap_management_certificate_pem: bootstrap
                .public
                .management_certificate_pem
                .clone(),
        },
        fixed_member_name,
    }
}

fn wireguard_device(
    document: &AuthorizationDocument,
    target: &MemberRecord,
) -> WireGuardDeviceCreateRequest {
    WireGuardDeviceCreateRequest {
        server_id: document.server_id,
        endpoint: ServerEndpoint {
            host: "203.0.113.4".into(),
            wireguard_port: 51820,
        },
        member_name: target.name.clone(),
        device_name: "Router".into(),
        target_member_id: Some(target.id),
        member_policy: MemberPolicy::default(),
        wireguard_public_key: STANDARD.encode([31_u8; 32]),
        preshared_key: STANDARD.encode([32_u8; 32]),
    }
}

async fn document(state: &AppState) -> AuthorizationDocument {
    state.authorization.as_ref().unwrap().read().await.clone()
}

async fn replace(state: &AppState, document: AuthorizationDocument) {
    *state.authorization.as_ref().unwrap().write().await = document;
}

fn status<T>(result: Result<T, ApiError>) -> StatusCode {
    result.err().expect("the request was refused").status
}

#[tokio::test]
async fn named_join_code_binds_the_name_and_refuses_other_shapes() {
    let (_directory, state) = fixture();
    let before = document(&state).await;
    let owner = identity(&before.devices[0]);
    let bootstrap = LocalIdentity::generate("Named bootstrap").unwrap();

    let (next, grant) = prepare_invitation(
        &state,
        &before,
        &owner,
        invitation(&before, &bootstrap, None, true),
    )
    .unwrap();
    assert!(grant.claims.fixed_member_name);
    assert_eq!(grant.claims.member_name, "Ayşe");
    assert_eq!(grant.claims.schema_version, 4);
    assert!(next.validate().is_ok());
    // Without the option the grant is exactly what older servers issued.
    let (_, plain) = prepare_invitation(
        &state,
        &before,
        &owner,
        invitation(&before, &bootstrap, None, false),
    )
    .unwrap();
    assert!(!plain.claims.fixed_member_name);
    assert_eq!(plain.claims.schema_version, 1);
    assert!(
        serde_json::to_value(&plain.claims)
            .unwrap()
            .get("fixed_member_name")
            .is_none()
    );

    let mut multi_use = invitation(&before, &bootstrap, None, true);
    multi_use.request.max_uses = 2;
    let targeted = invitation(&before, &bootstrap, Some(&before.members[2]), true);
    let mut joiner_names_nothing = invitation(&before, &bootstrap, None, true);
    joiner_names_nothing.request.recipient_names = false;
    let mut hidden = invitation(&before, &bootstrap, None, true);
    hidden.request.member_name = "Ay\u{202E}şe".into();
    for body in [multi_use, targeted, joiner_names_nothing, hidden] {
        assert_eq!(
            status(
                create_invitation_handler(
                    State(state.clone()),
                    Extension(owner.clone()),
                    Json(body)
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(document(&state).await, before);

    // The joiner may choose only the device name, and only a clean one.
    let joiner = LocalIdentity::generate("Joiner").unwrap();
    let enrollment = |names: Option<EnrollmentNames>| EnrollmentRequest {
        names,
        claims: grant.claims.clone(),
        signature: grant.signature.clone(),
        token: TOKEN.into(),
        device_wireguard_public_key: joiner.public.wireguard_public_key.clone(),
        device_management_certificate_pem: joiner.public.management_certificate_pem.clone(),
        device_preshared_key: None,
        platform: None,
    };
    let device_only = |device_name: &str| {
        Some(EnrollmentNames {
            member_name: None,
            device_name: device_name.into(),
        })
    };
    assert_eq!(
        resolve_enrollment_names(&enrollment(device_only(" My phone "))).unwrap(),
        ("Ayşe".to_owned(), "My phone".to_owned())
    );
    assert!(resolve_enrollment_names(&enrollment(device_only("Pho\u{200B}ne"))).is_err());
    assert!(resolve_enrollment_names(&enrollment(None)).is_err());
    replace(&state, next.clone()).await;
    let bootstrap_caller = CallerIdentity {
        certificate_fingerprint: certificate_fingerprint(
            &bootstrap.public.management_certificate_pem,
        )
        .unwrap(),
    };
    let renamed_by_joiner = enrollment(Some(EnrollmentNames {
        member_name: Some("Someone else".into()),
        device_name: "My phone".into(),
    }));
    assert_eq!(
        status(
            enrollment_handler(
                State(state.clone()),
                Extension(bootstrap_caller),
                Json(renamed_by_joiner)
            )
            .await
        ),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(document(&state).await, next);

    // An ordinary recipient-named grant still lets the joiner name the new person.
    let mut ordinary = enrollment(Some(EnrollmentNames {
        member_name: Some("Chosen".into()),
        device_name: "My phone".into(),
    }));
    ordinary.claims = plain.claims;
    assert_eq!(resolve_enrollment_names(&ordinary).unwrap().0, "Chosen");
}

#[tokio::test]
async fn rename_follows_management_rules_and_never_contains_traffic() {
    let (_directory, state) = fixture();
    let before = document(&state).await;
    let [owner, admin, family, _, other] =
        [0, 1, 2, 3, 4].map(|index| identity(&before.devices[index]));
    let member = |index: usize| before.members[index].id;
    for (caller, target) in [
        (&owner, 1),
        (&owner, 0),
        (&admin, 2),
        (&admin, 1),
        (&family, 2),
    ] {
        let next =
            renamed_member(&state, &before, caller, member(target), "Renamed".into()).unwrap();
        assert_eq!(next.members[target].name, "Renamed");
        let configuration = &state.configuration;
        let operational = state.operational_configuration.as_ref();
        let (applied, renamed) = (
            footprint(configuration, operational, &before).unwrap(),
            footprint(configuration, operational, &next).unwrap(),
        );
        assert_eq!(applied, renamed);
        assert!(!narrows(&applied, &renamed));
    }

    let rename = |caller: &CallerIdentity, target: MemberId, name: &str| {
        rename_member_handler(
            State(state.clone()),
            Extension(caller.clone()),
            AxumPath(target.to_string()),
            Json(RenameMemberRequest { name: name.into() }),
        )
    };
    for name in [
        "",
        "   ",
        &"x".repeat(65),
        "a\nb",
        "\u{202E}evil",
        "a\u{2066}b",
        "a\u{FEFF}",
    ] {
        assert_eq!(
            status(rename(&owner, member(2), name).await),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(validate_new_display_name(" 👩\u{200D}💻 Ayşe ").is_ok());
    assert_eq!(
        status(rename(&owner, MemberId::new(), "Ghost").await),
        StatusCode::NOT_FOUND
    );
    for (caller, target) in [(&admin, 0), (&family, 3), (&family, 1), (&family, 0)] {
        assert_eq!(
            status(rename(caller, member(target), "Taken over").await),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(document(&state).await, before);

    // An Admin cannot rename another Admin.
    let mut second_admin = before.clone();
    second_admin.members[3].administrator = true;
    replace(&state, second_admin.clone()).await;
    assert_eq!(
        status(rename(&admin, member(3), "Demoted").await),
        StatusCode::FORBIDDEN
    );
    // A suspended person cannot rename themself.
    let mut suspended = before.clone();
    suspended.set_member_suspended(member(2), true).unwrap();
    replace(&state, suspended.clone()).await;
    assert_eq!(
        status(rename(&family, member(2), "Still me").await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(document(&state).await, suspended);

    // A device join code for the person carries their signed name, so it must go first.
    replace(&state, before.clone()).await;
    let bootstrap = LocalIdentity::generate("Device join code").unwrap();
    let (with_code, _) = prepare_invitation(
        &state,
        &before,
        &owner,
        invitation(&before, &bootstrap, Some(&before.members[2]), false),
    )
    .unwrap();
    replace(&state, with_code.clone()).await;
    assert_eq!(
        status(rename(&owner, member(2), "Renamed").await),
        StatusCode::CONFLICT
    );
    assert_eq!(document(&state).await, with_code);

    // Member renames share the per-device budget; refused attempts count too.
    replace(&state, before.clone()).await;
    for _ in 0..MEMBER_MUTATIONS_PER_MINUTE {
        assert_eq!(
            status(rename(&other, member(2), "Nope").await),
            StatusCode::FORBIDDEN
        );
    }
    let limited = rename(&other, member(3), "Me").await.err().unwrap();
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.code, ErrorCode::RateLimited);
    assert_eq!(document(&state).await, before);
}

#[tokio::test]
async fn an_admin_adds_own_devices_but_still_cannot_target_other_admins_or_the_owner() {
    let (_directory, state) = fixture();
    let mut before = document(&state).await;
    before.members[3].administrator = true;
    replace(&state, before.clone()).await;
    let [admin, family] = [1, 2].map(|index| identity(&before.devices[index]));
    let admin_member = before.members[1].clone();
    assert!(!admin_member.policy.add_own_devices);
    let bootstrap = LocalIdentity::generate("Admin device").unwrap();

    let (next, grant) = prepare_invitation(
        &state,
        &before,
        &admin,
        invitation(&before, &bootstrap, Some(&admin_member), false),
    )
    .unwrap();
    assert_eq!(grant.claims.target_member_id, Some(admin_member.id));
    assert!(next.validate().is_ok());
    let (next, device) = prepare_wireguard_device(
        &state,
        &before,
        &admin,
        wireguard_device(&before, &admin_member),
    )
    .unwrap();
    assert_eq!(device.member_id, admin_member.id);
    assert!(next.validate().is_ok());

    let invite = |caller: &CallerIdentity, body| {
        create_invitation_handler(State(state.clone()), Extension(caller.clone()), Json(body))
    };
    let add = |caller: &CallerIdentity, request| {
        crate::wireguard_device::create_wireguard_device_handler(
            State(state.clone()),
            Extension(caller.clone()),
            Json(request),
        )
    };
    for target in [&before.members[0], &before.members[3]] {
        assert_eq!(
            status(invite(&admin, invitation(&before, &bootstrap, Some(target), false)).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(add(&admin, wireguard_device(&before, target)).await),
            StatusCode::FORBIDDEN
        );
    }
    // A Member still needs the delegated permission for their own devices.
    assert_eq!(
        status(
            invite(
                &family,
                invitation(&before, &bootstrap, Some(&before.members[2]), false)
            )
            .await
        ),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(add(&family, wireguard_device(&before, &before.members[2])).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(document(&state).await, before);

    // The Admin's own limits still apply: device limit, expiry and suspension.
    let mut limited = before.clone();
    limited
        .set_member_policy(
            admin_member.id,
            MemberPolicy {
                device_limit: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
    replace(&state, limited.clone()).await;
    let limited_member = limited.members[1].clone();
    assert_eq!(
        status(
            invite(
                &admin,
                invitation(&limited, &bootstrap, Some(&limited_member), false)
            )
            .await
        ),
        StatusCode::CONFLICT
    );
    assert_eq!(
        status(add(&admin, wireguard_device(&limited, &limited_member)).await),
        StatusCode::CONFLICT
    );
    let mut expired = before.clone();
    expired
        .set_member_policy(
            admin_member.id,
            MemberPolicy {
                expires_at_unix: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
    let mut suspended = before.clone();
    suspended
        .set_member_suspended(admin_member.id, true)
        .unwrap();
    for document_state in [expired, suspended] {
        let target = document_state.members[1].clone();
        replace(&state, document_state.clone()).await;
        assert_eq!(
            status(
                invite(
                    &admin,
                    invitation(&document_state, &bootstrap, Some(&target), false)
                )
                .await
            ),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(add(&admin, wireguard_device(&document_state, &target)).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(document(&state).await, document_state);
    }
}

#[tokio::test]
async fn invitation_issuers_are_shown_only_with_invitations_the_caller_already_sees() {
    let (_directory, state) = fixture();
    let before = document(&state).await;
    let owner = identity(&before.devices[0]);
    let bootstrap = LocalIdentity::generate("Owner join code").unwrap();
    let (next, grant) = prepare_invitation(
        &state,
        &before,
        &owner,
        invitation(&before, &bootstrap, None, false),
    )
    .unwrap();
    replace(&state, next).await;
    let snapshot = |device: usize| {
        let state = state.clone();
        let caller = identity(&before.devices[device]);
        async move {
            membership_handler(State(state), Extension(caller))
                .await
                .unwrap()
                .0
                .payload
        }
    };
    for manager in [0, 1] {
        let invitations = snapshot(manager).await.active_invitations;
        assert_eq!(invitations.len(), 1);
        assert_eq!(invitations[0].id, grant.claims.invitation_id);
        assert_eq!(
            invitations[0].issued_by_member_id,
            Some(before.members[0].id)
        );
    }
    assert!(snapshot(2).await.active_invitations.is_empty());
}

#[tokio::test]
async fn state_written_by_the_previous_version_loads_unchanged() {
    let (_directory, state) = fixture();
    let before = document(&state).await;
    let owner = identity(&before.devices[0]);
    let bootstrap = LocalIdentity::generate("Legacy join code").unwrap();
    let (next, _) = prepare_invitation(
        &state,
        &before,
        &owner,
        invitation(&before, &bootstrap, None, false),
    )
    .unwrap();
    // The previous version stored no issuer on older grants and allowed any visible name.
    let mut legacy = serde_json::to_value(&next).unwrap();
    assert!(
        legacy["invitations"][0]["claims"]
            .get("fixed_member_name")
            .is_none()
    );
    legacy["invitations"][0]
        .as_object_mut()
        .unwrap()
        .remove("issued_by");
    legacy["members"][2]["name"] = "Family \u{202E}".into();
    legacy["schema_version"] = serde_json::Value::from(1);
    let path = state
        .paths
        .authorization
        .with_file_name("legacy-authorization.json");
    fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    let loaded = load_authorization(&path).unwrap();
    assert_eq!(loaded.members[2].name, "Family \u{202E}");
    let summary = &loaded.snapshot(unix_time()).active_invitations[0];
    assert_eq!(summary.issued_by_member_id, None);
    assert!(!loaded.invitations[0].claims.fixed_member_name);
    assert_eq!(serde_json::to_value(&loaded).unwrap(), legacy);
}

#[tokio::test]
async fn person_names_are_unique_after_nfkc_and_case_folding() {
    let (_directory, state) = fixture();
    let mut before = document(&state).await;
    before.members[3].name = "åsa".into();
    replace(&state, before.clone()).await;
    let [owner, family] = [0, 2].map(|index| identity(&before.devices[index]));
    let taken = |error: ApiError| {
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, ErrorCode::ConflictDetected);
        assert_eq!(error.message, sirinvpn_protocol::PERSON_NAME_TAKEN_MESSAGE);
    };

    // Rename: another person's name in any case or compatibility form is refused.
    for name in ["Admin", "ADMIN", "Ａｄｍｉｎ", "ÅSA"] {
        let result = rename_member_handler(
            State(state.clone()),
            Extension(family.clone()),
            AxumPath(before.members[2].id.to_string()),
            Json(RenameMemberRequest { name: name.into() }),
        )
        .await;
        taken(result.err().unwrap());
    }
    // Changing only the case of one's own name is fine.
    let next = renamed_member(
        &state,
        &before,
        &family,
        before.members[2].id,
        "FAMILY".into(),
    )
    .unwrap();
    assert_eq!(next.members[2].name, "FAMILY");

    // Creating a person: a named join code, an issuer-named code, a WireGuard-only person.
    let bootstrap = LocalIdentity::generate("Name bootstrap").unwrap();
    let mut named = invitation(&before, &bootstrap, None, true);
    named.request.member_name = "Ａｄｍｉｎ".into();
    taken(
        prepare_invitation(&state, &before, &owner, named)
            .err()
            .unwrap(),
    );
    let mut issuer_named = invitation(&before, &bootstrap, None, false);
    issuer_named.request.recipient_names = false;
    issuer_named.request.member_name = "ÅSA".into();
    taken(
        prepare_invitation(&state, &before, &owner, issuer_named)
            .err()
            .unwrap(),
    );
    let mut wireguard_only = wireguard_device(&before, &before.members[2]);
    wireguard_only.target_member_id = None;
    wireguard_only.member_name = "admin".into();
    taken(
        prepare_wireguard_device(&state, &before, &owner, wireguard_only)
            .err()
            .unwrap(),
    );
    // A recipient-named code carries only a placeholder; the joiner's choice is checked.
    let mut placeholder = invitation(&before, &bootstrap, None, false);
    placeholder.request.member_name = "Admin".into();
    let (with_code, grant) = prepare_invitation(&state, &before, &owner, placeholder).unwrap();

    // Enrollment: the joiner's chosen name is checked against existing people.
    replace(&state, with_code.clone()).await;
    let joiner = LocalIdentity::generate("Name joiner").unwrap();
    let request = EnrollmentRequest {
        names: Some(EnrollmentNames {
            member_name: Some("ÅSA".into()),
            device_name: "Phone".into(),
        }),
        claims: grant.claims,
        signature: grant.signature,
        token: TOKEN.into(),
        device_wireguard_public_key: joiner.public.wireguard_public_key.clone(),
        device_management_certificate_pem: joiner.public.management_certificate_pem.clone(),
        device_preshared_key: None,
        platform: None,
    };
    let bootstrap_caller = CallerIdentity {
        certificate_fingerprint: certificate_fingerprint(
            &bootstrap.public.management_certificate_pem,
        )
        .unwrap(),
    };
    taken(
        enrollment_handler(
            State(state.clone()),
            Extension(bootstrap_caller),
            Json(request),
        )
        .await
        .err()
        .unwrap(),
    );
    assert_eq!(document(&state).await, with_code);
}

#[test]
fn stored_duplicate_person_names_still_load() {
    let (_directory, state) = fixture();
    let mut stored = state
        .authorization
        .as_ref()
        .unwrap()
        .blocking_read()
        .clone();
    stored.members[3].name = "ADMIN".into();
    stored.members[2].name = stored.members[1].name.clone();
    write_authorization(&state.paths.authorization, &stored).unwrap();
    let loaded = load_authorization(&state.paths.authorization).unwrap();
    assert!(loaded.validate().is_ok());
    assert_eq!(loaded, stored);
}
