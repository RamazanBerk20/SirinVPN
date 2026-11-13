use super::*;

/// What a VPS that honours `fixed_member_name` signs for `body`.
fn signed_named(
    profile: &ServerProfile,
    body: &InvitationCreateBody,
    key: &str,
) -> InvitationCreateResponse {
    let mut response = signed_response(profile, &body.request, key);
    response.claims.fixed_member_name = body.fixed_member_name;
    response.claims.schema_version = response.claims.required_schema_version();
    let signing = SigningKey::from_pkcs8_pem(key).unwrap();
    let signature = signing.sign(&serde_json::to_vec(&response.claims).unwrap());
    response.signature = STANDARD.encode(signature.to_bytes());
    response
}

fn named_draft(profile: &ServerProfile) -> InvitationDraft {
    InvitationDraft::new(profile, "Grandma", "New device", 3600)
        .unwrap()
        .with_recipient_names(true)
        .with_fixed_member_name(true)
        .unwrap()
}

#[test]
fn a_named_join_code_round_trips_and_the_joiner_names_only_the_device() {
    let (profile, key) = owner_profile();
    let draft = named_draft(&profile);
    let body = serde_json::to_value(draft.body()).unwrap();
    assert_eq!(body["fixed_member_name"], true);
    assert_eq!(body["member_name"], "Grandma");
    let response = signed_named(&profile, &draft.body(), &key);
    let code = draft.finish(response).unwrap();
    let mut decoded = DecodedInvitation::decode(code.expose()).unwrap();
    assert!(decoded.member_name_fixed());
    assert!(decoded.creates_member());
    assert_eq!(decoded.member_name(), "Grandma");
    // The fixed name cannot be replaced, and a device name is still required.
    assert!(
        decoded
            .set_recipient_names(Some("Someone else"), Some("Phone"))
            .is_err()
    );
    assert!(decoded.set_recipient_names(None, None).is_err());
    decoded.set_recipient_names(None, Some("Phone")).unwrap();
    let names = decoded.enrollment_binding().names.unwrap();
    assert_eq!(
        (names.member_name, names.device_name.as_str()),
        (None, "Phone")
    );
}

#[test]
fn an_older_vps_that_drops_the_name_flag_is_refused() {
    let (profile, key) = owner_profile();
    let draft = named_draft(&profile);
    // An older VPS deserializes the plain request and signs a code the joiner could rename.
    let response = signed_response(&profile, draft.request(), &key);
    assert!(matches!(
        draft.finish(response),
        Err(InvitationError::BindingMismatch)
    ));
}

#[test]
fn without_the_flag_the_body_is_the_plain_request_and_bad_combinations_fail() {
    let (profile, key) = owner_profile();
    let draft = InvitationDraft::new(&profile, "Alice", "Laptop", 3600).unwrap();
    assert_eq!(
        serde_json::to_value(draft.body()).unwrap(),
        serde_json::to_value(draft.request()).unwrap()
    );
    // A VPS that adds the flag on its own is refused too.
    let mut named = draft.body();
    named.fixed_member_name = true;
    assert!(draft.finish(signed_named(&profile, &named, &key)).is_err());
    // Needs recipient names, a new person and one use.
    let plain = InvitationDraft::new(&profile, "Alice", "Laptop", 3600).unwrap();
    assert!(plain.with_fixed_member_name(true).is_err());
    let reusable = InvitationDraft::new(&profile, "Family", "Phone", 3600)
        .unwrap()
        .with_recipient_names(true)
        .with_policy(3, Default::default())
        .unwrap();
    assert!(reusable.with_fixed_member_name(true).is_err());
    assert!(
        named_draft(&profile)
            .with_policy(2, Default::default())
            .is_err()
    );
    let target = InvitationDraft::new_for_target(
        &profile,
        "Existing",
        "New device",
        3600,
        InvitationTarget {
            member_id: Some(MemberId::new()),
            role: Some(ServerRole::Member),
            administrator: false,
        },
    )
    .unwrap()
    .with_recipient_names(true);
    assert!(target.with_fixed_member_name(true).is_err());
}
