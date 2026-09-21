use super::*;

#[test]
fn recipient_labels_are_separate_from_the_signed_authority() {
    let (profile, private_key) = owner_profile();
    let draft = InvitationDraft::new(&profile, "Invited member", "New device", 3600)
        .unwrap()
        .with_recipient_names(true);
    let response = signed_response(&profile, draft.request(), &private_key);
    let code = draft.finish(response.clone()).unwrap();
    let mut decoded = DecodedInvitation::decode(code.expose()).unwrap();
    let permanent = LocalIdentity::generate("Phone").unwrap();
    assert!(decoded.set_recipient_names(None, Some("Phone")).is_err());
    assert!(
        decoded
            .set_recipient_names(Some("a".repeat(65).as_str()), Some("Phone"))
            .is_err()
    );
    decoded
        .set_recipient_names(Some("Chosen nickname"), Some("My Android"))
        .unwrap();
    let request = decoded.enrollment_request(&permanent.public);
    assert_eq!(request.claims, response.claims);
    assert_eq!(request.signature, response.signature);
    assert_eq!(
        request.names.as_ref().unwrap().member_name.as_deref(),
        Some("Chosen nickname")
    );
    assert_eq!(request.names, decoded.enrollment_binding().names);
    let mut changed = response;
    changed.claims.recipient_names = false;
    assert!(validate_invitation_response(&changed).is_err());
}

#[test]
fn adding_a_device_cannot_rename_or_reassign_an_existing_member() {
    let (profile, private_key) = owner_profile();
    let target = MemberId::new();
    let draft = InvitationDraft::new_for_target(
        &profile,
        "Existing member",
        "New device",
        3600,
        InvitationTarget {
            member_id: Some(target),
            role: Some(ServerRole::Member),
            administrator: true,
        },
    )
    .unwrap()
    .with_recipient_names(true);
    let response = signed_response(&profile, draft.request(), &private_key);
    let code = draft.finish(response).unwrap();
    let mut decoded = DecodedInvitation::decode(code.expose()).unwrap();
    assert!(!decoded.creates_member());
    assert!(
        decoded
            .set_recipient_names(Some("Replacement"), Some("Phone"))
            .is_err()
    );
    decoded
        .set_recipient_names(None, Some("Second phone"))
        .unwrap();
    assert_eq!(decoded.member_name(), "Existing member");
    assert_eq!(decoded.enrollment_binding().member_id, target);
    assert!(decoded.enrollment_binding().administrator);
}

#[test]
fn legacy_invitation_labels_and_serialized_signatures_remain_unchanged() {
    let (profile, key) = owner_profile();
    let draft = InvitationDraft::new(&profile, "Alice", "Laptop", 3600).unwrap();
    let response = signed_response(&profile, draft.request(), &key);
    assert!(
        serde_json::to_value(&response.claims)
            .unwrap()
            .get("recipient_names")
            .is_none()
    );
    let code = draft.finish(response).unwrap();
    let mut decoded = DecodedInvitation::decode(code.expose()).unwrap();
    assert!(!decoded.recipient_names());
    assert!(decoded.set_recipient_names(None, None).is_ok());
    assert!(
        decoded
            .set_recipient_names(Some("Other"), Some("Phone"))
            .is_err()
    );
}
