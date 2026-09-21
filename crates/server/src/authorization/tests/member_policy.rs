use super::*;

#[test]
fn limits_and_expiration_survive_storage_without_removing_identities() {
    let mut document = state();
    let (member_id, _) = add_member(&mut document, "Limited", false);
    let device = document.devices.last().unwrap().clone();
    document
        .set_member_policy(
            member_id,
            MemberPolicy {
                device_limit: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(document.schema_version, 3);
    assert!(document.ensure_device_capacity(member_id).is_err());
    assert!(document.access_for_device(&device).is_some());
    document
        .set_member_policy(
            member_id,
            MemberPolicy {
                expires_at_unix: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(document.access_for_device(&device).is_none());
    assert!(
        !document
            .desired_peers(2)
            .iter()
            .any(|peer| peer.public_key == device.wireguard_public_key)
    );
    assert!(document.devices.contains(&device));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    write_authorization(&path, &document).unwrap();
    assert_eq!(load_authorization(&path).unwrap(), document);
    document.schema_version = 2;
    assert!(document.validate().is_err());
    document.schema_version = 3;
    document
        .set_member_policy(member_id, MemberPolicy::default())
        .unwrap();
    assert_eq!(document.schema_version, 1);
    assert!(document.access_for_device(&device).is_some());
}

#[test]
fn owner_policy_is_unrestricted_and_ownership_clears_destination_limits() {
    let mut document = state();
    let owner_id = document.members[0].id;
    assert!(
        document
            .set_member_policy(
                owner_id,
                MemberPolicy {
                    device_limit: Some(1),
                    ..Default::default()
                }
            )
            .is_err()
    );
    let (member_id, _) = add_member(&mut document, "Next owner", false);
    document
        .set_member_policy(
            member_id,
            MemberPolicy {
                device_limit: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
    let device_id = document.devices.last().unwrap().id;
    document.transfer_ownership(device_id).unwrap();
    assert!(
        document
            .members
            .iter()
            .find(|member| member.id == member_id)
            .unwrap()
            .policy
            .is_default()
    );
    document.validate().unwrap();
}
