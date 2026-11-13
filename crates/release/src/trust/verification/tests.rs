use super::*;

#[test]
fn first_server_baseline_cannot_replay_a_policy_or_forget_a_vps_revocation() {
    let (root_private, root) = crate::generate_signing_keypair().unwrap();
    let (_, retired) = crate::generate_signing_keypair().unwrap();
    let (_, current) = crate::generate_signing_keypair().unwrap();
    let retired_id = crate::public_key_id(&retired).unwrap();
    let policy = |sequence, keys, revoked| {
        let bytes =
            encode_trust_policy(&build_trust_policy(sequence, keys, revoked).unwrap()).unwrap();
        let signature = sign_trust_policy(&bytes, &root_private).unwrap();
        (bytes, signature)
    };
    let (old, old_signature) = policy(1, vec![retired.clone()], vec![]);
    let (active, signature) = policy(2, vec![current.clone()], vec![retired_id.clone()]);
    let installed = canonical_json(&InstalledReleaseTrust {
        schema_version: 1,
        policy: parse_trust_policy(&active).unwrap(),
        signature: parse_trust_signature(&signature).unwrap(),
    })
    .unwrap();
    assert!(matches!(
        verify_update_with_root(Some(&installed), &old, &old_signature, &root),
        Err(ReleaseError::TrustPolicyRollback)
    ));
    let (forgotten, forgotten_signature) = policy(3, vec![current.clone(), retired], vec![]);
    assert!(matches!(
        verify_update_with_root(Some(&installed), &forgotten, &forgotten_signature, &root),
        Err(ReleaseError::TrustPolicyUnrevokesKey)
    ));
    assert_eq!(
        verify_update_with_root(Some(&installed), &active, &signature, &root)
            .unwrap()
            .policy
            .sequence,
        2
    );
    let (new, new_signature) = policy(3, vec![current], vec![retired_id]);
    assert_eq!(
        verify_update_with_root(Some(&installed), &new, &new_signature, &root)
            .unwrap()
            .policy
            .sequence,
        3
    );
    let mut damaged = installed;
    damaged[0] = b'!';
    assert!(verify_update_with_root(Some(&damaged), &new, &new_signature, &root).is_err());
}

#[test]
fn a_fresh_installation_cannot_go_below_the_embedded_trust_floor() {
    let (root_private, root) = crate::generate_signing_keypair().unwrap();
    let (_, retired) = crate::generate_signing_keypair().unwrap();
    let (_, current) = crate::generate_signing_keypair().unwrap();
    let retired_id = crate::public_key_id(&retired).unwrap();
    let policy = |sequence, keys, revoked| {
        let bytes =
            encode_trust_policy(&build_trust_policy(sequence, keys, revoked).unwrap()).unwrap();
        let signature = sign_trust_policy(&bytes, &root_private).unwrap();
        (bytes, signature)
    };
    let (stale, stale_signature) = policy(1, vec![retired.clone()], vec![]);
    let (floor, floor_signature) = policy(2, vec![current.clone()], vec![retired_id.clone()]);
    let embedded = trust_floor_record(Some((&floor, &floor_signature)), &root)
        .unwrap()
        .unwrap();

    // Without the floor a fresh store accepts the stale policy; with it, it may not.
    assert!(verify_update_with_floor(None, &stale, &stale_signature, &root, None).is_ok());
    assert!(matches!(
        verify_update_with_floor(None, &stale, &stale_signature, &root, Some(&embedded)),
        Err(ReleaseError::TrustPolicyRollback)
    ));
    let (forgotten, forgotten_signature) = policy(3, vec![current.clone(), retired], vec![]);
    assert!(matches!(
        verify_update_with_floor(
            None,
            &forgotten,
            &forgotten_signature,
            &root,
            Some(&embedded)
        ),
        Err(ReleaseError::TrustPolicyUnrevokesKey)
    ));
    let (newer, newer_signature) = policy(3, vec![current], vec![retired_id]);
    for (bytes, signature) in [(&floor, &floor_signature), (&newer, &newer_signature)] {
        assert!(verify_update_with_floor(None, bytes, signature, &root, Some(&embedded)).is_ok());
    }

    // A floor that the root never signed fails closed instead of being ignored.
    let (_, other_root) = crate::generate_signing_keypair().unwrap();
    assert!(trust_floor_record(Some((&floor, &floor_signature)), &other_root).is_err());
    assert!(trust_floor_record(None, &root).unwrap().is_none());
}

#[test]
fn the_embedded_floor_if_any_verifies_under_the_bundled_root() {
    // Fails the build's tests when release/ holds a policy the bundled root did not sign.
    embedded_trust_floor_sequence().unwrap();
}
