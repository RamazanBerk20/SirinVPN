use super::*;
use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey};

fn key() -> Zeroizing<String> {
    let server = LocalIdentity::generate("Test server").unwrap();
    let owner = LocalIdentity::generate("Owner").unwrap();
    let owner_id = MemberId::new();
    let profile: ServerProfile = serde_json::from_value(serde_json::json!({
        "schema_version":1, "id": ServerId::new(), "name":"Recovery test", "endpoint":{"host":"203.0.113.4","wireguard_port":51820},
        "client_tunnel_address":"10.77.0.2", "server_tunnel_address":"10.77.0.1", "server_wireguard_public_key":server.public.wireguard_public_key,
        "pinned_server_certificate_pem":server.public.management_certificate_pem, "client_management_certificate_pem":owner.public.management_certificate_pem,
        "identity_reference":"owner-test", "role":"owner", "member_id":owner_id, "device_id":DeviceId::new()
    })).unwrap();
    let draft = RecoveryKeyDraft::new(&profile, None).unwrap();
    let claims = RecoveryKeyClaims {
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: None,
        schema_version: 1,
        recovery_id: draft.request.recovery_id,
        server_id: profile.id,
        owner_member_id: owner_id,
        issuer_member_id: owner_id,
        server_name: profile.name.clone(),
        endpoint: profile.endpoint.clone(),
        endpoint_generation: 0,
        server_tunnel_address: profile.server_tunnel_address,
        management_port: DEFAULT_MANAGEMENT_PORT,
        server_wireguard_public_key: profile.server_wireguard_public_key.clone(),
        pinned_server_certificate_pem: profile.pinned_server_certificate_pem.clone(),
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
        recovery_tunnel_address: "10.77.0.254".parse().unwrap(),
        recovery_wireguard_public_key: draft.request.recovery_wireguard_public_key.clone(),
        recovery_management_certificate_pem: draft
            .request
            .recovery_management_certificate_pem
            .clone(),
    };
    let signing = SigningKey::from_pkcs8_pem(&server.secret.management_private_key_pem).unwrap();
    let signature = STANDARD.encode(
        signing
            .sign(&serde_json::to_vec(&claims).unwrap())
            .to_bytes(),
    );
    draft
        .finish(RecoveryKeyResponse { claims, signature })
        .unwrap()
}

#[test]
fn self_contained_recovery_key_and_encrypted_package_are_authenticated() {
    let key = key();
    let decoded = DecodedRecoveryKey::decode(&key).unwrap();
    assert_eq!(
        decoded
            .bootstrap_profile()
            .client_tunnel_address
            .to_string(),
        "10.77.0.254"
    );
    assert!(!format!("{decoded:?}").contains(&decoded.secret().wireguard_private_key));
    let package = encrypt_recovery_package(&key, "a strong recovery password").unwrap();
    assert!(!String::from_utf8_lossy(&package).contains(key.as_str()));
    assert_eq!(
        decrypt_recovery_package(&package, "a strong recovery password")
            .unwrap()
            .as_str(),
        key.as_str()
    );
    assert!(decrypt_recovery_package(&package, "the incorrect password").is_err());
    let mut corrupted: serde_json::Value = serde_json::from_slice(&package).unwrap();
    corrupted["format"] = serde_json::json!("sirinvpn-device-backup");
    assert!(
        decrypt_recovery_package(
            &serde_json::to_vec(&corrupted).unwrap(),
            "a strong recovery password"
        )
        .is_err()
    );
    let mut response = decoded.encoded.response.clone();
    response.claims.owner_member_id = MemberId::new();
    assert!(validate_recovery_response(&response).is_err());
}
