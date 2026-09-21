use super::*;

use ed25519_dalek::{Signer, pkcs8::DecodePrivateKey};

use qrcode::{EcLevel, QrCode};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    PKCS_ED25519,
};

use sirinvpn_protocol::{
    DEFAULT_MANAGEMENT_PORT, DeviceId, InvitationClaims, MemberId, ServerEndpoint, ServerId,
};

fn server_identity() -> (String, String) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Test server");
    let mut params = CertificateParams::new(vec!["sirinvpn.local".to_owned()]).unwrap();
    params.distinguished_name = name;
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params.self_signed(&key).unwrap();
    (certificate.pem(), key.serialize_pem())
}

fn signed_response(
    profile: &ServerProfile,
    request: &InvitationCreateRequest,
    server_private_key: &str,
) -> InvitationCreateResponse {
    let claims = InvitationClaims {
        recipient_names: request.recipient_names,
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: None,
        max_uses: request.max_uses,
        member_policy: request.member_policy.clone(),
        schema_version: if request.max_uses > 1 || !request.member_policy.is_default() {
            2
        } else {
            1
        },
        invitation_id: InvitationId::new(),
        server_id: profile.id,
        server_name: profile.name.clone(),
        endpoint: profile.endpoint.clone(),
        endpoint_generation: profile.endpoint_generation,
        server_tunnel_address: profile.server_tunnel_address,
        management_port: DEFAULT_MANAGEMENT_PORT,
        server_wireguard_public_key: profile.server_wireguard_public_key.clone(),
        pinned_server_certificate_pem: profile.pinned_server_certificate_pem.clone(),
        obfuscated_udp: profile.obfuscated_udp.clone(),
        tcp_fallback: profile.tcp_fallback.clone(),
        tls_like: profile.tls_like.clone(),
        member_id: MemberId::new(),
        target_member_id: request.target_member_id,
        target_role: request.target_member_id.map(|_| ServerRole::Member),
        device_id: DeviceId::new(),
        member_name: request.member_name.clone(),
        device_name: request.device_name.clone(),
        role: ServerRole::Member,
        administrator: request.administrator,
        client_tunnel_address: "10.77.0.3".parse().unwrap(),
        bootstrap_tunnel_address: "10.77.0.224".parse().unwrap(),
        expires_at_unix: unix_time() + 600,
        token_hash: request.token_hash.clone(),
        bootstrap_wireguard_public_key: request.bootstrap_wireguard_public_key.clone(),
        bootstrap_management_certificate_pem: request.bootstrap_management_certificate_pem.clone(),
    };
    let key = SigningKey::from_pkcs8_pem(server_private_key).unwrap();
    let signature = key.sign(&serde_json::to_vec(&claims).unwrap());
    InvitationCreateResponse {
        claims,
        signature: STANDARD.encode(signature.to_bytes()),
    }
}

fn owner_profile() -> (ServerProfile, String) {
    let (certificate, private_key) = server_identity();
    let owner = LocalIdentity::generate("Owner").unwrap();
    (
        ServerProfile {
            favorite: false,
            schema_version: 1,
            id: ServerId::new(),
            name: "Test server".to_owned(),
            endpoint: ServerEndpoint {
                host: "203.0.113.4".to_owned(),
                wireguard_port: 51_820,
            },
            endpoint_generation: 0,
            pending_previous_endpoint: None,
            pending_previous_transports: None,
            endpoint_discovery_port: None,
            alternate_endpoint_hosts: Vec::new(),
            client_tunnel_address: "10.77.0.2".parse().unwrap(),
            server_tunnel_address: "10.77.0.1".parse().unwrap(),
            ipv6_tunnel_enabled: false,
            server_wireguard_public_key: owner.public.wireguard_public_key,
            pinned_server_certificate_pem: certificate,
            client_management_certificate_pem: owner.public.management_certificate_pem,
            identity_reference: "owner".to_owned(),
            role: ServerRole::Owner,
            administrator: false,
            member_id: None,
            device_id: None,
            obfuscated_udp: None,
            tcp_fallback: None,
            tls_like: None,
        },
        private_key,
    )
}

mod reusable;
mod signed_long_code_round_trip_preserves_only_bootstrap_secret;

mod recipient_names;
