use super::*;

/// Claims exactly as the previous server signed them: compact JSON in field order.
const LEGACY_CLAIMS: &str = concat!(
    r#"{"schema_version":1,"invitation_id":"00000000-0000-4000-8000-000000000001","#,
    r#""server_id":"00000000-0000-4000-8000-000000000002","server_name":"Home","#,
    r#""endpoint":{"host":"203.0.113.4","wireguard_port":51820},"#,
    r#""server_tunnel_address":"10.77.0.1","management_port":8443,"#,
    r#""server_wireguard_public_key":"server-key","pinned_server_certificate_pem":"server-pem","#,
    r#""member_id":"00000000-0000-4000-8000-000000000003","#,
    r#""device_id":"00000000-0000-4000-8000-000000000004","member_name":"Ayşe","#,
    r#""device_name":"Phone","recipient_names":true,"role":"member","#,
    r#""client_tunnel_address":"10.77.0.3","bootstrap_tunnel_address":"10.77.0.224","#,
    r#""expires_at_unix":2000,"token_hash":"hash","#,
    r#""bootstrap_wireguard_public_key":"bootstrap-key","#,
    r#""bootstrap_management_certificate_pem":"bootstrap-pem"}"#
);

#[test]
fn legacy_claims_keep_their_signed_bytes_and_version() {
    let claims: InvitationClaims = serde_json::from_str(LEGACY_CLAIMS).unwrap();
    assert!(!claims.fixed_member_name);
    assert_eq!(claims.required_schema_version(), 1);
    // A signature over the old bytes still verifies: re-serialization is byte-identical.
    assert_eq!(serde_json::to_string(&claims).unwrap(), LEGACY_CLAIMS);

    let mut named = claims;
    named.fixed_member_name = true;
    named.alternate_endpoint_hosts = vec!["vpn.example.net".into()];
    // The newest feature decides the version, so an older client rejects it as unknown.
    assert_eq!(named.required_schema_version(), 4);
    let value = serde_json::to_value(&named).unwrap();
    assert_eq!(value["fixed_member_name"], true);
}

#[test]
fn invitation_body_without_options_is_the_legacy_request() {
    let legacy = serde_json::json!({
        "server_id": ServerId::new(),
        "endpoint": { "host": "203.0.113.4", "wireguard_port": 51820 },
        "member_name": "Ayşe",
        "device_name": "Phone",
        "recipient_names": true,
        "member_policy": { "device_limit": 2 },
        "expires_in_seconds": 600,
        "token_hash": "hash",
        "bootstrap_wireguard_public_key": "key",
        "bootstrap_management_certificate_pem": "pem"
    });
    let body: InvitationCreateBody = serde_json::from_value(legacy.clone()).unwrap();
    assert!(!body.fixed_member_name);
    assert_eq!(body.request.max_uses, 1);
    assert_eq!(body.request.member_policy.device_limit, Some(2));
    let request: InvitationCreateRequest = serde_json::from_value(legacy).unwrap();
    assert_eq!(InvitationCreateBody::from(request.clone()), body);
    // Older servers parse the body as the request; with no option set it is the same JSON.
    assert_eq!(
        serde_json::to_string(&body).unwrap(),
        serde_json::to_string(&request).unwrap()
    );

    let named = InvitationCreateBody {
        request,
        fixed_member_name: true,
    };
    let value = serde_json::to_value(&named).unwrap();
    assert_eq!(value["fixed_member_name"], true);
    assert_eq!(
        serde_json::from_value::<InvitationCreateRequest>(value.clone()).unwrap(),
        named.request
    );
    assert_eq!(
        serde_json::from_value::<InvitationCreateBody>(value).unwrap(),
        named
    );
}

#[test]
fn legacy_invitation_summary_has_no_issuer_and_rename_body_is_strict() {
    let summary: ActiveInvitationSummary = serde_json::from_value(serde_json::json!({
        "id": InvitationId::new(),
        "member_name": "Ayşe",
        "device_name": "Phone",
        "expires_at_unix": 2000
    }))
    .unwrap();
    assert_eq!(summary.issued_by_member_id, None);
    assert!(
        serde_json::to_value(&summary)
            .unwrap()
            .get("issued_by_member_id")
            .is_none()
    );
    assert!(serde_json::from_str::<RenameMemberRequest>(r#"{"name":"A"}"#).is_ok());
    assert!(serde_json::from_str::<RenameMemberRequest>(r#"{"name":"A","role":"owner"}"#).is_err());
}
