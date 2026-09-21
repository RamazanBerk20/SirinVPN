use super::*;

#[test]
fn https_metadata_survives_fallback_and_restart_and_rejects_older_request_schemas() {
    let mut request = independent(true, true, true);
    let mut tls = selection(
        TransportKind::TlsLike,
        4443,
        Some(STANDARD.encode([9_u8; 32])),
        1280,
    );
    tls.server_certificate_sha256 = Some(STANDARD.encode([11_u8; 32]));
    tls.https = Some(sirinvpn_protocol::HttpsTransport {
        server_name: "vpn.example.org".into(),
        path: "/connect".into(),
    });
    let direct = selection(TransportKind::DirectUdp, 51_820, None, 1420);
    request.reconnect_candidates = policy_transport_candidates(&[direct, tls.clone()]);
    request
        .set_mtu_policy(sirinvpn_protocol::MtuPolicy::Automatic)
        .unwrap();
    assert_eq!(request.schema_version, 9);
    validate_request(&request).unwrap();
    let mut downgraded = request.clone();
    downgraded.schema_version = 8;
    assert!(validate_request(&downgraded).is_err());
    let mut candidate = request_for_reconnect_candidate(&request, &request.reconnect_candidates[1]);
    assert_eq!(candidate.https, tls.https);
    assert_eq!(candidate.endpoint_port, 4443);
    candidate.reconnect_candidates.clear();
    validate_request(&candidate).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let helper = LinuxNetworkHelper::new(runner(), dir.path().join("run"));
    helper.connect(&request).unwrap();
    let desired = helper.read_persistent().unwrap();
    assert_eq!(desired.schema_version, 4);
    assert_eq!(desired.request, request);
    assert_eq!(desired.request.reconnect_candidates[1].https, tls.https);
    let mut downgraded = desired;
    downgraded.schema_version = 3;
    helper.write_persistent(&downgraded).unwrap();
    assert!(helper.read_persistent().is_err());
}
