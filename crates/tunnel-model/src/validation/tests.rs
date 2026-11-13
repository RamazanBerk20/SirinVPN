use super::*;
use sirinvpn_protocol::MtuPolicy;

fn key(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

fn transport_key(transport: TransportKind) -> Option<String> {
    (transport != TransportKind::DirectUdp).then(|| key(3))
}

fn candidate(transport: TransportKind, mtu: u16) -> ReconnectCandidate {
    ReconnectCandidate {
        transport,
        endpoint_port: 51_820,
        server_transport_public_key: transport_key(transport),
        server_certificate_sha256: None,
        https: None,
        mtu,
    }
}

fn request(transport: TransportKind, policy: MtuPolicy, mtu: u16) -> TunnelConnectRequest {
    TunnelConnectRequest {
        endpoint_identity: None,
        endpoint_checkpoint: None,
        endpoint_publication_enabled: false,
        endpoint_dns_servers: Vec::new(),
        cdn_address: None,
        mtu_policy: Some(policy),
        schema_version: 8,
        server_id: ServerId::new(),
        endpoint_host: "203.0.113.8".to_owned(),
        endpoint_port: 51_820,
        transport,
        server_transport_public_key: transport_key(transport),
        server_certificate_sha256: None,
        https: None,
        reconnect_candidates: Vec::new(),
        client_address: Ipv4Addr::new(10, 77, 0, 2),
        server_public_key: key(1),
        private_key: key(2),
        dns_address: Ipv4Addr::new(10, 77, 0, 1),
        client_ipv6_address: None,
        mtu,
        persistent_protection: false,
        policy: Some(ConnectionPolicy::default()),
        routing: TunnelRoutingPolicy::default(),
        preshared_key: None,
        subnet_routes: Default::default(),
    }
}

#[test]
fn manual_mtu_must_be_limited_to_the_obfuscated_udp_ceiling() {
    let manual = MtuPolicy::Manual { value: 1_420 };
    validate_request(&request(TransportKind::ObfuscatedUdp, manual, 1_398)).unwrap();
    assert!(validate_request(&request(TransportKind::ObfuscatedUdp, manual, 1_420)).is_err());
    validate_request(&request(TransportKind::DirectUdp, manual, 1_420)).unwrap();
    assert!(validate_request(&request(TransportKind::DirectUdp, manual, 1_398)).is_err());
    let below = MtuPolicy::Manual { value: 1_300 };
    validate_request(&request(TransportKind::ObfuscatedUdp, below, 1_300)).unwrap();
}

#[test]
fn manual_mtu_policy_limits_each_reconnect_candidate() {
    let mut request = request(TransportKind::DirectUdp, MtuPolicy::Automatic, 1_420);
    request.reconnect_candidates = vec![
        candidate(TransportKind::DirectUdp, 1_420),
        candidate(TransportKind::ObfuscatedUdp, 1_320),
        candidate(TransportKind::TcpFallback, 1_280),
    ];
    request
        .set_mtu_policy(MtuPolicy::Manual { value: 1_420 })
        .unwrap();
    assert_eq!(request.mtu, 1_420);
    assert_eq!(
        request
            .reconnect_candidates
            .iter()
            .map(|candidate| candidate.mtu)
            .collect::<Vec<_>>(),
        [1_420, 1_398, 1_420]
    );
    validate_request(&request).unwrap();

    request.reconnect_candidates[1].mtu = 1_420;
    assert!(validate_request(&request).is_err());
}

#[test]
fn sessions_saved_before_the_ceiling_are_normalized_on_load() {
    let manual = MtuPolicy::Manual { value: 1_420 };
    let mut saved = request(TransportKind::ObfuscatedUdp, manual, 1_420);
    saved.reconnect_candidates = vec![
        candidate(TransportKind::ObfuscatedUdp, 1_420),
        candidate(TransportKind::TcpFallback, 1_420),
    ];
    assert!(validate_request(&saved).is_err());
    saved.reapply_manual_mtu();
    validate_request(&saved).unwrap();
    assert_eq!(saved.mtu, 1_398);
}

#[test]
fn one_schema_derivation_covers_every_feature_combination() {
    let https = || sirinvpn_protocol::HttpsTransport {
        server_name: "vpn.example.com".into(),
        path: "/sirinvpn".into(),
        cdn: false,
    };
    let legacy = |transport| {
        let mut request = request(transport, MtuPolicy::Automatic, 1_420);
        request.mtu_policy = None;
        request.policy = None;
        request.mtu = 1_280;
        if transport == TransportKind::TlsLike {
            request.server_certificate_sha256 = Some(key(4));
        }
        request
    };
    for (transport, expected) in [
        (TransportKind::DirectUdp, 2),
        (TransportKind::ObfuscatedUdp, 3),
        (TransportKind::TcpFallback, 4),
        (TransportKind::TlsLike, 5),
    ] {
        let mut request = legacy(transport);
        assert_eq!(request.required_schema(), expected, "{transport:?}");
        request.schema_version = request.required_schema();
        validate_request(&request).unwrap();
    }
    let mut routed = legacy(TransportKind::DirectUdp);
    routed.routing = TunnelRoutingPolicy::full_tunnel(true);
    assert_eq!(routed.required_schema(), 6);
    routed.policy = Some(ConnectionPolicy::default());
    assert_eq!(routed.required_schema(), 7);
    routed.mtu_policy = Some(MtuPolicy::Automatic);
    assert_eq!(routed.required_schema(), 8);
    routed.mtu = 1_420;
    routed.schema_version = routed.required_schema();
    validate_request(&routed).unwrap();
    let mut tls = routed.clone();
    tls.transport = TransportKind::TlsLike;
    tls.server_transport_public_key = Some(key(3));
    tls.server_certificate_sha256 = Some(key(4));
    tls.https = Some(https());
    assert_eq!(tls.required_schema(), 9);
    tls.schema_version = tls.required_schema();
    validate_request(&tls).unwrap();
    routed.routing = TunnelRoutingPolicy::selected_applications(false);
    // Schema 11 also needs signed endpoint identity, which validation checks separately.
    assert_eq!(routed.required_schema(), 11);

    // Writers derive the schema instead of keeping their own ladders.
    let mut candidate_base = request(TransportKind::DirectUdp, MtuPolicy::Automatic, 1_420);
    candidate_base.reconnect_candidates = vec![
        candidate(TransportKind::DirectUdp, 1_420),
        candidate(TransportKind::ObfuscatedUdp, 1_398),
    ];
    let derived = request_for_reconnect_candidate(
        &candidate_base,
        &candidate_base.reconnect_candidates[1].clone(),
    );
    assert_eq!(derived.schema_version, derived.required_schema());
    let mut mtu = legacy(TransportKind::DirectUdp);
    mtu.policy = Some(ConnectionPolicy::default());
    mtu.set_mtu_policy(MtuPolicy::Automatic).unwrap();
    assert_eq!((mtu.schema_version, mtu.required_schema()), (8, 8));
}

#[test]
fn endpoint_hosts_must_arrive_normalised() {
    let mut padded = request(TransportKind::DirectUdp, MtuPolicy::Automatic, 1_420);
    padded.endpoint_host = "203.0.113.8\n".into();
    assert!(validate_request(&padded).is_err());
}
