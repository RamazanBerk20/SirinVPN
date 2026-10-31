use super::*;

#[test]
fn https_cdn_mode_is_opt_in_and_invisible_when_off() {
    let legacy = r#"{"server_name":"vpn.example.org","path":"/connect"}"#;
    let https: HttpsTransport = serde_json::from_str(legacy).unwrap();
    assert!(!https.cdn && https.is_valid());
    // Existing signed descriptors keep their exact bytes.
    assert_eq!(serde_json::to_string(&https).unwrap(), legacy);
    let cdn = HttpsTransport { cdn: true, ..https };
    assert_eq!(
        serde_json::to_string(&cdn).unwrap(),
        r#"{"server_name":"vpn.example.org","path":"/connect","cdn":true}"#
    );

    let mut descriptor = EndpointDescriptor {
        endpoint: ServerEndpoint {
            host: "203.0.113.8".into(),
            wireguard_port: 51_820,
        },
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: Some(4_443),
        ipv6_tunnel_enabled: false,
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: Some(TlsLikeEndpoint {
            port: 443,
            server_public_key: String::new(),
            certificate_sha256: String::new(),
            https: Some(cdn.clone()),
        }),
    };
    // A CDN proxies only the HTTPS port, never the retained direct discovery port.
    assert_eq!(descriptor.cdn_host(), Some("vpn.example.org"));
    assert_eq!(descriptor.discovery_port(), Some(443));
    descriptor.tls_like.as_mut().unwrap().https = Some(HttpsTransport { cdn: false, ..cdn });
    assert_eq!(descriptor.cdn_host(), None);
    assert_eq!(descriptor.discovery_port(), Some(4_443));
}
