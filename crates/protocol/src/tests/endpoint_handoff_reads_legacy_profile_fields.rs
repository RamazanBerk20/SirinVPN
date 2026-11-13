use super::*;

fn saved_profile(extra: serde_json::Value) -> ServerProfile {
    // The on-disk profile shape written by every earlier client.
    let mut profile = serde_json::json!({
        "schema_version": 1,
        "id": "8f4f6c55-3f0e-4c47-9a7e-3d1f3b0f2a11",
        "name": "Home VPS",
        "endpoint": {"host": "203.0.113.20", "wireguard_port": 51820},
        "client_tunnel_address": "10.77.0.2",
        "server_tunnel_address": "10.77.0.1",
        "server_wireguard_public_key": "public",
        "pinned_server_certificate_pem": "certificate",
        "client_management_certificate_pem": "client-certificate",
        "identity_reference": "identity",
        "role": "owner"
    });
    profile
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(profile).unwrap()
}

#[test]
fn endpoint_handoff_reads_legacy_profile_fields() {
    let previous = serde_json::json!({"host": "203.0.113.10", "wireguard_port": 51820});
    assert_eq!(
        saved_profile(serde_json::json!({}))
            .endpoint_handoff()
            .unwrap(),
        EndpointHandoff::Current
    );

    // Before transport descriptors, only the previous endpoint was saved.
    let legacy = saved_profile(serde_json::json!({"pending_previous_endpoint": previous}));
    let handoff = legacy.endpoint_handoff().unwrap();
    let EndpointHandoff::AwaitingPublication {
        previous_endpoint,
        previous_transports: None,
    } = &handoff
    else {
        panic!("legacy handoff was not read: {handoff:?}");
    };
    assert_eq!(previous_endpoint.host, "203.0.113.10");

    let descriptor = serde_json::json!({
        "endpoint": previous,
        "ipv6_tunnel_enabled": false,
        "obfuscated_udp": null,
        "tcp_fallback": null,
        "tls_like": null
    });
    let current = saved_profile(serde_json::json!({
        "pending_previous_endpoint": previous,
        "pending_previous_transports": descriptor,
    }));
    let EndpointHandoff::AwaitingPublication {
        previous_transports: Some(transports),
        ..
    } = current.endpoint_handoff().unwrap()
    else {
        panic!("descriptor handoff was not read");
    };
    assert_eq!(transports.endpoint.host, "203.0.113.10");

    // Writing the handoff back produces the same legacy fields, byte for byte.
    let mut rewritten = current.clone();
    rewritten.set_endpoint_handoff(current.endpoint_handoff().unwrap());
    assert_eq!(
        serde_json::to_value(&rewritten).unwrap(),
        serde_json::to_value(&current).unwrap()
    );
    rewritten.set_endpoint_handoff(EndpointHandoff::Current);
    assert_eq!(rewritten.pending_previous_endpoint, None);
    assert_eq!(rewritten.pending_previous_transports, None);

    // Combinations no writer produces are refused instead of silently ignored.
    for contradictory in [
        saved_profile(serde_json::json!({"pending_previous_transports": descriptor})),
        saved_profile(serde_json::json!({
            "pending_previous_endpoint": {"host": "203.0.113.11", "wireguard_port": 51820},
            "pending_previous_transports": descriptor,
        })),
        saved_profile(serde_json::json!({
            "role": "member",
            "pending_previous_endpoint": previous,
        })),
    ] {
        assert!(matches!(
            contradictory.endpoint_handoff(),
            Err(ValidationError::InvalidEndpointHandoff)
        ));
    }
}
