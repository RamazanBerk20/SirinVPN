use super::*;
mod socket_protection;
use sirinvpn_protocol::{ServerId, ServerRole, TlsLikeEndpoint};

fn profile(obfuscated_udp: Option<ObfuscatedUdpEndpoint>) -> ServerProfile {
    ServerProfile {
        favorite: false,
        schema_version: 1,
        id: ServerId::new(),
        name: "Test".to_owned(),
        endpoint: ServerEndpoint {
            host: "203.0.113.8".to_owned(),
            wireguard_port: 51_820,
        },
        endpoint_generation: 0,
        pending_previous_endpoint: None,
        pending_previous_transports: None,
        endpoint_discovery_port: None,
        alternate_endpoint_hosts: Vec::new(),
        client_tunnel_address: "10.77.0.2".parse().unwrap(),
        server_tunnel_address: "10.77.0.1".parse().unwrap(),
        server_wireguard_public_key: STANDARD.encode([8_u8; 32]),
        pinned_server_certificate_pem: "certificate".to_owned(),
        client_management_certificate_pem: "client certificate".to_owned(),
        identity_reference: "identity".to_owned(),
        role: ServerRole::Owner,
        administrator: false,
        member_id: None,
        device_id: None,
        ipv6_tunnel_enabled: false,
        obfuscated_udp,
        tcp_fallback: None,
        tls_like: None,
    }
}

#[test]
fn direct_engine_preserves_the_validated_wireguard_endpoint() {
    let profile = profile(None);
    let selection = TransportEngine
        .select(&profile, TransportKind::DirectUdp)
        .unwrap();

    assert_eq!(selection.kind, TransportKind::DirectUdp);
    assert_eq!(selection.network_endpoint, profile.endpoint);
    assert_eq!(selection.wireguard_endpoint, profile.endpoint);
    assert_eq!(selection.mtu, DIRECT_MTU);
    assert_eq!(selection.server_transport_public_key, None);
}

#[test]
fn automatic_plan_prefers_direct_then_the_installed_wrapper() {
    let profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    let selections = TransportEngine
        .plan(&profile, TransportPreference::Automatic)
        .unwrap();

    assert_eq!(
        selections
            .iter()
            .map(|selection| selection.kind)
            .collect::<Vec<_>>(),
        vec![TransportKind::DirectUdp, TransportKind::ObfuscatedUdp]
    );
}

#[test]
fn automatic_plan_uses_tcp_only_after_both_udp_paths() {
    let mut profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    profile.tcp_fallback = Some(TcpFallbackEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    });

    let selections = TransportEngine
        .plan(&profile, TransportPreference::Automatic)
        .unwrap();
    assert_eq!(
        selections
            .iter()
            .map(|selection| selection.kind)
            .collect::<Vec<_>>(),
        vec![
            TransportKind::DirectUdp,
            TransportKind::ObfuscatedUdp,
            TransportKind::TcpFallback,
        ]
    );
    let tcp = &selections[2];
    assert_eq!(tcp.network_endpoint.wireguard_port, 443);
    assert_eq!(tcp.wireguard_endpoint.wireguard_port, TCP_CLIENT_RELAY_PORT);
    assert_eq!(tcp.mtu, TCP_FALLBACK_MTU);
}

#[test]
fn tls_like_selection_pins_the_certificate_and_precedes_raw_tcp() {
    let mut profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    profile.tcp_fallback = Some(TcpFallbackEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    });
    profile.tls_like = Some(TlsLikeEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
        certificate_sha256: STANDARD.encode([10_u8; 32]),
        https: None,
    });

    let selections = TransportEngine
        .plan(&profile, TransportPreference::Automatic)
        .unwrap();
    assert_eq!(
        selections
            .iter()
            .map(|selection| selection.kind)
            .collect::<Vec<_>>(),
        vec![
            TransportKind::DirectUdp,
            TransportKind::ObfuscatedUdp,
            TransportKind::TlsLike,
            TransportKind::TcpFallback,
        ]
    );
    let tls = &selections[2];
    assert_eq!(
        tls.wireguard_endpoint.wireguard_port,
        TLS_LIKE_CLIENT_RELAY_PORT
    );
    assert_eq!(
        tls.server_certificate_sha256.as_deref(),
        profile
            .tls_like
            .as_ref()
            .map(|endpoint| endpoint.certificate_sha256.as_str())
    );
    assert_eq!(tls.mtu, TLS_LIKE_MTU);
}

#[test]
fn network_profiles_apply_bounded_transport_orders() {
    let mut profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    profile.tcp_fallback = Some(TcpFallbackEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    });
    let kinds = |network_profile, cached_transport| {
        TransportEngine
            .automatic_plan(&profile, network_profile, cached_transport)
            .unwrap()
            .into_iter()
            .map(|selection| selection.kind)
            .collect::<Vec<_>>()
    };

    assert_eq!(
        kinds(NetworkProfile::Normal, Some(TransportKind::TcpFallback)),
        vec![
            TransportKind::DirectUdp,
            TransportKind::ObfuscatedUdp,
            TransportKind::TcpFallback,
        ]
    );
    assert_eq!(
        kinds(NetworkProfile::Restricted, None),
        vec![
            TransportKind::ObfuscatedUdp,
            TransportKind::TcpFallback,
            TransportKind::DirectUdp,
        ]
    );
    assert_eq!(
        kinds(NetworkProfile::Extreme, None),
        vec![
            TransportKind::TcpFallback,
            TransportKind::ObfuscatedUdp,
            TransportKind::DirectUdp,
        ]
    );
}

#[test]
fn automatic_reuses_only_an_installed_cached_transport() {
    let mut full_profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    full_profile.tcp_fallback = Some(TcpFallbackEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    });
    let cached = TransportEngine
        .automatic_plan(
            &full_profile,
            NetworkProfile::Automatic,
            Some(TransportKind::TcpFallback),
        )
        .unwrap();
    assert_eq!(
        cached
            .into_iter()
            .map(|selection| selection.kind)
            .collect::<Vec<_>>(),
        vec![
            TransportKind::TcpFallback,
            TransportKind::DirectUdp,
            TransportKind::ObfuscatedUdp,
        ]
    );

    let unavailable = TransportEngine
        .automatic_plan(
            &profile(None),
            NetworkProfile::Automatic,
            Some(TransportKind::TcpFallback),
        )
        .unwrap();
    assert_eq!(unavailable.len(), 1);
    assert_eq!(unavailable[0].kind, TransportKind::DirectUdp);
}

#[test]
fn automatic_plan_uses_only_capabilities_the_profile_has() {
    let selections = TransportEngine
        .plan(&profile(None), TransportPreference::Automatic)
        .unwrap();
    assert_eq!(selections.len(), 1);
    assert_eq!(selections[0].kind, TransportKind::DirectUdp);
}

#[test]
fn manual_plan_contains_only_the_requested_transport() {
    let profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    let selections = TransportEngine
        .plan(&profile, TransportPreference::ObfuscatedUdp)
        .unwrap();
    assert_eq!(selections.len(), 1);
    assert_eq!(selections[0].kind, TransportKind::ObfuscatedUdp);
}

#[test]
fn android_relay_configuration_omits_the_linux_socket_mark() {
    let udp = client_relay_config_unmarked(
        "203.0.113.8:443".parse().unwrap(),
        &STANDARD.encode([7_u8; 32]),
        &STANDARD.encode([9_u8; 32]),
    )
    .unwrap();
    let tcp = tcp_client_relay_config_unmarked(
        "203.0.113.8:443".parse().unwrap(),
        &STANDARD.encode([7_u8; 32]),
        &STANDARD.encode([9_u8; 32]),
    )
    .unwrap();
    let tls = tls_like_client_relay_config_unmarked(
        "203.0.113.8:443".parse().unwrap(),
        &STANDARD.encode([7_u8; 32]),
        &STANDARD.encode([9_u8; 32]),
        &STANDARD.encode([11_u8; 32]),
    )
    .unwrap();

    assert_eq!(udp.local_listen, "127.0.0.1:51821".parse().unwrap());
    assert_eq!(tcp.local_listen, "127.0.0.1:51822".parse().unwrap());
    assert_eq!(tls.local_listen, "127.0.0.1:51823".parse().unwrap());
    assert_eq!(udp.server_address, "203.0.113.8:443".parse().unwrap());
    assert_eq!(tcp.server_address, "203.0.113.8:443".parse().unwrap());
    assert_eq!(tls.server_address, "203.0.113.8:443".parse().unwrap());
    assert_eq!(udp.socket_mark, None);
    assert_eq!(tcp.socket_mark, None);
    assert_eq!(tls.socket_mark, None);
}

#[tokio::test]
async fn automatic_executor_cleans_a_failed_attempt_before_fallback() {
    use std::sync::{Arc, Mutex};

    let profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    let selections = TransportEngine
        .plan(&profile, TransportPreference::Automatic)
        .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let attempt_events = events.clone();
    let cleanup_events = events.clone();

    let established = establish_automatic(
        selections,
        move |selection| {
            let events = attempt_events.clone();
            async move {
                events.lock().unwrap().push(("attempt", selection.kind));
                if selection.kind == TransportKind::DirectUdp {
                    AutomaticAttempt::Unavailable
                } else {
                    AutomaticAttempt::Connected("connected")
                }
            }
        },
        move |kind| {
            let events = cleanup_events.clone();
            async move {
                events.lock().unwrap().push(("cleanup", kind));
                Ok::<_, ()>(())
            }
        },
    )
    .await
    .unwrap();

    assert_eq!(established.selection.kind, TransportKind::ObfuscatedUdp);
    assert_eq!(established.value, "connected");
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            ("attempt", TransportKind::DirectUdp),
            ("cleanup", TransportKind::DirectUdp),
            ("attempt", TransportKind::ObfuscatedUdp),
        ]
    );
}

#[tokio::test]
async fn automatic_executor_stops_when_cleanup_cannot_be_proven() {
    let profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    let selections = TransportEngine
        .plan(&profile, TransportPreference::Automatic)
        .unwrap();
    let mut attempts = 0;

    let error = establish_automatic(
        selections,
        |_| {
            attempts += 1;
            async { AutomaticAttempt::<()>::Unavailable }
        },
        |_| async { Err::<(), _>("cleanup failed") },
    )
    .await
    .unwrap_err();

    assert_eq!(error, AutomaticConnectError::CleanupFailed);
    assert_eq!(attempts, 1);
}

#[tokio::test]
async fn automatic_executor_does_not_fallback_after_a_fatal_attempt() {
    let profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    let selections = TransportEngine
        .plan(&profile, TransportPreference::Automatic)
        .unwrap();
    let mut attempts = 0;
    let mut cleanups = 0;

    let error = establish_automatic(
        selections,
        |_| {
            attempts += 1;
            async { AutomaticAttempt::<()>::Abort("authorization was denied".to_owned()) }
        },
        |_| {
            cleanups += 1;
            async { Ok::<_, ()>(()) }
        },
    )
    .await
    .unwrap_err();

    assert_eq!(
        error,
        AutomaticConnectError::Aborted("authorization was denied".to_owned())
    );
    assert_eq!(attempts, 1);
    assert_eq!(cleanups, 1);
}

#[tokio::test]
async fn automatic_executor_restores_networking_after_every_unavailable_candidate() {
    let profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    let selections = TransportEngine
        .plan(&profile, TransportPreference::Automatic)
        .unwrap();
    let mut cleanups = Vec::new();

    let error = establish_automatic(
        selections,
        |_| async { AutomaticAttempt::<()>::Unavailable },
        |kind| {
            cleanups.push(kind);
            async { Ok::<_, ()>(()) }
        },
    )
    .await
    .unwrap_err();

    assert_eq!(error, AutomaticConnectError::Unavailable);
    assert_eq!(
        cleanups,
        vec![TransportKind::DirectUdp, TransportKind::ObfuscatedUdp]
    );
}

#[test]
fn obfuscated_engine_uses_the_public_relay_and_local_wireguard_endpoint() {
    let profile = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([9_u8; 32]),
    }));
    let selection = TransportEngine
        .select(&profile, TransportKind::ObfuscatedUdp)
        .unwrap();

    assert_eq!(selection.kind, TransportKind::ObfuscatedUdp);
    assert_eq!(selection.network_endpoint.host, "203.0.113.8");
    assert_eq!(selection.network_endpoint.wireguard_port, 443);
    assert_eq!(selection.wireguard_endpoint.host, "127.0.0.1");
    assert_eq!(
        selection.wireguard_endpoint.wireguard_port,
        CLIENT_RELAY_PORT
    );
    assert_eq!(selection.mtu, OBFUSCATED_UDP_MTU);
    assert!(selection.server_transport_public_key.is_some());
}

#[test]
fn obfuscated_engine_requires_a_valid_server_capability() {
    assert!(matches!(
        TransportEngine.select(&profile(None), TransportKind::ObfuscatedUdp),
        Err(TransportError::Unavailable)
    ));
    let invalid = profile(Some(ObfuscatedUdpEndpoint {
        port: 443,
        server_public_key: "invalid".to_owned(),
    }));
    assert!(matches!(
        TransportEngine.select(&invalid, TransportKind::ObfuscatedUdp),
        Err(TransportError::InvalidKey)
    ));
}

#[test]
fn direct_engine_rejects_an_unusable_endpoint() {
    let mut profile = profile(None);
    profile.endpoint.host = "vpn.example; reboot".to_owned();
    assert!(
        TransportEngine
            .select(&profile, TransportKind::DirectUdp)
            .is_err()
    );

    profile.endpoint.host = "vpn.example".to_owned();
    profile.endpoint.wireguard_port = 0;
    assert!(
        TransportEngine
            .select(&profile, TransportKind::DirectUdp)
            .is_err()
    );
}
