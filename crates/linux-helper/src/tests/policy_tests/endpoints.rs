use super::*;
use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey};
use sirinvpn_protocol::{
    EndpointDescriptor, EndpointIdentity, EndpointTransitionClaims, EndpointTransitionResponse,
    ServerEndpoint, TcpFallbackEndpoint, TlsLikeEndpoint,
};
use std::sync::atomic::AtomicUsize;

#[derive(Clone, Default)]
struct EndpointRunner {
    policy: PolicyRunner,
    response: Arc<Mutex<Option<EndpointTransitionResponse>>>,
    queries: Arc<AtomicUsize>,
    sources: Arc<Mutex<Vec<IpAddr>>>,
}
impl CommandRunner for EndpointRunner {
    fn run(&self, p: &str, a: &[&str], input: Option<&[u8]>) -> Result<()> {
        self.policy.run(p, a, input)
    }
    fn output(&self, p: &str, a: &[&str]) -> Result<Vec<u8>> {
        self.policy.output(p, a)
    }
    fn endpoint_checkpoint(
        &self,
        _: &EndpointIdentity,
        _: &str,
        source: IpAddr,
    ) -> Result<Option<EndpointTransitionResponse>> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        self.sources.lock().unwrap().push(source);
        Ok(self.response.lock().unwrap().clone())
    }
    fn endpoint_addresses(&self, host: &str, _: &[SocketAddr]) -> Vec<IpAddr> {
        if host == CDN_HOST {
            return vec![CDN_ADDRESS.parse().unwrap()];
        }
        host.parse().ok().into_iter().collect()
    }
}

const CDN_HOST: &str = "cdn.example.org";
const CDN_ADDRESS: &str = "192.0.2.80";

/// HTTPS through a CDN first, then Direct UDP to the VPS.
fn cdn_fixture() -> TunnelConnectRequest {
    let (mut base, _) = fixture(true);
    let descriptor = &mut base.endpoint_identity.as_mut().unwrap().descriptor;
    descriptor.tls_like.as_mut().unwrap().https = Some(sirinvpn_protocol::HttpsTransport {
        server_name: CDN_HOST.into(),
        path: "/connect".into(),
        cdn: true,
    });
    let selections = [TransportKind::TlsLike, TransportKind::DirectUdp].map(|kind| {
        let mut selection = sirinvpn_transport::TransportEngine
            .select_descriptor(descriptor, kind)
            .unwrap();
        selection.mtu = 1280;
        selection
    });
    base.reconnect_candidates = policy_transport_candidates(&selections);
    let mut request = request_for_reconnect_candidate(&base, &base.reconnect_candidates[0]);
    request.reconnect_candidates = base.reconnect_candidates.clone();
    request
}

#[test]
fn https_through_a_cdn_reaches_only_its_resolved_address_and_discovery_follows_it() {
    let request = cdn_fixture();
    validate_request(&request).unwrap();
    let cdn: IpAddr = CDN_ADDRESS.parse().unwrap();
    for invalid in ["127.0.0.1", "0.0.0.0", "ff02::1"] {
        let mut tampered = request.clone();
        tampered.cdn_address = Some(invalid.parse().unwrap());
        assert!(validate_request(&tampered).is_err(), "{invalid}");
    }
    // A CDN address needs a signed CDN name, and CDN mode needs signed endpoint state.
    let (mut plain, _) = fixture(true);
    plain.cdn_address = Some(cdn);
    assert!(validate_request(&plain).is_err());
    let mut unsigned = request.clone();
    unsigned.reconnect_candidates.clear();
    unsigned.endpoint_identity = None;
    unsigned.schema_version = 9;
    unsigned.https.as_mut().unwrap().cdn = false;
    validate_request(&unsigned).unwrap();
    unsigned.https.as_mut().unwrap().cdn = true;
    assert!(validate_request(&unsigned).is_err());

    let directory = tempfile::tempdir().unwrap();
    let runner = EndpointRunner {
        policy: runner(),
        ..Default::default()
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().into());
    // The helper resolves the signed name itself and replaces any app-supplied address.
    let mut sent = request.clone();
    sent.cdn_address = Some("192.0.2.66".parse().unwrap());
    helper.connect(&sent).unwrap();
    let mut desired = helper.read_persistent().unwrap();
    assert_eq!(desired.request.cdn_address, Some(cdn));
    let vps = desired.endpoint;
    assert_ne!(vps, cdn);
    let carrier = fs::read_to_string(helper.carrier_config_path(TransportKind::TlsLike)).unwrap();
    assert!(carrier.contains(&format!("\"server_address\":\"{cdn}:443\"")));

    // Only marked carrier sockets may reach the CDN, and only on the HTTPS port.
    let guard = runner.policy.guard.lock().unwrap().clone().unwrap();
    let cdn_rules = guard
        .iter()
        .map(|object| object.to_string())
        .filter(|rule| rule.contains(&format!("\"{cdn}\"")))
        .collect::<Vec<_>>();
    assert_eq!(cdn_rules.len(), 1, "{cdn_rules:?}");
    for expected in ["\"mark\"", "51820", "\"tcp\"", "\"dport\"", "443"] {
        assert!(cdn_rules[0].contains(expected), "{}", cdn_rules[0]);
    }
    assert!(guard.iter().any(|object| {
        let rule = object.to_string();
        rule.contains(&format!("\"{vps}\"")) && rule.contains("51820") && rule.contains("\"udp\"")
    }));
    let mut unresolved = desired.request.clone();
    unresolved.cdn_address = None;
    assert!(
        !serde_json::to_string(&guard_objects(&unresolved, vps))
            .unwrap()
            .contains(CDN_ADDRESS)
    );
    assert!(unresolved.outer_address(vps).is_none());

    let mut state = helper.read_state().unwrap();
    for (transport, source) in [
        (TransportKind::TlsLike, cdn),
        (TransportKind::DirectUdp, vps),
    ] {
        state.transport = transport;
        state.endpoint_monitor = Some(crate::endpoints::EndpointMonitor::default());
        helper
            .inspect_endpoint_checkpoint(&mut desired, &mut state, true)
            .unwrap();
        assert_eq!(runner.sources.lock().unwrap().last(), Some(&source));
    }
}

fn fixture(reconnect: bool) -> (TunnelConnectRequest, EndpointTransitionResponse) {
    let identity = sirinvpn_core::LocalIdentity::generate("Endpoint test").unwrap();
    let mut request = independent(true, reconnect, false);
    request.schema_version = 10;
    request.mtu_policy = Some(sirinvpn_protocol::MtuPolicy::Manual { value: 1280 });
    request.mtu = 1280;
    request.server_public_key = identity.public.wireguard_public_key.clone();
    let descriptor = EndpointDescriptor {
        endpoint: ServerEndpoint {
            host: request.endpoint_host.clone(),
            wireguard_port: request.endpoint_port,
        },
        alternate_endpoint_hosts: vec!["203.0.113.9".into()],
        endpoint_discovery_port: Some(443),
        ipv6_tunnel_enabled: false,
        obfuscated_udp: None,
        tcp_fallback: Some(TcpFallbackEndpoint {
            port: 443,
            server_public_key: STANDARD.encode([17_u8; 32]),
        }),
        tls_like: Some(TlsLikeEndpoint {
            port: 443,
            server_public_key: STANDARD.encode([17_u8; 32]),
            certificate_sha256: STANDARD.encode([18_u8; 32]),
            https: None,
        }),
    };
    request.endpoint_identity = Some(EndpointIdentity {
        server_id: request.server_id,
        server_wireguard_public_key: request.server_public_key.clone(),
        pinned_server_certificate_pem: identity.public.management_certificate_pem.clone(),
        generation: 1,
        descriptor: descriptor.clone(),
    });
    let claims = EndpointTransitionClaims {
        schema_version: 2,
        server_id: request.server_id,
        generation: 8,
        server_name: "Endpoint test".into(),
        previous_endpoint: descriptor.endpoint.clone(),
        previous_transports: Some(descriptor.clone()),
        endpoint: ServerEndpoint {
            host: "2001:db8::8".into(),
            wireguard_port: 51821,
        },
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: Some(443),
        server_tunnel_address: "10.77.0.1".parse().unwrap(),
        management_port: 8443,
        server_wireguard_public_key: identity.public.wireguard_public_key,
        pinned_server_certificate_pem: identity.public.management_certificate_pem,
        authorization_fingerprint: "01".repeat(32),
        ipv6_tunnel_enabled: false,
        obfuscated_udp: None,
        tcp_fallback: descriptor.tcp_fallback,
        tls_like: descriptor.tls_like,
    };
    let key = SigningKey::from_pkcs8_pem(&identity.secret.management_private_key_pem).unwrap();
    let signature = STANDARD.encode(key.sign(&serde_json::to_vec(&claims).unwrap()).to_bytes());
    (request, EndpointTransitionResponse { claims, signature })
}

#[test]
fn signed_catchup_preserves_policy_keys_routing_and_manual_mtu_before_ipv6_handoff() {
    let directory = tempfile::tempdir().unwrap();
    let runner = EndpointRunner {
        policy: runner(),
        ..Default::default()
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().into());
    let (request, response) = fixture(true);
    helper.connect(&request).unwrap();
    let mut desired = helper.read_persistent().unwrap();
    let mut state = helper.read_state().unwrap();
    state.endpoint_monitor = Some(crate::endpoints::EndpointMonitor::default());
    *runner.response.lock().unwrap() = Some(response.clone());
    assert_eq!(
        helper
            .inspect_endpoint_checkpoint(&mut desired, &mut state, false)
            .unwrap(),
        Some(ReconcileOutcome::AwaitingHandshake)
    );
    let updated = helper.read_persistent().unwrap();
    assert_eq!(updated.endpoint, "2001:db8::8".parse::<IpAddr>().unwrap());
    assert_eq!(updated.request.endpoint_port, 51821);
    assert_eq!(updated.request.private_key, request.private_key);
    assert_eq!(updated.request.policy, request.policy);
    assert_eq!(updated.request.routing, request.routing);
    assert_eq!(updated.request.mtu_policy, request.mtu_policy);
    assert_eq!(updated.request.mtu, 1280);
    assert_eq!(
        updated
            .request
            .endpoint_identity
            .as_ref()
            .unwrap()
            .generation,
        8
    );
    assert_eq!(
        helper
            .read_state()
            .unwrap()
            .endpoint_monitor
            .unwrap()
            .accepted,
        Some(response)
    );
    assert!(helper.guard_is_verified(&updated.request, updated.endpoint));
    assert!(
        !runner
            .policy
            .base
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(p, a, _)| p == "nft" && a == &["delete", "table", "inet", "sirinvpn_guard"])
    );
}

#[test]
fn paused_or_recovery_disabled_sessions_make_no_endpoint_probe() {
    for paused in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let runner = EndpointRunner {
            policy: runner(),
            ..Default::default()
        };
        let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().into());
        let (request, response) = fixture(paused);
        helper.connect(&request).unwrap();
        let mut desired = helper.read_persistent().unwrap();
        let mut state = helper.read_state().unwrap();
        state.has_connected = true;
        state.waiting_for_user = paused;
        state.endpoint_monitor = Some(crate::endpoints::EndpointMonitor::default());
        *runner.response.lock().unwrap() = Some(response);
        let before = runner.queries.load(Ordering::SeqCst);
        assert!(
            helper
                .inspect_endpoint_checkpoint(&mut desired, &mut state, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(runner.queries.load(Ordering::SeqCst), before);
        assert_eq!(
            helper.read_persistent().unwrap().request.endpoint_host,
            request.endpoint_host
        );
    }
}

#[test]
fn a_failed_guard_transaction_keeps_the_working_endpoint_and_rejects_tampered_updates() {
    let directory = tempfile::tempdir().unwrap();
    let runner = EndpointRunner {
        policy: runner(),
        ..Default::default()
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().into());
    let (request, response) = fixture(true);
    helper.connect(&request).unwrap();
    let mut desired = helper.read_persistent().unwrap();
    let mut state = helper.read_state().unwrap();
    state.endpoint_monitor = Some(crate::endpoints::EndpointMonitor::default());
    let mut tampered = response.clone();
    tampered.claims.endpoint.wireguard_port = 60000;
    *runner.response.lock().unwrap() = Some(tampered);
    assert!(
        helper
            .inspect_endpoint_checkpoint(&mut desired, &mut state, false)
            .unwrap()
            .is_none()
    );
    state.endpoint_monitor = Some(crate::endpoints::EndpointMonitor::default());
    *runner.response.lock().unwrap() = Some(response);
    runner
        .policy
        .transaction_failed
        .store(true, Ordering::SeqCst);
    assert!(
        helper
            .inspect_endpoint_checkpoint(&mut desired, &mut state, false)
            .is_err()
    );
    assert_eq!(
        helper.read_persistent().unwrap().request.endpoint_host,
        request.endpoint_host
    );
    assert!(runner.policy.base.interface_exists.load(Ordering::SeqCst));
    assert!(helper.guard_is_verified(&request, desired.endpoint));
}

#[test]
fn alternate_addresses_cycle_without_replacing_transport_kinds_or_extending_recovery_permission() {
    let directory = tempfile::tempdir().unwrap();
    let runner = EndpointRunner {
        policy: runner(),
        ..Default::default()
    };
    let helper = LinuxNetworkHelper::new(runner, directory.path().into());
    let (mut request, _) = fixture(false);
    request
        .endpoint_identity
        .as_mut()
        .unwrap()
        .descriptor
        .alternate_endpoint_hosts
        .push("203.0.113.10".into());
    helper.connect(&request).unwrap();
    let mut desired = helper.read_persistent().unwrap();
    let mut state = helper.read_state().unwrap();
    state.initial_attempts = 1;
    let first = desired.endpoint;
    helper.next_endpoint(&mut desired, &state).unwrap();
    assert_eq!(desired.endpoint, "203.0.113.9".parse::<IpAddr>().unwrap());
    for _ in 0..5 {
        state.initial_attempts = 255;
        helper.next_endpoint(&mut desired, &state).unwrap();
        assert_eq!(desired.endpoint, "203.0.113.10".parse::<IpAddr>().unwrap());
        helper.next_endpoint(&mut desired, &state).unwrap();
        assert_eq!(desired.endpoint, first);
        helper.next_endpoint(&mut desired, &state).unwrap();
        assert_eq!(desired.endpoint, "203.0.113.9".parse::<IpAddr>().unwrap());
    }
    assert!(!desired.request.connection_policy().automatic_reconnect);
    assert_eq!(desired.request.transport, request.transport);
}

#[test]
fn manually_updating_a_paused_endpoint_keeps_it_paused_with_its_existing_protection() {
    for kill in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let runner = EndpointRunner {
            policy: runner(),
            ..Default::default()
        };
        let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().into());
        let (mut request, response) = fixture(false);
        request.policy.as_mut().unwrap().kill_switch = kill;
        helper.connect(&request).unwrap();
        helper.pause_session(request.server_id).unwrap();
        let updated = helper.apply_endpoint_checkpoint(&response).unwrap();
        assert!(updated.waiting_for_user);
        assert_eq!(updated.policy, request.policy);
        assert!(!runner.policy.base.interface_exists.load(Ordering::SeqCst));
        let desired = helper.read_persistent().unwrap();
        assert_eq!(desired.endpoint, "2001:db8::8".parse::<IpAddr>().unwrap());
        assert_eq!(desired.request.mtu_policy, request.mtu_policy);
        if kill {
            assert!(helper.guard_is_verified(&desired.request, desired.endpoint));
        } else {
            assert!(helper.guard_is_absent().unwrap());
        }
    }
}
