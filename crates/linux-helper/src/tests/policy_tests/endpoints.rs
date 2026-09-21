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
        _: IpAddr,
    ) -> Result<Option<EndpointTransitionResponse>> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        Ok(self.response.lock().unwrap().clone())
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
