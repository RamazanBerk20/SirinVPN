use super::*;

fn current() -> CurrentConnection {
    CurrentConnection {
        state: ConnectionState::Connected,
        selected_server: true,
        another_server: false,
        recovering: false,
        waiting_for_user: false,
        protection: Protection::Armed,
        transport: Some(TransportKind::DirectUdp),
        split_routes: false,
        split_applications: false,
        ipv6_tunneled: false,
        ipv6_blocked: true,
        mtu: Some(MtuStatus {
            policy: MtuPolicy::Automatic,
            configured: 1420,
            suggested: Some(1320),
            outcome: MtuProbeOutcome::Measured,
        }),
        quality: None,
    }
}

#[test]
fn active_recovery_and_other_servers_cannot_trigger_remote_probes_or_claim_verified_mtu() {
    let mut state = current();
    assert!(state.can_probe());
    assert_eq!(
        local_checks(Some(&state))
            .iter()
            .find(|c| c.code == "local_mtu")
            .unwrap()
            .level,
        DiagnosticLevel::Warning
    );
    state.recovering = true;
    assert!(!state.can_probe());
    assert!(
        !local_checks(Some(&state))
            .iter()
            .any(|c| c.code == "local_mtu")
    );
    state.recovering = false;
    state.selected_server = false;
    state.another_server = true;
    assert!(!state.can_probe());
    assert!(
        !local_checks(Some(&state))
            .iter()
            .any(|c| c.code == "local_transport")
    );
    assert_eq!(local_checks(None)[0].level, DiagnosticLevel::Fail);
}

#[test]
fn authorization_errors_discard_server_text_and_tls_cause_requires_typed_evidence() {
    let error = ManagementError::RequestRejected {
        code: ErrorCode::AuthorizationFailed,
        message: "PRIVATE KEY password token recovery-secret".into(),
    };
    let output = management_failure(&error);
    assert!(output.message.contains("suspension"));
    assert!(!output.message.contains("PRIVATE KEY"));
    let io = std::io::Error::other(rustls::Error::InvalidCertificate(
        rustls::CertificateError::UnknownIssuer,
    ));
    assert!(contains_tls_failure(&io));
    assert!(contains_tls_failure(&std::io::Error::other(io)));
    assert!(!contains_tls_failure(&std::io::Error::other(
        "certificate failure untrusted free text"
    )));
}
