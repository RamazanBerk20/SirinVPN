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

#[test]
fn known_messages_carry_their_cause_and_a_vps_cannot_set_one() {
    let cause = |check: DiagnosticCheck| check.cause;
    assert_eq!(
        cause(management_failure(&ManagementError::ConnectionFailed)).as_deref(),
        Some("management_unreachable")
    );
    assert_eq!(
        cause(management_failure(&ManagementError::DiagnosticTlsFailed)).as_deref(),
        Some("management_clock")
    );
    assert_eq!(
        cause(management_failure(&ManagementError::RequestRejected {
            code: ErrorCode::PermissionDenied,
            message: String::new(),
        }))
        .as_deref(),
        Some("management_access_rejected")
    );
    assert_eq!(
        cause(management_failure(&ManagementError::ProtocolMismatch)),
        None
    );
    let mtu = |outcome, suggested| {
        mtu_check(Some(MtuStatus {
            policy: MtuPolicy::Automatic,
            configured: 1420,
            suggested,
            outcome,
        }))
    };
    assert_eq!(
        cause(mtu(MtuProbeOutcome::Pending, None)).as_deref(),
        Some("mtu_pending")
    );
    assert_eq!(
        cause(mtu(MtuProbeOutcome::Measured, None)).as_deref(),
        Some("mtu_pending")
    );
    assert_eq!(cause(mtu(MtuProbeOutcome::Measured, Some(1320))), None);
    assert_eq!(cause(mtu_check(None)).as_deref(), Some("not_measured"));
    let mut sent = check("interface", "x", DiagnosticLevel::Warning, text("x", "x"));
    sent.cause = Some("management_clock".into());
    sent.message_key = Some("protection_armed".into());
    let mut passed = check("forwarding", "x", DiagnosticLevel::Pass, text("x", "x"));
    passed.cause = Some("not_measured".into());
    let report = sanitize(report(vec![sent, passed]));
    assert_eq!(report.checks[0].cause.as_deref(), Some("not_measured"));
    assert_eq!(report.checks[1].cause, None);
    // Message keys, like causes, are the client's own: a VPS cannot pick which text is shown.
    assert_eq!(
        report.checks[0].message_key.as_deref(),
        Some("state_unreadable")
    );
    assert_eq!(
        report.checks[1].message_key.as_deref(),
        Some("forwarding_pass")
    );
    let json = serde_json::to_value(&report.checks[1]).unwrap();
    assert!(json.get("cause").is_none());
}

#[test]
fn every_local_message_has_a_key_and_its_values_fill_the_english_text() {
    let mut state = current();
    state.quality = Some(TransportQualitySample {
        transport: TransportKind::DirectUdp,
        probes_sent: 8,
        probes_received: 7,
        latency_micros: 27_400,
        jitter_micros: 1_200,
    });
    let checks = local_checks(Some(&state));
    assert!(checks.iter().all(|check| check.message_key.is_some()));
    let quality = checks.iter().find(|c| c.code == "local_quality").unwrap();
    assert!(
        quality
            .message
            .starts_with("7 of 8 probes returned; average latency 27 ms")
    );
    assert_eq!(quality.message_params["latency"], "27");
    let mtu = checks.iter().find(|c| c.code == "local_mtu").unwrap();
    assert_eq!(mtu.message_key.as_deref(), Some("mtu_smaller"));
    assert!(
        mtu.message
            .starts_with("Automatic MTU: 1420 bytes. The path supports")
    );
    assert_eq!(mtu.message_params["policy"], "automatic");
    assert_eq!(mtu.message_params["size"], "1420");
    assert!(!mtu.message.contains('{'));
}
