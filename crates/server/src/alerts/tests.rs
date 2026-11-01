use super::*;
use std::sync::OnceLock;
use tokio::io::AsyncReadExt;

const MINUTE: u64 = 60;

fn problems(values: &[Problem]) -> BTreeSet<Problem> {
    values.iter().copied().collect()
}

/// Runs one check at `now` and records a successful delivery.
fn tick(state: &mut AlertState, current: &[Problem], now: u64) -> Option<Notice> {
    let notice = due(state, &problems(current), now)?;
    delivered(state, &notice, now);
    Some(notice)
}

#[test]
fn a_problem_is_sent_once_after_it_persists_and_its_recovery_once_after_it_clears() {
    let mut state = AlertState::default();
    let disk = [Problem::DiskNearlyFull];
    assert_eq!(tick(&mut state, &disk, 0), None);
    assert_eq!(
        tick(&mut state, &disk, 5 * MINUTE),
        Some(Notice {
            problems: disk.to_vec(),
            resolved: Vec::new()
        })
    );
    for check in 2..20 {
        assert_eq!(tick(&mut state, &disk, check * 5 * MINUTE), None);
    }
    assert_eq!(
        tick(&mut state, &[], 100 * MINUTE),
        Some(Notice {
            problems: Vec::new(),
            resolved: disk.to_vec()
        })
    );
    assert_eq!(tick(&mut state, &[], 105 * MINUTE), None);
    assert!(state.notified.is_empty() && state.first_seen.is_empty());
}

#[test]
fn a_problem_seen_in_only_one_check_is_never_sent() {
    let mut state = AlertState::default();
    for check in 0..10 {
        let current: &[Problem] = if check % 2 == 0 {
            &[Problem::ServiceDown]
        } else {
            &[]
        };
        assert_eq!(tick(&mut state, current, check * 5 * MINUTE), None);
    }
}

#[test]
fn notices_are_spaced_and_capped_and_only_the_net_change_is_sent() {
    let mut state = AlertState::default();
    tick(&mut state, &[Problem::DiskNearlyFull], 0);
    assert!(tick(&mut state, &[Problem::DiskNearlyFull], 5 * MINUTE).is_some());
    let both = [Problem::DiskNearlyFull, Problem::ServiceDown];
    assert_eq!(tick(&mut state, &both, 10 * MINUTE), None);
    // Confirmed but held: the previous notice was ten minutes ago.
    assert_eq!(tick(&mut state, &both, 15 * MINUTE), None);
    assert_eq!(
        tick(&mut state, &both, 20 * MINUTE),
        Some(Notice {
            problems: vec![Problem::ServiceDown],
            resolved: Vec::new()
        })
    );
    // Cleared and back again while the limit holds: the receiver hears nothing.
    tick(&mut state, &[Problem::DiskNearlyFull], 25 * MINUTE);
    assert_eq!(tick(&mut state, &both, 30 * MINUTE), None);
    assert_eq!(tick(&mut state, &both, 40 * MINUTE), None);

    // A flapping service reaches the daily cap and then waits for the oldest notice to age out.
    let mut state = AlertState::default();
    let mut sent = Vec::new();
    for check in 0..(2 * DAY_SECONDS / (5 * MINUTE)) {
        let now = check * 5 * MINUTE;
        let current: &[Problem] = if (check / 2) % 2 == 0 {
            &[Problem::ServiceDown]
        } else {
            &[]
        };
        if tick(&mut state, current, now).is_some() {
            sent.push(now);
        }
    }
    assert!(
        sent.windows(2)
            .all(|pair| pair[1] - pair[0] >= MIN_SECONDS_BETWEEN_ALERTS)
    );
    for (index, time) in sent.iter().enumerate() {
        let window = sent[index..]
            .iter()
            .take_while(|later| **later - time < DAY_SECONDS)
            .count();
        assert!(window <= MAX_ALERTS_PER_DAY);
    }
    assert_eq!(
        sent.iter().filter(|time| **time < DAY_SECONDS).count(),
        MAX_ALERTS_PER_DAY
    );
}

#[test]
fn a_pending_restart_waits_three_days_and_a_failed_delivery_is_retried() {
    let mut state = AlertState::default();
    let restart = [Problem::RestartPending];
    assert_eq!(tick(&mut state, &restart, 0), None);
    assert_eq!(
        tick(&mut state, &restart, RESTART_PENDING_SECONDS - 1),
        None
    );
    let current = problems(&restart);
    let notice = due(&mut state, &current, RESTART_PENDING_SECONDS).unwrap();
    // Not delivered: the next check offers the same notice again.
    assert_eq!(
        due(&mut state, &current, RESTART_PENDING_SECONDS + 5 * MINUTE),
        Some(notice)
    );
}

#[test]
fn stopped_units_and_restart_loops_are_read_from_systemctl_show() {
    let units = ["sirinvpn-server.service", "unbound.service"];
    let show = |server: &str, restarts: u64| {
        format!("ActiveState={server}\nNRestarts={restarts}\n\nNRestarts=0\nActiveState=active\n")
    };
    let (found, counters) = service_problems(&show("active", 7), &units, &BTreeMap::new());
    assert!(found.is_empty(), "a first reading is not a loop");
    assert_eq!(counters["sirinvpn-server.service"], 7);
    let (found, _) = service_problems(&show("activating", 9), &units, &counters);
    assert!(found.is_empty(), "two restarts are not a loop");
    let (found, _) = service_problems(&show("activating", 10), &units, &counters);
    assert_eq!(found, problems(&[Problem::ServiceRestarting]));
    let (found, _) = service_problems(&show("failed", 0), &units, &counters);
    assert_eq!(found, problems(&[Problem::ServiceDown]));
    let (found, counters) = service_problems("", &units, &counters);
    assert!(
        found.is_empty() && counters.is_empty(),
        "unreadable is not down"
    );
}

#[test]
fn notice_text_is_fixed() {
    let text = message(&Notice {
        problems: vec![Problem::DiskNearlyFull, Problem::ServiceDown],
        resolved: vec![Problem::DnsFailing],
    });
    assert_eq!(text.title, "SirinVPN: your VPS needs attention");
    assert_eq!(
        text.body,
        "The VPS disk is over 90% full.\nA SirinVPN service on the VPS has stopped.\nResolved: Private DNS."
    );
    let recovered = message(&Notice {
        problems: Vec::new(),
        resolved: vec![Problem::RestartPending],
    });
    assert_eq!(recovered.title, "SirinVPN: VPS problem resolved");
    assert_eq!(recovered.body, "Resolved: Pending restart.");
}

#[tokio::test]
async fn private_and_loopback_targets_are_refused_unless_allowed() {
    for url in [
        "https://127.0.0.1/topic",
        "https://[::1]:8443/topic",
        "https://10.77.0.5/topic",
        "https://localhost/topic",
    ] {
        let parsed = reqwest::Url::parse(url).unwrap();
        assert_eq!(
            checked_addresses(&parsed, false).await,
            Err(AlertFailure::Address),
            "{url}"
        );
        assert!(checked_addresses(&parsed, true).await.is_ok(), "{url}");
    }
    let public = reqwest::Url::parse("https://9.9.9.9:8443/topic").unwrap();
    assert_eq!(
        checked_addresses(&public, false).await,
        Ok(vec!["9.9.9.9:8443".parse().unwrap()])
    );
    // Refused before any connection is attempted.
    let (port, receiver) = receiver(200).await;
    assert_eq!(
        send(&format!("https://127.0.0.1:{port}/topic"), false, None).await,
        Err((AlertFailure::Address, None))
    );
    receiver.abort();
}

fn server_configuration() -> Arc<ServerConfig> {
    static CONFIGURATION: OnceLock<Arc<ServerConfig>> = OnceLock::new();
    CONFIGURATION
        .get_or_init(|| {
            let authority_key = KeyPair::generate().unwrap();
            let mut authority = CertificateParams::new(Vec::<String>::new()).unwrap();
            authority.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let authority = authority.self_signed(&authority_key).unwrap();
            let key = KeyPair::generate().unwrap();
            let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
                .unwrap()
                .signed_by(&key, &authority, &authority_key)
                .unwrap();
            *TEST_ROOT.lock().unwrap() = Some(authority.pem().into_bytes());
            Arc::new(
                ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone()],
                    PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                )
                .unwrap(),
            )
        })
        .clone()
}

/// A one-request HTTPS receiver on loopback that answers `status` and returns the request.
async fn receiver(status: u16) -> (u16, tokio::task::JoinHandle<String>) {
    let acceptor = TlsAcceptor::from(server_configuration());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map_or(0, |value| value.trim().parse::<usize>().unwrap());
                if body.len() >= length {
                    break;
                }
            }
            assert!(read > 0, "the request ended early");
        }
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status} Status\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let _ = stream.shutdown().await;
        String::from_utf8(request).unwrap()
    });
    (port, task)
}

#[tokio::test]
async fn ntfy_webhook_and_heartbeat_requests_carry_only_the_fixed_notice() {
    let notice = message(&Notice {
        problems: vec![Problem::SecurityUpdatesOff],
        resolved: Vec::new(),
    });
    let (port, receiver_task) = receiver(200).await;
    let url = format!("https://127.0.0.1:{port}/sirinvpn-topic");
    assert_eq!(
        send(&url, true, Some((&notice, AlertFormat::Ntfy))).await,
        Ok(())
    );
    let request = receiver_task.await.unwrap();
    let lower = request.to_ascii_lowercase();
    assert!(lower.starts_with("post /sirinvpn-topic http/1.1\r\n"));
    assert!(lower.contains("\r\ntitle: sirinvpn: your vps needs attention\r\n"));
    assert!(lower.contains("\r\ntags: warning\r\n"));
    assert!(request.ends_with(
        "\r\n\r\nAutomatic security updates on the VPS are off or could not be confirmed."
    ));

    let (port, receiver_task) = receiver(200).await;
    let url = format!("https://127.0.0.1:{port}/hook?token=x");
    assert_eq!(
        send(&url, true, Some((&test_message(), AlertFormat::Webhook))).await,
        Ok(())
    );
    let request = receiver_task.await.unwrap();
    assert!(request.starts_with("POST /hook?token=x HTTP/1.1\r\n"));
    let body: serde_json::Value =
        serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "event": "test",
            "title": "SirinVPN test alert",
            "message": "This test alert came from your SirinVPN VPS. Alerts reach this address.",
            "text": "SirinVPN test alert\nThis test alert came from your SirinVPN VPS. Alerts reach this address.",
            "problems": [],
            "resolved": [],
        })
    );

    let (port, receiver_task) = receiver(200).await;
    assert_eq!(
        send(&format!("https://127.0.0.1:{port}/ping/abc"), true, None).await,
        Ok(())
    );
    assert!(
        receiver_task
            .await
            .unwrap()
            .starts_with("GET /ping/abc HTTP/1.1\r\n")
    );

    let (port, receiver_task) = receiver(403).await;
    assert_eq!(
        send(&format!("https://127.0.0.1:{port}/topic"), true, None).await,
        Err((AlertFailure::Rejected, Some(403)))
    );
    receiver_task.await.unwrap();
}

#[tokio::test]
async fn the_timer_task_records_heartbeats_and_forgets_everything_when_alerts_are_off() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = sirinvpn_core::LocalIdentity::generate("Alert owner").unwrap();
    initialize(
        &paths,
        "Alerts",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51820,
    )
    .unwrap();
    let state_directory = tempfile::tempdir().unwrap();
    let (port, receiver_task) = receiver(200).await;
    let mut document = load_authorization(&paths.authorization).unwrap();
    document.alerts = AlertPolicy {
        heartbeat_url: Some(format!("https://127.0.0.1:{port}/ping")),
        allow_private_addresses: true,
        ..Default::default()
    };
    write_authorization(&paths.authorization, &document).unwrap();
    let stale = AlertState {
        notified: problems(&[Problem::DiskNearlyFull]),
        sent: vec![unix_time()],
        ..Default::default()
    };
    write_state(state_directory.path(), &stale).unwrap();

    check(&paths, state_directory.path()).await.unwrap();
    receiver_task.await.unwrap();
    let state = read_state(state_directory.path());
    // Problems told to another address are forgotten; the rate limit is kept.
    assert!(state.notified.is_empty());
    assert_eq!(state.sent, stale.sent);
    assert!(state.status.heartbeat_sent_at_unix.is_some());
    assert_eq!(state.status.heartbeat_failure, None);
    assert_eq!(
        state.status.policy_sha256,
        Some(fingerprint(&document.alerts))
    );

    document.alerts = AlertPolicy::default();
    write_authorization(&paths.authorization, &document).unwrap();
    check(&paths, state_directory.path()).await.unwrap();
    assert!(!state_directory.path().join(STATE_FILE).exists());
}
