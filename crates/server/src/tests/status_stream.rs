use super::*;
use axum::body::Body;
use futures_util::StreamExt;

#[tokio::test]
async fn stream_delivers_repeated_authorized_samples_and_closes_on_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Stream owner").unwrap();
    initialize(
        &paths,
        "Stream test",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let authorization = Arc::new(RwLock::new(
        load_authorization(&paths.authorization).unwrap(),
    ));
    let state = AppState {
        recovery: Default::default(),
        measurement_ready: false,
        leak_test_ready: false,
        configuration: load_configuration(&paths).unwrap(),
        operational_configuration: None,
        paths,
        authorization: Some(authorization.clone()),
        redemption_failures: Arc::new(Mutex::new(HashMap::new())),
        live_metrics: Arc::new(Mutex::new(LiveMetricSampler::default())),
        transport_peers: AuthorizedPeers::default(),
        transport_activity: ActiveTransportRegistry::default(),
        speed_test: Default::default(),
        throttle: Default::default(),
    };
    let caller = CallerIdentity {
        certificate_fingerprint: certificate_fingerprint(&owner.public.management_certificate_pem)
            .unwrap(),
    };
    let denied = super::super::status_stream::status_stream_handler(
        State(state.clone()),
        Extension(CallerIdentity {
            certificate_fingerprint: "unknown".into(),
        }),
    )
    .await;
    assert!(matches!(
        denied,
        Err(ApiError {
            status: StatusCode::FORBIDDEN,
            ..
        })
    ));
    let response =
        super::super::status_stream::status_stream_handler(State(state), Extension(caller))
            .await
            .unwrap_or_else(|_| panic!("owner rejected"));
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut body = Body::into_data_stream(response.into_body());
    for _ in 0..2 {
        let bytes = tokio::time::timeout(Duration::from_secs(5), body.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("event: status"));
        assert!(text.contains("\"caller_role\":\"owner\""));
        assert!(text.contains("\"server_name\":\"Stream test\""));
    }
    authorization.write().await.devices.clear();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), body.next())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn every_reader_shares_one_host_sampler() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Feed owner").unwrap();
    initialize(
        &paths,
        "Feed test",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let configuration = load_configuration(&paths).unwrap();
    let feed = super::super::status_stream::StatusFeed::default();
    let mut readers: Vec<_> = (0..50).map(|_| feed.subscribe(&configuration)).collect();
    let mut samples = Vec::new();
    for reader in &mut readers {
        samples.push(
            reader
                .wait_for(Option::is_some)
                .await
                .unwrap()
                .clone()
                .unwrap(),
        );
    }
    // Fifty subscribers and a REST read cost one host reading, not fifty-one.
    let rest = feed.latest(&configuration).await;
    assert!(
        samples
            .iter()
            .all(|sample| Arc::ptr_eq(sample, &samples[0]))
    );
    assert!(Arc::ptr_eq(&rest, &samples[0]));
    assert_eq!(rest.status.server_name, "Feed test");
    // The task stops once nobody listens, and a later reader starts a fresh one.
    drop(readers);
    tokio::time::sleep(super::super::status_stream::STATUS_SAMPLE_INTERVAL * 3).await;
    let later = feed.latest(&configuration).await;
    assert!(!Arc::ptr_eq(&later, &rest));
}
