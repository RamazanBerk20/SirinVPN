use super::*;

mod crash;

struct Model {
    authority: AuthorizationDocument,
    kernel: Vec<AuthorizationDocument>,
    published: AuthorizationDocument,
    contained: bool,
    faults: VecDeque<(Stage, bool)>,
    stages: Vec<Stage>,
    configuration: ServerConfiguration,
}
struct Fake(Mutex<Model>);
impl Effects for Fake {
    fn intent(&self, _: &AuthorizationDocument, _: &AuthorizationDocument, _: u64) -> Result<()> {
        Ok(())
    }
    fn authority(&self) -> Result<AuthorizationDocument> {
        Ok(self.0.lock().unwrap().authority.clone())
    }
    fn footprint(&self, document: &AuthorizationDocument) -> Result<Footprint> {
        footprint(&self.0.lock().unwrap().configuration, None, document)
    }
    async fn execute(&self, stage: Stage, document: &AuthorizationDocument) -> Result<()> {
        let mut model = self.0.lock().unwrap();
        model.stages.push(stage);
        let fault = model
            .faults
            .front()
            .copied()
            .filter(|(expected, _)| *expected == stage);
        if fault.is_some() {
            model.faults.pop_front();
        }
        if fault == Some((stage, false)) {
            bail!("fixture before effect");
        }
        match stage {
            Stage::Contain => model.contained = true,
            Stage::Quarantine => model.kernel[0] = document.clone(),
            Stage::Wireguard => model.kernel[1] = document.clone(),
            Stage::Isolation => model.kernel[2] = document.clone(),
            Stage::Forwarding => model.kernel[3] = document.clone(),
            Stage::Persist => model.authority = document.clone(),
            Stage::Transport | Stage::Checkpoint => model.published = document.clone(),
            Stage::Complete => model.contained = false,
        }
        if fault.is_some() {
            bail!("fixture after partial effect");
        }
        Ok(())
    }
}
fn fixture() -> (
    AuthorizationDocument,
    AuthorizationDocument,
    Fake,
    Mutex<RecoveryState>,
) {
    let dir = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(dir.path());
    let owner = sirinvpn_core::LocalIdentity::generate("fixture").unwrap();
    initialize(
        &paths,
        "fixture",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51820,
    )
    .unwrap();
    let a = load_authorization(&paths.authorization).unwrap();
    let mut b = a.clone();
    b.devices[0].peer_communication_enabled = !b.devices[0].peer_communication_enabled;
    let io = Fake(Mutex::new(Model {
        authority: a.clone(),
        kernel: vec![a.clone(); 4],
        published: a.clone(),
        contained: false,
        faults: VecDeque::new(),
        stages: vec![],
        configuration: load_configuration(&paths).unwrap(),
    }));
    (a, b, io, Mutex::default())
}

#[tokio::test]
async fn every_stage_failure_is_truthful_and_recoverable() {
    for stage in [
        Stage::Contain,
        Stage::Quarantine,
        Stage::Wireguard,
        Stage::Isolation,
        Stage::Forwarding,
        Stage::Persist,
        Stage::Transport,
        Stage::Checkpoint,
        Stage::Complete,
    ] {
        for partial in [false, true] {
            let (mut a, b, io, state) = fixture();
            io.0.lock().unwrap().faults.push_back((stage, partial));
            assert!(commit(&io, &state, &mut a, b).await.is_err(), "{stage:?}");
            recover(&io, &state, &mut a).await.unwrap();
            let model = io.0.lock().unwrap();
            assert!(
                model
                    .kernel
                    .iter()
                    .all(|document| document == &model.authority)
            );
            assert_eq!(model.published, model.authority);
            assert_eq!(a, model.authority);
            assert!(!model.contained);
            assert!(!needs_recovery(&state));
        }
    }
}

#[tokio::test]
async fn warm_cache_and_unchanged_peer_vector_cannot_hide_failed_rollback() {
    let (mut a, b, io, state) = fixture();
    let old = a.clone();
    commit(&io, &state, &mut a, old.clone()).await.unwrap();
    let cached = a.desired_peers(unix_time());
    assert_eq!(cached, b.desired_peers(unix_time()));
    io.0.lock().unwrap().faults.extend([
        (Stage::Forwarding, true),
        (Stage::Wireguard, false),
        (Stage::Isolation, false),
    ]);
    assert!(commit(&io, &state, &mut a, b.clone()).await.is_err());
    assert_eq!(cached, a.desired_peers(unix_time()));
    assert!(needs_recovery(&state));
    {
        let model = io.0.lock().unwrap();
        assert_eq!(model.authority, old);
        assert_eq!(model.kernel[1], b);
        assert!(model.contained);
        assert_eq!(model.stages.last(), Some(&Stage::Checkpoint));
    }
    assert!(commit(&io, &state, &mut a, b).await.is_err());
    recover(&io, &state, &mut a).await.unwrap();
    assert!(
        io.0.lock()
            .unwrap()
            .kernel
            .iter()
            .all(|document| document == &old)
    );
    assert!(!needs_recovery(&state));
}

#[tokio::test]
async fn failed_rollback_stages_do_not_prevent_remaining_restoration() {
    for failed in [
        Stage::Quarantine,
        Stage::Wireguard,
        Stage::Isolation,
        Stage::Forwarding,
        Stage::Transport,
        Stage::Checkpoint,
    ] {
        let (mut a, b, io, state) = fixture();
        io.0.lock()
            .unwrap()
            .faults
            .extend([(Stage::Forwarding, true), (failed, false)]);
        assert!(commit(&io, &state, &mut a, b).await.is_err());
        let model = io.0.lock().unwrap();
        assert!(model.contained);
        assert_eq!(model.stages.last(), Some(&Stage::Checkpoint));
        assert!(needs_recovery(&state));
    }
}

#[tokio::test]
async fn post_rename_failure_never_restores_old_authority() {
    let (mut a, b, io, state) = fixture();
    io.0.lock()
        .unwrap()
        .faults
        .push_back((Stage::Persist, true));
    let error = commit(&io, &state, &mut a, b.clone()).await.unwrap_err();
    assert!(error.message.contains("was committed"));
    assert_eq!(a, b);
    assert_eq!(io.0.lock().unwrap().authority, b);
    // The error reports the commit; once recovery enforced it, the state is plainly Healthy
    // instead of carrying a stale in-flight `committed` flag.
    assert!(!needs_recovery(&state));
    assert!(!status(&state).committed);
}

fn contained(io: &Fake) -> usize {
    let mut model = io.0.lock().unwrap();
    let count = model
        .stages
        .iter()
        .filter(|stage| **stage == Stage::Contain)
        .count();
    model.stages.clear();
    count
}

#[tokio::test]
async fn a_handler_commit_is_not_applied_again_by_the_periodic_loop() {
    let (mut a, b, io, state) = fixture();
    commit(&io, &state, &mut a, b.clone()).await.unwrap();
    assert_eq!(contained(&io), 1);
    // The loop's tick: the same document and peers are already enforced.
    let mut next = a.clone();
    next.prune_expired(unix_time());
    assert!(is_applied(&io, &state, &a, &next));
    commit(&io, &state, &mut a, next).await.unwrap();
    assert!(io.0.lock().unwrap().stages.is_empty());
    assert_eq!(status(&state).generation, 1);
}

#[tokio::test]
async fn only_changes_that_remove_access_contain_traffic() {
    let (mut a, _, io, state) = fixture();
    let mut isolated = a.clone();
    isolated.devices[0].peer_communication_enabled = false;
    // Nothing is known about the kernel yet: contain.
    commit(&io, &state, &mut a, isolated.clone()).await.unwrap();
    assert_eq!(contained(&io), 1);
    let mut reachable = isolated.clone();
    reachable.devices[0].peer_communication_enabled = true;
    commit(&io, &state, &mut a, reachable.clone())
        .await
        .unwrap();
    assert_eq!(contained(&io), 0, "an addition must not interrupt traffic");
    assert_eq!(io.0.lock().unwrap().kernel[2], reachable);
    commit(&io, &state, &mut a, isolated.clone()).await.unwrap();
    assert_eq!(contained(&io), 1, "a removal must contain");
    // A changed peer (here its preshared key) counts as removing the old grant.
    let mut rekeyed = isolated.clone();
    rekeyed.devices[0].preshared_key = Some(STANDARD.encode([9; 32]));
    commit(&io, &state, &mut a, rekeyed).await.unwrap();
    assert_eq!(contained(&io), 1);
    assert!(!io.0.lock().unwrap().contained);
    assert!(!needs_recovery(&state));
}

#[tokio::test]
async fn a_key_rotation_swaps_the_key_before_persist_without_containing_others() {
    let (mut a, _, io, state) = fixture();
    let settled = a.clone();
    commit(&io, &state, &mut a, settled).await.unwrap();
    contained(&io);
    let next = sirinvpn_core::LocalIdentity::generate("rotated").unwrap();
    let mut rotated = a.clone();
    let old_key = rotated.devices[0].wireguard_public_key.clone();
    rotated.devices[0].wireguard_public_key = next.public.wireguard_public_key.clone();
    rotated.devices[0].certificate_fingerprint =
        certificate_fingerprint(&next.public.management_certificate_pem).unwrap();
    rotated.devices[0].management_certificate_pem = next.public.management_certificate_pem;
    commit(&io, &state, &mut a, rotated.clone()).await.unwrap();
    let stages = io.0.lock().unwrap().stages.clone();
    assert_eq!(
        contained(&io),
        0,
        "a key rotation must not interrupt other devices"
    );
    // The old key leaves the kernel before the new document is durable.
    let position = |stage| stages.iter().position(|s| *s == stage).unwrap();
    assert!(position(Stage::Wireguard) < position(Stage::Persist));
    let (kernel, authority) = {
        let model = io.0.lock().unwrap();
        (model.kernel[1].clone(), model.authority.clone())
    };
    assert!(
        kernel
            .desired_peers(unix_time())
            .iter()
            .all(|peer| peer.public_key != old_key)
    );
    assert_eq!(authority, rotated);

    // A failed rotation still recovers under containment.
    let mut again = a.clone();
    again.devices[0].wireguard_public_key = STANDARD.encode([42; 32]);
    io.0.lock()
        .unwrap()
        .faults
        .push_back((Stage::Wireguard, true));
    assert!(commit(&io, &state, &mut a, again).await.is_err());
    assert_eq!(contained(&io), 1);
    assert_eq!(a, rotated);
}

#[tokio::test]
async fn a_failed_addition_still_recovers_under_containment() {
    let (mut a, _, io, state) = fixture();
    let mut isolated = a.clone();
    isolated.devices[0].peer_communication_enabled = false;
    commit(&io, &state, &mut a, isolated.clone()).await.unwrap();
    contained(&io);
    let mut reachable = isolated.clone();
    reachable.devices[0].peer_communication_enabled = true;
    io.0.lock()
        .unwrap()
        .faults
        .push_back((Stage::Isolation, true));
    assert!(commit(&io, &state, &mut a, reachable).await.is_err());
    assert_eq!(contained(&io), 1);
    let model = io.0.lock().unwrap();
    assert!(model.kernel.iter().all(|document| *document == isolated));
    assert!(!model.contained);
}

#[test]
fn narrowing_is_judged_against_what_was_enforced() {
    let peer = |key: u8, routes: &[&str]| DesiredPeer {
        public_key: STANDARD.encode([key; 32]),
        address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, key)),
        preshared_key: None,
        subnet_routes: routes.iter().map(|route| route.to_string()).collect(),
    };
    let applied = Footprint {
        peers: vec![peer(2, &[])],
        ..Default::default()
    };
    let mut next = applied.clone();
    assert!(!narrows(&applied, &next));
    next.peers.push(peer(3, &[]));
    assert!(!narrows(&applied, &next));
    // An added router could take traffic from an existing route: contain.
    next.peers.push(peer(4, &["192.168.1.0/24"]));
    assert!(narrows(&applied, &next));
    // A peer that expired by time is still enforced until a commit removes it.
    assert!(narrows(&applied, &Footprint::default()));
    let handoff = Footprint {
        handoff_source: true,
        ..applied.clone()
    };
    assert!(narrows(&applied, &handoff) && narrows(&handoff, &applied));
    let forwarded = |rules: &str| Footprint {
        forwarding: Some(format!(
            "flush chain inet sirinvpn_filter port_forward\n{rules}"
        )),
        ..applied.clone()
    };
    assert!(!narrows(&forwarded(""), &forwarded("add rule a accept\n")));
    assert!(narrows(&forwarded("add rule a accept\n"), &forwarded("")));

    // A replaced key at the same address and routes (key rotation) keeps every grant.
    let with_transport = |peers: Vec<DesiredPeer>| Footprint {
        transport: peers
            .iter()
            .map(|peer| decode_key(&peer.public_key).unwrap())
            .collect(),
        peers,
        ..Default::default()
    };
    let rekeyed = |key: u8, like: &DesiredPeer| DesiredPeer {
        public_key: STANDARD.encode([key; 32]),
        ..like.clone()
    };
    let applied = with_transport(vec![peer(2, &[]), peer(5, &["10.1.0.0/24"])]);
    assert!(!narrows(
        &applied,
        &with_transport(vec![rekeyed(9, &peer(2, &[])), peer(5, &["10.1.0.0/24"])])
    ));
    // Not a replacement: the routes change, the old key stays elsewhere, or the old key
    // vanishes from the relays without a replacing peer.
    let mut routed = rekeyed(9, &peer(2, &[]));
    routed.subnet_routes = vec!["10.2.0.0/24".into()];
    assert!(narrows(
        &applied,
        &with_transport(vec![routed, peer(5, &["10.1.0.0/24"])])
    ));
    let mut moved = peer(2, &[]);
    moved.address = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 7));
    assert!(narrows(
        &applied,
        &with_transport(vec![
            rekeyed(9, &peer(2, &[])),
            moved,
            peer(5, &["10.1.0.0/24"])
        ])
    ));
    assert!(narrows(
        &applied,
        &Footprint {
            transport: vec![decode_key(&peer(5, &[]).public_key).unwrap()],
            ..applied.clone()
        }
    ));
}

#[test]
fn startup_discards_an_intent_that_root_maintenance_made_stale() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = sirinvpn_core::LocalIdentity::generate("fixture").unwrap();
    let id = ServerId::new();
    let init = |host: &str| {
        initialize_with_transport_capabilities(
            &paths,
            "fixture",
            &owner.public.management_certificate_pem,
            id,
            &owner.public.wireguard_public_key,
            51820,
            ServerCapabilities {
                public_host: Some(host.into()),
                ..Default::default()
            },
        )
        .unwrap()
    };
    init("8.8.8.8");
    let a = load_authorization(&paths.authorization).unwrap();
    let mut b = a.clone();
    b.devices[0].peer_communication_enabled = !b.devices[0].peer_communication_enabled;
    // The daemon died after its intent; repair then signed a new endpoint into the file.
    journal::write(&paths, &a, &b, 7).unwrap();
    init("9.9.9.9");
    assert_eq!(
        journal::inspect(&paths).unwrap(),
        journal::Consistency::Stale
    );
    assert!(journal::validate(&paths).is_err());
    assert!(journal::discard_stale(&paths).unwrap());
    journal::validate(&paths).unwrap();
    assert_eq!(
        journal::inspect(&paths).unwrap(),
        journal::Consistency::Absent
    );
    // A matching intent is the transaction's own and stays for recovery.
    let c = load_authorization(&paths.authorization).unwrap();
    journal::write(&paths, &c, &b, 8).unwrap();
    assert!(!journal::discard_stale(&paths).unwrap());
    assert_eq!(
        journal::inspect(&paths).unwrap(),
        journal::Consistency::Previous
    );
    // A malformed intent still fails closed.
    let path = paths.authorization.with_extension("recovery.json");
    sirinvpn_platform::files::atomic_write(&path, b"{}", true).unwrap();
    assert!(journal::discard_stale(&paths).is_err());
}

#[tokio::test]
async fn publication_failure_recovers_committed_policy_and_exact_retry_is_idempotent() {
    let (mut a, b, io, state) = fixture();
    io.0.lock()
        .unwrap()
        .faults
        .push_back((Stage::Checkpoint, false));
    assert!(commit(&io, &state, &mut a, b.clone()).await.is_err());
    assert_eq!(a, b);
    assert!(needs_recovery(&state));
    recover(&io, &state, &mut a).await.unwrap();
    commit(&io, &state, &mut a, b.clone()).await.unwrap();
    assert_eq!(io.0.lock().unwrap().authority, b);
}

#[test]
fn containment_is_scoped_and_preserves_management_and_host_ssh() {
    let dir = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(dir.path());
    let owner = sirinvpn_core::LocalIdentity::generate("fixture").unwrap();
    initialize(
        &paths,
        "fixture",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51820,
    )
    .unwrap();
    let configuration = load_configuration(&paths).unwrap();
    let batch = containment(&configuration, true);
    assert!(batch.contains("tcp dport 8443 accept"));
    assert!(!batch.contains("flush ruleset"));
    for line in batch.lines().filter(|line| line.ends_with(" drop")) {
        assert!(line.contains("\"sirinvpn0\""));
    }
}

#[tokio::test]
async fn cancelled_mutation_remains_dirty_until_authority_is_reconciled() {
    struct Interrupted<'a>(&'a Fake);
    impl Effects for Interrupted<'_> {
        fn intent(
            &self,
            a: &AuthorizationDocument,
            b: &AuthorizationDocument,
            generation: u64,
        ) -> Result<()> {
            self.0.intent(a, b, generation)
        }
        fn authority(&self) -> Result<AuthorizationDocument> {
            self.0.authority()
        }
        async fn execute(&self, stage: Stage, document: &AuthorizationDocument) -> Result<()> {
            self.0.execute(stage, document).await?;
            if stage == Stage::Wireguard {
                std::future::pending::<()>().await;
            }
            Ok(())
        }
    }
    let (mut a, b, io, state) = fixture();
    let old = a.clone();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            commit(&Interrupted(&io), &state, &mut a, b)
        )
        .await
        .is_err()
    );
    assert!(needs_recovery(&state));
    assert!(io.0.lock().unwrap().contained);
    recover(&io, &state, &mut a).await.unwrap();
    assert_eq!(a, old);
    assert!(
        io.0.lock()
            .unwrap()
            .kernel
            .iter()
            .all(|document| document == &old)
    );
}

#[test]
fn recovery_journal_rejects_future_schema_wrong_authority_and_symlinks() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = sirinvpn_core::LocalIdentity::generate("fixture").unwrap();
    initialize(
        &paths,
        "fixture",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51820,
    )
    .unwrap();
    let a = load_authorization(&paths.authorization).unwrap();
    journal::write(&paths, &a, &a, 1).unwrap();
    journal::validate(&paths).unwrap();
    let path = paths.authorization.with_extension("recovery.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["schema_version"] = serde_json::json!(99);
    sirinvpn_platform::files::atomic_write(&path, &serde_json::to_vec(&value).unwrap(), true)
        .unwrap();
    assert!(journal::validate(&paths).is_err());
    value["schema_version"] = serde_json::json!(1);
    value["previous"] = serde_json::json!("0".repeat(64));
    value["next"] = serde_json::json!("1".repeat(64));
    sirinvpn_platform::files::atomic_write(&path, &serde_json::to_vec(&value).unwrap(), true)
        .unwrap();
    assert!(journal::validate(&paths).is_err());
    fs::remove_file(&path).unwrap();
    symlink(&paths.authorization, &path).unwrap();
    assert!(journal::validate(&paths).is_err());
}
