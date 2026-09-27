use super::*;

mod crash;

struct Model {
    authority: AuthorizationDocument,
    kernel: Vec<AuthorizationDocument>,
    published: AuthorizationDocument,
    contained: bool,
    faults: VecDeque<(Stage, bool)>,
    stages: Vec<Stage>,
}
struct Fake(Mutex<Model>);
impl Effects for Fake {
    fn intent(&self, _: &AuthorizationDocument, _: &AuthorizationDocument, _: u64) -> Result<()> {
        Ok(())
    }
    fn authority(&self) -> Result<AuthorizationDocument> {
        Ok(self.0.lock().unwrap().authority.clone())
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
    assert!(status(&state).committed);
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
