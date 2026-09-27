//! Real process/VM termination and private persistence; network effects remain modeled.
use super::*;
use std::io::Write;

struct Disk {
    paths: ServerPaths,
    crash_at: Option<String>,
    hold_for_power_cut: bool,
}
impl Effects for Disk {
    fn intent(
        &self,
        previous: &AuthorizationDocument,
        next: &AuthorizationDocument,
        generation: u64,
    ) -> Result<()> {
        journal::write(&self.paths, previous, next, generation)
    }
    fn authority(&self) -> Result<AuthorizationDocument> {
        journal::validate(&self.paths)?;
        load_authorization(&self.paths.authorization)
    }
    async fn execute(&self, stage: Stage, document: &AuthorizationDocument) -> Result<()> {
        let parent = self.paths.authorization.parent().unwrap();
        match stage {
            Stage::Persist => write_authorization(&self.paths.authorization, document)?,
            Stage::Complete => {
                journal::remove(&self.paths)?;
                fs::remove_file(parent.join("contained"))?;
            }
            Stage::Contain => {
                sirinvpn_platform::files::atomic_write(&parent.join("contained"), b"1", true)?
            }
            _ => sirinvpn_platform::files::atomic_write(
                &parent.join(format!("{stage:?}.json")),
                &serde_json::to_vec(document)?,
                true,
            )?,
        }
        if self.crash_at.as_ref() == Some(&format!("{stage:?}")) {
            if self.hold_for_power_cut {
                println!("SIRINVPN_POWER_CUT_READY {stage:?}");
                std::io::stdout().flush()?;
                std::future::pending::<()>().await;
            }
            std::process::exit(86); // No destructors or best-effort rollback.
        }
        Ok(())
    }
}

#[tokio::test]
async fn crash_child() {
    let Ok(root) = std::env::var("SIRINVPN_AUTHORIZATION_CRASH_FIXTURE") else {
        return;
    };
    let paths = ServerPaths::under(Path::new(&root));
    let stage = std::env::var("SIRINVPN_AUTHORIZATION_CRASH_STAGE").unwrap();
    let power_mode = std::env::var("SIRINVPN_AUTHORIZATION_POWER_MODE").ok();
    if let Some(mode) = power_mode.as_deref() {
        // Only the owned, network-disabled container in the disposable VM may
        // hold a transaction for a hard power cut. This module is test-only.
        assert_eq!(root, "/power-fixture");
        assert_eq!(
            std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
            Ok("1")
        );
        assert!(Path::new("/.dockerenv").is_file());
        assert!(matches!(
            stage.as_str(),
            "Forwarding" | "Persist" | "Checkpoint"
        ));
        if mode == "recover" {
            let previous = load_authorization(&Path::new(&root).join("previous.json")).unwrap();
            verify_recovery(paths, previous, stage != "Forwarding").await;
            return;
        }
        assert_eq!(mode, "prepare");
        assert!(
            !paths.authorization.exists(),
            "Refuse existing fixture authority"
        );
        let (previous, _, _, _) = fixture();
        sirinvpn_platform::files::create_private_directory(paths.authorization.parent().unwrap())
            .unwrap();
        write_authorization(&Path::new(&root).join("previous.json"), &previous).unwrap();
        write_authorization(&paths.authorization, &previous).unwrap();
    }
    let mut current = load_authorization(&paths.authorization).unwrap();
    let mut next = current.clone();
    next.devices[0].peer_communication_enabled = !next.devices[0].peer_communication_enabled;
    let io = Disk {
        paths,
        crash_at: Some(stage),
        hold_for_power_cut: power_mode.is_some(),
    };
    commit(&io, &Mutex::default(), &mut current, next)
        .await
        .unwrap();
    panic!("crash boundary was not exercised");
}

#[tokio::test]
async fn process_death_preserves_durable_authority_and_reconstructs_effects() {
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
        let directory = tempfile::tempdir().unwrap();
        let paths = ServerPaths::under(directory.path());
        let (a, _, _, _) = fixture();
        sirinvpn_platform::files::create_private_directory(paths.authorization.parent().unwrap())
            .unwrap();
        write_authorization(&paths.authorization, &a).unwrap();
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "authorization_transaction::tests::crash::crash_child",
                "--nocapture",
            ])
            .env("SIRINVPN_AUTHORIZATION_CRASH_FIXTURE", directory.path())
            .env("SIRINVPN_AUTHORIZATION_CRASH_STAGE", format!("{stage:?}"))
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(10), command.output())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "{stage:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let committed = matches!(
            stage,
            Stage::Persist | Stage::Transport | Stage::Checkpoint | Stage::Complete
        );
        verify_recovery(paths, a, committed).await;
    }
}

async fn verify_recovery(paths: ServerPaths, previous: AuthorizationDocument, committed: bool) {
    let io = Disk {
        paths,
        crash_at: None,
        hold_for_power_cut: false,
    };
    let mut current = previous.clone(); // Simulates stale memory at restart.
    let state = Mutex::default();
    recover(&io, &state, &mut current).await.unwrap();
    let mut expected = previous;
    if committed {
        expected.devices[0].peer_communication_enabled =
            !expected.devices[0].peer_communication_enabled;
    }
    assert_eq!(current, expected);
    assert_eq!(current, io.authority().unwrap());
    for effect in [
        Stage::Quarantine,
        Stage::Wireguard,
        Stage::Isolation,
        Stage::Forwarding,
        Stage::Transport,
        Stage::Checkpoint,
    ] {
        let bytes = fs::read(
            io.paths
                .authorization
                .parent()
                .unwrap()
                .join(format!("{effect:?}.json")),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<AuthorizationDocument>(&bytes).unwrap(),
            current
        );
    }
    assert!(!needs_recovery(&state));
    assert!(
        !io.paths
            .authorization
            .parent()
            .unwrap()
            .join("contained")
            .exists()
    );
}
