use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Output},
};

const NONCE: &str = "0123456789abcdef0123456789abcdef";

/// A VPS-shaped directory tree in which generated shell runs with shimmed
/// system tools, as in `maintenance_recovery`.
struct Vps {
    directory: tempfile::TempDir,
}

impl Vps {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        for path in [
            "bin",
            "run",
            "usr/local/lib",
            "var/lib/sirinvpn-maintenance",
            "etc/systemd/system",
        ] {
            fs::create_dir_all(directory.path().join(path)).unwrap();
        }
        let vps = Self { directory };
        // `is-active` reports a running safety timer only when the test says so.
        vps.shim(
            "systemctl",
            r#"case "$*" in
  "is-active --quiet "*.timer) [ -f "$SIRINVPN_TEST_ROOT/timer-active" ] ;;
  *) exit 0 ;;
esac"#,
        );
        vps
    }
    fn path(&self, path: &str) -> PathBuf {
        self.directory.path().join(path)
    }
    fn write(&self, path: &str, data: &str) {
        let path = self.path(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
    fn shim(&self, program: &str, body: &str) {
        let path = self.path("bin").join(program);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn run(&self, script: &str) -> Output {
        let root = self.directory.path().to_str().unwrap();
        let mut script = script.to_owned();
        for path in ["/var/lib", "/usr/local/lib", "/etc", "/run"] {
            script = script.replace(path, &format!("{root}{path}"));
        }
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .env("PATH", format!("{root}/bin:/usr/bin:/bin"))
            .env("SIRINVPN_TEST_ROOT", root)
            .output()
            .unwrap()
    }
    fn state(&self, uninstall: bool) -> RemoteTransactionState {
        let output = self.run(&maintenance::state_command(NONCE, uninstall));
        assert!(output.status.success());
        RemoteTransactionState::parse(std::str::from_utf8(&output.stdout).unwrap()).unwrap()
    }
    fn backup(&self) -> String {
        format!("var/lib/sirinvpn-maintenance/sirinvpn-install-{NONCE}.backup")
    }
}

#[test]
fn the_vps_reports_each_transaction_state_from_its_markers() {
    let vps = Vps::new();
    assert_eq!(vps.state(false), RemoteTransactionState::Unknown);
    // Uninstall keeps no record: its result is whether the server remains.
    assert_eq!(vps.state(true), RemoteTransactionState::Committed);
    vps.write("usr/local/lib/sirinvpn/sirinvpn-server", "server");
    assert_eq!(vps.state(true), RemoteTransactionState::RolledBack);

    // Stopped before arming changed nothing; stopped while arming must roll back.
    vps.write(&format!("{}.preparing/existing", vps.backup()), "");
    assert_eq!(vps.state(false), RemoteTransactionState::RolledBack);
    vps.write(&format!("{}/existing", vps.backup()), "");
    assert_eq!(vps.state(false), RemoteTransactionState::Armed);
    vps.write(&format!("{}/backup-ready", vps.backup()), "");
    assert_eq!(vps.state(false), RemoteTransactionState::Armed);
    vps.write(&format!("{}/committed", vps.backup()), "");
    assert_eq!(vps.state(false), RemoteTransactionState::Committed);

    // A script that still holds the maintenance lock is running, not interrupted:
    // even when armed, since that script may be this transaction's commit.
    fs::remove_file(vps.path(&format!("{}/committed", vps.backup()))).unwrap();
    let mut holder = Command::new("flock")
        .arg(vps.path("run/sirinvpn-maintenance.lock"))
        .args(["sleep", "30"])
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    while vps.state(false) != RemoteTransactionState::Preparing {
        assert!(started.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(50));
    }
    fs::remove_file(vps.path(&format!("{}/backup-ready", vps.backup()))).unwrap();
    assert_eq!(vps.state(false), RemoteTransactionState::Preparing);
    holder.kill().unwrap();
    holder.wait().unwrap();

    fs::remove_dir_all(vps.path(&vps.backup())).unwrap();
    fs::remove_dir_all(vps.path(&format!("{}.preparing", vps.backup()))).unwrap();
    vps.write(
        &format!("var/lib/sirinvpn-maintenance/sirinvpn-install-{NONCE}.outcome"),
        "committed\n",
    );
    assert_eq!(vps.state(false), RemoteTransactionState::Committed);
    assert_eq!(RemoteTransactionState::parse("$(id)"), None);
}

#[test]
fn a_committed_transaction_leaves_an_outcome_after_its_backup_is_gone() {
    let vps = Vps::new();
    vps.write(&format!("{}/backup-ready", vps.backup()), "");
    let output = vps.run(&maintenance::commit(NONCE, false));
    assert!(output.status.success(), "{output:?}");
    assert!(!vps.path(&vps.backup()).exists());
    assert_eq!(vps.state(false), RemoteTransactionState::Committed);

    // Uninstall removes those records with everything else.
    let output = vps.run(&uninstall_commit_command("uninstall"));
    assert!(!output.status.success(), "no uninstall backup is armed");
    vps.write(
        "var/lib/sirinvpn-maintenance/sirinvpn-uninstall-uninstall.backup/backup-ready",
        "",
    );
    let output = vps.run(&uninstall_commit_command("uninstall"));
    assert!(output.status.success(), "{output:?}");
    assert!(!vps.path("var/lib/sirinvpn-maintenance").exists());
}

#[test]
fn a_live_transaction_from_another_client_is_never_rolled_back_by_a_new_one() {
    let vps = Vps::new();
    let rollback = format!("var/lib/sirinvpn-maintenance/sirinvpn-rollback-{NONCE}.sh");
    vps.write(
        &rollback,
        &format!(
            ": >\"{}/rolled-back\"\nrm -f \"$0\"\n",
            vps.path("").display()
        ),
    );
    vps.write(&format!("{}/owner", vps.backup()), "0123456789abcdef\n");
    vps.write(&format!("run/sirinvpn-install-{NONCE}.live"), "");
    vps.write("timer-active", "");

    let busy = vps.run(&maintenance::recover_pending());
    assert_eq!(busy.status.code(), Some(75));
    assert!(!vps.path("rolled-back").exists());
    let failure = install_failure::InstallFailure::from_output(&busy.stdout, 75)
        .unwrap()
        .to_string();
    assert!(failure.contains("0123456789abcdef"), "{failure}");

    // The safety timer already fired (or the VPS rebooted): the transaction is abandoned.
    fs::remove_file(vps.path("timer-active")).unwrap();
    let recovered = vps.run(&maintenance::recover_pending());
    assert!(recovered.status.success());
    assert!(vps.path("rolled-back").exists());
}

#[test]
fn the_client_journal_names_one_unresolved_transaction_until_it_ends() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::new(directory.path().join("transaction.json"));
    let target = SshTarget {
        host: "203.0.113.9".into(),
        port: 22,
        username: "root".into(),
        authentication: SshAuthentication::Agent,
        sudo_password: None,
        expected_host_key_sha256: Some("SHA256:pin".into()),
    };
    assert!(journal.read().unwrap().is_none());
    let mut transaction =
        Transaction::begin(Some(&journal), TransactionOperation::Install, &target).unwrap();
    let entry = journal.read().unwrap().unwrap();
    assert_eq!(entry.step, TransactionStep::Staged);
    assert_eq!(entry.host_key_sha256, "SHA256:pin");
    assert!(valid_nonce(&entry.nonce));
    let mode = fs::metadata(journal.server_path(&target.host))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    transaction.advance(TransactionStep::CommitSent).unwrap();
    assert_eq!(
        journal.read().unwrap().unwrap().step,
        TransactionStep::CommitSent
    );
    assert!(matches!(
        Transaction::begin(Some(&journal), TransactionOperation::Install, &target),
        Err(InstallerError::TransactionUnresolved { host }) if host == target.host
    ));

    // Resolution refuses another VPS before connecting anywhere.
    let other = SshTarget {
        expected_host_key_sha256: Some("SHA256:other".into()),
        ..target.clone()
    };
    assert!(matches!(
        Provisioner::resolve_transaction(&other, &journal),
        Err(InstallerError::InvalidInput(_))
    ));

    transaction.advance(TransactionStep::Committed).unwrap();
    assert!(journal.read().unwrap().is_none());

    fs::write(journal.server_path(&target.host), b"{\"nonce\":\"$(id)\"}").unwrap();
    assert!(journal.read_server(&target.host).is_err());
}

#[test]
fn a_committed_profile_is_offered_only_for_a_confirmed_commit() {
    let identity = LocalIdentity::generate("Journal fixture").unwrap();
    let profile: ServerProfile = serde_json::from_value(serde_json::json!({
        "schema_version":1, "id":ServerId::new(), "name":"Journal fixture",
        "endpoint":{"host":"203.0.113.4","wireguard_port":51820},
        "client_tunnel_address":"10.77.0.2", "server_tunnel_address":"10.77.0.1",
        "server_wireguard_public_key":identity.public.wireguard_public_key,
        "pinned_server_certificate_pem":identity.public.management_certificate_pem,
        "client_management_certificate_pem":identity.public.management_certificate_pem,
        "identity_reference":"fixture", "role":"owner"
    }))
    .unwrap();
    let resolved = |state| ResolvedTransaction {
        entry: JournalEntry {
            schema_version: 1,
            operation: TransactionOperation::Install,
            nonce: NONCE.into(),
            host: "203.0.113.4".into(),
            port: 22,
            host_key_sha256: "SHA256:pin".into(),
            step: TransactionStep::CommitSent,
            committed_profile: Some(profile.clone()),
        },
        state,
    };
    assert_eq!(
        resolved(RemoteTransactionState::Committed).committed_profile(),
        Some(&profile)
    );
    for state in [
        RemoteTransactionState::RolledBack,
        RemoteTransactionState::Armed,
        RemoteTransactionState::Unknown,
    ] {
        assert!(resolved(state).committed_profile().is_none());
    }
}

#[test]
fn a_lost_commit_reply_is_decided_only_by_the_vps() {
    use journal::AfterFailedCommit::*;
    assert_eq!(
        after_failed_commit(Some(RemoteTransactionState::Committed)),
        Committed
    );
    assert_eq!(
        after_failed_commit(Some(RemoteTransactionState::Armed)),
        RollBack
    );
    assert_eq!(
        after_failed_commit(Some(RemoteTransactionState::RolledBack)),
        RolledBack
    );
    // A held lock after the commit was sent may be that very commit.
    assert_eq!(
        after_failed_commit(Some(RemoteTransactionState::Preparing)),
        Uncertain
    );
    // No answer, or no record, must never be read as failure: keys stay.
    assert_eq!(after_failed_commit(None), Uncertain);
    assert_eq!(
        after_failed_commit(Some(RemoteTransactionState::Unknown)),
        Uncertain
    );
    let error = InstallerError::CommitUncertain {
        nonce: NONCE.into(),
    }
    .to_string();
    assert!(error.contains("keep this device's keys") && error.contains(NONCE));
}

/// What the VPS does while the client's replies get lost. Mirrors the shell:
/// a slow commit still holds the maintenance lock, so a rollback waits for it
/// and then finds the transaction committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Remote {
    Armed,
    /// The commit script is still running (holding the lock).
    Committing,
    Committed,
    RolledBack,
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    /// The request never ran.
    Request,
    /// The request ran; its reply was lost.
    Reply,
}

struct FaultyVps {
    state: Remote,
    /// A lost commit reply leaves the commit still running.
    slow_commit: bool,
    /// The VPS's state command checks the lock; an older one says `armed` while locked.
    reports_lock: bool,
    calls: usize,
    faults: Vec<(usize, Fault)>,
}

impl FaultyVps {
    fn fault(&mut self) -> Option<Fault> {
        let call = self.calls;
        self.calls += 1;
        self.faults
            .iter()
            .find(|(at, _)| *at == call)
            .map(|(_, fault)| *fault)
    }
}

impl CommitRemote for FaultyVps {
    fn send_commit(&mut self) -> anyhow::Result<()> {
        let fault = self.fault();
        if matches!(fault, Some(Fault::Request)) {
            anyhow::bail!("request lost");
        }
        if fault.is_some() {
            self.state = if self.slow_commit {
                Remote::Committing
            } else {
                Remote::Committed
            };
            anyhow::bail!("reply lost");
        }
        self.state = Remote::Committed;
        Ok(())
    }

    fn query(&mut self) -> Option<RemoteTransactionState> {
        if self.fault().is_some() {
            return None;
        }
        Some(match self.state {
            Remote::Armed => RemoteTransactionState::Armed,
            Remote::Committing if self.reports_lock => RemoteTransactionState::Preparing,
            Remote::Committing => RemoteTransactionState::Armed,
            Remote::Committed => RemoteTransactionState::Committed,
            Remote::RolledBack => RemoteTransactionState::RolledBack,
        })
    }

    fn roll_back(&mut self) {
        if matches!(self.fault(), Some(Fault::Request)) {
            return;
        }
        self.state = match self.state {
            // `flock` waits for the commit, which then wins.
            Remote::Committing => Remote::Committed,
            Remote::Armed => Remote::RolledBack,
            state => state,
        };
    }
}

/// Every caller deletes the new Owner key (install) or keeps a removed server
/// (uninstall) on a plain error; only `Ok` and `CommitUncertain` keep both.
fn discards_owner_key(result: &Result<(), InstallerError>) -> bool {
    matches!(result, Err(error) if !matches!(error, InstallerError::CommitUncertain { .. }))
}

#[test]
fn a_lost_reply_anywhere_in_the_commit_exchange_never_discards_a_key_the_vps_may_use() {
    let target = SshTarget {
        host: "203.0.113.9".into(),
        port: 22,
        username: "root".into(),
        authentication: SshAuthentication::Agent,
        sudo_password: None,
        expected_host_key_sha256: Some("SHA256:pin".into()),
    };
    // Calls: 0 commit, 1 state query, 2 rollback, 3 state query after the rollback.
    let mut scenarios = vec![Vec::new()];
    for first in 0..4 {
        for fault in [Fault::Request, Fault::Reply] {
            scenarios.push(vec![(first, fault)]);
            for second in first + 1..4 {
                scenarios.push(vec![(first, fault), (second, Fault::Reply)]);
            }
        }
    }
    let mut confirmed_rollbacks = 0;
    for faults in scenarios {
        for slow_commit in [false, true] {
            for reports_lock in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let journal =
                    TransactionJournal::new(directory.path().join("vps-transaction.json"));
                let mut transaction =
                    Transaction::begin(Some(&journal), TransactionOperation::Install, &target)
                        .unwrap();
                transaction.advance(TransactionStep::Verified).unwrap();
                let mut vps = FaultyVps {
                    state: Remote::Armed,
                    slow_commit,
                    reports_lock,
                    calls: 0,
                    faults: faults.clone(),
                };
                let result = transaction.commit_with(&mut vps, "commit");
                let case = format!(
                    "{faults:?} slow={slow_commit} lock={reports_lock}: {result:?}, VPS {:?}",
                    vps.state
                );
                let journaled = journal.read_server(&target.host).unwrap().is_some();
                if matches!(vps.state, Remote::Committed | Remote::Committing) {
                    assert!(
                        !discards_owner_key(&result),
                        "the Owner key must survive: {case}"
                    );
                }
                match &result {
                    Ok(()) => assert_eq!(vps.state, Remote::Committed, "{case}"),
                    Err(InstallerError::CommitUncertain { .. }) => {
                        assert!(journaled, "an uncertain outcome keeps its journal: {case}")
                    }
                    Err(_) => {
                        // The only discarding path: the VPS confirmed the rollback.
                        assert_eq!(vps.state, Remote::RolledBack, "{case}");
                        assert!(!journaled, "{case}");
                        confirmed_rollbacks += 1;
                    }
                }
            }
        }
    }
    assert!(
        confirmed_rollbacks > 0,
        "a confirmed rollback still ends the transaction"
    );
}

fn journal_target(host: &str) -> SshTarget {
    SshTarget {
        host: host.into(),
        port: 22,
        username: "root".into(),
        authentication: SshAuthentication::Agent,
        sudo_password: None,
        expected_host_key_sha256: Some("SHA256:pin".into()),
    }
}

#[test]
fn a_stuck_transaction_blocks_only_its_own_server() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::new(directory.path().join("vps-transaction.json"));
    let stuck = journal_target("203.0.113.9");
    let other = journal_target("198.51.100.7");
    let mut transaction =
        Transaction::begin(Some(&journal), TransactionOperation::Install, &stuck).unwrap();
    transaction.advance(TransactionStep::CommitSent).unwrap();

    assert!(matches!(
        Transaction::begin(Some(&journal), TransactionOperation::Install, &stuck),
        Err(InstallerError::TransactionUnresolved { .. })
    ));
    // The same host, spelled differently, is the same server.
    assert!(
        Transaction::begin(
            Some(&journal),
            TransactionOperation::Uninstall,
            &journal_target("203.0.113.9.")
        )
        .is_err()
    );
    let mut unrelated =
        Transaction::begin(Some(&journal), TransactionOperation::Install, &other).unwrap();
    assert_eq!(journal.entries().unwrap().len(), 2);
    unrelated.advance(TransactionStep::Committed).unwrap();
    assert_eq!(journal.entries().unwrap().len(), 1);
    assert_eq!(journal.read().unwrap().unwrap().host, stuck.host);
    // A damaged record blocks its own host only.
    fs::write(journal.server_path(&other.host), b"{").unwrap();
    assert!(Transaction::begin(Some(&journal), TransactionOperation::Install, &other).is_err());
    assert_eq!(journal.entries().unwrap().len(), 1);
    assert!(journal.abandon(&other.host).unwrap());
    Transaction::begin(Some(&journal), TransactionOperation::Install, &other).unwrap();
}

#[test]
fn an_earlier_versions_single_journal_moves_to_its_server_and_abandon_keeps_keys() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("vps-transaction.json");
    let journal = TransactionJournal::new(&legacy);
    let entry = JournalEntry {
        schema_version: 1,
        operation: TransactionOperation::Install,
        nonce: NONCE.into(),
        host: "203.0.113.9".into(),
        port: 22,
        host_key_sha256: "SHA256:pin".into(),
        step: TransactionStep::CommitSent,
        committed_profile: None,
    };
    // Exactly what the previous version wrote, with its pending-secret marker.
    fs::write(&legacy, serde_json::to_vec(&entry).unwrap()).unwrap();
    fs::write(directory.path().join("vps-transaction-secret"), "identity").unwrap();
    let key = directory.path().join("owner-key");
    fs::write(&key, "secret").unwrap();

    assert!(journal.read_server("198.51.100.7").unwrap().is_none());
    assert!(!legacy.exists());
    assert_eq!(
        journal.read_server("203.0.113.9").unwrap(),
        Some(entry.clone())
    );
    assert_eq!(
        fs::read_to_string(journal.pending_secret_path("203.0.113.9")).unwrap(),
        "identity"
    );
    assert!(
        Transaction::begin(
            Some(&journal),
            TransactionOperation::Install,
            &journal_target("203.0.113.9")
        )
        .is_err()
    );

    // Abandoning another server changes nothing here.
    assert!(!journal.abandon("198.51.100.7").unwrap());
    assert!(journal.read_server("203.0.113.9").unwrap().is_some());
    assert!(journal.abandon("203.0.113.9").unwrap());
    assert!(journal.read_server("203.0.113.9").unwrap().is_none());
    assert!(!journal.pending_secret_path("203.0.113.9").exists());
    assert!(key.exists(), "abandon never touches key material");

    // An unreadable old journal names no server: abandoning any host drops it.
    fs::write(&legacy, b"{").unwrap();
    assert!(journal.read_server("198.51.100.7").is_err());
    assert!(journal.abandon("198.51.100.7").unwrap());
    assert!(journal.entries().unwrap().is_empty());
}
