//! The SSH maintenance transaction (install, repair, restore, signed baseline,
//! uninstall) as an explicit state machine. The client records its step in a
//! private journal before each remote step, so a crash, sleep or lost reply
//! leaves enough to finish cleanly: `Provisioner::resolve_transaction` reads
//! the VPS's own state for that nonce and either confirms the commit or rolls
//! the transaction back. The VPS state stays authoritative; the journal only
//! names the transaction and the profile to keep if it committed.

use super::*;

const JOURNAL_SCHEMA_VERSION: u16 = 1;
const MAX_JOURNAL_BYTES: usize = 256 * 1024;

/// Client-side steps, in order; each is journaled before its remote request.
/// From `Armed` on, only the VPS knows whether the change is still applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStep {
    /// The script and artifacts are being staged; the VPS is unchanged.
    Staged,
    /// The script was sent: it arms rollback (timer and boot guard) before changing anything.
    Armed,
    /// The server identity initialization was sent (install family only).
    Initialized,
    /// Health verification was sent.
    Verified,
    /// Commit was sent and its reply has not arrived.
    CommitSent,
    Committed,
    RolledBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionOperation {
    /// Install, repair, restore and signed-baseline installation share this transaction.
    Install,
    Uninstall,
}

/// One transaction's state as the VPS reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTransactionState {
    /// A maintenance script holds the VPS's lock (still running, perhaps this
    /// transaction's commit), or stopped before arming rollback.
    Preparing,
    /// Applied and armed, not committed: it will roll back within 5 minutes or at boot.
    Armed,
    Committed,
    /// The VPS is in its pre-transaction state (rolled back, or never changed).
    RolledBack,
    /// No record: never reached the VPS, made by an older client, or older than 30 days.
    Unknown,
}

impl RemoteTransactionState {
    pub(super) fn parse(output: &str) -> Option<Self> {
        Some(match output.trim() {
            "preparing" => Self::Preparing,
            "armed" => Self::Armed,
            "committed" => Self::Committed,
            "rolled_back" => Self::RolledBack,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }

    /// Whether the transaction has ended one way or the other.
    pub fn is_final(self) -> bool {
        matches!(self, Self::Committed | Self::RolledBack)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    pub schema_version: u16,
    pub operation: TransactionOperation,
    pub nonce: String,
    pub host: String,
    pub port: u16,
    pub host_key_sha256: String,
    pub step: TransactionStep,
    /// The profile `install` would have returned, recorded before commit. Repair and
    /// restore callers merge it exactly as they merge a successful outcome's profile.
    pub committed_profile: Option<ServerProfile>,
}

/// Private files that hold at most one unresolved transaction per VPS host, so a
/// stuck transaction blocks only its own server. `path` is the single-file
/// journal of earlier versions; the per-host files sit beside it and an old
/// file is moved to its host's file on first use.
#[derive(Clone, Debug)]
pub struct TransactionJournal {
    path: PathBuf,
}

fn read_entry(path: &Path) -> Result<Option<JournalEntry>, InstallerError> {
    let bytes = match sirinvpn_platform::files::read_bounded(path, MAX_JOURNAL_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(phase_error("transaction journal", anyhow!(error))),
    };
    let damaged = || InstallerError::InvalidInput("the transaction journal is damaged".to_owned());
    let entry: JournalEntry = serde_json::from_slice(&bytes).map_err(|_| damaged())?;
    if entry.schema_version != JOURNAL_SCHEMA_VERSION || !valid_nonce(&entry.nonce) {
        return Err(damaged());
    }
    Ok(Some(entry))
}

fn remove_file(path: &Path) -> Result<bool, InstallerError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(phase_error("transaction journal", anyhow!(error))),
    }
}

/// Hosts compare as the SSH layer resolves them: case and a trailing dot do not matter.
fn same_host(left: &str, right: &str) -> bool {
    left.trim()
        .trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim().trim_end_matches('.'))
}

impl TransactionJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The single-file journal of earlier versions (migrated on first use).
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn stem(&self) -> String {
        self.path.file_stem().map_or_else(
            || "vps-transaction".into(),
            |stem| stem.to_string_lossy().into_owned(),
        )
    }

    fn sibling(&self, name: String) -> PathBuf {
        self.path.with_file_name(name)
    }

    fn host_key(host: &str) -> String {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        hex::encode(Sha256::digest(host.as_bytes()))[..32].to_owned()
    }

    /// The journal file of one VPS host.
    pub fn server_path(&self, host: &str) -> PathBuf {
        self.sibling(format!("{}.{}.json", self.stem(), Self::host_key(host)))
    }

    fn legacy_secret_marker(&self) -> PathBuf {
        self.sibling(format!("{}-secret", self.stem()))
    }

    /// Where the CLI names the new Owner key of an install in progress on `host`.
    pub fn pending_secret_path(&self, host: &str) -> PathBuf {
        self.sibling(format!("{}-secret.{}", self.stem(), Self::host_key(host)))
    }

    /// Moves an earlier version's single journal (and its pending-secret marker)
    /// to its host's files. A damaged old journal stays and is reported.
    fn migrate(&self) -> Result<(), InstallerError> {
        let Some(entry) = read_entry(&self.path)? else {
            return Ok(());
        };
        let to = self.server_path(&entry.host);
        // shortcut: an old journal whose host already has a new one is left in place and ignored; both cannot come from one device in practice.
        if to.exists() {
            return Ok(());
        }
        if self.legacy_secret_marker().exists() {
            fs::rename(
                self.legacy_secret_marker(),
                self.pending_secret_path(&entry.host),
            )
            .map_err(|error| phase_error("transaction journal", anyhow!(error)))?;
        }
        fs::rename(&self.path, to)
            .map_err(|error| phase_error("transaction journal", anyhow!(error)))
    }

    /// The unresolved transaction on `host`, if any. A damaged record for that host is an error.
    pub fn read_server(&self, host: &str) -> Result<Option<JournalEntry>, InstallerError> {
        self.migrate()?;
        read_entry(&self.server_path(host))
    }

    /// Every readable unresolved transaction on this device, oldest file name first.
    /// A damaged per-host record is skipped here; it still blocks its own host.
    pub fn entries(&self) -> Result<Vec<JournalEntry>, InstallerError> {
        self.migrate()?;
        let prefix = format!("{}.", self.stem());
        let directory = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty());
        let directory = directory.unwrap_or(Path::new("."));
        let listing = match fs::read_dir(directory) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(phase_error("transaction journal", anyhow!(error))),
        };
        let mut paths: Vec<PathBuf> = listing
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.strip_prefix(&prefix)
                            .and_then(|rest| rest.strip_suffix(".json"))
                            .is_some_and(|key| {
                                key.len() == 32 && key.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                    })
            })
            .collect();
        paths.sort();
        Ok(paths
            .iter()
            .filter_map(|path| read_entry(path).ok().flatten())
            .collect())
    }

    /// The first unresolved transaction on this device, for callers that settle
    /// them one at a time without naming a server.
    pub fn read(&self) -> Result<Option<JournalEntry>, InstallerError> {
        Ok(self.entries()?.into_iter().next())
    }

    /// Whether an unresolved transaction blocks maintenance of this saved server:
    /// one on its host, or one that would commit this server's profile.
    pub fn blocks_server(&self, profile: &ServerProfile) -> Result<bool, InstallerError> {
        Ok(self.read_server(&profile.endpoint.host)?.is_some()
            || self.entries()?.iter().any(|entry| {
                same_host(&entry.host, &profile.endpoint.host)
                    || entry
                        .committed_profile
                        .as_ref()
                        .is_some_and(|planned| planned.id == profile.id)
            }))
    }

    /// Forgets the unresolved transaction on `host` without asking the VPS, with
    /// its pending-secret marker. The VPS may have committed or rolled back; no
    /// key is touched. A damaged record (for this host, or an earlier version's
    /// single journal that cannot be read) goes too. Returns whether anything was removed.
    pub fn abandon(&self, host: &str) -> Result<bool, InstallerError> {
        let legacy = match self.migrate() {
            Ok(()) => false,
            Err(InstallerError::InvalidInput(_)) => {
                remove_file(&self.legacy_secret_marker())?;
                remove_file(&self.path)?
            }
            Err(error) => return Err(error),
        };
        let marker = remove_file(&self.pending_secret_path(host))?;
        Ok(remove_file(&self.server_path(host))? || marker || legacy)
    }

    fn write(&self, entry: &JournalEntry) -> Result<(), InstallerError> {
        let bytes = serde_json::to_vec(entry)
            .map_err(|error| phase_error("transaction journal", anyhow!(error)))?;
        sirinvpn_platform::files::atomic_write(&self.server_path(&entry.host), &bytes, true)
            .map_err(|error| phase_error("transaction journal", anyhow!(error)))
    }

    fn remove(&self, host: &str) -> Result<(), InstallerError> {
        remove_file(&self.server_path(host)).map(|_| ())
    }
}

pub(super) fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The running transaction: its step is journaled before the remote step runs.
pub(super) struct Transaction<'a> {
    journal: Option<&'a TransactionJournal>,
    pub(super) entry: JournalEntry,
}

impl<'a> Transaction<'a> {
    /// Refuses to start while the journal still names an unresolved transaction.
    pub(super) fn begin(
        journal: Option<&'a TransactionJournal>,
        operation: TransactionOperation,
        target: &SshTarget,
    ) -> Result<Self, InstallerError> {
        if let Some(journal) = journal
            && journal.read_server(&target.host)?.is_some()
        {
            return Err(InstallerError::TransactionUnresolved {
                host: target.host.clone(),
            });
        }
        let mut transaction = Self {
            journal,
            entry: JournalEntry {
                schema_version: JOURNAL_SCHEMA_VERSION,
                operation,
                nonce: Uuid::new_v4().simple().to_string(),
                host: target.host.clone(),
                port: target.port,
                host_key_sha256: target.expected_host_key_sha256.clone().unwrap_or_default(),
                step: TransactionStep::Staged,
                committed_profile: None,
            },
        };
        transaction.advance(TransactionStep::Staged)?;
        Ok(transaction)
    }

    pub(super) fn nonce(&self) -> &str {
        &self.entry.nonce
    }

    pub(super) fn advance(&mut self, step: TransactionStep) -> Result<(), InstallerError> {
        self.entry.step = step;
        match (self.journal, step) {
            (None, _) => Ok(()),
            // A finished transaction needs no recovery record.
            (Some(journal), TransactionStep::Committed | TransactionStep::RolledBack) => {
                journal.remove(&self.entry.host)
            }
            (Some(journal), _) => journal.write(&self.entry),
        }
    }

    /// Journals the next step; a journal that cannot be written stops the
    /// transaction (rolled back) rather than continue unrecorded.
    pub(super) fn step(
        &mut self,
        session: &Session,
        target: &SshTarget,
        step: TransactionStep,
    ) -> Result<(), InstallerError> {
        match self.advance(step) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.abort(session, target, error)),
        }
    }

    /// Steps a failed operation back out. The journal stays only if the VPS could
    /// not confirm the rollback, so a later resolve can finish it.
    pub(super) fn abort(
        &mut self,
        session: &Session,
        target: &SshTarget,
        error: InstallerError,
    ) -> InstallerError {
        if self.entry.step != TransactionStep::Staged {
            run_rollback_now(session, target, &self.rollback_path());
        }
        let confirmed = self.entry.step == TransactionStep::Staged
            || matches!(
                query_state(session, target, &self.entry),
                Some(RemoteTransactionState::RolledBack | RemoteTransactionState::Unknown)
            );
        if confirmed {
            let _ = self.advance(TransactionStep::RolledBack);
        }
        error
    }

    /// Sends the commit. A lost reply is resolved by asking the VPS (reconnecting
    /// with the same pin when the session is gone). Anything but a confirmed
    /// commit or a confirmed rollback is `CommitUncertain`, with the journal kept
    /// for a later resolve: a plain error means the VPS reported it rolled back.
    pub(super) fn commit(
        &mut self,
        session: &Session,
        target: &SshTarget,
        command: &str,
        phase: &'static str,
    ) -> Result<(), InstallerError> {
        let rollback = self.rollback_path();
        let mut remote = LiveCommit {
            session,
            reconnected: None,
            target,
            command,
            rollback: &rollback,
            operation: self.entry.operation,
            nonce: self.entry.nonce.clone(),
        };
        self.commit_with(&mut remote, phase)
    }

    /// The commit exchange over any remote, so tests can lose each reply.
    pub(super) fn commit_with(
        &mut self,
        remote: &mut impl CommitRemote,
        phase: &'static str,
    ) -> Result<(), InstallerError> {
        self.advance(TransactionStep::CommitSent)?;
        let error = match remote.send_commit() {
            Ok(()) => return self.committed(),
            Err(error) => phase_error(phase, error),
        };
        let mut state = remote.query();
        if after_failed_commit(state) == AfterFailedCommit::RollBack {
            // The commit may still hold the lock: the rollback then waits for it
            // and finds it committed. Only the VPS's answer afterwards counts.
            remote.roll_back();
            state = remote.query();
        }
        match after_failed_commit(state) {
            AfterFailedCommit::Committed => self.committed(),
            AfterFailedCommit::RolledBack => {
                let _ = self.advance(TransactionStep::RolledBack);
                Err(error)
            }
            // Not confirmed either way: the journal stays and every key is kept.
            AfterFailedCommit::RollBack | AfterFailedCommit::Uncertain => {
                Err(InstallerError::CommitUncertain {
                    nonce: self.entry.nonce.clone(),
                })
            }
        }
    }

    /// The VPS committed: a journal that cannot be removed must not turn that
    /// into a failure (callers delete keys on failure); resolve removes it later.
    fn committed(&mut self) -> Result<(), InstallerError> {
        let _ = self.advance(TransactionStep::Committed);
        Ok(())
    }

    fn rollback_path(&self) -> String {
        maintenance::rollback_path(
            &self.entry.nonce,
            self.entry.operation == TransactionOperation::Uninstall,
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum AfterFailedCommit {
    Committed,
    RollBack,
    RolledBack,
    Uncertain,
}

/// A failed commit request is not proof of anything: the commit may have run
/// before the failure. Only the VPS's answer decides; no answer is uncertain.
pub(super) fn after_failed_commit(state: Option<RemoteTransactionState>) -> AfterFailedCommit {
    match state {
        Some(RemoteTransactionState::Committed) => AfterFailedCommit::Committed,
        Some(RemoteTransactionState::Armed) => AfterFailedCommit::RollBack,
        Some(RemoteTransactionState::RolledBack) => AfterFailedCommit::RolledBack,
        // `Preparing` here means a script (perhaps this commit) still holds the lock.
        Some(RemoteTransactionState::Preparing | RemoteTransactionState::Unknown) | None => {
            AfterFailedCommit::Uncertain
        }
    }
}

/// The remote calls that settle a commit: each one's reply can be lost.
pub(super) trait CommitRemote {
    fn send_commit(&mut self) -> anyhow::Result<()>;
    /// The VPS's state for this transaction's nonce; `None` when it could not be asked.
    fn query(&mut self) -> Option<RemoteTransactionState>;
    fn roll_back(&mut self);
}

struct LiveCommit<'a> {
    session: &'a Session,
    /// The pinned session opened when the original one stopped answering.
    reconnected: Option<Session>,
    target: &'a SshTarget,
    command: &'a str,
    rollback: &'a str,
    operation: TransactionOperation,
    nonce: String,
}

impl LiveCommit<'_> {
    fn live(&self) -> &Session {
        self.reconnected.as_ref().unwrap_or(self.session)
    }
}

impl CommitRemote for LiveCommit<'_> {
    fn send_commit(&mut self) -> anyhow::Result<()> {
        run_privileged(self.session, self.target, self.command).map(drop)
    }

    fn query(&mut self) -> Option<RemoteTransactionState> {
        if let Ok(state) = remote_state(self.live(), self.target, self.operation, &self.nonce) {
            return Some(state);
        }
        self.reconnected = Some(reconnect(self.target)?);
        remote_state(self.live(), self.target, self.operation, &self.nonce).ok()
    }

    fn roll_back(&mut self) {
        run_rollback_now(self.live(), self.target, self.rollback);
    }
}

pub(super) fn reconnect(target: &SshTarget) -> Option<Session> {
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(2));
        }
        let Ok(session) = connect_transport(target) else {
            continue;
        };
        if verify_host_key(&session, target.expected_host_key_sha256.as_deref()).is_ok()
            && authenticate(&session, target).is_ok()
        {
            return Some(session);
        }
        return None;
    }
    None
}

fn query_state(
    session: &Session,
    target: &SshTarget,
    entry: &JournalEntry,
) -> Option<RemoteTransactionState> {
    remote_state(session, target, entry.operation, &entry.nonce).ok()
}

pub(super) fn remote_state(
    session: &Session,
    target: &SshTarget,
    operation: TransactionOperation,
    nonce: &str,
) -> Result<RemoteTransactionState, InstallerError> {
    if !valid_nonce(nonce) {
        return Err(InstallerError::InvalidInput(
            "the transaction identifier is invalid".to_owned(),
        ));
    }
    let output = run_privileged(
        session,
        target,
        &maintenance::state_command(nonce, operation == TransactionOperation::Uninstall),
    )
    .map_err(|error| phase_error("transaction status", error))?;
    RemoteTransactionState::parse(&output).ok_or_else(|| {
        phase_error(
            "transaction status",
            anyhow!("the VPS reported an unknown transaction state"),
        )
    })
}

/// What `resolve_transaction` found and did.
#[derive(Clone, Debug, Serialize)]
pub struct ResolvedTransaction {
    pub entry: JournalEntry,
    pub state: RemoteTransactionState,
}

impl ResolvedTransaction {
    /// The profile to keep: present only when the VPS confirms the commit.
    pub fn committed_profile(&self) -> Option<&ServerProfile> {
        (self.state == RemoteTransactionState::Committed)
            .then_some(self.entry.committed_profile.as_ref())
            .flatten()
    }
}

impl Provisioner {
    /// Read-only: where one transaction stands on the VPS. For a caller that got
    /// `CommitUncertain { nonce }` without a journal.
    pub fn transaction_status(
        target: &SshTarget,
        operation: TransactionOperation,
        nonce: &str,
    ) -> Result<RemoteTransactionState, InstallerError> {
        let session = pinned_session(target)?;
        remote_state(&session, target, operation, nonce)
    }

    /// Finish the transaction this device's journal names for `target`'s host: confirm a commit, or
    /// roll back one that is applied but uncommitted. The journal is removed once
    /// the VPS reports a final state. `None` means the journal was empty.
    pub fn resolve_transaction(
        target: &SshTarget,
        journal: &TransactionJournal,
    ) -> Result<Option<ResolvedTransaction>, InstallerError> {
        let Some(entry) = journal.read_server(&target.host)? else {
            return Ok(None);
        };
        if !same_host(&entry.host, &target.host)
            || entry.port != target.port
            || target.expected_host_key_sha256.as_deref() != Some(entry.host_key_sha256.as_str())
        {
            return Err(InstallerError::InvalidInput(
                "the unresolved transaction belongs to a different VPS or SSH host key".to_owned(),
            ));
        }
        let session = pinned_session(target)?;
        let mut state = remote_state(&session, target, entry.operation, &entry.nonce)?;
        // Without a sent commit, a VPS with no record never committed this nonce.
        if state == RemoteTransactionState::Unknown && entry.step != TransactionStep::CommitSent {
            state = RemoteTransactionState::RolledBack;
        }
        if state == RemoteTransactionState::Armed {
            run_rollback_now(
                &session,
                target,
                &maintenance::rollback_path(
                    &entry.nonce,
                    entry.operation == TransactionOperation::Uninstall,
                ),
            );
            state = remote_state(&session, target, entry.operation, &entry.nonce)?;
        }
        if state.is_final() {
            journal.remove(&entry.host)?;
        }
        Ok(Some(ResolvedTransaction { entry, state }))
    }
}

fn pinned_session(target: &SshTarget) -> Result<Session, InstallerError> {
    let session = connect_transport(target).map_err(|error| phase_error("connection", error))?;
    verify_host_key(&session, target.expected_host_key_sha256.as_deref())?;
    authenticate(&session, target)?;
    Ok(session)
}
