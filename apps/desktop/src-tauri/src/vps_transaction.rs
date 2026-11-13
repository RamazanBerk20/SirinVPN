//! Shared rules for Owner VPS maintenance: the transaction journal and lost
//! commit replies, Owner preconditions, the server payload, dry runs and the
//! "already in progress" answer.

use super::*;
use serde_json::{Value, json};
use sirinvpn_core::ProfileStoreError;
use sirinvpn_installer::{
    InstallPlan, InstallerError, MaintenanceBlocker, OwnerDeviceState, OwnerMaintenance,
    RemoteTransactionState, ResolvedTransaction, ServerBinarySource, TransactionJournal,
    TransactionOperation, owner_maintenance_ready,
};

pub(crate) const OPERATION_IN_PROGRESS: &str =
    "Another change to this server is already in progress. Wait for it to finish, then try again.";
const ROLLED_BACK: &str = "The VPS rolled the change back, so nothing changed. You can try again.";

pub(crate) fn rolled_back() -> CommandError {
    CommandError::coded("install_rolled_back", ROLLED_BACK, json!({}))
}

/// Key rotations and endpoint updates share one lock per server; a second runner
/// gets one clear answer (`operation_in_progress`) instead of the lock's internals.
pub(crate) fn operation_error<E: std::error::Error + Send + Sync + 'static>(
    error: E,
) -> CommandError {
    command_error(error)
}

/// One journal file per VPS host, beside the path the CLI and Android use.
pub(crate) fn journal(paths: &ClientPaths) -> TransactionJournal {
    TransactionJournal::new(paths.configuration_directory.join("vps-transaction.json"))
}

/// The packaged server payload: one per VPS architecture when both are shipped.
pub(crate) fn server_payload() -> Result<ServerBinarySource, String> {
    #[cfg(debug_assertions)]
    if let Some(path) = env::var_os("SIRINVPN_SERVER_BINARY")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
    {
        return Ok(path.into());
    }
    // Windows ships the x86_64 payload under the unsuffixed name.
    #[cfg(windows)]
    const X86_64: &str = "sirinvpn-server";
    #[cfg(not(windows))]
    const X86_64: &str = "sirinvpn-server-x86_64";
    let x86_64 = resolve_binary(
        "SIRINVPN_SERVER_BINARY_X86_64",
        "/usr/lib/sirinvpn/sirinvpn-server-x86_64",
        X86_64,
    );
    let aarch64 = resolve_binary(
        "SIRINVPN_SERVER_BINARY_AARCH64",
        "/usr/lib/sirinvpn/sirinvpn-server-aarch64",
        "sirinvpn-server-aarch64",
    );
    if let (Ok(x86_64), Ok(aarch64)) = (x86_64, aarch64) {
        return Ok(ServerBinarySource::by_architecture(x86_64, aarch64));
    }
    resolve_binary(
        "SIRINVPN_SERVER_BINARY",
        "/usr/lib/sirinvpn/sirinvpn-server",
        "sirinvpn-server",
    )
    .map(Into::into)
    .map_err(safe_error)
}

/// The shared Owner maintenance rules, asked before every operation that changes
/// or reads the VPS as its Owner. Every blocker is reported, one sentence each.
pub(crate) fn ensure_owner_maintenance_ready(
    paths: &ClientPaths,
    profile: &ServerProfile,
    operation: OwnerMaintenance,
) -> Result<(), CommandError> {
    let status = invoke_helper("status", None).map_err(safe_error)?;
    let state = OwnerDeviceState {
        role: profile.role,
        disconnected: status.state == ConnectionState::Disconnected,
        kill_switch_enabled: status.kill_switch_enabled,
        auto_reconnect_enabled: status.auto_reconnect_enabled,
        pending_key_rotation: has_pending_key_rotation(paths, profile.id).map_err(safe_error)?,
        unresolved_transaction: journal(paths).blocks_server(profile).map_err(safe_error)?,
    };
    owner_maintenance_ready(operation, &state).map_err(|blockers| maintenance_blocked(&blockers))
}

/// `params` mirror Android: the blocker names and their messages, one sentence each.
pub(crate) fn maintenance_blocked(blockers: &[MaintenanceBlocker]) -> CommandError {
    let messages: Vec<String> = blockers
        .iter()
        .map(|blocker| {
            let message = blocker.message();
            let mut first = message.chars();
            let head = first
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_default();
            format!("{head}{}.", first.as_str())
        })
        .collect();
    CommandError::coded(
        "maintenance_blocked",
        messages.join(" "),
        json!({"blockers": blockers, "messages": messages}),
    )
}

/// What the VPS said about a transaction whose commit reply was lost.
pub(crate) enum Settlement {
    Committed(Box<ServerProfile>),
    RolledBack,
    /// Keep every key and the journal.
    Unknown(String),
}

pub(crate) fn settle(resolved: &Result<Option<ResolvedTransaction>, InstallerError>) -> Settlement {
    match resolved {
        Ok(Some(resolved)) => match (resolved.state, resolved.committed_profile()) {
            (RemoteTransactionState::RolledBack, _) => Settlement::RolledBack,
            (RemoteTransactionState::Committed, Some(profile)) => {
                Settlement::Committed(Box::new(profile.clone()))
            }
            (state, _) => Settlement::Unknown(format!("the VPS reports it as {state:?}")),
        },
        Ok(None) => Settlement::Unknown("this device has no record of the change".to_owned()),
        Err(error) => Settlement::Unknown(error.to_string()),
    }
}

pub(crate) fn outcome_unknown(host: &str, reason: &str) -> CommandError {
    CommandError::coded(
        "install_outcome_unknown",
        format!(
            "The outcome on {host} is unknown: the VPS may have applied the change, but its confirmation was lost ({reason}). This device kept its keys. Check the change again when the VPS is reachable."
        ),
        json!({"host": host, "reason": reason}),
    )
}

/// A confirmed commit owns the server side: endpoint, transports and the server
/// identity. An endpoint moved without a signed generation keeps the old one
/// pending, so members can still be moved to the new VPS.
pub(crate) fn merge_committed(current: &mut ServerProfile, committed: &ServerProfile) {
    *current = sirinvpn_installer::merge_committed_profile(current, committed);
}

/// Saves a profile the VPS confirmed: merged into the saved one, else a new install.
pub(crate) fn save_committed(
    paths: &ClientPaths,
    committed: &ServerProfile,
) -> Result<ServerProfile, String> {
    let store = paths.profile_store();
    match store.update(committed.id, |current| {
        merge_committed(current, committed);
        Ok(current.clone())
    }) {
        Err(ProfileStoreError::NotFound) => {
            store.upsert(committed.clone()).map_err(safe_error)?;
            Ok(committed.clone())
        }
        saved => saved.map_err(safe_error),
    }
}

/// Restores a VPS backup through the journal and keeps only the server side of
/// the saved profile. Called by `restore_vps_backup`.
pub(crate) fn restore_server(
    paths: &ClientPaths,
    request: sirinvpn_installer::ServerRestoreRequest,
) -> Result<Value, CommandError> {
    let id = request.profile.id;
    let pinned = request.target.clone();
    let journal = journal(paths);
    match Provisioner::restore_server_backup_with_journal(request, &journal) {
        Ok(outcome) => {
            let saved = paths
                .profile_store()
                .update(id, |current| {
                    merge_committed(current, &outcome.profile);
                    Ok(current.clone())
                })
                .map_err(|_| {
                    CommandError::from("The VPS was restored, but this device couldn’t save its new address. Before connecting, restore again with “Replace an existing SirinVPN install” on.")
                })?;
            let mut output = serde_json::to_value(&outcome).map_err(safe_error)?;
            output["profile"] = serde_json::to_value(saved).map_err(safe_error)?;
            Ok(output)
        }
        Err(InstallerError::CommitUncertain { .. }) => {
            match settle(&Provisioner::resolve_transaction(&pinned, &journal)) {
                Settlement::Committed(committed) => Ok(json!({
                    "events": [], "profile": save_committed(paths, &committed)?,
                    "resolved_after_lost_reply": true,
                })),
                Settlement::RolledBack => Err(rolled_back()),
                Settlement::Unknown(reason) => Err(outcome_unknown(&pinned.host, &reason)),
            }
        }
        Err(error) => Err(command_error(error)),
    }
}

/// A fresh SSH login for the VPS the journal names; host, port and pin come from the journal.
/// Other login fields (port, pin) are ignored, as on Android.
#[derive(Default, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct TransactionLoginInput {
    #[serde(default)]
    username: String,
    /// "saved" (the default) uses this host's remembered login.
    #[serde(default)]
    authentication: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    private_key_path: Option<String>,
    #[serde(default)]
    private_key_passphrase: Option<String>,
    #[serde(default)]
    sudo_password: Option<String>,
}

fn transaction_target(
    entry: &sirinvpn_installer::JournalEntry,
    login: &mut TransactionLoginInput,
) -> Result<SshTarget, String> {
    let authentication = std::mem::take(&mut login.authentication);
    crate::ssh_login::resolve_target(crate::ssh_login::SshLoginInput {
        host: entry.host.clone(),
        ssh_port: entry.port,
        username: std::mem::take(&mut login.username),
        authentication: if authentication.is_empty() {
            "saved".to_owned()
        } else {
            authentication
        },
        password: login.password.take(),
        private_key_path: login.private_key_path.take(),
        private_key_passphrase: login.private_key_passphrase.take(),
        sudo_password: login.sudo_password.take(),
        host_key_sha256: entry.host_key_sha256.clone(),
    })
}

fn summary(entry: &sirinvpn_installer::JournalEntry) -> Value {
    json!({
        "transaction": entry.nonce, "host": entry.host, "port": entry.port,
        "operation": entry.operation, "step": entry.step,
        "server_id": entry.committed_profile.as_ref().map(|profile| profile.id),
        "state": null,
    })
}

/// The unresolved transaction on `host`, or else the first one on this device.
fn unresolved(
    paths: &ClientPaths,
    host: Option<&str>,
) -> Result<Option<sirinvpn_installer::JournalEntry>, CommandError> {
    let journal = journal(paths);
    match host {
        Some(host) => journal.read_server(host),
        None => journal.read(),
    }
    .map_err(|error| safe_error(error).into())
}

/// The unresolved VPS transaction on this device (on `host` when given), if any.
/// With a login, it also asks the VPS where the transaction stands (read-only).
#[tauri::command]
pub(crate) async fn install_transaction_status(
    state: State<'_, AppState>,
    input: Option<TransactionLoginInput>,
    host: Option<String>,
) -> Result<Option<Value>, CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<_, CommandError> {
        let Some(entry) = unresolved(&paths, host.as_deref())? else {
            return Ok(None);
        };
        let mut summary = summary(&entry);
        if let Some(mut login) = input {
            let target = transaction_target(&entry, &mut login)?;
            let state = Provisioner::transaction_status(&target, entry.operation, &entry.nonce)
                .map_err(command_error)?;
            summary["state"] = json!(state);
        }
        Ok(Some(summary))
    })
    .await
    .map_err(|_| CommandError::from("Checking the VPS change was interrupted. Try again."))?
}

/// Finishes the transaction the journal names (on `host` when given): keeps a
/// confirmed commit, or rolls an uncommitted one back. Nothing local is deleted
/// unless the VPS confirms the rollback.
#[tauri::command]
pub(crate) async fn resolve_install_transaction(
    state: State<'_, AppState>,
    input: TransactionLoginInput,
    host: Option<String>,
) -> Result<Option<Value>, CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || resolve_blocking(&paths, input, host.as_deref()))
        .await
        .map_err(|_| CommandError::from("Checking the VPS change was interrupted. Try again."))?
}

/// Forgets the unresolved transaction on `host` without contacting the VPS. The
/// VPS may have committed or rolled the change back; every key is kept. `None`
/// when nothing was recorded for that host.
#[tauri::command]
pub(crate) async fn abandon_install_transaction(
    state: State<'_, AppState>,
    host: String,
) -> Result<Option<Value>, CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || abandon_blocking(&paths, &host))
        .await
        .map_err(|_| CommandError::from("Forgetting the VPS change was interrupted. Try again."))?
}

pub(crate) fn abandon_blocking(
    paths: &ClientPaths,
    host: &str,
) -> Result<Option<Value>, CommandError> {
    let journal = journal(paths);
    let entry = journal.read_server(host).ok().flatten();
    if !journal.abandon(host).map_err(safe_error)? {
        return Ok(None);
    }
    let mut summary = entry
        .as_ref()
        .map_or_else(|| json!({"host": host}), summary);
    summary["state"] = json!("abandoned");
    summary["keys_kept"] = json!(true);
    Ok(Some(summary))
}

fn resolve_blocking(
    paths: &ClientPaths,
    mut input: TransactionLoginInput,
    host: Option<&str>,
) -> Result<Option<Value>, CommandError> {
    let journal = journal(paths);
    let Some(entry) = unresolved(paths, host)? else {
        return Ok(None);
    };
    let mut summary = summary(&entry);
    let target = transaction_target(&entry, &mut input)?;
    let resolved = Provisioner::resolve_transaction(&target, &journal);
    // An uninstall commits nothing to keep; removing the local server is a separate step.
    if entry.operation == TransactionOperation::Uninstall
        && matches!(&resolved, Ok(Some(done)) if done.state == RemoteTransactionState::Committed)
    {
        summary["state"] = json!("committed");
        return Ok(Some(summary));
    }
    match settle(&resolved) {
        Settlement::Committed(committed) => {
            summary["profile"] =
                serde_json::to_value(save_committed(paths, &committed)?).map_err(safe_error)?;
            summary["state"] = json!("committed");
            crate::hetzner::forget_installed(&paths.configuration_directory, &entry.host);
        }
        Settlement::RolledBack => {
            summary["state"] = json!("rolled_back");
            discard_rolled_back_install(paths, &entry)?;
        }
        Settlement::Unknown(reason) => return Err(outcome_unknown(&entry.host, &reason)),
    }
    Ok(Some(summary))
}

/// A rolled-back install leaves a new Owner key no saved server uses: delete it.
fn discard_rolled_back_install(
    paths: &ClientPaths,
    entry: &sirinvpn_installer::JournalEntry,
) -> Result<(), String> {
    let Some(planned) = &entry.committed_profile else {
        return Ok(());
    };
    let in_use = paths
        .profile_store()
        .load()
        .map_err(safe_error)?
        .iter()
        .any(|profile| {
            profile.id == planned.id || profile.identity_reference == planned.identity_reference
        });
    if !in_use
        && paths
            .secret_store()
            .delete(&planned.identity_reference)
            .is_err()
    {
        return Err("The VPS rolled the setup back, but its new key couldn’t be deleted. Unlock secure storage and check again.".to_owned());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum PlanInput {
    Install(ProvisionInput),
    Repair(RepairInput),
    Restore(VpsRestoreInput),
    Uninstall(UninstallInput),
}

/// Dry run: what the operation would run and change on the VPS. Nothing changes,
/// and no secret used for it is returned.
#[tauri::command]
pub(crate) async fn plan_server_operation(
    state: State<'_, AppState>,
    input: PlanInput,
) -> Result<Value, CommandError> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || plan_blocking(&paths, input))
        .await
        .map_err(|_| CommandError::from("Preparing the plan was interrupted. Try again."))?
}

fn owner_profile(paths: &ClientPaths, server_id: &str) -> Result<ServerProfile, String> {
    let profile = find_profile(paths, server_id)?;
    if profile.role != ServerRole::Owner {
        return Err("Only the Owner can maintain this VPS.".to_owned());
    }
    Ok(profile)
}

fn plan_blocking(paths: &ClientPaths, input: PlanInput) -> Result<Value, CommandError> {
    let mut extra = Vec::new();
    let (plan, target) = match input {
        PlanInput::Install(mut input) => {
            let identity = new_identity_for_server(&input.name).map_err(safe_error)?;
            let request = install_request(&mut input, ServerId::new(), identity.public)?;
            let target = request.target.clone();
            (Provisioner::plan_install(request), target)
        }
        PlanInput::Repair(mut input) => {
            let profile = owner_profile(paths, &input.server_id)?;
            let request = repair_request(paths, &mut input, &profile)?;
            let target = request.target.clone();
            (Provisioner::plan_repair(request), target)
        }
        PlanInput::Restore(mut input) => {
            let profile = owner_profile(paths, &input.server_id)?;
            let request = restore_request(paths, &mut input, profile)?;
            extra.push(request.password.clone());
            let target = request.target.clone();
            (Provisioner::plan_restore_server_backup(request), target)
        }
        PlanInput::Uninstall(mut input) => {
            let profile = owner_profile(paths, &input.server_id)?;
            let request = uninstall_request(&profile, &mut input)?;
            let target = request.target.clone();
            (Provisioner::plan_uninstall(request), target)
        }
    };
    let plan = plan.map_err(command_error)?;
    let mut secrets: Vec<&str> = extra.iter().map(|secret| secret.as_str()).collect();
    secrets.extend(target_secrets(&target));
    Ok(plan_output(&plan, &secrets)?)
}

fn target_secrets(target: &SshTarget) -> Vec<&str> {
    let mut secrets: Vec<&str> = target.sudo_password.iter().map(|s| s.as_str()).collect();
    match &target.authentication {
        SshAuthentication::Password(password) => secrets.push(password),
        SshAuthentication::PrivateKey { passphrase, .. } => {
            secrets.extend(passphrase.as_deref().map(String::as_str))
        }
        SshAuthentication::PrivateKeyMemory {
            private_key_pem,
            passphrase,
        } => {
            secrets.push(private_key_pem);
            secrets.extend(passphrase.as_deref().map(String::as_str));
        }
        SshAuthentication::Agent => {}
    }
    secrets
}

/// Refuses a plan that would show any secret used to make it.
fn plan_output(plan: &InstallPlan, secrets: &[&str]) -> Result<Value, String> {
    let value = serde_json::to_value(plan).map_err(safe_error)?;
    let text = value.to_string();
    for secret in secrets.iter().filter(|secret| secret.len() >= 4) {
        // The plan is JSON, so look for the secret as JSON escapes it.
        let escaped = serde_json::to_string(secret).map_err(safe_error)?;
        if text.contains(&escaped[1..escaped.len() - 1]) {
            return Err(
                "The plan would reveal a secret you entered, so it was not shown.".to_owned(),
            );
        }
    }
    Ok(value)
}

/// Builds a restore request; `restore_vps_backup` and the dry run share it.
pub(crate) fn restore_request(
    paths: &ClientPaths,
    input: &mut VpsRestoreInput,
    profile: ServerProfile,
) -> Result<sirinvpn_installer::ServerRestoreRequest, String> {
    if input.path.trim().is_empty() || input.host.trim().is_empty() {
        return Err("Choose an encrypted VPS backup and destination host.".to_owned());
    }
    let source =
        crate::picked_files::granted(crate::picked_files::Purpose::VpsBackupRestore, &input.path)?;
    let identity = explicit_secret(paths, &profile.identity_reference)?
        .public_identity(&profile.client_management_certificate_pem)
        .map_err(safe_error)?;
    Ok(sirinvpn_installer::ServerRestoreRequest {
        profile,
        target: crate::ssh_login::resolve_target(crate::ssh_login::SshLoginInput {
            host: input.host.trim().to_owned(),
            ssh_port: input.ssh_port,
            username: input.username.clone(),
            authentication: input.authentication.clone(),
            password: input.password.take(),
            private_key_path: input.private_key_path.take(),
            private_key_passphrase: input.private_key_passphrase.take(),
            sudo_password: input.sudo_password.take(),
            host_key_sha256: input.host_key_sha256.clone(),
        })?,
        server_binary: server_payload()?,
        identity,
        source,
        password: Zeroizing::new(std::mem::take(&mut input.backup_password)),
        replace_existing_installation: input.replace_existing,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sirinvpn_core::{KeyRotationError, ServerOperationError};

    fn profile() -> ServerProfile {
        serde_json::from_value(json!({
            "schema_version": 1, "id": ServerId::new(), "name": "Home",
            "endpoint": {"host": "203.0.113.1", "wireguard_port": 51820},
            "client_tunnel_address": "10.0.0.2", "server_tunnel_address": "10.0.0.1",
            "server_wireguard_public_key": "old-key", "pinned_server_certificate_pem": "old-cert",
            "client_management_certificate_pem": "client-cert", "identity_reference": "identity",
            "role": "owner",
        }))
        .unwrap()
    }

    /// The store holds `profile`, then the user renames and stars it.
    pub(crate) fn store_with_rename(profile: &ServerProfile) -> (tempfile::TempDir, ClientPaths) {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().to_path_buf());
        paths.profile_store().upsert(profile.clone()).unwrap();
        paths
            .profile_store()
            .update_presentation(profile.id, Some("Renamed".into()), Some(true))
            .unwrap();
        (directory, paths)
    }

    fn saved(paths: &ClientPaths, id: ServerId) -> ServerProfile {
        paths
            .profile_store()
            .load()
            .unwrap()
            .into_iter()
            .find(|profile| profile.id == id)
            .unwrap()
    }

    #[test]
    fn a_busy_server_is_reported_as_in_progress() {
        use sirinvpn_core::EndpointTransitionError as Endpoint;
        let busy = || ServerOperationError::AlreadyInProgress;
        let message = |error: CommandError| error.into_message();
        assert_eq!(
            message(operation_error(KeyRotationError::Operation(busy()))),
            OPERATION_IN_PROGRESS
        );
        assert_eq!(
            message(operation_error(Endpoint::Operation(busy()))),
            OPERATION_IN_PROGRESS
        );
        assert_eq!(
            message(operation_error(Endpoint::KeyRotation(
                KeyRotationError::Operation(busy())
            ))),
            OPERATION_IN_PROGRESS
        );
        assert_eq!(message(operation_error(busy())), OPERATION_IN_PROGRESS);
        assert_ne!(
            message(operation_error(Endpoint::OwnerRequired)),
            OPERATION_IN_PROGRESS
        );
    }

    #[test]
    fn transaction_outcomes_and_blockers_are_coded() {
        let value = |error: CommandError| serde_json::to_value(error).unwrap();
        let unknown = value(outcome_unknown(
            "203.0.113.1",
            "the VPS reports it as Armed",
        ));
        assert_eq!(unknown["code"], "install_outcome_unknown");
        assert_eq!(
            unknown["params"],
            json!({"host": "203.0.113.1", "reason": "the VPS reports it as Armed"})
        );
        let rolled = value(rolled_back());
        assert_eq!(
            (rolled["code"].as_str(), rolled["message"].as_str()),
            (Some("install_rolled_back"), Some(ROLLED_BACK))
        );
        let blocked = value(maintenance_blocked(&[MaintenanceBlocker::Connected]));
        assert_eq!(blocked["code"], "maintenance_blocked");
        assert_eq!(blocked["params"]["blockers"], json!(["connected"]));
        assert_eq!(blocked["params"]["messages"], json!([blocked["message"]]));
    }

    #[test]
    fn every_blocker_is_one_sentence() {
        let state = OwnerDeviceState {
            role: ServerRole::Owner,
            disconnected: false,
            kill_switch_enabled: true,
            auto_reconnect_enabled: false,
            pending_key_rotation: false,
            unresolved_transaction: true,
        };
        let blockers = owner_maintenance_ready(OwnerMaintenance::Repair, &state).unwrap_err();
        assert_eq!(
            maintenance_blocked(&blockers).into_message(),
            "Disconnect from this VPS first. Turn off the kill switch and auto-reconnect first. Resolve the interrupted VPS maintenance transaction first."
        );
    }

    #[test]
    fn a_confirmed_commit_keeps_a_concurrent_rename() {
        let stale = profile();
        let (_directory, paths) = store_with_rename(&stale);
        let mut committed = stale.clone();
        committed.endpoint.host = "198.51.100.7".into();
        committed.server_wireguard_public_key = "new-key".into();
        let kept = save_committed(&paths, &committed).unwrap();
        let saved = saved(&paths, stale.id);
        assert_eq!(kept, saved);
        assert_eq!((saved.name.as_str(), saved.favorite), ("Renamed", true));
        assert_eq!(saved.endpoint.host, "198.51.100.7");
        assert_eq!(saved.server_wireguard_public_key, "new-key");
        // Moved without a signed generation: the old endpoint stays pending for members.
        assert_eq!(saved.pending_previous_endpoint.unwrap().host, "203.0.113.1");
    }

    #[test]
    fn abandoning_forgets_one_hosts_transaction_and_keeps_its_keys() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().to_path_buf());
        let entry = sirinvpn_installer::JournalEntry {
            schema_version: 1,
            operation: TransactionOperation::Install,
            nonce: "0".repeat(32),
            host: "203.0.113.1".into(),
            port: 22,
            host_key_sha256: "SHA256:pin".into(),
            step: sirinvpn_installer::TransactionStep::CommitSent,
            committed_profile: Some(profile()),
        };
        // Written as the previous version did: one file for the device.
        std::fs::write(journal(&paths).path(), serde_json::to_vec(&entry).unwrap()).unwrap();
        paths.profile_store().upsert(profile()).unwrap();
        let other = profile();
        let mut moved = other.clone();
        moved.endpoint.host = "198.51.100.7".into();
        moved.id = ServerId::new();
        assert!(journal(&paths).blocks_server(&profile()).unwrap());
        assert!(!journal(&paths).blocks_server(&moved).unwrap());

        assert!(abandon_blocking(&paths, "198.51.100.7").unwrap().is_none());
        let abandoned = abandon_blocking(&paths, "203.0.113.1").unwrap().unwrap();
        assert_eq!(
            (
                abandoned["state"].as_str(),
                abandoned["keys_kept"].as_bool()
            ),
            (Some("abandoned"), Some(true))
        );
        assert_eq!(abandoned["transaction"], json!("0".repeat(32)));
        assert!(journal(&paths).read().unwrap().is_none());
        assert_eq!(paths.profile_store().load().unwrap().len(), 1);
    }

    #[test]
    fn a_committed_install_is_saved_as_new() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().to_path_buf());
        let committed = profile();
        save_committed(&paths, &committed).unwrap();
        assert_eq!(saved(&paths, committed.id), committed);
    }

    #[test]
    fn a_plan_that_echoes_a_secret_is_refused() {
        let plan: InstallPlan = InstallPlan {
            operation: "repair",
            host: "203.0.113.1".into(),
            nonce: "n".into(),
            discovery: None,
            network_preflight: None,
            managed_paths: vec![],
            steps: vec![sirinvpn_installer::PlanStep::Run {
                privileged: true,
                command: "echo 'pa\"ss-word'".into(),
                stdin_bytes: None,
            }],
        };
        assert!(plan_output(&plan, &["pa\"ss-word"]).is_err());
        assert!(plan_output(&plan, &["other-secret", "abc"]).is_ok());
    }
}
