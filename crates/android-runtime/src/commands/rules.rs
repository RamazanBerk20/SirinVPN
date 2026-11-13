//! Command rules that need no JNI: profile field ownership, coded errors and
//! transaction outcomes. Kept apart so they can be unit tested on the host.

use serde_json::{Value, json};
use sirinvpn_installer::{MaintenanceBlocker, RemoteTransactionState, ResolvedTransaction};
use sirinvpn_protocol::{ServerProfile, ServerRole};

/// An error the UI can tell apart: sent as `{"error": message, "code": code, "params": params}`.
#[derive(Debug)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
    pub params: Value,
}

impl CommandError {
    pub fn new(code: &'static str, message: impl Into<String>, params: Value) -> Self {
        Self {
            code,
            message: message.into(),
            params,
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CommandError {}

/// The response for an error that carries a code, or `None` for the generic mapping.
pub fn coded_error(error: &anyhow::Error) -> Option<Value> {
    use sirinvpn_core::ServerOperationError::AlreadyInProgress as Busy;
    use sirinvpn_core::{EndpointTransitionError as E, KeyRotationError as K};
    if let Some(error) = error.downcast_ref::<CommandError>() {
        return Some(json!({"error": error.message, "code": error.code, "params": error.params}));
    }
    let busy = matches!(error.downcast_ref::<K>(), Some(K::Operation(Busy)))
        || matches!(
            error.downcast_ref::<E>(),
            Some(E::Operation(Busy) | E::KeyRotation(K::Operation(Busy)))
        )
        || matches!(error.downcast_ref(), Some(Busy));
    busy.then(|| {
        json!({
            "error": "Another change to this server is already in progress. Wait for it to finish, then try again.",
            "code": "operation_in_progress",
            "params": {},
        })
    })
}

/// The response for a failed command: a coded error keeps its own message; a typed error
/// with a code keeps `message`, the generic text chosen for it; anything else is plain.
pub fn error_response(error: &anyhow::Error, message: String) -> Value {
    if let Some(coded) = coded_error(error) {
        return coded;
    }
    match error.chain().find_map(typed_code) {
        Some((code, params)) => json!({"error": message, "code": code, "params": params}),
        None => json!({ "error": message }),
    }
}

/// Codes the desktop app sends for the same typed errors (`command_error.rs` there).
fn typed_code(error: &(dyn std::error::Error + 'static)) -> Option<(&'static str, Value)> {
    use sirinvpn_core::{BackupError, InvitationError, ManagementError, ServerBackupError};
    use sirinvpn_installer::{InstallerError, hetzner::HetznerError};
    if let Some(error) = error.downcast_ref::<InstallerError>() {
        return match error {
            InstallerError::PhaseFailed { phase, .. } => {
                Some(("install_phase_failed", json!({ "phase": phase })))
            }
            InstallerError::HostKeyUnknown { .. }
            | InstallerError::HostKeyMismatch
            | InstallerError::AuthenticationFailed => Some(("install_ssh_failed", json!({}))),
            InstallerError::Incompatible(_) | InstallerError::ExistingInstallation => {
                Some(("install_incompatible", json!({})))
            }
            InstallerError::ServerBackup(ServerBackupError::AuthenticationFailed) => {
                Some(("backup_wrong_password", json!({})))
            }
            InstallerError::TransactionUnresolved { host } => {
                Some(("transaction_unresolved", json!({ "host": host })))
            }
            _ => None,
        };
    }
    if let Some(HetznerError::Uncertain(server)) = error.downcast_ref::<HetznerError>() {
        return Some((
            "hetzner_create_uncertain",
            json!({ "server": server, "name": server }),
        ));
    }
    if matches!(
        error.downcast_ref::<BackupError>(),
        Some(BackupError::AuthenticationFailed)
    ) || matches!(
        error.downcast_ref::<sirinvpn_core::EncryptedBackupError>(),
        Some(sirinvpn_core::EncryptedBackupError::AuthenticationFailed)
    ) || matches!(
        error.downcast_ref::<ServerBackupError>(),
        Some(ServerBackupError::AuthenticationFailed)
    ) {
        return Some(("backup_wrong_password", json!({})));
    }
    match error.downcast_ref::<InvitationError>() {
        Some(InvitationError::Expired) => return Some(("invitation_expired", json!({}))),
        Some(InvitationError::InvalidCode | InvitationError::InvalidSignature) => {
            return Some(("invitation_invalid", json!({})));
        }
        _ => {}
    }
    if error
        .downcast_ref::<ManagementError>()
        .is_some_and(person_name_taken)
    {
        return Some(("person_name_taken", json!({})));
    }
    matches!(
        error.downcast_ref::<ManagementError>(),
        Some(ManagementError::RequestRejected {
            code: sirinvpn_protocol::ErrorCode::InvitationExpired,
            ..
        })
    )
    .then(|| ("invitation_expired", json!({})))
}

/// The VPS answers a taken person name with a plain conflict (older clients can't parse a new
/// code), so its fixed message is what tells it apart.
pub fn person_name_taken(error: &sirinvpn_core::ManagementError) -> bool {
    matches!(error, sirinvpn_core::ManagementError::RequestRejected {
        code: sirinvpn_protocol::ErrorCode::ConflictDetected,
        message,
    } if message == sirinvpn_protocol::PERSON_NAME_TAKEN_MESSAGE)
}

/// A VPS refusal whose request tells which case it is (`port_forward_public_port`,
/// `invitation_used`, `person_has_join_codes`); the VPS's own text is kept.
pub fn refused(code: &'static str, error: sirinvpn_core::ManagementError) -> CommandError {
    CommandError::new(code, error.to_string(), json!({}))
}

pub fn maintenance_blocked(blockers: &[MaintenanceBlocker]) -> CommandError {
    let messages: Vec<&str> = blockers.iter().map(|blocker| blocker.message()).collect();
    CommandError::new(
        "maintenance_blocked",
        messages.join("\n"),
        json!({"blockers": blockers, "messages": messages}),
    )
}

/// `server_status` owns what the VPS reports about this device's membership. A status
/// fetched with an identity that has since been rotated away is not applied.
pub fn adopt_caller_fields(current: &mut ServerProfile, learned: &ServerProfile) {
    if current.identity_reference != learned.identity_reference {
        return;
    }
    current.role = learned.role;
    current.administrator = learned.administrator;
    current.member_id = learned.member_id;
    current.device_id = learned.device_id;
    current.subnet_routes = learned.subnet_routes.clone();
}

/// `transfer_ownership` owns only the role this device keeps afterwards.
pub fn demote_after_transfer(current: &mut ServerProfile) {
    current.role = ServerRole::Member;
    current.administrator = true;
}

/// Restore (or a repair/restore the VPS confirmed after a lost reply) owns the server
/// side: endpoint, transports and the restored server identity. A committed profile
/// that moved the endpoint without a signed generation keeps the old one pending, so
/// members can still be moved to the new VPS.
pub fn merge_committed(current: &mut ServerProfile, committed: &ServerProfile) {
    *current = sirinvpn_installer::merge_committed_profile(current, committed);
}

/// What the VPS said about a transaction whose commit reply was lost.
#[derive(Debug)]
pub enum Settlement {
    Committed(Box<ServerProfile>),
    RolledBack,
    /// Keep every key and the journal.
    Unknown(String),
}

pub fn settle<E: std::fmt::Display>(
    resolved: Result<Option<ResolvedTransaction>, E>,
) -> Settlement {
    match resolved {
        Ok(Some(resolved)) => match (resolved.state, resolved.committed_profile()) {
            (RemoteTransactionState::RolledBack, _) => Settlement::RolledBack,
            (RemoteTransactionState::Committed, Some(profile)) => {
                Settlement::Committed(Box::new(profile.clone()))
            }
            (state, _) => Settlement::Unknown(format!("{state:?}")),
        },
        Ok(None) => Settlement::Unknown("no transaction record".to_owned()),
        Err(error) => Settlement::Unknown(error.to_string()),
    }
}

pub fn outcome_unknown(host: &str, reason: &str) -> CommandError {
    CommandError::new(
        "install_outcome_unknown",
        "The VPS may have applied the change, but its confirmation was lost. This device kept its keys. Check the transaction again when the VPS is reachable.",
        json!({"host": host, "reason": reason}),
    )
}

pub fn rolled_back() -> CommandError {
    CommandError::new(
        "install_rolled_back",
        "The VPS rolled the change back, so nothing changed. You can retry the operation.",
        json!({}),
    )
}

/// A dry-run plan goes back to the UI: refuse it if any secret used for it appears in it.
pub fn ensure_no_secrets(plan: &Value, secrets: &[&str]) -> anyhow::Result<()> {
    let text = plan.to_string();
    for secret in secrets.iter().filter(|secret| secret.len() >= 4) {
        // The plan text is JSON, so look for the secret as JSON escapes it.
        let escaped = serde_json::to_string(secret)?;
        if text.contains(&escaped[1..escaped.len() - 1]) {
            anyhow::bail!("The plan would reveal a secret input; it was not returned.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sirinvpn_core::{ClientPaths, ServerOperationError};
    use sirinvpn_installer::{JournalEntry, TransactionOperation, TransactionStep};
    use sirinvpn_protocol::{ServerEndpoint, ServerId};

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

    /// A long flow loaded `stale`, then the user renamed and starred the server.
    fn store_with_concurrent_rename() -> (tempfile::TempDir, ClientPaths, ServerProfile) {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().join("client"));
        let stale = profile();
        paths.profile_store().insert(stale.clone()).unwrap();
        paths
            .profile_store()
            .update_presentation(stale.id, Some("Renamed".into()), Some(true))
            .unwrap();
        (directory, paths, stale)
    }

    fn saved(paths: &ClientPaths) -> ServerProfile {
        paths.profile_store().load().unwrap().remove(0)
    }

    #[test]
    fn status_update_keeps_a_concurrent_rename() {
        let (_directory, paths, stale) = store_with_concurrent_rename();
        let mut learned = stale.clone();
        learned.administrator = true;
        learned.role = ServerRole::Member;
        paths
            .profile_store()
            .update(stale.id, |current| {
                adopt_caller_fields(current, &learned);
                Ok(())
            })
            .unwrap();
        let saved = saved(&paths);
        assert_eq!((saved.name.as_str(), saved.favorite), ("Renamed", true));
        assert_eq!(
            (saved.role, saved.administrator),
            (ServerRole::Member, true)
        );
    }

    #[test]
    fn status_from_a_rotated_identity_is_ignored() {
        let mut current = profile();
        let mut learned = current.clone();
        learned.identity_reference = "rotated-away".into();
        learned.role = ServerRole::Member;
        adopt_caller_fields(&mut current, &learned);
        assert_eq!(current.role, ServerRole::Owner);
    }

    #[test]
    fn transfer_keeps_a_concurrent_rename() {
        let (_directory, paths, stale) = store_with_concurrent_rename();
        paths
            .profile_store()
            .update(stale.id, |current| {
                demote_after_transfer(current);
                Ok(())
            })
            .unwrap();
        let saved = saved(&paths);
        assert_eq!(saved.name, "Renamed");
        assert_eq!(
            (saved.role, saved.administrator),
            (ServerRole::Member, true)
        );
    }

    #[test]
    fn restore_keeps_a_concurrent_rename_and_the_old_endpoint_pending() {
        let (_directory, paths, stale) = store_with_concurrent_rename();
        let mut committed = stale.clone();
        committed.name = "From backup".into();
        committed.endpoint = ServerEndpoint {
            host: "198.51.100.7".into(),
            wireguard_port: 51820,
        };
        committed.pinned_server_certificate_pem = "new-cert".into();
        paths
            .profile_store()
            .update(stale.id, |current| {
                merge_committed(current, &committed);
                Ok(())
            })
            .unwrap();
        let saved = saved(&paths);
        assert_eq!((saved.name.as_str(), saved.favorite), ("Renamed", true));
        assert_eq!(saved.endpoint.host, "198.51.100.7");
        assert_eq!(saved.pinned_server_certificate_pem, "new-cert");
        assert_eq!(saved.pending_previous_endpoint.unwrap().host, "203.0.113.1");
    }

    #[test]
    fn a_busy_server_is_reported_as_in_progress() {
        let errors = [
            anyhow::Error::from(sirinvpn_core::KeyRotationError::Operation(
                ServerOperationError::AlreadyInProgress,
            )),
            anyhow::Error::from(sirinvpn_core::EndpointTransitionError::Operation(
                ServerOperationError::AlreadyInProgress,
            )),
        ];
        for error in errors {
            let coded = coded_error(&error).unwrap();
            assert_eq!(coded["code"], "operation_in_progress");
            assert!(
                coded["error"]
                    .as_str()
                    .unwrap()
                    .starts_with("Another change")
            );
        }
        assert!(coded_error(&anyhow::anyhow!("other")).is_none());
    }

    #[test]
    fn typed_errors_get_the_desktop_codes_and_keep_the_generic_message() {
        use sirinvpn_core::{BackupError, InvitationError, ManagementError, ServerBackupError};
        use sirinvpn_installer::{InstallerError, hetzner::HetznerError};
        let response = |error: anyhow::Error| error_response(&error, "generic".into());
        let phase = response(
            InstallerError::PhaseFailed {
                phase: "network preflight",
                message: "x".into(),
            }
            .into(),
        );
        assert_eq!(
            phase,
            json!({"error": "generic", "code": "install_phase_failed", "params": {"phase": "network preflight"}})
        );
        let cases: Vec<(anyhow::Error, &str)> = vec![
            (InstallerError::HostKeyMismatch.into(), "install_ssh_failed"),
            (
                InstallerError::AuthenticationFailed.into(),
                "install_ssh_failed",
            ),
            (
                InstallerError::Incompatible("x".into()).into(),
                "install_incompatible",
            ),
            (
                InstallerError::ExistingInstallation.into(),
                "install_incompatible",
            ),
            (
                BackupError::AuthenticationFailed.into(),
                "backup_wrong_password",
            ),
            (
                ServerBackupError::AuthenticationFailed.into(),
                "backup_wrong_password",
            ),
            (
                sirinvpn_core::EncryptedBackupError::AuthenticationFailed.into(),
                "backup_wrong_password",
            ),
            (
                InstallerError::ServerBackup(ServerBackupError::AuthenticationFailed).into(),
                "backup_wrong_password",
            ),
            (
                InstallerError::TransactionUnresolved { host: "x".into() }.into(),
                "transaction_unresolved",
            ),
            (InvitationError::Expired.into(), "invitation_expired"),
            (
                InvitationError::InvalidSignature.into(),
                "invitation_invalid",
            ),
            (
                ManagementError::RequestRejected {
                    code: sirinvpn_protocol::ErrorCode::InvitationExpired,
                    message: "x".into(),
                }
                .into(),
                "invitation_expired",
            ),
            (
                HetznerError::Uncertain("sirinvpn-1".into()).into(),
                "hetzner_create_uncertain",
            ),
            (
                ManagementError::RequestRejected {
                    code: sirinvpn_protocol::ErrorCode::ConflictDetected,
                    message: sirinvpn_protocol::PERSON_NAME_TAKEN_MESSAGE.into(),
                }
                .into(),
                "person_name_taken",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(response(error)["code"], code);
        }
        let uncertain = response(HetznerError::Uncertain("sirinvpn-1".into()).into());
        assert_eq!(uncertain["params"]["server"], "sirinvpn-1");
        assert_eq!(
            response(anyhow::anyhow!("expired")),
            json!({"error": "generic"})
        );
        let used = anyhow::Error::from(refused(
            "invitation_used",
            ManagementError::ConnectionFailed,
        ));
        assert_eq!(response(used)["code"], "invitation_used");
    }

    #[test]
    fn coded_errors_keep_their_code_and_parameters() {
        let error = anyhow::Error::from(CommandError::new(
            "hetzner_create_uncertain",
            "maybe",
            json!({"name": "sirinvpn-0a1b2c3d"}),
        ));
        assert_eq!(
            coded_error(&error).unwrap(),
            json!({"error": "maybe", "code": "hetzner_create_uncertain", "params": {"name": "sirinvpn-0a1b2c3d"}})
        );
        let blocked = maintenance_blocked(&[MaintenanceBlocker::Connected]);
        assert_eq!(blocked.params["blockers"], json!(["connected"]));
        assert_eq!(blocked.message, MaintenanceBlocker::Connected.message());
    }

    fn resolved(
        state: RemoteTransactionState,
        profile: Option<ServerProfile>,
    ) -> ResolvedTransaction {
        ResolvedTransaction {
            entry: JournalEntry {
                schema_version: 1,
                operation: TransactionOperation::Install,
                nonce: "0".repeat(32),
                host: "203.0.113.1".into(),
                port: 22,
                host_key_sha256: "SHA256:pin".into(),
                step: TransactionStep::CommitSent,
                committed_profile: profile,
            },
            state,
        }
    }

    #[test]
    fn only_a_confirmed_commit_or_rollback_settles() {
        use RemoteTransactionState::*;
        let ok = |state, profile| settle::<String>(Ok(Some(resolved(state, profile))));
        assert!(matches!(
            ok(Committed, Some(profile())),
            Settlement::Committed(_)
        ));
        assert!(matches!(ok(RolledBack, None), Settlement::RolledBack));
        for state in [Committed, Armed, Preparing, Unknown] {
            assert!(matches!(ok(state, None), Settlement::Unknown(_)));
        }
        assert!(matches!(settle(Err("unreachable")), Settlement::Unknown(_)));
        assert!(matches!(settle::<String>(Ok(None)), Settlement::Unknown(_)));
    }

    #[test]
    fn a_plan_that_echoes_a_secret_is_refused() {
        let secrets = ["hunter2-\"secret\""];
        assert!(ensure_no_secrets(&json!({"steps": ["echo hi"]}), &secrets).is_ok());
        let echoed = json!({"steps": ["echo hunter2-\"secret\""]});
        assert!(ensure_no_secrets(&echoed, &secrets).is_err());
    }
}
