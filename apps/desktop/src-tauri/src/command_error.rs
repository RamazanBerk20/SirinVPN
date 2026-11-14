//! The error a command rejects with. Without a code it is the plain message string, as
//! before; with one it is `{"message", "code", "params"}`, so the interface can tell the
//! case apart without reading the text. Codes come only from typed errors, never from text.

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Value, json};
use sirinvpn_core::{InvitationError, ManagementError};
use sirinvpn_installer::{InstallerError, hetzner::HetznerError};
use sirinvpn_protocol::ErrorCode;
use std::error::Error;

#[derive(Debug)]
pub(crate) struct CommandError {
    code: Option<&'static str>,
    message: String,
    params: Value,
}

impl CommandError {
    /// `params` values are strings or arrays of strings.
    pub(crate) fn coded(code: &'static str, message: impl Into<String>, params: Value) -> Self {
        Self {
            code: Some(code),
            message: message.into(),
            params,
        }
    }

    /// Keeps the code but shows `message`, for commands that word every failure themselves.
    pub(crate) fn with_message(self, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            ..self
        }
    }

    #[cfg(windows)]
    pub(crate) fn has_code(&self) -> bool {
        self.code.is_some()
    }

    pub(crate) fn into_message(self) -> String {
        self.message
    }
}

impl From<String> for CommandError {
    fn from(message: String) -> Self {
        Self {
            code: None,
            message,
            params: Value::Null,
        }
    }
}

impl From<&str> for CommandError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Serialize for CommandError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Some(code) = self.code else {
            return serializer.serialize_str(&self.message);
        };
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("message", &self.message)?;
        map.serialize_entry("code", code)?;
        map.serialize_entry(
            "params",
            &if self.params.is_object() {
                self.params.clone()
            } else {
                json!({})
            },
        )?;
        map.end()
    }
}

/// Which request the VPS refused, where its answer alone does not say what the UI needs.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum Refused {
    /// `create_port_forward` answered `InvalidInput`: the public port is reserved or invalid.
    PublicPort,
    /// Enrollment found no invitation for this code: it was used up or cancelled.
    InvitationUsed,
    /// `rename_member` conflicted while the person has device join codes.
    PersonHasJoinCodes,
}

/// A VPS refusal with the request context the boundary maps to a code.
#[derive(Debug)]
pub(crate) struct Rejected {
    pub(crate) refused: Refused,
    pub(crate) error: ManagementError,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl Error for Rejected {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

/// The one mapping from typed errors to a command error. The message is the error's own
/// text, as `safe_error` shows it; a busy server gets the shared "already in progress" text.
pub(crate) fn command_error(error: impl Into<anyhow::Error>) -> CommandError {
    let error = error.into();
    for cause in error.chain() {
        if let Some((code, params)) = code_of(cause) {
            let message = if code == "operation_in_progress" {
                crate::vps_transaction::OPERATION_IN_PROGRESS.to_owned()
            } else {
                error.to_string()
            };
            return CommandError::coded(code, message, params);
        }
    }
    crate::safe_error(error).into()
}

fn code_of(error: &(dyn Error + 'static)) -> Option<(&'static str, Value)> {
    use sirinvpn_core::ServerOperationError::AlreadyInProgress as Busy;
    use sirinvpn_core::{BackupError, ServerBackupError};
    use sirinvpn_core::{EndpointTransitionError as Endpoint, KeyRotationError as Rotation};
    let none = || json!({});
    #[cfg(not(target_os = "android"))]
    if let Some(error) = error.downcast_ref::<sirinvpn_release_fetch::FetchError>() {
        use sirinvpn_release_fetch::FetchFailure;
        return match error.failure() {
            FetchFailure::RateLimited => Some(("release_rate_limited", none())),
            FetchFailure::Offline => Some(("release_offline", none())),
            FetchFailure::NoRelease => Some(("release_none", none())),
            FetchFailure::Other => None,
        };
    }
    if let Some(error) = error.downcast_ref::<InstallerError>() {
        return match error {
            InstallerError::PhaseFailed { phase, .. } => {
                Some(("install_phase_failed", json!({"phase": phase})))
            }
            InstallerError::HostKeyUnknown { .. }
            | InstallerError::HostKeyMismatch
            | InstallerError::AuthenticationFailed => Some(("install_ssh_failed", none())),
            InstallerError::Incompatible(_) | InstallerError::ExistingInstallation => {
                Some(("install_incompatible", none()))
            }
            InstallerError::ServerBackup(ServerBackupError::AuthenticationFailed) => {
                Some(("backup_wrong_password", none()))
            }
            InstallerError::TransactionUnresolved { host } => {
                Some(("transaction_unresolved", json!({"host": host})))
            }
            _ => None,
        };
    }
    if let Some(HetznerError::Uncertain(server)) = error.downcast_ref::<HetznerError>() {
        return Some(("hetzner_create_uncertain", json!({"server": server})));
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
        return Some(("backup_wrong_password", none()));
    }
    match error.downcast_ref::<InvitationError>() {
        Some(InvitationError::Expired) => return Some(("invitation_expired", none())),
        Some(InvitationError::InvalidCode | InvitationError::InvalidSignature) => {
            return Some(("invitation_invalid", none()));
        }
        _ => {}
    }
    if let Some(rejected) = error.downcast_ref::<Rejected>() {
        if person_name_taken(&rejected.error) {
            return Some(("person_name_taken", none()));
        }
        return Some((
            match rejected.refused {
                Refused::PublicPort => "port_forward_public_port",
                Refused::InvitationUsed => "invitation_used",
                Refused::PersonHasJoinCodes => "person_has_join_codes",
            },
            none(),
        ));
    }
    if error
        .downcast_ref::<ManagementError>()
        .is_some_and(person_name_taken)
    {
        return Some(("person_name_taken", none()));
    }
    if matches!(
        error.downcast_ref::<ManagementError>(),
        Some(ManagementError::RequestRejected {
            code: ErrorCode::InvitationExpired,
            ..
        })
    ) {
        return Some(("invitation_expired", none()));
    }
    let busy = matches!(
        error.downcast_ref::<Rotation>(),
        Some(Rotation::Operation(Busy))
    ) || matches!(
        error.downcast_ref::<Endpoint>(),
        Some(Endpoint::Operation(Busy) | Endpoint::KeyRotation(Rotation::Operation(Busy)))
    ) || matches!(error.downcast_ref(), Some(Busy));
    busy.then(|| ("operation_in_progress", none()))
}

/// The VPS answers a taken person name with a plain conflict (older clients can't parse a new
/// code), so its fixed message is what tells it apart.
fn person_name_taken(error: &ManagementError) -> bool {
    matches!(error, ManagementError::RequestRejected {
        code: ErrorCode::ConflictDetected,
        message,
    } if message == sirinvpn_protocol::PERSON_NAME_TAKEN_MESSAGE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sirinvpn_core::{
        EndpointTransitionError, KeyRotationError, ServerBackupError, ServerOperationError,
    };

    fn code(error: impl Into<anyhow::Error>) -> (Option<&'static str>, Value) {
        let error = command_error(error);
        (error.code, serde_json::to_value(&error).unwrap())
    }

    #[test]
    fn an_error_without_a_code_is_still_a_plain_string() {
        let error = CommandError::from("Enter the SSH password.".to_owned());
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            json!("Enter the SSH password.")
        );
        let (code, value) = code(InstallerError::InvalidInput("bad".into()));
        assert_eq!(code, None);
        assert_eq!(value, json!("invalid installation input: bad"));
    }

    #[test]
    fn a_coded_error_carries_its_message_code_and_params() {
        let (_, value) = code(InstallerError::PhaseFailed {
            phase: "network preflight",
            message: "boom".into(),
        });
        assert_eq!(
            value,
            json!({"message": "server transaction failed during network preflight: boom",
                "code": "install_phase_failed", "params": {"phase": "network preflight"}})
        );
        let (_, value) = code(HetznerError::Uncertain("sirinvpn-0a1b2c3d".into()));
        assert_eq!(value["code"], "hetzner_create_uncertain");
        assert_eq!(value["params"], json!({"server": "sirinvpn-0a1b2c3d"}));
        assert!(
            value["message"]
                .as_str()
                .unwrap()
                .contains("sirinvpn-0a1b2c3d")
        );
    }

    #[test]
    fn each_typed_error_maps_to_its_code() {
        let rejected = |refused| Rejected {
            refused,
            error: ManagementError::RequestRejected {
                code: ErrorCode::InvalidInput,
                message: "x".into(),
            },
        };
        let busy = || ServerOperationError::AlreadyInProgress;
        let name_taken = || ManagementError::RequestRejected {
            code: ErrorCode::ConflictDetected,
            message: sirinvpn_protocol::PERSON_NAME_TAKEN_MESSAGE.into(),
        };
        let cases: Vec<(anyhow::Error, &str)> = vec![
            (InstallerError::HostKeyMismatch.into(), "install_ssh_failed"),
            (
                InstallerError::HostKeyUnknown {
                    fingerprint: "SHA256:x".into(),
                }
                .into(),
                "install_ssh_failed",
            ),
            (
                InstallerError::AuthenticationFailed.into(),
                "install_ssh_failed",
            ),
            (
                InstallerError::Incompatible("old".into()).into(),
                "install_incompatible",
            ),
            (
                InstallerError::ExistingInstallation.into(),
                "install_incompatible",
            ),
            (
                InstallerError::ServerBackup(ServerBackupError::AuthenticationFailed).into(),
                "backup_wrong_password",
            ),
            (
                InstallerError::TransactionUnresolved {
                    host: "203.0.113.1".into(),
                }
                .into(),
                "transaction_unresolved",
            ),
            (
                sirinvpn_core::BackupError::AuthenticationFailed.into(),
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
            (InvitationError::Expired.into(), "invitation_expired"),
            (InvitationError::InvalidCode.into(), "invitation_invalid"),
            (
                InvitationError::InvalidSignature.into(),
                "invitation_invalid",
            ),
            (
                ManagementError::RequestRejected {
                    code: ErrorCode::InvitationExpired,
                    message: "the invitation has expired".into(),
                }
                .into(),
                "invitation_expired",
            ),
            (rejected(Refused::InvitationUsed).into(), "invitation_used"),
            (
                rejected(Refused::PublicPort).into(),
                "port_forward_public_port",
            ),
            (
                rejected(Refused::PersonHasJoinCodes).into(),
                "person_has_join_codes",
            ),
            (name_taken().into(), "person_name_taken"),
            (
                Rejected {
                    refused: Refused::PersonHasJoinCodes,
                    error: name_taken(),
                }
                .into(),
                "person_name_taken",
            ),
            (busy().into(), "operation_in_progress"),
            (
                KeyRotationError::Operation(busy()).into(),
                "operation_in_progress",
            ),
            (
                EndpointTransitionError::Operation(busy()).into(),
                "operation_in_progress",
            ),
            (
                EndpointTransitionError::KeyRotation(KeyRotationError::Operation(busy())).into(),
                "operation_in_progress",
            ),
            // Found through a wrapper's source chain too.
            (
                anyhow::Error::from(InvitationError::Expired).context("joining failed"),
                "invitation_expired",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(code(error).0, Some(expected), "{expected}");
        }
        assert_eq!(
            code(busy()).1["message"],
            crate::vps_transaction::OPERATION_IN_PROGRESS
        );
        for uncoded in [
            anyhow::Error::from(InvitationError::BindingMismatch),
            anyhow::Error::from(InstallerError::RestoreTargetOccupied),
            anyhow::Error::from(ManagementError::ConnectionFailed),
            anyhow::anyhow!("text that says expired or reserved"),
        ] {
            assert_eq!(code(uncoded).0, None);
        }
    }
}
