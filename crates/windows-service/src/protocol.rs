use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{EndpointTransitionResponse, ServerId};
use sirinvpn_tunnel_model::{LocalTunnelStatus, SwitchConnectRequest, TunnelConnectRequest};
use thiserror::Error;

pub const MAX_FRAME_BYTES: usize = 128 * 1024;
/// WireGuardNT's fixed UDP port for relayed sessions. Loopback carrier relays
/// accept datagrams only from 127.0.0.1 on this port. Same value as linux-helper; on
/// Windows any user may bind it first, so the pin narrows but does not stop a squatter.
pub const WIREGUARD_LISTEN_PORT: u16 = 1_023;
pub const IPC_VERSION: u16 = 1;

// The sole executable path operation installs routing rules; it never starts a
// process. Arguments/environment stay in the desktop. Windows supplies the SID.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRouteRequest {
    pub server_id: ServerId,
    pub executable: String,
}
/// Longest time a `WaitForChange` request is held open.
pub const MAX_WAIT_MS: u32 = 30_000;

/// Answered once the published status differs from the one numbered `after`
/// (immediately when `after` is absent or already stale), or after `timeout_ms`
/// (at most [`MAX_WAIT_MS`]) with the current status. Same ownership rules as Status.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusWait {
    pub after: Option<u64>,
    pub timeout_ms: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "payload",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum Operation {
    Status,
    Connect(TunnelConnectRequest),
    Disconnect,
    PauseForKeyRotation(ServerId),
    Resume(ServerId),
    PauseSession(ServerId),
    ReconnectSession(ServerId),
    SwitchSession(SwitchConnectRequest),
    ApplyEndpointCheckpoint(EndpointTransitionResponse),
    PublishEndpointCheckpoint(EndpointTransitionResponse),
    DisconnectSession(ServerId),
    RouteApplication(ApplicationRouteRequest),
    WaitForChange(StatusWait),
}

impl Operation {
    pub fn from_helper(command: &str, input: Option<&[u8]>) -> Result<Self, ServiceError> {
        let bytes = input.unwrap_or_default();
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ServiceError::InvalidRequest);
        }
        let invalid = |_| ServiceError::InvalidRequest;
        Ok(match command {
            "status" if bytes.is_empty() => Self::Status,
            "disconnect" if bytes.is_empty() => Self::Disconnect,
            "connect" => Self::Connect(serde_json::from_slice(bytes).map_err(invalid)?),
            "route-application" => {
                Self::RouteApplication(serde_json::from_slice(bytes).map_err(invalid)?)
            }
            "pause-for-key-rotation" => {
                Self::PauseForKeyRotation(serde_json::from_slice(bytes).map_err(invalid)?)
            }
            "resume" => Self::Resume(serde_json::from_slice(bytes).map_err(invalid)?),
            "pause-session" => Self::PauseSession(serde_json::from_slice(bytes).map_err(invalid)?),
            "reconnect-session" => {
                Self::ReconnectSession(serde_json::from_slice(bytes).map_err(invalid)?)
            }
            "switch-session" => {
                Self::SwitchSession(serde_json::from_slice(bytes).map_err(invalid)?)
            }
            "apply-endpoint-checkpoint" => {
                Self::ApplyEndpointCheckpoint(serde_json::from_slice(bytes).map_err(invalid)?)
            }
            "publish-endpoint-checkpoint" => {
                Self::PublishEndpointCheckpoint(serde_json::from_slice(bytes).map_err(invalid)?)
            }
            "disconnect-session" => {
                Self::DisconnectSession(serde_json::from_slice(bytes).map_err(invalid)?)
            }
            _ => return Err(ServiceError::InvalidRequest),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub operation: Operation,
}

impl Request {
    pub fn new(operation: Operation) -> Self {
        Self {
            version: IPC_VERSION,
            operation,
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, ServiceError> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(ServiceError::InvalidRequest);
        }
        let result: Self =
            serde_json::from_slice(bytes).map_err(|_| ServiceError::InvalidRequest)?;
        if result.version != IPC_VERSION {
            return Err(ServiceError::IncompatibleService);
        }
        Ok(result)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u16,
    pub result: Result<LocalTunnelStatus, ServiceError>,
    /// Number of the published status, sent only in reply to `WaitForChange` so
    /// older clients, which reject unknown fields, never see it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceError {
    #[error("The Windows networking service is unavailable. Repair the SirinVPN installation.")]
    Unavailable,
    #[error("The Windows networking service could not be authenticated.")]
    Unauthenticated,
    #[error("The Windows networking service needs a compatible application update.")]
    IncompatibleService,
    #[error("The local network request is invalid or unsupported.")]
    InvalidRequest,
    #[error("Another Windows user controls the current VPN session.")]
    OwnedByAnotherUser,
    #[error("The active VPN session changed. Refresh its status before retrying.")]
    SessionChanged,
    #[error("The Windows network operation failed. Check the tunnel and kill switch status.")]
    NetworkOperation,
    #[error("The Windows networking service is busy. Try again shortly.")]
    Busy,
    #[error(
        "Windows application routing requires the signed SirinVPN routing driver. Repair or update the installation."
    )]
    ApplicationDriverUnavailable,
    #[error(
        "Windows application routing requires the kill switch on and local-network access off."
    )]
    ApplicationPolicyRequired,
    #[error("Choose a native .exe on a fixed local drive, without links or redirected folders.")]
    InvalidApplication,
    #[error(
        "This session already routes 24 executables. Disconnect to clear the current selection."
    )]
    ApplicationLimit,
    #[error(
        "Another program is using the local port SirinVPN needs (127.0.0.1:{port}). Close it and try again.",
        port = WIREGUARD_LISTEN_PORT
    )]
    LocalPortInUse,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_operations_and_account_overrides_are_rejected() {
        for input in [
            r#"{"version":1,"operation":{"operation":"install-system"}}"#,
            r#"{"version":1,"operation":{"operation":"status"},"owner_sid":"S-1-5-18"}"#,
            r#"{"version":1,"operation":{"operation":"status","payload":"unexpected"}}"#,
            r#"{"version":2,"operation":{"operation":"status"}}"#,
        ] {
            assert!(Request::parse(input.as_bytes()).is_err());
        }
        assert!(Request::parse(br#"{"version":1,"operation":{"operation":"status"}}"#).is_ok());
        assert!(Operation::from_helper("status", Some(b"extra")).is_err());
        assert!(Operation::from_helper("launch-application", None).is_err());
        assert!(Request::parse(&vec![b' '; MAX_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn status_wait_is_additive_and_old_responses_carry_no_sequence() {
        let request = Request::parse(
            br#"{"version":1,"operation":{"operation":"wait-for-change","payload":{"after":7,"timeout_ms":30000}}}"#,
        )
        .unwrap();
        assert!(matches!(
            request.operation,
            Operation::WaitForChange(StatusWait {
                after: Some(7),
                timeout_ms: 30000
            })
        ));
        let plain = serde_json::to_value(Response {
            version: IPC_VERSION,
            result: Err(ServiceError::Busy),
            sequence: None,
        })
        .unwrap();
        assert!(plain.get("sequence").is_none());
        let parsed: Response =
            serde_json::from_str(r#"{"version":1,"result":{"Err":"busy"},"sequence":3}"#).unwrap();
        assert_eq!(parsed.sequence, Some(3));
    }
}
