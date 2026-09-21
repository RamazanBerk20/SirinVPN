use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{EndpointTransitionResponse, ServerId};
use sirinvpn_tunnel_model::{LocalTunnelStatus, SwitchConnectRequest, TunnelConnectRequest};
use thiserror::Error;

pub const MAX_FRAME_BYTES: usize = 128 * 1024;
pub const IPC_VERSION: u16 = 1;

// The sole executable path operation installs routing rules; it never starts a
// process. Arguments/environment stay in the desktop. Windows supplies the SID.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRouteRequest {
    pub server_id: ServerId,
    pub executable: String,
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
}
