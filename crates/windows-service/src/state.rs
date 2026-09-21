//! One encrypted current session and the route ownership needed to undo it.
//! There are no traffic samples, connection timestamps, or activity records here.
use crate::{
    ServiceError,
    network_plan::{self, RouteRecord},
};
use serde::{Deserialize, Serialize};
use sirinvpn_tunnel_model::TunnelConnectRequest;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SessionPhase {
    Connecting,
    Active,
    Held,
    Disconnecting,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedEndpoint {
    pub host: String,
    pub address: IpAddr,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedConnection {
    pub schema_version: u16,
    pub owner_sid: String,
    pub boot_nonce: uuid::Uuid,
    pub phase: SessionPhase,
    pub request: TunnelConnectRequest,
    pub endpoints: Vec<ResolvedEndpoint>,
    pub routes: Vec<RouteRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<crate::application_plan::SelectedApplication>,
}

impl SavedConnection {
    pub(crate) fn validate(&self) -> Result<(), ServiceError> {
        network_plan::validate(&self.request)?;
        if !(1..=2).contains(&self.schema_version)
            || !self.applications.is_empty()
                && (self.schema_version < 2
                    || self.request.routing.mode
                        != sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications)
            || self.applications.len() > crate::application_plan::MAX_APPLICATIONS
            || self
                .applications
                .iter()
                .any(|application| !application.validate())
            || self.owner_sid.len() > 184
            || !self.owner_sid.starts_with("S-1-")
            || !self
                .owner_sid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'S' | b'-'))
            || self.owner_sid == "S-1-5-18"
            || self.boot_nonce.is_nil()
            || self.endpoints.len() > 8
            || self.routes.len() > 1024
            || self.routes.iter().any(|route| !route.validate())
        {
            return Err(ServiceError::InvalidRequest);
        }
        for endpoint in &self.endpoints {
            let known = endpoint.host == self.request.endpoint_host
                || self
                    .request
                    .endpoint_identity
                    .as_ref()
                    .is_some_and(|identity| {
                        sirinvpn_tunnel_model::hosts(identity).any(|host| host == endpoint.host)
                    });
            if !known || !network_plan::usable_endpoint(endpoint.address) {
                return Err(ServiceError::InvalidRequest);
            }
        }
        Ok(())
    }

    pub(crate) fn authorize(&self, owner_sid: &str) -> Result<(), ServiceError> {
        if owner_sid == self.owner_sid {
            Ok(())
        } else {
            Err(ServiceError::OwnedByAnotherUser)
        }
    }

    pub(crate) fn may_resume_after_restart(&self, boot_nonce: uuid::Uuid) -> bool {
        if self.phase == SessionPhase::Disconnecting {
            return false;
        }
        if self.boot_nonce != boot_nonce {
            return self.request.connection_policy().connect_on_startup;
        }
        self.phase != SessionPhase::Held && self.request.connection_policy().automatic_reconnect
    }
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub(crate) use native::SessionStore;
