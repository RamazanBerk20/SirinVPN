//! Policy retained with an interrupted key rotation, separate from the old bundle.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationConnectionPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu_policy: Option<sirinvpn_protocol::MtuPolicy>,
    pub kill_switch: bool,
    pub automatic_reconnect: bool,
    pub connect_on_startup: bool,
    /// None is full tunnel unless selected_applications is true.
    /// Some carries the exact selected CIDRs and excludes application routing.
    pub selected_routes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub selected_applications: bool,
    pub allow_lan: bool,
}
