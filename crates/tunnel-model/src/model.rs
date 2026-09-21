use super::*;

pub const HELPER_PROTOCOL_VERSION: u16 = 18;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelRoutingMode {
    #[default]
    FullTunnel,
    SelectedRoutes,
    SelectedApplications,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct TunnelRoutingPolicy {
    #[serde(default)]
    pub mode: TunnelRoutingMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub included_routes: Vec<String>,
    #[serde(default)]
    pub allow_lan: bool,
}

impl TunnelRoutingPolicy {
    pub fn selected_applications(allow_lan: bool) -> Self {
        Self {
            mode: TunnelRoutingMode::SelectedApplications,
            included_routes: Vec::new(),
            allow_lan,
        }
    }
    pub fn full_tunnel(allow_lan: bool) -> Self {
        Self {
            mode: TunnelRoutingMode::FullTunnel,
            included_routes: Vec::new(),
            allow_lan,
        }
    }
    pub fn selected_routes(
        included_routes: impl IntoIterator<Item = String>,
        allow_lan: bool,
    ) -> Result<Self, String> {
        Ok(Self {
            mode: TunnelRoutingMode::SelectedRoutes,
            included_routes: normalize_included_routes(included_routes)?,
            allow_lan,
        })
    }
    pub fn is_legacy_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ReconnectCandidate {
    pub transport: TransportKind,
    pub endpoint_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_transport_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_certificate_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https: Option<sirinvpn_protocol::HttpsTransport>,
    pub mtu: u16,
}

pub fn automatic_reconnect_candidates(
    selections: &[TransportSelection],
    selected: TransportKind,
) -> Vec<ReconnectCandidate> {
    if selected == TransportKind::TlsLike
        || selections
            .iter()
            .filter(|selection| selection.kind != TransportKind::TlsLike)
            .count()
            < 2
        || !selections
            .iter()
            .any(|selection| selection.kind == selected && selection.kind != TransportKind::TlsLike)
    {
        return Vec::new();
    }
    let mut candidates = Vec::with_capacity(3);
    for selection in selections
        .iter()
        .filter(|selection| selection.kind == selected && selection.kind != TransportKind::TlsLike)
        .chain(selections.iter().filter(|selection| {
            selection.kind != selected && selection.kind != TransportKind::TlsLike
        }))
    {
        if candidates
            .iter()
            .any(|candidate: &ReconnectCandidate| candidate.transport == selection.kind)
        {
            continue;
        }
        candidates.push(candidate(selection));
        if candidates.len() == 3 {
            break;
        }
    }
    if candidates.len() < 2 {
        Vec::new()
    } else {
        candidates
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TunnelConnectRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_identity: Option<sirinvpn_protocol::EndpointIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_checkpoint: Option<sirinvpn_protocol::EndpointTransitionResponse>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub endpoint_publication_enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoint_dns_servers: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu_policy: Option<sirinvpn_protocol::MtuPolicy>,
    pub schema_version: u16,
    pub server_id: ServerId,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    #[serde(default, skip_serializing_if = "TransportKind::is_direct_udp")]
    pub transport: TransportKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_transport_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_certificate_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https: Option<sirinvpn_protocol::HttpsTransport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reconnect_candidates: Vec<ReconnectCandidate>,
    pub client_address: Ipv4Addr,
    pub server_public_key: String,
    pub private_key: String,
    pub dns_address: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ipv6_address: Option<Ipv6Addr>,
    pub mtu: u16,
    #[serde(default)]
    pub persistent_protection: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ConnectionPolicy>,
    #[serde(
        default,
        skip_serializing_if = "TunnelRoutingPolicy::is_legacy_default"
    )]
    pub routing: TunnelRoutingPolicy,
}

impl std::fmt::Debug for TunnelConnectRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunnelConnectRequest")
            .field("schema_version", &self.schema_version)
            .field("server_id", &self.server_id)
            .field("endpoint_host", &self.endpoint_host)
            .field("endpoint_port", &self.endpoint_port)
            .field("transport", &self.transport)
            .field(
                "server_transport_public_key",
                &self.server_transport_public_key,
            )
            .field("server_certificate_sha256", &self.server_certificate_sha256)
            .field("reconnect_candidates", &self.reconnect_candidates)
            .field("client_address", &self.client_address)
            .field("server_public_key", &self.server_public_key)
            .field("private_key", &"[REDACTED]")
            .field("dns_address", &self.dns_address)
            .field("client_ipv6_address", &self.client_ipv6_address)
            .field("mtu", &self.mtu)
            .field("persistent_protection", &self.persistent_protection)
            .field("policy", &self.policy)
            .field("routing", &self.routing)
            .finish()
    }
}
impl Drop for TunnelConnectRequest {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LocalTunnelStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_routing_backend: Option<ApplicationRoutingBackend>,
    #[serde(default)]
    pub application_routing_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_routing_ready: Option<bool>,
    #[serde(default)]
    pub endpoint_updates_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_checkpoint: Option<sirinvpn_protocol::EndpointTransitionResponse>,
    #[serde(default)]
    pub transport_quality_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_quality: Option<sirinvpn_protocol::TransportQualityStatus>,
    #[serde(default)]
    pub mtu_detection_supported: bool,
    #[serde(default)]
    pub https_transport_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<sirinvpn_protocol::MtuStatus>,
    #[serde(default)]
    pub connection_control_supported: bool,
    #[serde(default)]
    pub recovery_in_progress: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_service_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_status_known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ConnectionPolicy>,
    #[serde(default)]
    pub independent_policy_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_switch_state: Option<KillSwitchState>,
    #[serde(default)]
    pub connect_on_startup: bool,
    #[serde(default)]
    pub waiting_for_user: bool,
    #[serde(default)]
    pub traffic_metrics_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_counters_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub included_routes: Option<Vec<String>>,
    pub state: ConnectionState,
    pub interface_name: String,
    pub server_id: Option<ServerId>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_uptime_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_epoch: Option<String>,
    pub ipv6_blocked: bool,
    #[serde(default)]
    pub ipv6_tunneled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportKind>,
    #[serde(default)]
    pub kill_switch_enabled: bool,
    #[serde(default)]
    pub auto_reconnect_enabled: bool,
    #[serde(default)]
    pub transport_fallback_enabled: bool,
    #[serde(default)]
    pub routing_mode: TunnelRoutingMode,
    #[serde(default)]
    pub allow_lan: bool,
}

#[derive(Debug, Error)]
pub enum HelperError {
    #[error("the networking helper requires platform administrator authorization")]
    PermissionDenied,
    #[error("invalid tunnel configuration: {0}")]
    InvalidConfiguration(String),
    #[error("another application owns the SirinVPN interface or routing table")]
    OwnershipConflict,
    #[error("the network operation failed; check the local tunnel status before retrying")]
    NetworkOperationFailed,
    #[error("persistent protection could not be established safely")]
    PersistentProtectionUnavailable,
    #[error("disconnect the active local session before changing its server or policy")]
    ActivePolicy,
    #[error("runtime state is invalid")]
    InvalidState,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPolicy {
    pub kill_switch: bool,
    pub automatic_reconnect: bool,
    pub connect_on_startup: bool,
}
impl ConnectionPolicy {
    pub const fn legacy(enabled: bool) -> Self {
        Self {
            kill_switch: enabled,
            automatic_reconnect: enabled,
            connect_on_startup: enabled,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchState {
    Off,
    Armed,
    Blocking,
    Failed,
    Unknown,
}

impl TunnelConnectRequest {
    pub fn requires_https_support(&self) -> bool {
        self.https.is_some()
            || self
                .reconnect_candidates
                .iter()
                .any(|candidate| candidate.https.is_some())
    }
    pub fn desired_schema(&self) -> u16 {
        if self.schema_version >= 11 {
            6
        } else if self.schema_version >= 10 {
            5
        } else if self.schema_version >= 9 {
            4
        } else if self.mtu_policy.is_some() {
            3
        } else {
            2
        }
    }
    pub fn connection_policy(&self) -> ConnectionPolicy {
        self.policy
            .unwrap_or_else(|| ConnectionPolicy::legacy(self.persistent_protection))
    }
    pub fn set_mtu_policy(
        &mut self,
        policy: sirinvpn_protocol::MtuPolicy,
    ) -> Result<(), HelperError> {
        if self.policy.is_none() {
            return Err(HelperError::InvalidConfiguration(
                "MTU selection requires the managed connection policy".into(),
            ));
        }
        policy
            .validate(self.client_ipv6_address.is_some())
            .map_err(|message| HelperError::InvalidConfiguration(message.into()))?;
        self.schema_version = if self.routing.mode == TunnelRoutingMode::SelectedApplications {
            11
        } else if self.endpoint_identity.is_some() {
            10
        } else if self.requires_https_support() {
            9
        } else {
            8
        };
        self.mtu_policy = Some(policy);
        if let sirinvpn_protocol::MtuPolicy::Manual { value } = policy {
            self.mtu = value;
            for candidate in &mut self.reconnect_candidates {
                candidate.mtu = value;
            }
        }
        Ok(())
    }
}

/// Initial selection and session recovery share an ordered, bounded plan.
pub fn policy_transport_candidates(selections: &[TransportSelection]) -> Vec<ReconnectCandidate> {
    if selections.len() < 2 {
        Vec::new()
    } else {
        selections.iter().take(4).map(candidate).collect()
    }
}
fn candidate(selection: &TransportSelection) -> ReconnectCandidate {
    ReconnectCandidate {
        transport: selection.kind,
        endpoint_port: selection.network_endpoint.wireguard_port,
        server_transport_public_key: selection.server_transport_public_key.clone(),
        https: selection.https.clone(),
        server_certificate_sha256: selection.server_certificate_sha256.clone(),
        mtu: selection.mtu,
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchConnectRequest {
    pub expected_server_id: ServerId,
    pub request: TunnelConnectRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationLaunchRequest {
    pub server_id: ServerId,
    pub executable: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplicationLaunchResult {
    pub process_id: Option<u32>,
    pub completed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationRoutingBackend {
    LinuxNamespace,
    WindowsBindRedirect,
}

impl ApplicationLaunchRequest {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.executable.is_absolute() && self.executable.as_os_str().len() <= 4096,
            "choose an absolute executable path"
        );
        anyhow::ensure!(
            self.arguments.len() <= 64
                && self
                    .arguments
                    .iter()
                    .all(|arg| arg.len() <= 4096 && !arg.contains('\0'))
                && self.arguments.iter().map(String::len).sum::<usize>() <= 16384,
            "application arguments are too large"
        );
        anyhow::ensure!(self.environment.len() <= 6, "too many environment values");
        for (key, value) in &self.environment {
            anyhow::ensure!(
                matches!(
                    key.as_str(),
                    "DISPLAY"
                        | "WAYLAND_DISPLAY"
                        | "XAUTHORITY"
                        | "XDG_RUNTIME_DIR"
                        | "LANG"
                        | "LC_ALL"
                ) && value.len() <= 4096
                    && !value.chars().any(char::is_control),
                "unsupported application environment"
            );
        }
        Ok(())
    }
}

/// An authenticated server lease and an isolated, single-use measurement key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasureSessionRequest {
    pub server_id: ServerId,
    pub counter_epoch: String,
    pub lease: sirinvpn_protocol::MeasurementLease,
    pub private_key: String,
}
impl Drop for MeasureSessionRequest {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}
