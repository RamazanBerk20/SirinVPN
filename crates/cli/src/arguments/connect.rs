use super::*;

#[derive(Args)]
pub(crate) struct ConnectArguments {
    /// Only processes started by `sirinvpn run` use the tunnel; system DNS stays unchanged.
    #[arg(long, conflicts_with = "routes")]
    pub(crate) applications: bool,
    /// Fix the tunnel MTU. Otherwise safe packet delivery is measured automatically.
    #[arg(long, value_parser = clap::value_parser!(u16).range(576..=1420))]
    pub(crate) mtu: Option<u16>,
    pub(crate) server: String,
    /// Compatibility shortcut: enable kill switch, reconnect, and system-startup connection.
    #[arg(long, conflicts_with_all = ["kill_switch", "automatic_reconnect", "connect_on_startup"])]
    pub(crate) persistent: bool,
    #[arg(long)]
    pub(crate) kill_switch: bool,
    #[arg(long)]
    pub(crate) automatic_reconnect: bool,
    #[arg(long)]
    pub(crate) connect_on_startup: bool,
    #[arg(long, value_enum, default_value = "automatic")]
    pub(crate) transport: ConnectTransport,
    #[arg(long, value_enum)]
    pub(crate) network_profile: Option<ConnectNetworkProfile>,
    /// Route only these IPv4/IPv6 CIDRs through the VPN. Repeat for multiple routes.
    #[arg(long = "route", value_name = "CIDR")]
    pub(crate) routes: Vec<String>,
    /// Keep private, link-local, and multicast ranges on the physical network.
    #[arg(long)]
    pub(crate) allow_lan: bool,
}

// Parsed on Windows only to report that `run` is unsupported there.
#[derive(Args)]
#[cfg_attr(windows, allow(dead_code))]
pub(crate) struct ApplicationArguments {
    pub(crate) server: String,
    pub(crate) executable: PathBuf,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) arguments: Vec<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ConnectTransport {
    Automatic,
    Direct,
    Obfuscated,
    Tls,
    Tcp,
    Quic,
}

impl From<ConnectTransport> for TransportPreference {
    fn from(value: ConnectTransport) -> Self {
        match value {
            ConnectTransport::Automatic => Self::Automatic,
            ConnectTransport::Direct => Self::DirectUdp,
            ConnectTransport::Obfuscated => Self::ObfuscatedUdp,
            ConnectTransport::Tls => Self::TlsLike,
            ConnectTransport::Tcp => Self::TcpFallback,
            ConnectTransport::Quic => Self::Quic,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ConnectNetworkProfile {
    Automatic,
    Normal,
    Restricted,
    Extreme,
}

impl From<ConnectNetworkProfile> for NetworkProfile {
    fn from(value: ConnectNetworkProfile) -> Self {
        match value {
            ConnectNetworkProfile::Automatic => Self::Automatic,
            ConnectNetworkProfile::Normal => Self::Normal,
            ConnectNetworkProfile::Restricted => Self::Restricted,
            ConnectNetworkProfile::Extreme => Self::Extreme,
        }
    }
}
