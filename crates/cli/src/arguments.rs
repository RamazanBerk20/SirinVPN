//! Arguments.

use super::*;

#[derive(Subcommand)]
pub(super) enum Commands {
    HostKey(HostKeyArguments),
    Server {
        #[command(subcommand)]
        command: Box<ServerCommand>,
    },
    Connect(ConnectArguments),
    /// Launch a new native process in the active application tunnel.
    Run(ApplicationArguments),
    Disconnect,
    /// Retry a paused session using its active policy, without releasing its block.
    Resume(ServerSelector),
    Status,
    Diagnose(ServerSelector),
}

#[derive(Args)]
pub(super) struct HostKeyArguments {
    pub(super) host: String,
    #[arg(long, default_value_t = 22)]
    pub(super) port: u16,
}

#[derive(Subcommand)]
pub(super) enum ServerCommand {
    /// Check, install, roll back, or schedule signed VPS releases over pinned SSH.
    Release(crate::vps_release::Arguments),
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    Add(AddServerArguments),
    BackupVps(BackupVpsArguments),
    RestoreVps(RestoreVpsArguments),
    CreateEndpointUpdate(ServerSelector),
    PublishEndpointUpdate(EndpointUpdateCodeArguments),
    ApplyEndpointUpdate(EndpointUpdateCodeArguments),
    Join(JoinServerArguments),
    Export(ExportServerArguments),
    Import(ImportServerArguments),
    List,
    Remove(ServerSelector),
    Repair(RepairServerArguments),
    RotateKeys(RotateKeysArguments),
    Uninstall(UninstallServerArguments),
    Invite(InviteArguments),
    Members(ServerSelector),
    CancelInvitation(InvitationSelector),
    RenameDevice(RenameDeviceArguments),
    RevokeDevice(DeviceSelector),
    SetPeerCommunication(PeerCommunicationArguments),
    AddPortForward(AddPortForwardArguments),
    RemovePortForward(RemovePortForwardArguments),
    SetMemberAccess(MemberAccessArguments),
    /// Replace a member's device limits, UTC access times and delegated permissions.
    SetMemberPolicy(MemberPolicyArguments),
    /// Temporarily block every device belonging to a member.
    SuspendMember(MemberSelector),
    /// Restore access for the same retained member devices.
    ReactivateMember(MemberSelector),
    /// Permanently remove every device and pending enrollment for a member.
    RevokeMemberDevices(RevokeMemberDevicesArguments),
    TransferOwnership(TransferOwnershipArguments),
}

#[derive(Subcommand)]
pub(super) enum RecoveryCommand {
    Status(ServerSelector),
    Create(RecoveryCreateArguments),
    Policy(RecoveryPolicyArguments),
    Revoke(RecoveryRevokeArguments),
    Recover(RecoveryRestoreArguments),
}

#[derive(Args)]
pub(super) struct RecoveryCreateArguments {
    pub(super) server: String,
    #[arg(long, required_unless_present = "print_key")]
    pub(super) output: Option<PathBuf>,
    /// Explicitly print the complete sensitive offline recovery key.
    #[arg(long)]
    pub(super) print_key: bool,
    #[arg(long)]
    pub(super) replace_existing_key: bool,
    #[arg(long)]
    pub(super) confirm_sensitive_export: bool,
}
#[derive(Args)]
pub(super) struct RecoveryPolicyArguments {
    pub(super) server: String,
    /// Repeat for each authorized Admin. Omit to disable administrator recovery.
    #[arg(long)]
    pub(super) administrator_member_id: Vec<String>,
}
#[derive(Args)]
pub(super) struct RecoveryRevokeArguments {
    pub(super) server: String,
    pub(super) recovery_id: String,
}
#[derive(Args)]
pub(super) struct RecoveryRestoreArguments {
    #[arg(long, conflicts_with = "input")]
    pub(super) key_stdin: bool,
    #[arg(long)]
    pub(super) input: Option<PathBuf>,
    #[arg(long, default_value = "Recovered Owner device")]
    pub(super) device_name: String,
    #[arg(long)]
    pub(super) confirm_replace_owner_devices: bool,
    #[arg(long)]
    pub(super) replace_existing_profile: bool,
}

#[derive(Args)]
pub(super) struct JoinServerArguments {
    #[arg(long, help = "Read the secret invitation code from standard input")]
    pub(super) code_stdin: bool,
}

#[derive(Args)]
pub(super) struct EndpointUpdateCodeArguments {
    pub(super) server: String,
    #[arg(
        long,
        help = "Read the signed endpoint update code from standard input"
    )]
    pub(super) code_stdin: bool,
}

#[derive(Args)]
pub(super) struct ExportServerArguments {
    pub(super) server: String,
    #[arg(long)]
    pub(super) output: PathBuf,
    #[arg(long)]
    pub(super) confirm_sensitive_export: bool,
}

#[derive(Args)]
pub(super) struct ImportServerArguments {
    #[arg(long)]
    pub(super) input: PathBuf,
}

#[derive(Args)]
pub(super) struct InviteArguments {
    pub(super) server: String,
    #[arg(
        long,
        required_unless_present = "member_id",
        conflicts_with = "member_id"
    )]
    pub(super) member_name: Option<String>,
    #[arg(long, conflicts_with = "member_name")]
    pub(super) member_id: Option<String>,
    #[arg(long, conflicts_with = "member_id")]
    pub(super) admin: bool,
    #[arg(long)]
    pub(super) device_name: String,
    #[arg(long, default_value_t = 3_600)]
    pub(super) expires_in: u32,
    #[arg(long, default_value_t = 1)]
    pub(super) max_uses: u16,
    /// JSON member policy; additional-device invitations inherit existing policy.
    #[arg(long, conflicts_with = "member_id")]
    pub(super) policy_file: Option<PathBuf>,
}

#[derive(Args)]
pub(super) struct MemberPolicyArguments {
    pub(super) server: String,
    pub(super) member_id: String,
    #[arg(long)]
    pub(super) policy_file: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
pub(super) enum AccessLevel {
    Admin,
    Member,
}

#[derive(Clone, Copy, ValueEnum)]
pub(super) enum PeerCommunicationMode {
    InternetOnly,
    Peers,
}

#[derive(Clone, Copy, ValueEnum)]
pub(super) enum PortForwardProtocolArgument {
    Tcp,
    Udp,
}

impl From<PortForwardProtocolArgument> for PortForwardProtocol {
    fn from(value: PortForwardProtocolArgument) -> Self {
        match value {
            PortForwardProtocolArgument::Tcp => Self::Tcp,
            PortForwardProtocolArgument::Udp => Self::Udp,
        }
    }
}

#[derive(Args)]
pub(super) struct PeerCommunicationArguments {
    pub(super) server: String,
    pub(super) device_id: String,
    #[arg(long, value_enum)]
    pub(super) mode: PeerCommunicationMode,
}

#[derive(Args)]
pub(super) struct AddPortForwardArguments {
    pub(super) server: String,
    pub(super) device_id: String,
    #[arg(long, value_enum)]
    pub(super) protocol: PortForwardProtocolArgument,
    #[arg(long)]
    pub(super) public_port: u16,
    #[arg(long)]
    pub(super) device_port: u16,
    #[arg(long)]
    pub(super) confirm_public_exposure: bool,
}

#[derive(Args)]
pub(super) struct RemovePortForwardArguments {
    pub(super) server: String,
    #[arg(long, value_enum)]
    pub(super) protocol: PortForwardProtocolArgument,
    #[arg(long)]
    pub(super) public_port: u16,
}

#[derive(Args)]
pub(super) struct MemberAccessArguments {
    pub(super) server: String,
    pub(super) member_id: String,
    #[arg(long, value_enum)]
    pub(super) level: AccessLevel,
}

#[derive(Args)]
pub(super) struct MemberSelector {
    pub(super) server: String,
    pub(super) member_id: String,
}

#[derive(Args)]
pub(super) struct RevokeMemberDevicesArguments {
    pub(super) server: String,
    pub(super) member_id: String,
    #[arg(
        long,
        help = "Confirm permanently removing every device, invitation and port forward for this member"
    )]
    pub(super) confirm_revoke_all: bool,
}

#[derive(Args)]
pub(super) struct TransferOwnershipArguments {
    pub(super) server: String,
    pub(super) destination_device_id: String,
    #[arg(long)]
    pub(super) confirm_transfer: bool,
}

#[derive(Args)]
pub(super) struct InvitationSelector {
    pub(super) server: String,
    pub(super) invitation_id: String,
}

#[derive(Args)]
pub(super) struct DeviceSelector {
    pub(super) server: String,
    pub(super) device_id: String,
}

#[derive(Args)]
pub(super) struct RenameDeviceArguments {
    pub(super) server: String,
    pub(super) device_id: String,
    #[arg(long)]
    pub(super) name: String,
}

#[derive(Args)]
pub(super) struct ServerSelector {
    pub(super) server: String,
}

#[derive(Args)]
pub(super) struct ConnectArguments {
    /// Only processes started by `sirinvpn run` use the tunnel; system DNS stays unchanged.
    #[arg(long, conflicts_with = "routes")]
    pub(super) applications: bool,
    /// Fix the tunnel MTU. Otherwise safe packet delivery is measured automatically.
    #[arg(long, value_parser = clap::value_parser!(u16).range(576..=1420))]
    pub(super) mtu: Option<u16>,
    pub(super) server: String,
    /// Compatibility shortcut: enable kill switch, reconnect, and system-startup connection.
    #[arg(long, conflicts_with_all = ["kill_switch", "automatic_reconnect", "connect_on_startup"])]
    pub(super) persistent: bool,
    #[arg(long)]
    pub(super) kill_switch: bool,
    #[arg(long)]
    pub(super) automatic_reconnect: bool,
    #[arg(long)]
    pub(super) connect_on_startup: bool,
    #[arg(long, value_enum, default_value = "automatic")]
    pub(super) transport: ConnectTransport,
    #[arg(long, value_enum)]
    pub(super) network_profile: Option<ConnectNetworkProfile>,
    /// Route only these IPv4/IPv6 CIDRs through the VPN. Repeat for multiple routes.
    #[arg(long = "route", value_name = "CIDR")]
    pub(super) routes: Vec<String>,
    /// Keep private, link-local, and multicast ranges on the physical network.
    #[arg(long)]
    pub(super) allow_lan: bool,
}

#[derive(Args)]
pub(super) struct ApplicationArguments {
    pub(super) server: String,
    pub(super) executable: PathBuf,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(super) arguments: Vec<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(super) enum ConnectTransport {
    Automatic,
    Direct,
    Obfuscated,
    Tls,
    Tcp,
}

impl From<ConnectTransport> for TransportPreference {
    fn from(value: ConnectTransport) -> Self {
        match value {
            ConnectTransport::Automatic => Self::Automatic,
            ConnectTransport::Direct => Self::DirectUdp,
            ConnectTransport::Obfuscated => Self::ObfuscatedUdp,
            ConnectTransport::Tls => Self::TlsLike,
            ConnectTransport::Tcp => Self::TcpFallback,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(super) enum ConnectNetworkProfile {
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

#[derive(Args)]
pub(super) struct AddServerArguments {
    /// Report addresses, NAT indications, required ports and conflicts without installing.
    #[arg(long, conflicts_with = "replace_existing")]
    pub(super) preflight_only: bool,
    #[arg(long)]
    pub(super) name: String,
    #[arg(long)]
    pub(super) host: String,
    #[arg(long, default_value = "root")]
    pub(super) username: String,
    #[arg(long, default_value_t = 22)]
    pub(super) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(super) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(super) ssh_agent: bool,
    #[arg(long)]
    pub(super) host_key: String,
    #[arg(long)]
    pub(super) server_binary: Option<PathBuf>,
    #[arg(long)]
    pub(super) passwordless_sudo: bool,
    /// Replace an existing SirinVPN identity after SSH authorization.
    #[arg(long)]
    pub(super) replace_existing: bool,
    #[command(flatten)]
    pub(super) dns: DnsPolicyArguments,
    #[arg(long, value_name = "DNS_NAME=IP")]
    pub(super) private_dns_record: Vec<PrivateDnsRecord>,
    #[command(flatten)]
    pub(super) transport: TransportArguments,
}

#[derive(Args)]
pub(super) struct DnsPolicyArguments {
    /// Forward this domain suffix to explicit private or TLS resolvers. Repeat for more zones.
    #[arg(long, value_name = "SUFFIX=IP[,IP] or SUFFIX=IP#TLS_NAME")]
    pub(super) split_dns_zone: Vec<sirinvpn_protocol::DnsSplitZone>,
    #[arg(
        long,
        conflicts_with_all = ["dns_over_tls_endpoint", "dns_over_https_endpoint"]
    )]
    pub(super) recursive_dns: bool,
    #[arg(
        long,
        value_name = "IP#AUTHENTICATION_NAME",
        conflicts_with_all = ["recursive_dns", "dns_over_https_endpoint"]
    )]
    pub(super) dns_over_tls_endpoint: Vec<DnsOverTlsEndpoint>,
    #[arg(
        long,
        value_name = "IP#AUTHENTICATION_NAME/PATH",
        conflicts_with_all = ["recursive_dns", "dns_over_tls_endpoint"]
    )]
    pub(super) dns_over_https_endpoint: Vec<DnsOverHttpsEndpoint>,
}

impl DnsPolicyArguments {
    pub(super) fn requested(&self) -> Option<DnsUpstream> {
        let default = if self.recursive_dns {
            Some(DnsUpstream::Recursive)
        } else if !self.dns_over_tls_endpoint.is_empty() {
            Some(DnsUpstream::DnsOverTls {
                endpoints: self.dns_over_tls_endpoint.clone(),
            })
        } else if !self.dns_over_https_endpoint.is_empty() {
            Some(DnsUpstream::DnsOverHttps {
                endpoints: self.dns_over_https_endpoint.clone(),
            })
        } else {
            None
        };
        if self.split_dns_zone.is_empty() {
            default
        } else {
            Some(DnsUpstream::Split {
                default: Box::new(default.unwrap_or_default()),
                zones: self.split_dns_zone.clone(),
            })
        }
    }
}

#[derive(Args)]
pub(super) struct UninstallServerArguments {
    pub(super) server: String,
    #[arg(long, default_value = "root")]
    pub(super) username: String,
    #[arg(long, default_value_t = 22)]
    pub(super) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(super) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(super) ssh_agent: bool,
    #[arg(long)]
    pub(super) host_key: String,
    #[arg(long)]
    pub(super) passwordless_sudo: bool,
    #[arg(long)]
    pub(super) confirm_uninstall: bool,
}

#[derive(Args)]
pub(super) struct RepairServerArguments {
    pub(super) server: String,
    #[arg(long, default_value = "root")]
    pub(super) username: String,
    #[arg(long, default_value_t = 22)]
    pub(super) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(super) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(super) ssh_agent: bool,
    #[arg(long)]
    pub(super) host_key: String,
    #[arg(long)]
    pub(super) server_binary: Option<PathBuf>,
    #[arg(long)]
    pub(super) passwordless_sudo: bool,
    #[arg(long)]
    pub(super) confirm_repair: bool,
    #[command(flatten)]
    pub(super) dns: DnsPolicyArguments,
    #[command(flatten)]
    pub(super) private_dns: PrivateDnsRecordArguments,
    #[command(flatten)]
    pub(super) transport: TransportArguments,
}

#[derive(Args)]
pub(super) struct BackupVpsArguments {
    pub(super) server: String,
    #[arg(long)]
    pub(super) output: PathBuf,
    #[arg(long, default_value = "root")]
    pub(super) username: String,
    #[arg(long, default_value_t = 22)]
    pub(super) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(super) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(super) ssh_agent: bool,
    #[arg(long)]
    pub(super) host_key: String,
    #[arg(long)]
    pub(super) server_binary: Option<PathBuf>,
    #[arg(long)]
    pub(super) passwordless_sudo: bool,
    #[arg(long)]
    pub(super) confirm_server_backup: bool,
}

#[derive(Args)]
pub(super) struct RestoreVpsArguments {
    pub(super) server: String,
    #[arg(long)]
    pub(super) input: PathBuf,
    #[arg(long)]
    pub(super) host: String,
    #[arg(long, default_value = "root")]
    pub(super) username: String,
    #[arg(long, default_value_t = 22)]
    pub(super) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(super) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(super) ssh_agent: bool,
    #[arg(long)]
    pub(super) host_key: String,
    #[arg(long)]
    pub(super) server_binary: Option<PathBuf>,
    #[arg(long)]
    pub(super) passwordless_sudo: bool,
    #[arg(long)]
    pub(super) replace_existing: bool,
    #[arg(long)]
    pub(super) confirm_server_restore: bool,
}

#[derive(Args)]
pub(super) struct PrivateDnsRecordArguments {
    #[arg(
        long,
        value_name = "DNS_NAME=IP",
        conflicts_with = "clear_private_dns_records"
    )]
    pub(super) private_dns_record: Vec<PrivateDnsRecord>,
    #[arg(long, conflicts_with = "private_dns_record")]
    pub(super) clear_private_dns_records: bool,
}

impl PrivateDnsRecordArguments {
    pub(super) fn requested(&self) -> Option<Vec<PrivateDnsRecord>> {
        if self.clear_private_dns_records {
            Some(Vec::new())
        } else if self.private_dns_record.is_empty() {
            None
        } else {
            Some(self.private_dns_record.clone())
        }
    }
}

#[derive(Args)]
pub(super) struct RotateKeysArguments {
    pub(super) server: String,
    #[arg(long)]
    pub(super) confirm_key_rotation: bool,
}

#[derive(Serialize)]
pub(super) struct CombinedStatus {
    pub(super) local: LocalTunnelStatus,
    pub(super) server: Option<sirinvpn_protocol::ServerStatus>,
}

#[derive(Serialize)]
pub(super) struct BackupOperationResult {
    pub(super) operation: &'static str,
    pub(super) server_id: ServerId,
    pub(super) name: String,
}

#[derive(Serialize)]
pub(super) struct RepairOperationResult {
    pub(super) repaired: bool,
    pub(super) server_id: ServerId,
    pub(super) artifact_sha256: String,
    pub(super) dns_upstream: DnsUpstream,
    pub(super) private_dns_records: Vec<PrivateDnsRecord>,
}

#[derive(Serialize)]
pub(super) struct EndpointUpdateCodeResult {
    pub(super) server_id: ServerId,
    pub(super) generation: u64,
    pub(super) previous_endpoint: ServerEndpoint,
    pub(super) endpoint: ServerEndpoint,
    pub(super) code: String,
}

#[derive(Args)]
pub(super) struct TransportArguments {
    #[arg(long)]
    pub(super) public_host: Option<String>,
    #[arg(long, conflicts_with = "clear_alternate_hosts")]
    pub(super) alternate_host: Vec<String>,
    #[arg(long)]
    pub(super) clear_alternate_hosts: bool,
    #[arg(long)]
    pub(super) wireguard_port: Option<u16>,
    #[arg(long)]
    pub(super) obfuscated_udp_port: Option<u16>,
    /// TCP and TLS share an authenticated listener.
    #[arg(long)]
    pub(super) tcp_tls_port: Option<u16>,
    #[arg(long, conflicts_with = "disable_https")]
    pub(super) https_server_name: Option<String>,
    #[arg(long, conflicts_with = "disable_https")]
    pub(super) https_path: Option<String>,
    /// Absolute PEM certificate-chain path already present on the VPS.
    #[arg(
        long,
        requires = "https_private_key_path",
        conflicts_with = "disable_https"
    )]
    pub(super) https_certificate_path: Option<String>,
    /// Absolute matching private-key path already present on the VPS.
    #[arg(
        long,
        requires = "https_certificate_path",
        conflicts_with = "disable_https"
    )]
    pub(super) https_private_key_path: Option<String>,
    #[arg(long)]
    pub(super) disable_https: bool,
}

impl TransportArguments {
    pub(super) fn requested(
        &self,
        profile: Option<&ServerProfile>,
    ) -> Result<Option<sirinvpn_installer::TransportSetup>> {
        if self.wireguard_port.is_none()
            && self.public_host.is_none()
            && self.alternate_host.is_empty()
            && !self.clear_alternate_hosts
            && self.obfuscated_udp_port.is_none()
            && self.tcp_tls_port.is_none()
            && self.https_server_name.is_none()
            && self.https_path.is_none()
            && self.https_certificate_path.is_none()
            && !self.disable_https
        {
            return Ok(None);
        }
        let mut setup = profile
            .map(sirinvpn_installer::TransportSetup::from_profile)
            .unwrap_or_default();
        if let Some(host) = &self.public_host {
            setup.public_host = Some(host.clone());
        }
        if !self.alternate_host.is_empty() || self.clear_alternate_hosts {
            setup.alternate_endpoint_hosts = self.alternate_host.clone();
        }
        if let Some(port) = self.wireguard_port {
            setup.wireguard_port = port;
        }
        if let Some(port) = self.obfuscated_udp_port {
            setup.obfuscated_udp_port = port;
        }
        if let Some(port) = self.tcp_tls_port {
            setup.tcp_tls_port = port;
        }
        if let Some(name) = &self.https_server_name {
            setup.https = Some(sirinvpn_protocol::HttpsTransport {
                server_name: name.clone(),
                path: self.https_path.clone().unwrap_or_else(|| "/connect".into()),
            });
        } else if let Some(path) = &self.https_path {
            setup
                .https
                .as_mut()
                .context("specify --https-server-name to enable HTTPS first")?
                .path = path.clone();
        }
        setup.https_certificate_path = self.https_certificate_path.clone();
        setup.https_private_key_path = self.https_private_key_path.clone();
        setup.disable_https = self.disable_https;
        if self.disable_https {
            setup.https = None;
        }
        setup.validate()?;
        Ok(Some(setup))
    }
}
