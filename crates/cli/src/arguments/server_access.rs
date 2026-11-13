use super::*;

#[derive(Args)]
pub(crate) struct JoinServerArguments {
    #[arg(long, help = "Read the secret invitation code from standard input")]
    pub(crate) code_stdin: bool,
}

#[derive(Args)]
pub(crate) struct EndpointUpdateCodeArguments {
    pub(crate) server: String,
    #[arg(
        long,
        help = "Read the signed endpoint update code from standard input"
    )]
    pub(crate) code_stdin: bool,
}

#[derive(Args)]
pub(crate) struct ExportServerArguments {
    pub(crate) server: String,
    #[arg(long)]
    pub(crate) output: PathBuf,
    #[arg(long)]
    pub(crate) confirm_sensitive_export: bool,
}

#[derive(Args)]
pub(crate) struct ImportServerArguments {
    #[arg(long)]
    pub(crate) input: PathBuf,
}

#[derive(Args)]
pub(crate) struct InviteArguments {
    pub(crate) server: String,
    #[arg(
        long,
        required_unless_present = "member_id",
        conflicts_with = "member_id"
    )]
    pub(crate) member_name: Option<String>,
    #[arg(long, conflicts_with = "member_name")]
    pub(crate) member_id: Option<String>,
    #[arg(long, conflicts_with = "member_id")]
    pub(crate) admin: bool,
    #[arg(long)]
    pub(crate) device_name: String,
    #[arg(long, default_value_t = 3_600)]
    pub(crate) expires_in: u32,
    #[arg(long, default_value_t = 1)]
    pub(crate) max_uses: u16,
    /// JSON member policy; additional-device invitations inherit existing policy.
    #[arg(long, conflicts_with = "member_id")]
    pub(crate) policy_file: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct WireGuardDeviceArguments {
    pub(crate) server: String,
    #[arg(
        long,
        required_unless_present = "member_id",
        conflicts_with = "member_id"
    )]
    pub(crate) member_name: Option<String>,
    #[arg(long, conflicts_with = "member_name")]
    pub(crate) member_id: Option<String>,
    #[arg(long)]
    pub(crate) device_name: String,
    /// JSON member policy for a new member; additional devices inherit existing policy.
    #[arg(long, conflicts_with = "member_id")]
    pub(crate) policy_file: Option<PathBuf>,
    /// New file for the configuration. It holds the device's only private key.
    #[arg(long)]
    pub(crate) output: PathBuf,
    /// Also print the configuration as a QR code for the WireGuard mobile apps.
    #[arg(long)]
    pub(crate) qr: bool,
}

#[derive(Args)]
pub(crate) struct MemberPolicyArguments {
    pub(crate) server: String,
    pub(crate) member_id: String,
    #[arg(long)]
    pub(crate) policy_file: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum AccessLevel {
    Admin,
    Member,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum PeerCommunicationMode {
    InternetOnly,
    Peers,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum PortForwardProtocolArgument {
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
pub(crate) struct PeerCommunicationArguments {
    pub(crate) server: String,
    pub(crate) device_id: String,
    #[arg(long, value_enum)]
    pub(crate) mode: PeerCommunicationMode,
}

#[derive(Args)]
pub(crate) struct DevicePairArguments {
    pub(crate) server: String,
    /// The device that may start connections.
    pub(crate) device_id: String,
    pub(crate) peer_device_id: String,
    /// The peer only answers connections the device started.
    #[arg(long)]
    pub(crate) one_way: bool,
}

#[derive(Args)]
pub(crate) struct DeviceUnpairArguments {
    pub(crate) server: String,
    pub(crate) device_id: String,
    pub(crate) peer_device_id: String,
}

#[derive(Args)]
pub(crate) struct SubnetRoutesArguments {
    pub(crate) server: String,
    pub(crate) device_id: String,
    /// A private IPv4 CIDR such as 192.168.1.0/24; repeat it, or omit it to remove all routes.
    #[arg(long = "route")]
    pub(crate) routes: Vec<String>,
}

#[derive(Args)]
pub(crate) struct AddPortForwardArguments {
    pub(crate) server: String,
    pub(crate) device_id: String,
    #[arg(long, value_enum)]
    pub(crate) protocol: PortForwardProtocolArgument,
    #[arg(long)]
    pub(crate) public_port: u16,
    #[arg(long)]
    pub(crate) device_port: u16,
    #[arg(long)]
    pub(crate) confirm_public_exposure: bool,
}

#[derive(Args)]
pub(crate) struct RemovePortForwardArguments {
    pub(crate) server: String,
    #[arg(long, value_enum)]
    pub(crate) protocol: PortForwardProtocolArgument,
    #[arg(long)]
    pub(crate) public_port: u16,
}

#[derive(Args)]
pub(crate) struct MemberAccessArguments {
    pub(crate) server: String,
    pub(crate) member_id: String,
    #[arg(long, value_enum)]
    pub(crate) level: AccessLevel,
}

#[derive(Args)]
pub(crate) struct MemberSelector {
    pub(crate) server: String,
    pub(crate) member_id: String,
}

#[derive(Args)]
pub(crate) struct RevokeMemberDevicesArguments {
    pub(crate) server: String,
    pub(crate) member_id: String,
    #[arg(
        long,
        help = "Confirm permanently removing every device, invitation and port forward for this member"
    )]
    pub(crate) confirm_revoke_all: bool,
}

#[derive(Args)]
pub(crate) struct TransferOwnershipArguments {
    pub(crate) server: String,
    pub(crate) destination_device_id: String,
    #[arg(long)]
    pub(crate) confirm_transfer: bool,
}

#[derive(Args)]
pub(crate) struct InvitationSelector {
    pub(crate) server: String,
    pub(crate) invitation_id: String,
}

#[derive(Args)]
pub(crate) struct DeviceSelector {
    pub(crate) server: String,
    pub(crate) device_id: String,
}

#[derive(Args)]
pub(crate) struct RenameDeviceArguments {
    pub(crate) server: String,
    pub(crate) device_id: String,
    #[arg(long)]
    pub(crate) name: String,
}

#[derive(Args)]
pub(crate) struct ServerSelector {
    pub(crate) server: String,
}
