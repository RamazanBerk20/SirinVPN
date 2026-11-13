//! Arguments.

use super::*;

#[derive(Subcommand)]
pub(super) enum Commands {
    /// Inspect storage protection, explicitly allow fallback, or retry local cleanup.
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
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
    Status(StatusArguments),
    Diagnose(ServerSelector),
    /// Measure download, upload and latency through the tunnel to this VPS (not internet speed).
    /// Owner and Admins only; the result is printed here and kept nowhere.
    SpeedTest(ServerSelector),
}

#[derive(Args)]
pub(super) struct StatusArguments {
    /// Keep running and print the local tunnel each time its lifecycle phase changes.
    /// With --json, one compact JSON object per line (newline-delimited JSON).
    #[arg(long)]
    pub(super) watch: bool,
}

#[derive(Subcommand)]
pub(super) enum StorageCommand {
    Status,
    /// Require secure storage for new credentials (the default).
    RequireSecure,
    /// Consent to unencrypted, permission-protected files when the keyring fails.
    AllowPrivateFile,
    /// Migrate this profile's credential to the system keyring.
    Migrate(ServerSelector),
    /// Retry incomplete local deletions; does not revoke server access.
    RetryCleanup,
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
    /// Opt-in ad and tracker blocking on the VPS resolver for every device.
    DnsBlocking {
        #[command(subcommand)]
        command: DnsBlockingCommand,
    },
    /// Opt-in VPS alerts to an ntfy topic or webhook, and a heartbeat for outside monitors.
    Alerts {
        #[command(subcommand)]
        command: AlertsCommand,
    },
    Add(AddServerArguments),
    /// Create a Debian 13 VPS on Hetzner Cloud and install SirinVPN on it over a pre-pinned SSH key.
    /// Reads the API token from HCLOUD_TOKEN or a hidden prompt; the token is not stored.
    CreateHetzner(CreateHetznerArguments),
    BackupVps(BackupVpsArguments),
    /// Show the scheduled VPS backups set up in the app: last backup age and warnings.
    BackupStatus,
    RestoreVps(RestoreVpsArguments),
    /// Show an interrupted VPS maintenance transaction and the state the VPS reports for it. Changes nothing.
    TransactionStatus(TransactionLoginArguments),
    /// Finish an interrupted VPS maintenance transaction: keep the change if the VPS committed it, undo it if not.
    /// `--abandon <SERVER>` instead forgets that server's transaction without asking the VPS; every key is kept.
    Resolve(ResolveArguments),
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
    /// Add a device that joins through a standard WireGuard app or router, Direct UDP only.
    AddWireguardDevice(WireGuardDeviceArguments),
    Members(ServerSelector),
    CancelInvitation(InvitationSelector),
    RenameDevice(RenameDeviceArguments),
    RevokeDevice(DeviceSelector),
    SetPeerCommunication(PeerCommunicationArguments),
    /// Replace the LAN ranges one of the Owner's devices forwards for peers that may reach it.
    SetSubnetRoutes(SubnetRoutesArguments),
    /// Let two devices reach each other whatever their peer-communication mode, or replace their pair.
    PairDevices(DevicePairArguments),
    UnpairDevices(DeviceUnpairArguments),
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

#[derive(Subcommand)]
pub(super) enum DnsBlockingCommand {
    /// Show the chosen lists, allowed domains, built-in lists and the latest VPS refresh.
    Status(ServerSelector),
    /// Turn blocking on. Given lists or allowed domains replace the stored ones.
    Enable(DnsBlockingArguments),
    /// Turn blocking off and keep the chosen lists and allowed domains.
    Disable(ServerSelector),
}

#[derive(Subcommand)]
pub(super) enum AlertsCommand {
    /// Show the alert and heartbeat addresses and the latest VPS results.
    Status(ServerSelector),
    /// Replace the alert settings. An address left out is removed.
    Set(AlertsArguments),
    /// Remove both addresses. The VPS stops checking and sending.
    Off(ServerSelector),
    /// Send a test notice from the VPS to the saved alert address.
    Test(ServerSelector),
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("address").required(true).multiple(true).args(["ntfy", "webhook", "heartbeat"])))]
pub(super) struct AlertsArguments {
    pub(super) server: String,
    /// An ntfy topic address that receives problem and recovery notices.
    #[arg(long, conflicts_with = "webhook")]
    pub(super) ntfy: Option<String>,
    /// An HTTPS webhook that receives the same notices as JSON.
    #[arg(long)]
    pub(super) webhook: Option<String>,
    /// An address the VPS requests every five minutes, for a missed-heartbeat monitor.
    #[arg(long)]
    pub(super) heartbeat: Option<String>,
    /// Allow addresses that are, or resolve to, private, loopback or VPN addresses.
    #[arg(long)]
    pub(super) allow_private: bool,
}

#[derive(Args)]
pub(super) struct DnsBlockingArguments {
    pub(super) server: String,
    /// A built-in list name from `status` or an HTTPS address. Repeat for more lists.
    #[arg(long = "list")]
    pub(super) lists: Vec<String>,
    /// A domain and its subdomains that must never be blocked. Repeat for more.
    #[arg(long = "allow", conflicts_with = "clear_allowlist")]
    pub(super) allow: Vec<String>,
    #[arg(long)]
    pub(super) clear_allowlist: bool,
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

mod server_access;
pub(super) use server_access::*;

mod connect;
pub(super) use connect::*;

mod vps;
pub(super) use vps::*;

mod transport;
pub(super) use transport::*;

#[cfg(test)]
mod tests;
