use super::*;

#[derive(Args)]
pub(crate) struct AddServerArguments {
    /// Report addresses, NAT indications, required ports and conflicts without installing.
    #[arg(long, conflicts_with = "replace_existing")]
    pub(crate) preflight_only: bool,
    /// Connect read-only and print every command and file change an install would make, then stop.
    #[arg(long, conflicts_with = "preflight_only")]
    pub(crate) plan: bool,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) host: String,
    #[arg(long, default_value = "root")]
    pub(crate) username: String,
    #[arg(long, default_value_t = 22)]
    pub(crate) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(crate) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) ssh_agent: bool,
    #[arg(long)]
    pub(crate) host_key: String,
    #[arg(long)]
    pub(crate) server_binary: Option<PathBuf>,
    #[arg(long)]
    pub(crate) passwordless_sudo: bool,
    /// Replace an existing SirinVPN identity after SSH authorization.
    #[arg(long)]
    pub(crate) replace_existing: bool,
    #[command(flatten)]
    pub(crate) dns: DnsPolicyArguments,
    #[arg(long, value_name = "DNS_NAME=IP")]
    pub(crate) private_dns_record: Vec<PrivateDnsRecord>,
    /// On a VPS without IPv4, reach IPv4-only websites through this NAT64 gateway's /96 prefix.
    #[arg(long, value_name = "PREFIX/96", value_parser = sirinvpn_installer::parse_nat64_prefix)]
    pub(crate) nat64_prefix: Option<std::net::Ipv6Addr>,
    #[command(flatten)]
    pub(crate) transport: TransportArguments,
}

#[derive(Args)]
pub(crate) struct CreateHetznerArguments {
    #[arg(long)]
    pub(crate) name: String,
    /// Hetzner location, such as fsn1. Defaults to the first location Hetzner lists.
    #[arg(long)]
    pub(crate) location: Option<String>,
    /// Hetzner server type, such as cx23. Defaults to the cheapest x86 type in the location.
    #[arg(long)]
    pub(crate) server_type: Option<String>,
    /// Create the server at this monthly price, as printed by a run without this option.
    #[arg(long, value_name = "AMOUNT")]
    pub(crate) accept_monthly_price: Option<String>,
    #[arg(long)]
    pub(crate) server_binary: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) dns: DnsPolicyArguments,
    #[arg(long, value_name = "DNS_NAME=IP")]
    pub(crate) private_dns_record: Vec<PrivateDnsRecord>,
    #[command(flatten)]
    pub(crate) transport: TransportArguments,
}

#[derive(Args)]
pub(crate) struct DnsPolicyArguments {
    /// Forward this domain suffix to explicit private or TLS resolvers. Repeat for more zones.
    #[arg(long, value_name = "SUFFIX=IP[,IP] or SUFFIX=IP#TLS_NAME")]
    pub(crate) split_dns_zone: Vec<sirinvpn_protocol::DnsSplitZone>,
    #[arg(
        long,
        conflicts_with_all = ["dns_over_tls_endpoint", "dns_over_https_endpoint"]
    )]
    pub(crate) recursive_dns: bool,
    #[arg(
        long,
        value_name = "IP#AUTHENTICATION_NAME",
        conflicts_with_all = ["recursive_dns", "dns_over_https_endpoint"]
    )]
    pub(crate) dns_over_tls_endpoint: Vec<DnsOverTlsEndpoint>,
    #[arg(
        long,
        value_name = "IP#AUTHENTICATION_NAME/PATH",
        conflicts_with_all = ["recursive_dns", "dns_over_tls_endpoint"]
    )]
    pub(crate) dns_over_https_endpoint: Vec<DnsOverHttpsEndpoint>,
}

impl DnsPolicyArguments {
    pub(crate) fn requested(&self) -> Option<DnsUpstream> {
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
pub(crate) struct UninstallServerArguments {
    pub(crate) server: String,
    #[arg(long, default_value = "root")]
    pub(crate) username: String,
    #[arg(long, default_value_t = 22)]
    pub(crate) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(crate) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) ssh_agent: bool,
    #[arg(long)]
    pub(crate) host_key: String,
    #[arg(long)]
    pub(crate) passwordless_sudo: bool,
    #[arg(long)]
    pub(crate) confirm_uninstall: bool,
    /// Connect read-only and print every command and file change this would make, then stop.
    #[arg(long)]
    pub(crate) plan: bool,
}

#[derive(Args)]
pub(crate) struct RepairServerArguments {
    pub(crate) server: String,
    #[arg(long, default_value = "root")]
    pub(crate) username: String,
    #[arg(long, default_value_t = 22)]
    pub(crate) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(crate) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) ssh_agent: bool,
    #[arg(long)]
    pub(crate) host_key: String,
    #[arg(long)]
    pub(crate) server_binary: Option<PathBuf>,
    #[arg(long)]
    pub(crate) passwordless_sudo: bool,
    #[arg(long)]
    pub(crate) confirm_repair: bool,
    /// Connect read-only and print every command and file change this would make, then stop.
    #[arg(long)]
    pub(crate) plan: bool,
    /// Turn the OS's automatic security updates on even where they are installed but off.
    #[arg(long)]
    pub(crate) enable_security_updates: bool,
    #[command(flatten)]
    pub(crate) dns: DnsPolicyArguments,
    #[command(flatten)]
    pub(crate) private_dns: PrivateDnsRecordArguments,
    /// Without either flag the VPS keeps its current NAT64 choice.
    #[arg(long, value_name = "PREFIX/96", value_parser = sirinvpn_installer::parse_nat64_prefix, conflicts_with = "no_nat64")]
    pub(crate) nat64_prefix: Option<std::net::Ipv6Addr>,
    #[arg(long)]
    pub(crate) no_nat64: bool,
    #[command(flatten)]
    pub(crate) transport: TransportArguments,
}

#[derive(Args)]
pub(crate) struct BackupVpsArguments {
    pub(crate) server: String,
    #[arg(long)]
    pub(crate) output: PathBuf,
    #[arg(long, default_value = "root")]
    pub(crate) username: String,
    #[arg(long, default_value_t = 22)]
    pub(crate) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(crate) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) ssh_agent: bool,
    #[arg(long)]
    pub(crate) host_key: String,
    #[arg(long)]
    pub(crate) server_binary: Option<PathBuf>,
    #[arg(long)]
    pub(crate) passwordless_sudo: bool,
    #[arg(long)]
    pub(crate) confirm_server_backup: bool,
}

#[derive(Args)]
pub(crate) struct RestoreVpsArguments {
    pub(crate) server: String,
    #[arg(long)]
    pub(crate) input: PathBuf,
    #[arg(long)]
    pub(crate) host: String,
    #[arg(long, default_value = "root")]
    pub(crate) username: String,
    #[arg(long, default_value_t = 22)]
    pub(crate) ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(crate) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) ssh_agent: bool,
    #[arg(long)]
    pub(crate) host_key: String,
    #[arg(long)]
    pub(crate) server_binary: Option<PathBuf>,
    #[arg(long)]
    pub(crate) passwordless_sudo: bool,
    #[arg(long)]
    pub(crate) replace_existing: bool,
    #[arg(long)]
    pub(crate) confirm_server_restore: bool,
    /// Connect read-only and print every command and file change this would make, then stop.
    #[arg(long)]
    pub(crate) plan: bool,
}

#[derive(Args)]
pub(crate) struct PrivateDnsRecordArguments {
    #[arg(
        long,
        value_name = "DNS_NAME=IP",
        conflicts_with = "clear_private_dns_records"
    )]
    pub(crate) private_dns_record: Vec<PrivateDnsRecord>,
    #[arg(long, conflicts_with = "private_dns_record")]
    pub(crate) clear_private_dns_records: bool,
}

impl PrivateDnsRecordArguments {
    pub(crate) fn requested(&self) -> Option<Vec<PrivateDnsRecord>> {
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
pub(crate) struct ResolveArguments {
    #[command(flatten)]
    pub(crate) login: TransactionLoginArguments,
    /// Forget this server's unresolved transaction (a saved server's name or ID, or the VPS host)
    /// without contacting the VPS. The VPS may be committed or rolled back; no key is deleted.
    #[arg(long, value_name = "SERVER", conflicts_with = "server")]
    pub(crate) abandon: Option<String>,
}

/// The VPS address, SSH port and pinned host key come from the interrupted transaction itself.
#[derive(Args)]
pub(crate) struct TransactionLoginArguments {
    /// The server whose transaction to use (a saved server's name or ID, or the VPS host);
    /// needed only when more than one is unresolved.
    #[arg(long, value_name = "SERVER")]
    pub(crate) server: Option<String>,
    #[arg(long, default_value = "root")]
    pub(crate) username: String,
    #[arg(long, conflicts_with = "ssh_agent")]
    pub(crate) ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) ssh_agent: bool,
    #[arg(long)]
    pub(crate) passwordless_sudo: bool,
}

#[derive(Args)]
pub(crate) struct RotateKeysArguments {
    pub(crate) server: String,
    #[arg(long)]
    pub(crate) confirm_key_rotation: bool,
}

#[derive(Serialize)]
pub(crate) struct CombinedStatus {
    pub(crate) local: LocalTunnelStatus,
    pub(crate) server: Option<sirinvpn_protocol::ServerStatus>,
    pub(crate) preshared_key_rotation_recommended: bool,
}

#[derive(Serialize)]
pub(crate) struct BackupOperationResult {
    pub(crate) operation: &'static str,
    pub(crate) server_id: ServerId,
    pub(crate) name: String,
}

#[derive(Serialize)]
pub(crate) struct RepairOperationResult {
    pub(crate) repaired: bool,
    pub(crate) server_id: ServerId,
    pub(crate) artifact_sha256: String,
    pub(crate) dns_upstream: DnsUpstream,
    pub(crate) private_dns_records: Vec<PrivateDnsRecord>,
}

#[derive(Serialize)]
pub(crate) struct EndpointUpdateCodeResult {
    pub(crate) server_id: ServerId,
    pub(crate) generation: u64,
    pub(crate) previous_endpoint: ServerEndpoint,
    pub(crate) endpoint: ServerEndpoint,
    pub(crate) code: String,
}
