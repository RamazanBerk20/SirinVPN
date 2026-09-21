use clap::{Args, Parser, Subcommand};
use sirinvpn_protocol::{
    DEFAULT_OBFUSCATED_UDP_PORT, DEFAULT_TCP_FALLBACK_PORT, DEFAULT_TLS_LIKE_PORT,
    DnsOverHttpsEndpoint, DnsOverTlsEndpoint, DnsUpstream, PrivateDnsRecord, ServerId,
};
use sirinvpn_server::{
    MAX_SERVER_BACKUP_SNAPSHOT_BYTES, ServerCapabilities, ServerPaths, default_wireguard_port,
    export_backup_state, initialize_with_transport_capabilities, install_network_guard,
    restore_backup_state, serve, serve_doh_proxy, validate_state,
};
use std::{fs, io::Read, io::Write, path::PathBuf};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "sirinvpn-server")]
struct Arguments {
    #[arg(long, default_value = "/etc/sirinvpn")]
    state_directory: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct InitArguments {
    #[arg(long)]
    public_host: Option<String>,
    #[arg(long)]
    previous_public_host: Option<String>,
    #[arg(long, requires = "public_host")]
    alternate_host: Vec<String>,
    #[arg(long)]
    name: String,
    #[arg(long)]
    owner_certificate: PathBuf,
    #[arg(long)]
    server_id: ServerId,
    #[arg(long)]
    owner_wireguard_public_key: String,
    #[arg(long, default_value_t = default_wireguard_port())]
    wireguard_port: u16,
    #[arg(long)]
    ipv6_tunnel_enabled: Option<bool>,
    #[arg(long, default_value_t = DEFAULT_OBFUSCATED_UDP_PORT)]
    obfuscated_udp_port: u16,
    #[arg(long, default_value_t = DEFAULT_TCP_FALLBACK_PORT)]
    tcp_fallback_port: u16,
    #[arg(long, default_value_t = DEFAULT_TLS_LIKE_PORT)]
    tls_like_port: u16,
    #[arg(long)]
    https_server_name: Option<String>,
    #[arg(long, default_value = "/connect")]
    https_path: String,
    #[arg(long, requires_all = ["https_private_key", "https_server_name"])]
    https_certificate: Option<PathBuf>,
    #[arg(long, requires_all = ["https_certificate", "https_server_name"])]
    https_private_key: Option<PathBuf>,
    #[arg(long)]
    update_transport_ports: bool,
    #[arg(long, conflicts_with = "https_server_name")]
    disable_https: bool,
    #[arg(
        long,
        conflicts_with_all = ["dns_over_tls_endpoint", "dns_over_https_endpoint"]
    )]
    recursive_dns: bool,
    #[arg(
        long,
        value_name = "IP#AUTHENTICATION_NAME",
        conflicts_with_all = ["recursive_dns", "dns_over_https_endpoint"]
    )]
    dns_over_tls_endpoint: Vec<DnsOverTlsEndpoint>,
    #[arg(
        long,
        value_name = "IP#AUTHENTICATION_NAME/PATH",
        conflicts_with_all = ["recursive_dns", "dns_over_tls_endpoint"]
    )]
    dns_over_https_endpoint: Vec<DnsOverHttpsEndpoint>,
    #[arg(long, conflicts_with_all = ["recursive_dns", "dns_over_tls_endpoint", "dns_over_https_endpoint"])]
    dns_policy_json: Option<String>,
    #[arg(
        long,
        value_name = "DNS_NAME=IP",
        conflicts_with = "clear_private_dns_records"
    )]
    private_dns_record: Vec<PrivateDnsRecord>,
    #[arg(long, conflicts_with = "private_dns_record")]
    clear_private_dns_records: bool,
}

#[derive(Subcommand)]
enum Command {
    Release {
        #[command(subcommand)]
        command: sirinvpn_server::release_update::ReleaseCommand,
    },
    Init(Box<InitArguments>),
    ValidateState,
    NetworkGuard,
    BackupState {
        #[arg(long)]
        server_id: ServerId,
        #[arg(long)]
        owner_certificate: PathBuf,
    },
    RestoreState {
        #[arg(long)]
        server_id: ServerId,
        #[arg(long)]
        owner_certificate: PathBuf,
    },
    DohProxy,
    Serve,
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let paths = ServerPaths::under(arguments.state_directory);
    match arguments.command {
        Command::Release { command } => {
            match sirinvpn_server::release_update::run(command, paths).await {
                Ok(value) => println!("{}", serde_json::to_string(&value)?),
                Err(error) => {
                    // Return a bounded functional error only to the requesting
                    // SSH command. The service never persists release output.
                    println!("{}", serde_json::json!({"error": error.to_string()}));
                    return Err(error);
                }
            }
        }
        Command::Init(arguments) => {
            let InitArguments {
                public_host,
                previous_public_host,
                alternate_host,
                name,
                owner_certificate,
                server_id,
                owner_wireguard_public_key,
                wireguard_port,
                ipv6_tunnel_enabled,
                obfuscated_udp_port,
                tcp_fallback_port,
                tls_like_port,
                https_server_name,
                https_path,
                https_certificate,
                https_private_key,
                update_transport_ports,
                disable_https,
                recursive_dns,
                dns_over_tls_endpoint,
                dns_over_https_endpoint,
                dns_policy_json,
                private_dns_record,
                clear_private_dns_records,
            } = *arguments;
            let owner_certificate = fs::read_to_string(owner_certificate)?;
            let dns_upstream = if let Some(json) = dns_policy_json {
                anyhow::ensure!(json.len() <= 32_768, "DNS policy is oversized");
                let policy: DnsUpstream = serde_json::from_str(&json)?;
                sirinvpn_protocol::validate_dns_upstream(&policy)?;
                Some(policy)
            } else if recursive_dns {
                Some(DnsUpstream::Recursive)
            } else if dns_over_tls_endpoint.is_empty() {
                if dns_over_https_endpoint.is_empty() {
                    None
                } else {
                    Some(DnsUpstream::DnsOverHttps {
                        endpoints: dns_over_https_endpoint,
                    })
                }
            } else {
                Some(DnsUpstream::DnsOverTls {
                    endpoints: dns_over_tls_endpoint,
                })
            };
            let private_dns_records = if clear_private_dns_records {
                Some(Vec::new())
            } else if private_dns_record.is_empty() {
                None
            } else {
                Some(private_dns_record)
            };
            let result = initialize_with_transport_capabilities(
                &paths,
                &name,
                &owner_certificate,
                server_id,
                &owner_wireguard_public_key,
                wireguard_port,
                ServerCapabilities {
                    alternate_endpoint_hosts: public_host.as_ref().map(|_| alternate_host),
                    public_host,
                    previous_public_host,
                    ipv6_tunnel_enabled,
                    obfuscated_udp_port: Some(obfuscated_udp_port),
                    tcp_fallback_port: Some(tcp_fallback_port),
                    tls_like_port: Some(tls_like_port),
                    update_transport_ports,
                    disable_https,
                    https: https_server_name.map(|server_name| sirinvpn_protocol::HttpsTransport {
                        server_name,
                        path: https_path,
                    }),
                    https_certificate: https_certificate.zip(https_private_key).map(
                        |(certificate, private_key)| sirinvpn_server::HttpsCertificatePaths {
                            certificate,
                            private_key,
                        },
                    ),
                    dns_upstream,
                    private_dns_records,
                },
            )?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::ValidateState => validate_state(&paths)?,
        Command::NetworkGuard => install_network_guard(&paths).await?,
        Command::BackupState {
            server_id,
            owner_certificate,
        } => {
            let owner_certificate = fs::read_to_string(owner_certificate)?;
            let snapshot = export_backup_state(&paths, server_id, &owner_certificate)?;
            std::io::stdout().write_all(snapshot.as_slice())?;
        }
        Command::RestoreState {
            server_id,
            owner_certificate,
        } => {
            let owner_certificate = fs::read_to_string(owner_certificate)?;
            let mut snapshot = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take((MAX_SERVER_BACKUP_SNAPSHOT_BYTES + 1) as u64)
                .read_to_end(&mut snapshot)?;
            restore_backup_state(&paths, server_id, &owner_certificate, snapshot.as_slice())?;
        }
        Command::DohProxy => serve_doh_proxy(&paths).await?,
        Command::Serve => serve(&paths).await?,
    }
    Ok(())
}
