mod arguments;
use arguments::*;
mod provisioning;
use provisioning::*;
mod membership;
use membership::*;
mod member_lifecycle;
mod recovery;
use member_lifecycle::*;
mod profiles;
use profiles::*;
mod maintenance;
mod vps_release;
use maintenance::*;
mod connection;
mod connection_policy;
use connection::*;
use connection_policy::*;
mod output;
mod storage;
use output::*;
#[cfg_attr(windows, path = "helper_windows.rs")]
mod helper;
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use helper::*;
use serde::Serialize;
use sirinvpn_core::{
    ClientPaths, DecodedInvitation, EndpointTransitionCode, InvitationDraft, InvitationTarget,
    ManagementClient, ManagementError, NetworkContext, ProfileStore, RotationConnectionPolicy,
    SecretIdentity, SecretStore, apply_endpoint_transition, create_endpoint_transition,
    has_pending_key_rotation, publish_endpoint_transition, rotate_current_device_keys_with_policy,
};
use sirinvpn_installer::{
    InstallRequest, Provisioner, RepairRequest, ServerBackupRequest, ServerRestoreRequest,
    SshAuthentication, SshTarget, UninstallRequest, new_identity_for_server,
};
use sirinvpn_protocol::{
    ConnectionState, DeviceId, DiagnosticReport, DnsOverHttpsEndpoint, DnsOverTlsEndpoint,
    DnsUpstream, InvitationId, MemberId, MembershipSnapshot, NetworkProfile,
    PortForwardCreateRequest, PortForwardProtocol, PrivateDnsRecord, ServerEndpoint, ServerId,
    ServerProfile, ServerRole, TransportKind, TransportPreference, ipv6_tunnel_address,
};
use sirinvpn_transport::{
    AutomaticAttempt, TransportEngine, TransportSelection, establish_automatic,
};
use sirinvpn_tunnel_model::{
    ConnectionPolicy, LocalTunnelStatus, TunnelConnectRequest, TunnelRoutingPolicy,
    automatic_reconnect_candidates,
};
use std::{
    env,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "sirinvpn", about = "Local-only SirinVPN control plane")]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let paths = ClientPaths::discover()?;
    match cli.command {
        Commands::Storage { command } => storage::run(&paths, command),
        Commands::HostKey(arguments) => inspect_host_key(arguments),
        Commands::Server { command } => match *command {
            ServerCommand::Release(arguments) => vps_release::run(&paths, arguments, cli.json),
            ServerCommand::Recovery { command } => recovery::run(&paths, command, cli.json).await,
            ServerCommand::Add(arguments) => add_server(&paths, arguments, cli.json),
            ServerCommand::BackupVps(arguments) => backup_vps(&paths, arguments, cli.json),
            ServerCommand::RestoreVps(arguments) => restore_vps(&paths, arguments, cli.json),
            ServerCommand::CreateEndpointUpdate(selector) => {
                create_endpoint_update(&paths, selector, cli.json).await
            }
            ServerCommand::PublishEndpointUpdate(arguments) => {
                publish_endpoint_update(&paths, arguments, cli.json).await
            }
            ServerCommand::ApplyEndpointUpdate(arguments) => {
                apply_endpoint_update(&paths, arguments, cli.json).await
            }
            ServerCommand::Join(arguments) => join_server(&paths, arguments, cli.json).await,
            ServerCommand::Export(arguments) => export_server(&paths, arguments, cli.json),
            ServerCommand::Import(arguments) => import_server(&paths, arguments, cli.json),
            ServerCommand::List => list_servers(&paths.profile_store(), cli.json),
            ServerCommand::Remove(selector) => remove_server(&paths, &selector.server),
            ServerCommand::Repair(arguments) => repair_server(&paths, arguments, cli.json),
            ServerCommand::RotateKeys(arguments) => rotate_keys(&paths, arguments, cli.json).await,
            ServerCommand::Uninstall(arguments) => uninstall_server(&paths, arguments, cli.json),
            ServerCommand::Invite(arguments) => {
                create_invitation(&paths, arguments, cli.json).await
            }
            ServerCommand::Members(selector) => {
                show_membership(&paths, &selector.server, cli.json).await
            }
            ServerCommand::CancelInvitation(selector) => {
                cancel_invitation(&paths, selector, cli.json).await
            }
            ServerCommand::RenameDevice(arguments) => {
                rename_device(&paths, arguments, cli.json).await
            }
            ServerCommand::RevokeDevice(selector) => {
                revoke_device(&paths, selector, cli.json).await
            }
            ServerCommand::SetPeerCommunication(arguments) => {
                set_peer_communication(&paths, arguments, cli.json).await
            }
            ServerCommand::AddPortForward(arguments) => {
                add_port_forward(&paths, arguments, cli.json).await
            }
            ServerCommand::RemovePortForward(arguments) => {
                remove_port_forward(&paths, arguments, cli.json).await
            }
            ServerCommand::SetMemberAccess(arguments) => {
                set_member_access(&paths, arguments, cli.json).await
            }
            ServerCommand::SuspendMember(selector) => {
                set_member_suspension(&paths, selector, true, cli.json).await
            }
            ServerCommand::SetMemberPolicy(arguments) => {
                set_member_policy(&paths, arguments, cli.json).await
            }
            ServerCommand::ReactivateMember(selector) => {
                set_member_suspension(&paths, selector, false, cli.json).await
            }
            ServerCommand::RevokeMemberDevices(arguments) => {
                revoke_member_devices(&paths, arguments, cli.json).await
            }
            ServerCommand::TransferOwnership(arguments) => {
                transfer_ownership(&paths, arguments, cli.json).await
            }
        },
        Commands::Connect(arguments) => {
            let routing = if arguments.applications {
                TunnelRoutingPolicy::selected_applications(arguments.allow_lan)
            } else if arguments.routes.is_empty() {
                TunnelRoutingPolicy::full_tunnel(arguments.allow_lan)
            } else {
                TunnelRoutingPolicy::selected_routes(arguments.routes, arguments.allow_lan)
                    .map_err(anyhow::Error::msg)?
            };
            connect(
                &paths,
                &arguments.server,
                if arguments.persistent {
                    ConnectionPolicy::legacy(true)
                } else {
                    ConnectionPolicy {
                        kill_switch: arguments.kill_switch,
                        automatic_reconnect: arguments.automatic_reconnect,
                        connect_on_startup: arguments.connect_on_startup,
                    }
                },
                arguments.transport.into(),
                arguments.network_profile.map(Into::into),
                routing,
                arguments.mtu,
                cli.json,
            )
            .await
        }
        Commands::Resume(selector) => {
            let profile = resolve_profile(&paths.profile_store(), &selector.server)?;
            let input = serde_json::to_vec(&profile.id)?;
            let status = invoke_helper("resume", Some(&input))?;
            print_value(
                &status,
                cli.json,
                "Resuming the active connection policy. The traffic block was retained.",
            )
        }
        Commands::Run(arguments) => {
            let profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
            let launch = sirinvpn_tunnel_model::ApplicationLaunchRequest {
                server_id: profile.id,
                executable: arguments.executable,
                arguments: arguments.arguments,
                environment: [
                    "DISPLAY",
                    "WAYLAND_DISPLAY",
                    "XAUTHORITY",
                    "XDG_RUNTIME_DIR",
                    "LANG",
                    "LC_ALL",
                ]
                .into_iter()
                .filter_map(|key| env::var(key).ok().map(|value| (key.to_owned(), value)))
                .collect(),
            };
            launch.validate()?;
            let input = serde_json::to_vec(&launch)?;
            let result: sirinvpn_tunnel_model::ApplicationLaunchResult = serde_json::from_slice(
                &helper::invoke_helper_payload("launch-application", Some(&input))?,
            )?;
            let message = if result.completed {
                "The command finished. No running application was confirmed."
            } else {
                "A new process was launched in the VPN. Existing applications remain on their current network."
            };
            print_value(&result, cli.json, message)
        }
        Commands::Disconnect => disconnect(cli.json),
        Commands::Status => status(&paths, cli.json).await,
        Commands::Diagnose(selector) => diagnose(&paths, &selector.server, cli.json).await,
    }
}
