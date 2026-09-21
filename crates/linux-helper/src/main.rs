use clap::{Parser, Subcommand};
use sirinvpn_linux_helper::{
    HELPER_PROTOCOL_VERSION, LinuxNetworkHelper, authorize_invoking_user,
    install_system_integration, read_connect_request, require_root,
};

#[derive(Parser)]
#[command(name = "sirinvpn-helper")]
struct Arguments {
    #[command(subcommand)]
    command: HelperCommand,
}

#[derive(Subcommand)]
enum HelperCommand {
    Connect,
    ConnectManaged,
    MeasureSession,
    Disconnect,
    PauseForKeyRotation,
    Resume,
    PauseSession,
    ReconnectSession,
    SwitchSession,
    ApplyEndpointCheckpoint,
    PublishEndpointCheckpoint,
    DisconnectSession,
    Status,
    Version,
    RestoreKillSwitch,
    Supervise,
    Relay {
        #[arg(long)]
        transport: Option<String>,
    },
    InstallSystem,
    AuthorizeUser,
    LaunchApplication,
    #[command(hide = true)]
    ApplicationChild,
}

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let helper = LinuxNetworkHelper::system();
    let status = match arguments.command {
        HelperCommand::LaunchApplication | HelperCommand::ApplicationChild => {
            require_root()?;
            use std::io::Read;
            let mut bytes = Vec::new();
            std::io::stdin()
                .lock()
                .take(32769)
                .read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 32768, "application request too large");
            let request = serde_json::from_slice(&bytes)?;
            if matches!(arguments.command, HelperCommand::ApplicationChild) {
                helper.enter_application(&request)?;
                return Ok(());
            }
            let result = helper.launch_application(&request)?;
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }
        HelperCommand::ConnectManaged => {
            require_root()?;
            use std::io::Read;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin()
                .lock()
                .take(98305)
                .read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 98304, "managed connection too large");
            helper.connect_managed(&serde_json::from_slice(&bytes)?)?
        }
        HelperCommand::MeasureSession => {
            require_root()?;
            use std::io::Read;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().lock().take(4097).read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 4096, "measurement request too large");
            let request = serde_json::from_slice(&bytes)?;
            helper.measure_session(&request)?
        }
        HelperCommand::Connect => {
            require_root()?;
            let request = read_connect_request()?;
            helper.connect(&request)?
        }
        HelperCommand::Disconnect => {
            require_root()?;
            helper.disconnect()?
        }
        HelperCommand::PauseForKeyRotation => {
            require_root()?;
            use std::io::Read;
            let server_id = serde_json::from_reader(std::io::stdin().lock().take(256))?;
            helper.pause_for_key_rotation(server_id)?
        }
        HelperCommand::Resume => {
            require_root()?;
            use std::io::Read;
            let server_id = serde_json::from_reader(std::io::stdin().lock().take(256))?;
            helper.resume(server_id)?
        }
        HelperCommand::Status => helper.status()?,
        HelperCommand::PauseSession
        | HelperCommand::ReconnectSession
        | HelperCommand::DisconnectSession => {
            require_root()?;
            use std::io::Read;
            let id = serde_json::from_reader(std::io::stdin().lock().take(256))?;
            match arguments.command {
                HelperCommand::PauseSession => helper.pause_session(id)?,
                HelperCommand::ReconnectSession => helper.reconnect_session(id)?,
                _ => helper.disconnect_session(id)?,
            }
        }
        HelperCommand::ApplyEndpointCheckpoint | HelperCommand::PublishEndpointCheckpoint => {
            require_root()?;
            use std::io::Read;
            let mut input = Vec::new();
            std::io::stdin()
                .lock()
                .take(24577)
                .read_to_end(&mut input)?;
            anyhow::ensure!(input.len() <= 24576, "endpoint checkpoint is too large");
            let checkpoint = serde_json::from_slice(&input)?;
            match arguments.command {
                HelperCommand::ApplyEndpointCheckpoint => {
                    helper.apply_endpoint_checkpoint(&checkpoint)?
                }
                _ => helper.publish_endpoint_checkpoint(&checkpoint)?,
            }
        }
        HelperCommand::SwitchSession => {
            require_root()?;
            use std::io::Read;
            let mut input = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin()
                .lock()
                .take(65537)
                .read_to_end(&mut input)?;
            anyhow::ensure!(input.len() <= 65536, "session request too large");
            let request = serde_json::from_slice(&input)?;
            helper.switch_session(&request)?
        }
        HelperCommand::AuthorizeUser => {
            authorize_invoking_user()?;
            return Ok(());
        }
        HelperCommand::Version => {
            println!("{HELPER_PROTOCOL_VERSION}");
            return Ok(());
        }
        HelperCommand::RestoreKillSwitch => {
            require_root()?;
            helper.restore_kill_switch()?;
            return Ok(());
        }
        HelperCommand::Supervise => {
            require_root()?;
            helper.supervise()?;
            return Ok(());
        }
        HelperCommand::Relay { transport } => {
            let kind = transport
                .as_deref()
                .map(|value| match value {
                    "obfuscated_udp" => Ok(sirinvpn_protocol::TransportKind::ObfuscatedUdp),
                    "tcp_fallback" => Ok(sirinvpn_protocol::TransportKind::TcpFallback),
                    "tls_like" => Ok(sirinvpn_protocol::TransportKind::TlsLike),
                    _ => Err(anyhow::anyhow!("unknown carrier")),
                })
                .transpose()?;
            sirinvpn_linux_helper::run_transport_relay_for(kind)?;
            return Ok(());
        }
        HelperCommand::InstallSystem => {
            install_system_integration()?;
            return Ok(());
        }
    };
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
}
