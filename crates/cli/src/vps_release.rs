use super::*;
use sirinvpn_installer::{ServerReleaseAction, ServerReleaseRequest};

#[derive(Args)]
pub(super) struct Arguments {
    server: String,
    #[arg(long, default_value = "root")]
    username: String,
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,
    #[arg(long, conflicts_with = "ssh_agent")]
    ssh_key: Option<PathBuf>,
    #[arg(long)]
    ssh_agent: bool,
    #[arg(long)]
    host_key: String,
    #[arg(long)]
    passwordless_sudo: bool,
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Install a verified bundle through guarded SSH repair when no receipt exists.
    Bootstrap {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        manifest_sha256: String,
    },
    Status,
    Check {
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "stable")]
        channel: String,
    },
    Install {
        #[arg(long)]
        manifest_sha256: String,
    },
    Rollback {
        #[arg(long)]
        confirmed: bool,
    },
    Configure {
        #[arg(long)]
        enabled: bool,
        #[arg(long)]
        source: Option<String>,
    },
    Recover,
}

pub(super) fn run(paths: &ClientPaths, arguments: Arguments, json: bool) -> Result<()> {
    let profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    if profile.role != ServerRole::Owner {
        bail!("only the Owner can manage signed VPS releases");
    }
    if matches!(
        arguments.operation,
        Operation::Install { .. }
            | Operation::Rollback { .. }
            | Operation::Recover
            | Operation::Bootstrap { .. }
    ) {
        let status = invoke_helper("status", None)?;
        if status.state != ConnectionState::Disconnected
            || status.kill_switch_enabled
            || status.auto_reconnect_enabled
        {
            bail!("disconnect this computer before restarting the VPS services");
        }
        if has_pending_key_rotation(paths, profile.id)? {
            bail!("finish the pending device key rotation first");
        }
    }
    let bootstrap = match &arguments.operation {
        Operation::Bootstrap {
            bundle,
            manifest_sha256,
        } => Some((bundle.clone(), manifest_sha256.clone())),
        _ => None,
    };
    let action = match arguments.operation {
        Operation::Bootstrap { .. } => ServerReleaseAction::Status,
        Operation::Status => ServerReleaseAction::Status,
        Operation::Check { source, channel } => ServerReleaseAction::Check { source, channel },
        Operation::Install { manifest_sha256 } => ServerReleaseAction::Install { manifest_sha256 },
        Operation::Rollback { confirmed } => ServerReleaseAction::Rollback { confirmed },
        Operation::Configure { enabled, source } => {
            ServerReleaseAction::Configure { enabled, source }
        }
        Operation::Recover => ServerReleaseAction::Recover,
    };
    let authentication = if arguments.ssh_agent {
        SshAuthentication::Agent
    } else if let Some(path) = arguments.ssh_key {
        let passphrase = prompt_secret("SSH key passphrase (leave empty if none): ")?;
        SshAuthentication::PrivateKey {
            path,
            passphrase: (!passphrase.is_empty()).then_some(passphrase),
        }
    } else {
        SshAuthentication::Password(prompt_nonempty_secret("SSH password: ")?)
    };
    let sudo_password = if arguments.username == "root" || arguments.passwordless_sudo {
        None
    } else {
        Some(prompt_nonempty_secret("sudo password: ")?)
    };
    let secret = paths.secret_store().get(&profile.identity_reference)?;
    let identity = secret.public_identity(&profile.client_management_certificate_pem)?;
    let request = ServerReleaseRequest {
        target: SshTarget {
            host: profile.endpoint.host.clone(),
            port: arguments.ssh_port,
            username: arguments.username,
            authentication,
            sudo_password,
            expected_host_key_sha256: Some(arguments.host_key),
        },
        profile,
        identity,
        action,
    };
    let value = if let Some((directory, digest)) = bootstrap {
        let discovery = Provisioner::inspect_signed_baseline_target(&request)?;
        let bundle = std::sync::Arc::new(sirinvpn_installer::SignedServerBundle::open(
            &directory,
            &discovery.architecture,
        )?);
        if bundle.summary().manifest_sha256 != digest {
            bail!("the selected bundle differs from the reviewed signed manifest");
        }
        let profile = request.profile.clone();
        let outcome = Provisioner::install_signed_baseline(request, bundle)?;
        paths
            .profile_store()
            .upsert(outcome.repair.updated_profile(&profile))?;
        outcome.release
    } else {
        Provisioner::manage_server_release(request)?
    };
    println!(
        "{}",
        if json {
            serde_json::to_string(&value)?
        } else {
            serde_json::to_string_pretty(&value)?
        }
    );
    Ok(())
}
