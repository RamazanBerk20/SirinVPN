//! Provisioning.

use super::*;
use sirinvpn_installer::{ServerBinarySource, hetzner::*};
use std::sync::atomic::AtomicBool;

/// Where this device records unresolved VPS transactions (one per VPS host; an
/// earlier version's single file at this path is moved on first use).
pub(super) fn transaction_journal(paths: &ClientPaths) -> TransactionJournal {
    TransactionJournal::new(paths.configuration_directory.join("vps-transaction.json"))
}

/// Names the new Owner key of an install in progress on `host`, so `server resolve` can delete it if the VPS rolled back.
fn pending_secret_marker(paths: &ClientPaths, host: &str) -> PathBuf {
    transaction_journal(paths).pending_secret_path(host)
}

/// Writes the marker owner-only from the moment it exists (it names a secret).
fn record_pending_secret(paths: &ClientPaths, host: &str, reference: &str) -> std::io::Result<()> {
    use std::io::Write;
    let marker = pending_secret_marker(paths, host);
    // A leftover file would keep its old mode; `create_new` then sets ours.
    let _ = std::fs::remove_file(&marker);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(marker)?.write_all(reference.as_bytes())
}

fn forget_pending_secret(paths: &ClientPaths, host: &str) {
    let _ = std::fs::remove_file(pending_secret_marker(paths, host));
}

/// What the VPS said about a transaction whose commit reply was lost.
pub(super) enum Settlement {
    Committed(Box<ServerProfile>),
    RolledBack,
    /// Still unknown: the VPS was unreachable or has not finished. Keep every key and the journal.
    Unknown(String),
}

pub(super) fn settle(resolved: Result<Option<ResolvedTransaction>, InstallerError>) -> Settlement {
    match resolved {
        Ok(Some(resolved)) => match resolved.state {
            RemoteTransactionState::RolledBack => Settlement::RolledBack,
            RemoteTransactionState::Committed => match resolved.committed_profile() {
                Some(profile) => Settlement::Committed(Box::new(profile.clone())),
                None => Settlement::Unknown(
                    "the VPS committed the change, but this device holds no profile for it"
                        .to_owned(),
                ),
            },
            state => Settlement::Unknown(format!("the VPS reports the transaction as {state:?}")),
        },
        Ok(None) => Settlement::Unknown("this device has no record of the transaction".to_owned()),
        Err(error) => Settlement::Unknown(error.to_string()),
    }
}

/// Asks the VPS what became of the transaction in this device's journal.
pub(super) fn settle_uncertain(paths: &ClientPaths, target: &SshTarget) -> Settlement {
    settle(Provisioner::resolve_transaction(
        target,
        &transaction_journal(paths),
    ))
}

pub(super) fn unresolved_outcome(reason: &str) -> anyhow::Error {
    anyhow!(
        "The outcome on the VPS is unknown ({reason}). This device kept its keys and its record of the transaction. When the VPS is reachable, run `sirinvpn server resolve` to finish it; `sirinvpn server transaction-status` shows where it stands. If the VPS is gone for good, `sirinvpn server resolve --abandon <server>` forgets the record and keeps every key."
    )
}

/// Saves a profile the VPS on `host` confirmed: new for an install, merged for a repair or restore.
pub(super) fn save_committed_profile(
    paths: &ClientPaths,
    committed: &ServerProfile,
    host: &str,
) -> Result<ServerProfile> {
    let store = paths.profile_store();
    let saved = if store.load()?.iter().any(|p| p.id == committed.id) {
        store.update(committed.id, |current| {
            *current = sirinvpn_installer::merge_committed_profile(current, committed);
            Ok(current.clone())
        })?
    } else {
        store.upsert(committed.clone())?;
        committed.clone()
    };
    forget_pending_secret(paths, host);
    Ok(saved)
}

fn plan_output(plan: &InstallPlan, json: bool) -> Result<String> {
    Ok(if json {
        format!("{}\n", serde_json::to_string_pretty(plan)?)
    } else {
        plan.to_text()
    })
}

/// `--plan`: show what the operation would do. Nothing on the VPS or this device changed.
pub(super) fn print_plan(plan: &InstallPlan, json: bool) -> Result<()> {
    print!("{}", plan_output(plan, json)?);
    Ok(())
}

mod transactions;
use transactions::discard_new_secret;
#[cfg(test)]
use transactions::{discard_marked_secret, selected_transaction, transaction_target};
pub(crate) use transactions::{resolve_transaction, transaction_status};

pub(super) fn inspect_host_key(arguments: HostKeyArguments) -> Result<()> {
    let target = SshTarget {
        host: arguments.host,
        port: arguments.port,
        username: "unused".to_owned(),
        authentication: SshAuthentication::Agent,
        sudo_password: None,
        expected_host_key_sha256: None,
    };
    println!("{}", Provisioner::host_key_fingerprint(&target)?);
    Ok(())
}

pub(super) fn add_server(
    paths: &ClientPaths,
    arguments: AddServerArguments,
    json: bool,
) -> Result<()> {
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
    let target = SshTarget {
        host: arguments.host,
        port: arguments.ssh_port,
        username: arguments.username,
        authentication,
        sudo_password,
        expected_host_key_sha256: Some(arguments.host_key),
    };
    let transport = arguments.transport.requested(None)?.unwrap_or_default();
    if arguments.preflight_only {
        let report = Provisioner::inspect_server(&target, &transport, None)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "VPN endpoint: {} ({:?})",
                report.public_endpoint, report.exposure
            );
            for address in &report.assigned_addresses {
                println!(
                    "{}: {}/{}",
                    address.interface, address.address, address.prefix_length
                );
            }
            for port in &report.required_ports {
                println!("Required: {:?} {}", port.protocol, port.port);
            }
            for issue in &report.issues {
                println!(
                    "{}: {}",
                    if issue.blocking { "Conflict" } else { "Review" },
                    issue.message
                );
            }
        }
        if !report.can_install() {
            bail!("Preflight found conflicts; the VPS was not changed.");
        }
        return Ok(());
    }
    let identity = new_identity_for_server(&arguments.name)?;
    let server_id = ServerId::new();
    let request = InstallRequest {
        server_id,
        server_name: arguments.name,
        target,
        server_binary: resolve_server_binary(arguments.server_binary)?,
        identity: identity.public.clone(),
        identity_reference: server_id.to_string(),
        transport,
        dns_upstream: arguments.dns.requested().unwrap_or_default(),
        private_dns_records: arguments.private_dns_record,
        nat64_prefix: arguments.nat64_prefix,
        replace_existing_installation: arguments.replace_existing,
        enable_security_updates: false,
    };
    if arguments.plan {
        return print_plan(&Provisioner::plan_install(request)?, json);
    }
    install_new_server(paths, request, &identity.secret, json)
}

/// Installs with the new Owner identity and saves the profile.
fn install_new_server(
    paths: &ClientPaths,
    request: InstallRequest,
    secret: &SecretIdentity,
    json: bool,
) -> Result<()> {
    let identity_reference = request.identity_reference.clone();
    let target = request.target.clone();
    let host = target.host.as_str();
    // Refused before the marker of the unresolved install on this host is replaced.
    if transaction_journal(paths).read_server(host)?.is_some() {
        return Err(InstallerError::TransactionUnresolved {
            host: host.to_owned(),
        }
        .into());
    }
    let secrets = paths.secret_store();
    secrets.put(&identity_reference, secret)?;
    if let Err(error) = record_pending_secret(paths, host, &identity_reference) {
        discard_new_secret(paths, host, &identity_reference)?;
        return Err(anyhow!(error).context("could not record the new Owner key for this install"));
    }
    let (profile, events) =
        match Provisioner::install_with_journal(request, &transaction_journal(paths)) {
            Ok(outcome) => (outcome.profile, outcome.events),
            // The change may be live, so the Owner key stays until the VPS says otherwise.
            Err(InstallerError::CommitUncertain { .. }) => match settle_uncertain(paths, &target) {
                Settlement::Committed(profile) => (*profile, Vec::new()),
                Settlement::RolledBack => {
                    discard_new_secret(paths, host, &identity_reference)?;
                    bail!("The VPS rolled the installation back. Nothing was installed.");
                }
                Settlement::Unknown(reason) => return Err(unresolved_outcome(&reason)),
            },
            // Anything but `CommitUncertain` means the commit never ran or the VPS
            // confirmed the rollback, so the new key is used nowhere.
            Err(error) => {
                discard_new_secret(paths, host, &identity_reference)?;
                return Err(error.into());
            }
        };
    let profile = save_committed_profile(paths, &profile, host)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&profile)?);
    } else {
        for event in events {
            println!("{:?}: {}", event.phase, event.message);
        }
        println!("Server added: {} ({})", profile.name, profile.id);
    }
    Ok(())
}

mod hetzner;
pub(crate) use hetzner::create_hetzner_server;
#[cfg(test)]
use hetzner::{PendingChoice, host_key_note, pending_choice};

#[derive(Serialize)]
pub(super) struct InvitationOutput<'a> {
    pub(super) invitation_id: InvitationId,
    pub(super) expires_at_unix: u64,
    pub(super) code: &'a str,
}

pub(super) async fn create_invitation(
    paths: &ClientPaths,
    arguments: InviteArguments,
    json: bool,
) -> Result<()> {
    let (mut profile, secret) = connected_identity(paths, &arguments.server)?;
    let client = ManagementClient::new(&profile, &secret)?;
    let status = client.status().await?;
    if let Some(role) = status.caller_role {
        profile.role = role;
        profile.administrator = status.caller_administrator;
        save_caller_role(paths, &profile)?;
    }
    let advanced = arguments.admin || arguments.member_id.is_some();
    let mut policy = arguments
        .policy_file
        .as_deref()
        .map(read_member_policy)
        .transpose()?
        .unwrap_or_default();
    if profile.role == ServerRole::Member
        && !profile.administrator
        && arguments.member_id.is_none()
        && arguments.policy_file.is_none()
    {
        policy = client
            .membership()
            .await?
            .members
            .first()
            .context("this member's policy is unavailable")?
            .policy
            .clone();
        policy.invite_members = false;
    }
    if (arguments.max_uses > 1
        || !policy.is_default()
        || (profile.role == ServerRole::Member && !profile.administrator))
        && !client.configuration().await?.reusable_invitations_enabled
    {
        bail!("update the VPS before creating reusable or scoped invitations");
    }
    if advanced && !client.configuration().await?.advanced_invitations_enabled {
        bail!("the server must be upgraded before creating this invitation type");
    }
    let (member_name, target) = if let Some(member_id) = arguments.member_id {
        let member_id = member_id
            .parse::<MemberId>()
            .context("member identifier is invalid")?;
        let snapshot = client.membership().await?;
        let member = snapshot
            .members
            .iter()
            .find(|member| member.id == member_id)
            .ok_or_else(|| anyhow!("member was not found"))?;
        (
            member.name.clone(),
            InvitationTarget {
                member_id: Some(member.id),
                role: Some(member.role),
                administrator: member.administrator,
            },
        )
    } else {
        (
            arguments.member_name.context("member name is required")?,
            InvitationTarget {
                member_id: None,
                role: None,
                administrator: arguments.admin,
            },
        )
    };
    let draft = InvitationDraft::new_for_target(
        &profile,
        &member_name,
        &arguments.device_name,
        arguments.expires_in,
        target,
    )?
    .with_policy(arguments.max_uses, policy)?;
    let response = client.create_invitation(draft.request()).await?;
    let code = draft.finish(response)?;
    let output = InvitationOutput {
        invitation_id: code.invitation_id(),
        expires_at_unix: code.expires_at_unix(),
        code: code.expose(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Invitation {}", output.invitation_id);
        println!("Expires at Unix time {}", output.expires_at_unix);
        println!("Treat this single-use code like a password:");
        println!("{}", output.code);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
