//! Provisioning.

use super::*;

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
    let identity_reference = server_id.to_string();
    let request = InstallRequest {
        server_id,
        server_name: arguments.name,
        target,
        server_binary: resolve_server_binary(arguments.server_binary)?.into(),
        identity: identity.public.clone(),
        identity_reference: identity_reference.clone(),
        transport,
        dns_upstream: arguments.dns.requested().unwrap_or_default(),
        private_dns_records: arguments.private_dns_record,
        replace_existing_installation: arguments.replace_existing,
    };

    let secrets = paths.secret_store();
    secrets.put(&identity_reference, &identity.secret)?;
    let outcome = match Provisioner::install(request) {
        Ok(outcome) => outcome,
        Err(error) => {
            if secrets.delete(&identity_reference).is_err() {
                bail!(
                    "Provisioning failed; credential cleanup is incomplete. Unlock the secure store and retry credential cleanup."
                );
            }
            return Err(error.into());
        }
    };
    paths.profile_store().upsert(outcome.profile.clone())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome.profile)?);
    } else {
        for event in outcome.events {
            println!("{:?}: {}", event.phase, event.message);
        }
        println!(
            "Server added: {} ({})",
            outcome.profile.name, outcome.profile.id
        );
    }
    Ok(())
}

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
        paths.profile_store().upsert(profile.clone())?;
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
