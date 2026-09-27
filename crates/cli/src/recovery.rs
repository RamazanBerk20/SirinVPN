use super::*;
use sirinvpn_core::{DecodedRecoveryKey, PendingEnrollment, RecoveryKeyDraft};
use sirinvpn_protocol::{RecoveryId, RecoveryPolicy};

async fn client(paths: &ClientPaths, selector: &str) -> Result<(ServerProfile, ManagementClient)> {
    let (profile, secret) = connected_identity(paths, selector)?;
    let client = ManagementClient::new(&profile, &secret)?;
    if !client.configuration().await?.recovery_keys_enabled {
        bail!("update the VPS before configuring offline recovery");
    }
    Ok((profile, client))
}

pub(super) async fn run(paths: &ClientPaths, command: RecoveryCommand, json: bool) -> Result<()> {
    match command {
        RecoveryCommand::Status(selector) => {
            let settings = client(paths, &selector.server)
                .await?
                .1
                .recovery_settings()
                .await?;
            println!("{}", serde_json::to_string_pretty(&settings)?);
        }
        RecoveryCommand::Policy(arguments) => {
            let ids = arguments
                .administrator_member_id
                .iter()
                .map(|id| id.parse::<MemberId>())
                .collect::<Result<Vec<_>, _>>()?;
            let settings = client(paths, &arguments.server)
                .await?
                .1
                .update_recovery_policy(&RecoveryPolicy {
                    administrator_member_ids: ids,
                })
                .await?;
            print_value(&settings, json, "Administrator recovery policy updated.")?;
        }
        RecoveryCommand::Revoke(arguments) => {
            let id = arguments.recovery_id.parse::<RecoveryId>()?;
            let settings = client(paths, &arguments.server)
                .await?
                .1
                .revoke_recovery_key(id)
                .await?;
            print_value(&settings, json, "Offline recovery key revoked.")?;
        }
        RecoveryCommand::Create(arguments) => create(paths, arguments).await?,
        RecoveryCommand::Recover(arguments) => recover(paths, arguments, json).await?,
    }
    Ok(())
}

async fn create(paths: &ClientPaths, arguments: RecoveryCreateArguments) -> Result<()> {
    if !arguments.confirm_sensitive_export {
        bail!(
            "this key can replace all Owner devices; pass --confirm-sensitive-export to create and export it"
        );
    }
    let password = if let Some(path) = &arguments.output {
        if path.try_exists()? {
            bail!("the recovery package destination already exists");
        }
        let password =
            prompt_nonempty_secret("Recovery package password (at least 12 characters): ")?;
        let repeated = prompt_nonempty_secret("Repeat package password: ")?;
        if password.chars().count() < 12 || password.as_str() != repeated.as_str() {
            bail!("the package passwords must match and contain at least 12 characters");
        }
        Some(password)
    } else {
        None
    };
    let (profile, client) = client(paths, &arguments.server).await?;
    let settings = client.recovery_settings().await?;
    if settings.key.is_some() && !arguments.replace_existing_key {
        bail!(
            "a recovery key already exists; pass --replace-existing-key to invalidate and replace it"
        );
    }
    let draft = RecoveryKeyDraft::new(&profile, settings.key.map(|key| key.recovery_id))?;
    let response = client.create_recovery_key(draft.request()).await?;
    let code = draft.finish(response)?;
    if let (Some(path), Some(password)) = (&arguments.output, &password) {
        sirinvpn_core::write_recovery_package(path, &code, password)?;
        println!("Encrypted offline recovery package saved. Keep its password separately.");
    }
    if arguments.print_key {
        println!("{}", code.as_str());
    }
    Ok(())
}

async fn recover(
    paths: &ClientPaths,
    arguments: RecoveryRestoreArguments,
    json: bool,
) -> Result<()> {
    if !arguments.confirm_replace_owner_devices {
        bail!(
            "pass --confirm-replace-owner-devices to revoke all old Owner identities and consume the recovery key"
        );
    }
    if invoke_helper("status", None)?.state != ConnectionState::Disconnected {
        bail!("disconnect the current VPN before recovery");
    }
    let code = if let Some(path) = &arguments.input {
        let password = prompt_nonempty_secret("Recovery package password: ")?;
        sirinvpn_core::read_recovery_package(path, &password)?
    } else if arguments.key_stdin {
        let mut key = Zeroizing::new(String::new());
        std::io::stdin().take(32769).read_to_string(&mut key)?;
        key
    } else {
        prompt_nonempty_secret("Offline recovery key: ")?
    };
    let recovery = DecodedRecoveryKey::decode(&code)?;
    let bootstrap = recovery.bootstrap_profile();
    let existing = paths
        .profile_store()
        .load()?
        .into_iter()
        .find(|profile| profile.id == bootstrap.id);
    if existing.is_some() && !arguments.replace_existing_profile {
        bail!("pass --replace-existing-profile to replace the saved profile for this server");
    }
    if has_pending_key_rotation(paths, bootstrap.id)? {
        bail!("resolve the pending device key rotation before recovery");
    }
    let secrets = paths.secret_store();
    let mut pending = PendingEnrollment::open(
        paths,
        &secrets,
        bootstrap.id,
        &format!("recovery-{}", recovery.recovery_id()),
        &arguments.device_name,
    )?;
    let result = async {
        let profile = if let Some(profile) = pending.completed_profile() {
            profile
        } else {
            let bootstrap = recovery.current_bootstrap_profile().await?;
            test_endpoint_automatically(
                &bootstrap,
                recovery.secret(),
                NetworkProfile::Automatic,
                None,
                TunnelRoutingPolicy::default(),
            )
            .await?;
            let client = ManagementClient::new(&bootstrap, recovery.secret())?;
            let request = recovery.request(&pending.identity.public, arguments.device_name);
            let result = match client.recover_owner(&request).await {
                Err(ManagementError::ConnectionFailed) => client.recover_owner(&request).await?,
                result => result?,
            };
            recovery.permanent_profile(
                &result,
                &pending.identity.public,
                pending.identity_reference.clone(),
            )?
        };
        pending.commit_profile(paths, profile.clone(), arguments.replace_existing_profile)?;
        if let Some(old) = &existing
            && old.identity_reference != profile.identity_reference
        {
            secrets.delete(&old.identity_reference).map_err(|_| anyhow!(
                "Owner recovery committed; old credential cleanup is incomplete. Unlock the secure store and retry credential cleanup."
            ))?;
        }
        disconnect_candidate(profile.id)?;
        test_endpoint_automatically(
            &profile,
            &pending.identity.secret,
            NetworkProfile::Automatic,
            None,
            TunnelRoutingPolicy::default(),
        )
        .await?;
        Ok::<_, anyhow::Error>(profile)
    }
    .await;
    if result.is_err() {
        let _ = disconnect_candidate(bootstrap.id);
    }
    print_value(
        &result?,
        json,
        "Owner access recovered. Create a new offline recovery key after checking this connection.",
    )
}
