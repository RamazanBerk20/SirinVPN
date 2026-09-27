use super::*;

pub(super) fn run(paths: &ClientPaths, command: StorageCommand) -> Result<()> {
    #[cfg(not(any(windows, target_os = "android")))]
    {
        use sirinvpn_core::StoragePolicy;
        let store = paths.secret_store();
        match command {
            StorageCommand::Status => {
                let profiles = paths.profile_store().load()?;
                let statuses = profiles.into_iter().map(|p| {
                    Ok(serde_json::json!({"server_id":p.id,"storage":store.status(&p.identity_reference)?}))
                }).collect::<Result<Vec<_>>>()?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "policy":store.policy()?, "profiles":statuses,
                        "pending_cleanup":store.pending_cleanup()?.len()
                    }))?
                );
            }
            StorageCommand::RequireSecure => {
                store.set_policy(StoragePolicy::SecureStoreRequired)?
            }
            StorageCommand::AllowPrivateFile => {
                store.set_policy(StoragePolicy::AllowPrivateFile)?
            }
            StorageCommand::Migrate(selector) => {
                let profile = resolve_profile(&paths.profile_store(), &selector.server)?;
                store.migrate(
                    &profile.identity_reference,
                    &profile.client_management_certificate_pem,
                )?;
            }
            StorageCommand::RetryCleanup => {
                let mut failed = false;
                for reference in store.pending_cleanup()? {
                    failed |= store.delete(&reference).is_err();
                }
                if failed {
                    bail!("Credential cleanup remains incomplete; unlock the keyring and retry.");
                }
            }
        }
        Ok(())
    }
    #[cfg(any(windows, target_os = "android"))]
    {
        let _ = (paths, command);
        bail!(
            "Storage policy and keyring migration apply only to Linux; this platform uses its native protected store."
        )
    }
}
