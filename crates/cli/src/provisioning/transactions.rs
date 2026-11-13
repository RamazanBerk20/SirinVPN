use super::*;

fn ssh_login(
    arguments: &TransactionLoginArguments,
) -> Result<(SshAuthentication, Option<Zeroizing<String>>)> {
    let authentication = if arguments.ssh_agent {
        SshAuthentication::Agent
    } else if let Some(path) = arguments.ssh_key.clone() {
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
    Ok((authentication, sudo_password))
}

/// The VPS, port and host pin of the interrupted transaction, with a fresh login.
pub(super) fn transaction_target(
    entry: &JournalEntry,
    arguments: &TransactionLoginArguments,
) -> Result<SshTarget> {
    let (authentication, sudo_password) = ssh_login(arguments)?;
    Ok(SshTarget {
        host: entry.host.clone(),
        port: entry.port,
        username: arguments.username.clone(),
        authentication,
        sudo_password,
        expected_host_key_sha256: Some(entry.host_key_sha256.clone()),
    })
}

/// The VPS host a `SERVER` argument names: an unresolved transaction's host or
/// planned server, a saved server's address, or else the argument as a host.
fn transaction_host(paths: &ClientPaths, server: &str) -> Result<String> {
    let named = |entry: &JournalEntry| {
        entry.host.eq_ignore_ascii_case(server)
            || entry
                .committed_profile
                .as_ref()
                .is_some_and(|planned| planned.id.to_string() == server || planned.name == server)
    };
    if let Some(entry) = transaction_journal(paths)
        .entries()?
        .into_iter()
        .find(named)
    {
        return Ok(entry.host);
    }
    Ok(resolve_profile(&paths.profile_store(), server)
        .map_or_else(|_| server.to_owned(), |profile| profile.endpoint.host))
}

/// The unresolved transaction to act on: the named server's, or the only one.
pub(super) fn selected_transaction(
    paths: &ClientPaths,
    server: Option<&str>,
) -> Result<Option<JournalEntry>> {
    let journal = transaction_journal(paths);
    if let Some(server) = server {
        return Ok(journal.read_server(&transaction_host(paths, server)?)?);
    }
    let mut entries = journal.entries()?;
    if entries.len() > 1 {
        let hosts: Vec<&str> = entries.iter().map(|entry| entry.host.as_str()).collect();
        bail!(
            "VPS maintenance transactions are unresolved on {}. Name one with --server.",
            hosts.join(", ")
        );
    }
    Ok(entries.pop())
}

pub(crate) fn transaction_status(
    paths: &ClientPaths,
    arguments: TransactionLoginArguments,
    json: bool,
) -> Result<()> {
    let Some(entry) = selected_transaction(paths, arguments.server.as_deref())? else {
        println!("No VPS maintenance transaction is unresolved on this device.");
        return Ok(());
    };
    let target = transaction_target(&entry, &arguments)?;
    let state = Provisioner::transaction_status(&target, entry.operation, &entry.nonce)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "transaction": entry.nonce,
                "host": entry.host,
                "operation": entry.operation,
                "step": entry.step,
                "state": state,
            }))?
        );
    } else {
        println!(
            "Transaction {} on {} stopped at step {:?}; the VPS reports it as {state:?}.",
            entry.nonce, entry.host, entry.step
        );
        println!("Run `sirinvpn server resolve` to finish it.");
    }
    Ok(())
}

/// Forgets one server's unresolved transaction without contacting the VPS.
/// Deletes no key: the VPS may have committed the change.
fn abandon_transaction(paths: &ClientPaths, server: &str, json: bool) -> Result<()> {
    let host = transaction_host(paths, server)?;
    let journal = transaction_journal(paths);
    let entry = journal.read_server(&host).ok().flatten();
    if !journal.abandon(&host)? {
        println!("No VPS maintenance transaction is unresolved for {server} on this device.");
        return Ok(());
    }
    eprintln!(
        "WARNING: the interrupted VPS maintenance transaction on {host} was abandoned without asking the VPS.\n\
         The VPS may have committed the change or rolled it back; this device no longer knows which.\n\
         Every saved key was KEPT, including any new Owner key made for this transaction.\n\
         Check the VPS before relying on it: repair or restore it, or reinstall with --replace-existing."
    );
    if let Some(planned) = entry
        .as_ref()
        .and_then(|entry| entry.committed_profile.as_ref())
    {
        eprintln!(
            "The abandoned change would have saved server {} ({}); its key stays under reference {}.",
            planned.name, planned.id, planned.identity_reference
        );
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "abandoned": true,
                "host": host,
                "transaction": entry.as_ref().map(|entry| &entry.nonce),
                "operation": entry.as_ref().map(|entry| entry.operation),
                "keys_kept": true,
            })
        );
    }
    Ok(())
}

pub(crate) fn resolve_transaction(
    paths: &ClientPaths,
    arguments: ResolveArguments,
    json: bool,
) -> Result<()> {
    if let Some(server) = &arguments.abandon {
        return abandon_transaction(paths, server, json);
    }
    let arguments = arguments.login;
    let journal = transaction_journal(paths);
    let Some(entry) = selected_transaction(paths, arguments.server.as_deref())? else {
        println!("No VPS maintenance transaction is unresolved on this device.");
        return Ok(());
    };
    let target = transaction_target(&entry, &arguments)?;
    let resolved = Provisioner::resolve_transaction(&target, &journal);
    if let Ok(Some(resolved)) = &resolved
        && entry.operation == TransactionOperation::Uninstall
        && resolved.state == RemoteTransactionState::Committed
    {
        println!(
            "SirinVPN was removed from the VPS. Use `sirinvpn server remove` to delete its local profile and key."
        );
        return Ok(());
    }
    match settle(resolved) {
        Settlement::Committed(committed) => {
            let profile = save_committed_profile(paths, &committed, &entry.host)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&profile)?);
            } else {
                println!(
                    "The VPS had applied the change. Saved {} ({}) on this device.",
                    profile.name, profile.id
                );
            }
        }
        Settlement::RolledBack => {
            if entry.operation == TransactionOperation::Install {
                discard_marked_secret(paths, &entry.host)?;
            }
            println!(
                "The VPS is back in its state from before the change. This device's profile was not changed."
            );
        }
        Settlement::Unknown(reason) => return Err(unresolved_outcome(&reason)),
    }
    Ok(())
}

/// Deletes the new Owner key of an install the VPS confirmed rolled back, unless a saved profile uses it.
pub(super) fn discard_marked_secret(paths: &ClientPaths, host: &str) -> Result<()> {
    let Ok(reference) = std::fs::read_to_string(pending_secret_marker(paths, host)) else {
        return Ok(());
    };
    let reference = reference.trim();
    if !paths
        .profile_store()
        .load()?
        .iter()
        .any(|profile| profile.identity_reference == reference)
    {
        discard_new_secret(paths, host, reference)?;
    }
    forget_pending_secret(paths, host);
    Ok(())
}

pub(super) fn discard_new_secret(paths: &ClientPaths, host: &str, reference: &str) -> Result<()> {
    if paths.secret_store().delete(reference).is_err() {
        bail!(
            "Provisioning failed; credential cleanup is incomplete. Unlock the secure store and retry credential cleanup."
        );
    }
    forget_pending_secret(paths, host);
    Ok(())
}
