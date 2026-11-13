use super::*;

pub(crate) async fn create_hetzner_server(
    paths: &ClientPaths,
    arguments: CreateHetznerArguments,
    json: bool,
) -> Result<()> {
    let token = match env::var("HCLOUD_TOKEN") {
        Ok(token) if !token.is_empty() => Zeroizing::new(token),
        _ => prompt_nonempty_secret("Hetzner Cloud API token: ")?,
    };
    let client = HetznerClient::new(&token)?;
    let server_binary = resolve_server_binary(arguments.server_binary.clone())?;
    // Never create a second server while an earlier creation is unfinished.
    if let Some(provision) = HetznerProvision::pending(&paths.configuration_directory)
        .context("could not read the unfinished Hetzner server creations on this device")?
        .into_iter()
        .next()
    {
        return resume_or_delete(paths, &client, provision, arguments, server_binary, json).await;
    }
    let arm = server_binary.supports("aarch64");
    let catalog = client.catalog(arm).await?;
    let location = arguments
        .location
        .clone()
        .or_else(|| {
            catalog
                .locations
                .first()
                .map(|location| location.name.clone())
        })
        .context("Hetzner Cloud lists no location with an available server type")?;
    let server_type = arguments
        .server_type
        .clone()
        .or_else(|| {
            catalog
                .cheapest_x86(&location)
                .map(|kind| kind.name.clone())
        })
        .with_context(|| format!("no x86 server type is available in {location}"))?;
    let price = catalog
        .price(&location, &server_type)
        .with_context(|| format!("{server_type} is not available in {location}"))?
        .clone();
    if arguments.accept_monthly_price.as_deref() != Some(price.total_monthly.as_str()) {
        if json {
            println!("{}", serde_json::to_string_pretty(&catalog)?);
        } else {
            for kind in &catalog.server_types {
                if let Some(offer) = kind.prices.iter().find(|offer| offer.location == location) {
                    println!(
                        "{:<8} {:<4} {:>3} vCPU {:>4} GB RAM {:>5} GB disk  {} {}/month",
                        kind.name,
                        kind.architecture,
                        kind.cores,
                        kind.memory_gb,
                        kind.disk_gb,
                        offer.total_monthly,
                        catalog.currency
                    );
                }
            }
            let names = catalog
                .locations
                .iter()
                .map(|l| format!("{} ({})", l.name, l.city));
            println!("Locations: {}", names.collect::<Vec<_>>().join(", "));
            println!(
                "Selected: {server_type} in {location} with Debian 13 for {} {}/month (server {} + IPv4 {}), billed by Hetzner until deleted.",
                price.total_monthly,
                catalog.currency,
                price.server_monthly,
                price.ipv4_monthly.as_deref().unwrap_or("not reported")
            );
        }
        bail!(
            "Nothing was created. Re-run with --accept-monthly-price {} to create this server.",
            price.total_monthly
        );
    }

    let directory = &paths.configuration_directory;
    let prepared = PreparedServer::generate();
    save_login_key(directory, &prepared).context("could not save the new server's SSH key")?;
    let mut provision = HetznerProvision::requested(&prepared);
    if let Err(error) = provision.save(directory) {
        let _ = forget_login_key(directory, &prepared.name);
        return Err(anyhow!(error).context("could not record the new server's progress"));
    }
    let request = HetznerServerRequest {
        location,
        server_type,
        accepted_monthly_price: price.total_monthly,
    };
    let server = match client.create_server(&prepared, &request, arm).await {
        Ok(server) => server,
        Err(error) => {
            // After an uncertain create, the saved record lets a later run find the server by name.
            if !matches!(error, HetznerError::Uncertain(_)) {
                let _ = forget_login_key(directory, &prepared.name);
                let _ = HetznerProvision::forget(directory, &prepared.name);
            }
            return Err(error.into());
        }
    };
    provision
        .advance(directory, HetznerPhase::Created { server_id: server.id })
        .context("the server was created, but its progress could not be saved; run this command again to resume it")?;
    eprintln!(
        "Created {} (Hetzner ID {}). Waiting for it to start with SSH host key {}; Ctrl-C stops waiting.",
        server.name, server.id, server.host_key_sha256
    );
    finish_hetzner(paths, &client, provision, arguments, server_binary, json).await
}

/// What the Owner chose for an unfinished Hetzner creation.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum PendingChoice {
    Resume,
    Delete,
    Stop,
}

pub(super) fn pending_choice(answer: &str, server_known: bool) -> PendingChoice {
    match answer.trim().to_ascii_lowercase().as_str() {
        "r" | "resume" => PendingChoice::Resume,
        "d" | "delete" if server_known => PendingChoice::Delete,
        _ => PendingChoice::Stop,
    }
}

async fn resume_or_delete(
    paths: &ClientPaths,
    client: &HetznerClient,
    provision: HetznerProvision,
    arguments: CreateHetznerArguments,
    server_binary: ServerBinarySource,
    json: bool,
) -> Result<()> {
    let directory = &paths.configuration_directory;
    let server_id = provision.server_id();
    match server_id {
        Some(id) => eprintln!(
            "An earlier Hetzner server creation was not finished: {} (Hetzner ID {id}). Hetzner bills it until it is deleted.",
            provision.name
        ),
        None => eprintln!(
            "An earlier Hetzner server creation was not finished: {}. Hetzner may or may not have created it; resuming checks.",
            provision.name
        ),
    }
    eprint!(
        "No new server is created while this one is pending. [r] resume it{}, anything else stops: ",
        if server_id.is_some() {
            ", [d] delete it"
        } else {
            ""
        }
    );
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    match (pending_choice(&answer, server_id.is_some()), server_id) {
        (PendingChoice::Resume, _) => {
            finish_hetzner(paths, client, provision, arguments, server_binary, json).await
        }
        (PendingChoice::Delete, Some(id)) => {
            client.delete_server(id).await?;
            let _ = forget_login_key(directory, &provision.name);
            HetznerProvision::forget(directory, &provision.name)?;
            bail!("The pending server was deleted. Run the command again to create a new one.");
        }
        _ => bail!(
            "Nothing was changed. Run the command again to resume or delete {}.",
            provision.name
        ),
    }
}

/// Describes the server's SSH host key after a failed wait. A failed replacement carries
/// the replacement fingerprint in its own text, which the Owner needs as much as the pre-seeded one.
pub(super) fn host_key_note(error: &HetznerError, pre_seeded: &str) -> String {
    match error {
        HetznerError::HostKeyReplacement(_) => {
            format!("{error}. The pre-seeded host key was {pre_seeded}.")
        }
        _ => format!("Its SSH host key is {pre_seeded}."),
    }
}

/// Waits for the recorded server (resuming from wherever it stopped), then installs on it.
async fn finish_hetzner(
    paths: &ClientPaths,
    client: &HetznerClient,
    mut provision: HetznerProvision,
    arguments: CreateHetznerArguments,
    server_binary: ServerBinarySource,
    json: bool,
) -> Result<()> {
    let directory = &paths.configuration_directory;
    let login_key = load_login_key(directory, &provision.name)
        .context("the saved SSH key for this server is unavailable")?;
    let key_path = directory.join("ssh-keys").join(&provision.name);
    // Ctrl-C drops the wait instead of using the cancel flag; the saved progress stays.
    let never = AtomicBool::new(false);
    let ready = tokio::select! {
        ready = client.resume(directory, &mut provision, login_key.clone(), &never) => ready,
        _ = tokio::signal::ctrl_c() => Err(HetznerError::Cancelled),
    };
    let host_key_text;
    let result = match ready {
        Ok(ready) => {
            host_key_text = format!("Its SSH host key is {}.", ready.host_key_sha256);
            eprintln!(
                "{} is ready at {} with SSH host key {}. Installing SirinVPN; this cannot be interrupted.",
                provision.name, ready.ipv4, ready.host_key_sha256
            );
            let identity = new_identity_for_server(&arguments.name)?;
            let server_id = ServerId::new();
            install_new_server(
                paths,
                InstallRequest {
                    server_id,
                    server_name: arguments.name,
                    target: ssh_target(ready.ipv4, login_key, ready.host_key_sha256),
                    server_binary,
                    identity: identity.public.clone(),
                    identity_reference: server_id.to_string(),
                    transport: arguments.transport.requested(None)?.unwrap_or_default(),
                    dns_upstream: arguments.dns.requested().unwrap_or_default(),
                    private_dns_records: arguments.private_dns_record,
                    // Hetzner servers come with IPv4, so NAT64 never applies.
                    nat64_prefix: None,
                    replace_existing_installation: false,
                    enable_security_updates: false,
                },
                &identity.secret,
                json,
            )
        }
        Err(error) => {
            host_key_text = host_key_note(&error, &provision.pre_seeded_host_key_sha256);
            Err(error.into())
        }
    };
    if let Err(error) = &result {
        eprintln!("{error}");
        let Some(server_id) = provision.server_id() else {
            // Only a definite "no such server" drops the record; a failed lookup keeps it and its key.
            if matches!(HetznerProvision::load(directory, &provision.name), Ok(None)) {
                let _ = forget_login_key(directory, &provision.name);
            }
            return result;
        };
        eprint!(
            "Delete the Hetzner server {} (ID {server_id})? Hetzner bills it until it is deleted. [y/N] ",
            provision.name
        );
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim().eq_ignore_ascii_case("y") {
            client.delete_server(server_id).await?;
            let _ = forget_login_key(directory, &provision.name);
            HetznerProvision::forget(directory, &provision.name)?;
            bail!("The server was deleted.");
        }
        bail!(
            "The server was kept, and so was its saved progress: run this command again to resume it. Log in with: ssh -i {} root@<its IPv4>. {host_key_text}",
            key_path.display()
        );
    }
    if let Err(error) = HetznerProvision::forget(directory, &provision.name) {
        eprintln!("Warning: the finished server's progress record could not be removed: {error}");
    }
    eprintln!(
        "The root SSH key for {} is saved at {}.",
        provision.name,
        key_path.display()
    );
    result
}
