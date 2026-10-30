use super::*;
use sirinvpn_protocol::{DnsBlocklistPreset, DnsBlocklistSettings, normalize_dns_blocklist_name};

fn preset_name(preset: &DnsBlocklistPreset) -> String {
    preset.name.to_ascii_lowercase().replace(' ', "-")
}

fn list_source(value: &str, presets: &[DnsBlocklistPreset]) -> Result<String> {
    if let Some(preset) = presets.iter().find(|preset| preset_name(preset) == value) {
        return Ok(preset.url.clone());
    }
    if sirinvpn_protocol::valid_dns_blocklist_url(value) {
        return Ok(value.to_owned());
    }
    bail!("{value} is neither a built-in list name nor an HTTPS address")
}

fn print_settings(settings: &DnsBlocklistSettings, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(settings)?);
        return Ok(());
    }
    let (policy, status) = (&settings.policy, &settings.status);
    println!(
        "DNS blocking: {}{}",
        if policy.enabled { "on" } else { "off" },
        if settings.pending {
            " (waiting for the VPS to apply it)"
        } else {
            ""
        }
    );
    for url in &policy.sources {
        println!("  list: {url}");
    }
    for name in &policy.allowlist {
        println!("  allowed: {name}");
    }
    if status.active {
        println!(
            "Active list: {} blocked domains, built at Unix time {}",
            status.domain_count,
            status.updated_at_unix.unwrap_or_default()
        );
    }
    if let Some(failure) = status.failure {
        println!("Latest refresh failed ({failure:?}); the last good list stays in effect.");
    }
    println!("Built-in lists:");
    for preset in &settings.presets {
        println!("  {}  {}", preset_name(preset), preset.url);
    }
    Ok(())
}

pub(super) async fn run(
    paths: &ClientPaths,
    command: DnsBlockingCommand,
    json: bool,
) -> Result<()> {
    let server = match &command {
        DnsBlockingCommand::Status(selector) | DnsBlockingCommand::Disable(selector) => {
            &selector.server
        }
        DnsBlockingCommand::Enable(arguments) => &arguments.server,
    };
    let (profile, secret) = connected_identity(paths, server)?;
    let client = ManagementClient::new(&profile, &secret)?;
    if !client
        .configuration()
        .await?
        .dns_blocklist_management_enabled
    {
        bail!("repair this VPS with the current app before managing DNS blocking");
    }
    let settings = client.dns_blocklist().await?;
    let mut policy = settings.policy.clone();
    match command {
        DnsBlockingCommand::Status(_) => return print_settings(&settings, json),
        DnsBlockingCommand::Disable(_) => policy.enabled = false,
        DnsBlockingCommand::Enable(arguments) => {
            policy.enabled = true;
            if !arguments.lists.is_empty() {
                policy.sources = arguments
                    .lists
                    .iter()
                    .map(|value| list_source(value, &settings.presets))
                    .collect::<Result<_>>()?;
            }
            if arguments.clear_allowlist {
                policy.allowlist.clear();
            } else if !arguments.allow.is_empty() {
                policy.allowlist = arguments
                    .allow
                    .iter()
                    .map(|name| {
                        normalize_dns_blocklist_name(name)
                            .ok_or_else(|| anyhow!("{name} is not a valid domain name"))
                    })
                    .collect::<Result<_>>()?;
            }
        }
    }
    policy.validate().map_err(|error| anyhow!(error))?;
    print_settings(&client.update_dns_blocklist(&policy).await?, json)
}
