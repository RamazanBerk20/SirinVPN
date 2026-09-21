//! Output.

use super::*;

pub(super) fn dns_upstream_label(dns_upstream: &DnsUpstream) -> String {
    match dns_upstream {
        DnsUpstream::Split { default, zones } => format!(
            "split DNS ({} zones; default {})",
            zones.len(),
            dns_upstream_label(default)
        ),
        DnsUpstream::Recursive => "recursive".to_owned(),
        DnsUpstream::DnsOverTls { endpoints } => {
            format!("DNS-over-TLS, {} endpoint(s)", endpoints.len())
        }
        DnsUpstream::DnsOverHttps { endpoints } => {
            format!("DNS-over-HTTPS, {} endpoint(s)", endpoints.len())
        }
    }
}

pub(super) async fn diagnose(paths: &ClientPaths, selector: &str, json: bool) -> Result<()> {
    let profile = resolve_profile(&paths.profile_store(), selector)?;
    let local = invoke_helper("status", None)
        .ok()
        .map(|local| local.diagnostic_connection(profile.id));
    let secret = paths.secret_store().get(&profile.identity_reference).ok();
    let (mut report, dns) = tokio::join!(
        sirinvpn_core::diagnostics::diagnose(&profile, secret.as_ref(), local.as_ref()),
        async {
            if local
                .as_ref()
                .is_some_and(sirinvpn_core::diagnostics::CurrentConnection::can_probe)
            {
                Some(
                    sirinvpn_core::diagnostics::probe_private_dns(
                        profile.client_tunnel_address,
                        profile.server_tunnel_address,
                    )
                    .await,
                )
            } else {
                None
            }
        },
    );
    if let Some(dns) = dns {
        report.checks.insert(0, dns);
    }
    print_diagnostics(&report, json)
}

pub(super) fn print_diagnostics(report: &DiagnosticReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        for check in &report.checks {
            println!("{:?}  {}  {}", check.level, check.label, check.message);
        }
    }
    Ok(())
}

pub(super) fn resolve_profile(store: &ProfileStore, selector: &str) -> Result<ServerProfile> {
    let profiles = store.load()?;
    let parsed_id = selector.parse::<ServerId>().ok();
    let mut matches = profiles.into_iter().filter(|profile| {
        Some(profile.id) == parsed_id || profile.name.eq_ignore_ascii_case(selector)
    });
    let profile = matches
        .next()
        .ok_or_else(|| anyhow!("server profile was not found"))?;
    if matches.next().is_some() && parsed_id.is_none() {
        bail!("server name is ambiguous; use its local ID");
    }
    Ok(profile)
}

pub(super) fn prompt_secret(prompt: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .context("could not read the local secret prompt")
}

pub(super) fn prompt_nonempty_secret(prompt: &str) -> Result<Zeroizing<String>> {
    let value = prompt_secret(prompt)?;
    if value.is_empty() {
        bail!("a required secret was not entered");
    }
    Ok(value)
}

pub(super) fn print_value(value: &impl Serialize, json: bool, message: &str) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{message}");
    }
    Ok(())
}
