use super::*;
use sirinvpn_protocol::{AlertFailure, AlertFormat, AlertPolicy, AlertSettings};

fn failure_text(failure: AlertFailure, status: Option<u16>) -> String {
    match failure {
        AlertFailure::Address => {
            "the address did not resolve, or resolved to a private address that is not allowed"
                .to_owned()
        }
        AlertFailure::Connection => "the VPS could not reach it over HTTPS".to_owned(),
        AlertFailure::Rejected => match status {
            Some(status) => format!("it answered HTTP {status}"),
            None => "it refused the request".to_owned(),
        },
    }
}

fn print_settings(settings: &AlertSettings, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(settings)?);
        return Ok(());
    }
    let (policy, status) = (&settings.policy, &settings.status);
    match &policy.alert_url {
        Some(url) => println!(
            "Alerts: on, {} {url}",
            match policy.format {
                AlertFormat::Ntfy => "ntfy topic",
                AlertFormat::Webhook => "webhook",
            }
        ),
        None => println!("Alerts: off"),
    }
    match &policy.heartbeat_url {
        Some(url) => println!("Heartbeat: every five minutes to {url}"),
        None => println!("Heartbeat: off"),
    }
    if policy.allow_private_addresses {
        println!("Private and loopback addresses are allowed.");
    }
    if let Some(time) = status.checked_at_unix {
        println!("Latest VPS check at Unix time {time}");
    }
    if let Some(failure) = status.alert_failure {
        println!(
            "The latest alert was not delivered: {}. The VPS retries at its next check.",
            failure_text(failure, None)
        );
    }
    if let Some(failure) = status.heartbeat_failure {
        println!(
            "The latest heartbeat failed: {}.",
            failure_text(failure, None)
        );
    }
    Ok(())
}

pub(super) async fn run(paths: &ClientPaths, command: AlertsCommand, json: bool) -> Result<()> {
    let server = match &command {
        AlertsCommand::Status(selector)
        | AlertsCommand::Off(selector)
        | AlertsCommand::Test(selector) => &selector.server,
        AlertsCommand::Set(arguments) => &arguments.server,
    };
    let (profile, secret) = connected_identity(paths, server)?;
    let client = ManagementClient::new(&profile, &secret)?;
    if !client.configuration().await?.alerts_enabled {
        bail!("repair this VPS with the current app before setting VPS alerts");
    }
    let policy = match command {
        AlertsCommand::Status(_) => return print_settings(&client.alerts().await?, json),
        AlertsCommand::Test(_) => {
            let result = client.send_test_alert().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            return match result.failure {
                None if !json => {
                    println!("The VPS delivered a test alert.");
                    Ok(())
                }
                None => Ok(()),
                Some(failure) => bail!(
                    "the test alert was not delivered: {}",
                    failure_text(failure, result.http_status)
                ),
            };
        }
        AlertsCommand::Off(_) => AlertPolicy::default(),
        AlertsCommand::Set(arguments) => AlertPolicy {
            format: if arguments.webhook.is_some() {
                AlertFormat::Webhook
            } else {
                AlertFormat::Ntfy
            },
            alert_url: arguments.ntfy.or(arguments.webhook),
            heartbeat_url: arguments.heartbeat,
            allow_private_addresses: arguments.allow_private,
        },
    };
    policy.validate().map_err(|error| anyhow!(error))?;
    print_settings(&client.update_alerts(&policy).await?, json)
}
