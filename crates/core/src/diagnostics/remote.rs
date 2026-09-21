use super::{check, report};
use sirinvpn_protocol::{DiagnosticCheck, DiagnosticLevel, DiagnosticReport};
use std::collections::HashSet;
use zeroize::Zeroize;

/// Remote free-form labels, error messages and unknown checks are never displayed or exported.
/// Known DNS errors and bounded numeric readings are reconstructed from a finite vocabulary.
pub(crate) fn sanitize(mut incoming: DiagnosticReport) -> DiagnosticReport {
    let mut checks = Vec::new();
    let mut seen = HashSet::new();
    let mut omitted = incoming.checks.len() > 128;
    for (index, mut value) in incoming.checks.drain(..).enumerate() {
        let safe = (index < 128).then(|| sanitize_check(&value)).flatten();
        if let Some(safe) = safe {
            if seen.insert(safe.code.clone()) {
                checks.push(safe);
            } else {
                omitted = true;
            }
        } else {
            omitted = true;
        }
        value.label.zeroize();
        value.message.zeroize();
        value.code.zeroize();
    }
    if omitted || checks.is_empty() {
        checks.push(check("server_report_format", "VPS diagnostic compatibility", DiagnosticLevel::Warning,
            "Some server checks could not be safely interpreted. Use compatible app and server versions and rerun diagnostics."));
    }
    report(checks)
}

fn sanitize_check(value: &DiagnosticCheck) -> Option<DiagnosticCheck> {
    if let Some(label) = dns_label(&value.code) {
        let message = match value.level {
            DiagnosticLevel::Pass => dns_success(&value.message).unwrap_or_else(|| "The resolver returned a valid DNS response.".into()),
            DiagnosticLevel::Warning => "A current DNS response check is unavailable. Try again after other diagnostics finish.".into(),
            DiagnosticLevel::Fail => if DNS_ERRORS.contains(&value.message.as_str()) { value.message.clone() }
                else { "The resolver did not return a usable DNS response. Check its route, port, upstream configuration, TLS identity and clock.".into() },
        };
        return Some(check(&value.code, &label, value.level.clone(), &message));
    }
    let (label, success, failure) = match value.code.as_str() {
        "interface" => (
            "VPS VPN interface",
            "The configured VPS VPN interface exists.",
            "The VPS VPN interface is missing. Use server repair to restore it.",
        ),
        "wireguard" => (
            "VPS WireGuard",
            "The server reports its configured WireGuard interface as active.",
            "The running WireGuard identity, interface or port does not match the server configuration. Use server repair.",
        ),
        "dns" => (
            "VPS private DNS service",
            "The configured private resolver services are active.",
            "A private resolver service is inactive. Use server repair, then rerun diagnostics.",
        ),
        "forwarding" => (
            "VPS IPv4 forwarding",
            "IPv4 forwarding is enabled.",
            "IPv4 forwarding is disabled. Use server repair to restore forwarding.",
        ),
        "ipv6" => (
            "VPS IPv6 tunnel",
            "The server reports IPv6 forwarding and tunnel addressing as available.",
            "IPv6 forwarding, addressing or NAT is unavailable. Use server repair.",
        ),
        "server_process" => (
            "VPS system service",
            "The SirinVPN system service is active.",
            "The SirinVPN system service is inactive. Check its installation or use server repair.",
        ),
        "server_routes" => (
            "VPS routes",
            "The main routing table has an external default route and the configured tunnel subnet route.",
            "The external default route or tunnel subnet route is missing. Check VPS networking and use server repair for the tunnel route.",
        ),
        "server_firewall" => (
            "VPS firewall structure",
            "SirinVPN firewall hooks and tunnel isolation rules are present. Other firewall policies can still affect connectivity.",
            "SirinVPN firewall hooks or tunnel isolation rules are missing. Use server repair to restore its owned rules.",
        ),
        "server_nat4" => (
            "VPS IPv4 NAT",
            "A source masquerade rule exists for the configured tunnel subnet.",
            "The configured tunnel subnet has no source masquerade rule. Use server repair to restore IPv4 NAT.",
        ),
        "server_nat6" => (
            "VPS IPv6 NAT",
            "A source masquerade rule exists for the private IPv6 tunnel subnet.",
            "The private IPv6 subnet has no source masquerade rule. Use server repair to restore IPv6 NAT.",
        ),
        "server_ports" => (
            "VPS listening ports",
            "Configured VPN transport, private management and DNS listening sockets are present. This does not verify the provider firewall.",
            "A configured transport, private management or DNS listener is missing. Check server services or use server repair.",
        ),
        "server_mtu" => (
            "VPS interface MTU",
            "The VPS interface MTU meets the IP protocol minimum. Client probes determine the usable path MTU.",
            "The VPS tunnel interface MTU is below the IP protocol minimum. Use server repair.",
        ),
        "server_cpu" | "server_memory" | "server_disk" => return Some(resource(value)),
        "external_reachability" => {
            return Some(check(
                "external_reachability",
                "Provider firewall and public reachability",
                DiagnosticLevel::Warning,
                "Local listeners cannot establish public reachability. If a transport fails, check the VPS provider firewall and configured public ports.",
            ));
        }
        "diagnostics_busy" => {
            return Some(check(
                "diagnostics_busy",
                "VPS current diagnostics",
                DiagnosticLevel::Warning,
                "Another current-state check is running. Try again in a few seconds.",
            ));
        }
        _ => return None,
    };
    Some(check(
        &value.code,
        label,
        value.level.clone(),
        match value.level {
            DiagnosticLevel::Pass => success,
            DiagnosticLevel::Fail => failure,
            DiagnosticLevel::Warning => {
                "This current state could not be read. Check server tools and service permissions, then rerun diagnostics."
            }
        },
    ))
}

fn resource(value: &DiagnosticCheck) -> DiagnosticCheck {
    let label = match value.code.as_str() {
        "server_cpu" => "VPS CPU",
        "server_memory" => "VPS memory",
        _ => "VPS disk",
    };
    let number = value
        .message
        .strip_prefix("Current usage: ")
        .and_then(|text| text.split_once("%. "))
        .filter(|(_, ending)| {
            matches!(
                *ending,
                "Capacity is available."
                    | "Capacity is limited. Free resources or increase the VPS capacity."
            )
        })
        .and_then(|(number, _)| number.parse::<u8>().ok())
        .filter(|number| *number <= 100);
    match number {
        Some(number) => check(
            &value.code,
            label,
            if number >= 90 {
                DiagnosticLevel::Warning
            } else {
                DiagnosticLevel::Pass
            },
            &format!(
                "Current usage: {number}%. {}",
                if number >= 90 {
                    "Capacity is limited. Free resources or increase the VPS capacity."
                } else {
                    "Capacity is available."
                }
            ),
        ),
        None => check(
            &value.code,
            label,
            DiagnosticLevel::Warning,
            "A current resource reading is unavailable.",
        ),
    }
}

fn index(value: &str, maximum: u8) -> Option<u8> {
    let number: u8 = value.parse().ok()?;
    (number < maximum && value == number.to_string()).then_some(number + 1)
}

fn dns_label(code: &str) -> Option<String> {
    if code == "dns_probe_busy" {
        return Some("VPS DNS response checks".into());
    }
    if code == "dns_resolver_response" {
        return Some("VPS private resolver response".into());
    }
    if let Some(value) = code.strip_prefix("dns_tls_") {
        return Some(format!("VPS TLS resolver {}", index(value, 8)?));
    }
    if let Some(value) = code.strip_prefix("dns_https_") {
        return Some(format!("VPS HTTPS resolver {}", index(value, 8)?));
    }
    let value = code.strip_prefix("dns_zone_")?;
    if let Some((zone, endpoint)) = value.split_once('_') {
        Some(format!(
            "VPS split DNS zone {}, upstream {}",
            index(zone, 32)?,
            index(endpoint, 8)?
        ))
    } else {
        Some(format!("VPS split DNS zone {}", index(value, 32)?))
    }
}

fn dns_success(message: &str) -> Option<String> {
    let millis = message
        .strip_prefix("Valid DNS response in ")?
        .strip_suffix(" ms. No query history is retained.")?
        .parse::<u16>()
        .ok()?;
    (millis <= 5000)
        .then(|| format!("Valid DNS response in {millis} ms. No query history is retained."))
}

const DNS_ERRORS: &[&str] = &[
    "TCP connection failed. Check the resolver address, route and port 53 firewall.",
    "Authenticated HTTPS DNS failed. Check the resolver address, TLS name, HTTPS path and outbound port 443.",
    "No DNS reply within three seconds. Check upstream reachability and firewall rules; DNS protection remains enabled.",
    "The VPS certificate trust bundle is unavailable. Repair the CA certificates package.",
    "The VPS certificate trust bundle is invalid.",
    "The TLS resolver authentication name is invalid.",
    "The TLS resolver could not be reached. Check its IP, route and outbound port 853.",
    "TLS authentication failed. Check the resolver's certificate, configured TLS name and VPS clock.",
    "The DNS request could not be sent.",
    "The DNS resolver closed the connection without a reply.",
    "The DNS response had an invalid size.",
    "The DNS reply was incomplete.",
    "The DNS reply did not match the request or was truncated.",
    "The resolver returned SERVFAIL. Check its upstream reachability, DNSSEC validation and clock.",
    "The resolver refused this query. Check its client access policy and zone forwarding rules.",
    "The resolver returned a DNS error. Check its configured zone and upstream policy.",
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn free_text_and_unknown_or_duplicate_remote_checks_cannot_enter_a_report() {
        let secret =
            "BEGIN PRIVATE KEY ssh-password enrollment-token recovery-secret export-password";
        let report = sanitize(report(vec![
            check("interface", secret, DiagnosticLevel::Fail, secret),
            check("dns_zone_0_1", secret, DiagnosticLevel::Fail, secret),
            check(
                "server_disk",
                secret,
                DiagnosticLevel::Pass,
                &format!("Current usage: 10%. {secret}"),
            ),
            check("local_tunnel", secret, DiagnosticLevel::Pass, secret),
            check("interface", secret, DiagnosticLevel::Pass, secret),
        ]));
        let text = serde_json::to_string(&report).unwrap();
        for value in secret.split_whitespace() {
            assert!(!text.contains(value));
        }
        assert_eq!(
            report
                .checks
                .iter()
                .filter(|c| c.code == "interface")
                .count(),
            1
        );
        assert!(!report.checks.iter().any(|c| c.code == "local_tunnel"));
        assert_eq!(
            report
                .checks
                .iter()
                .find(|c| c.code == "server_disk")
                .unwrap()
                .level,
            DiagnosticLevel::Warning
        );
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.code == "server_report_format")
        );
    }
    #[test]
    fn bounded_numeric_readings_and_known_dns_causes_survive_sanitization() {
        let report = sanitize(report(vec![
            check(
                "server_memory",
                "ignored",
                DiagnosticLevel::Pass,
                "Current usage: 95%. Capacity is available.",
            ),
            check("dns_tls_0", "ignored", DiagnosticLevel::Fail, DNS_ERRORS[7]),
            check(
                "dns_resolver_response",
                "ignored",
                DiagnosticLevel::Pass,
                "Valid DNS response in 82 ms. No query history is retained.",
            ),
        ]));
        assert_eq!(report.checks[0].level, DiagnosticLevel::Warning);
        assert_eq!(report.checks[1].message, DNS_ERRORS[7]);
        assert!(report.checks[2].message.contains("82 ms"));
        assert!(dns_label("dns_zone_01").is_none());
        assert!(dns_label("dns_zone_32").is_none());
    }
}
