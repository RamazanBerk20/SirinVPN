use super::{Text, caused, check, report, text};
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
            text("report_format", "Some server checks could not be safely interpreted. Use compatible app and server versions and rerun diagnostics.")));
    }
    report(checks)
}

fn sanitize_check(value: &DiagnosticCheck) -> Option<DiagnosticCheck> {
    // Only local leak checks are not applicable; a VPS report claiming it is malformed.
    if value.level == DiagnosticLevel::NotApplicable {
        return None;
    }
    if let Some(label) = dns_label(&value.code) {
        let message = match value.level {
            DiagnosticLevel::Pass => dns_success(&value.message).unwrap_or_else(|| {
                text("dns_valid", "The resolver returned a valid DNS response.")
            }),
            DiagnosticLevel::Warning | DiagnosticLevel::NotApplicable => {
                return Some(caused(
                    check(
                        &value.code,
                        &label,
                        value.level.clone(),
                        text(
                            "dns_unavailable",
                            "A current DNS response check is unavailable. Try again after other diagnostics finish.",
                        ),
                    ),
                    "not_measured",
                ));
            }
            DiagnosticLevel::Fail => {
                // The VPS's words are kept only when they are one of these known causes.
                DNS_ERRORS
                    .iter()
                    .find(|(_, english)| *english == value.message)
                    .map(|(key, english)| text(key, english))
                    .unwrap_or_else(|| text("dns_failed", "The resolver did not return a usable DNS response. Check its route, port, upstream configuration, TLS identity and clock."))
            }
        };
        return Some(check(&value.code, &label, value.level.clone(), message));
    }
    let (label, success, failure) = match value.code.as_str() {
        "interface" => (
            "VPS VPN interface",
            text("interface_pass", "The configured VPS VPN interface exists."),
            text(
                "interface_fail",
                "The VPS VPN interface is missing. Use server repair to restore it.",
            ),
        ),
        "wireguard" => (
            "VPS WireGuard",
            text(
                "wireguard_pass",
                "The server reports its configured WireGuard interface as active.",
            ),
            text(
                "wireguard_fail",
                "The running WireGuard identity, interface or port does not match the server configuration. Use server repair.",
            ),
        ),
        "dns" => (
            "VPS private DNS service",
            text(
                "dns_pass",
                "The configured private resolver services are active.",
            ),
            text(
                "dns_fail",
                "A private resolver service is inactive. Use server repair, then rerun diagnostics.",
            ),
        ),
        "forwarding" => (
            "VPS IPv4 forwarding",
            text("forwarding_pass", "IPv4 forwarding is enabled."),
            text(
                "forwarding_fail",
                "IPv4 forwarding is disabled. Use server repair to restore forwarding.",
            ),
        ),
        "ipv6" => (
            "VPS IPv6 tunnel",
            text(
                "ipv6_pass",
                "The server reports IPv6 forwarding and tunnel addressing as available.",
            ),
            text(
                "ipv6_fail",
                "IPv6 forwarding, addressing or NAT is unavailable. Use server repair.",
            ),
        ),
        "server_process" => (
            "VPS system service",
            text(
                "server_process_pass",
                "The SirinVPN system service is active.",
            ),
            text(
                "server_process_fail",
                "The SirinVPN system service is inactive. Check its installation or use server repair.",
            ),
        ),
        "server_routes" => (
            "VPS routes",
            text(
                "server_routes_pass",
                "The main routing table has an external IPv4 or IPv6 default route and the configured tunnel subnet route.",
            ),
            text(
                "server_routes_fail",
                "The external default route or tunnel subnet route is missing. Check VPS networking and use server repair for the tunnel route.",
            ),
        ),
        "server_firewall" => (
            "VPS firewall structure",
            text(
                "server_firewall_pass",
                "SirinVPN firewall hooks and tunnel isolation rules are present. Other firewall policies can still affect connectivity.",
            ),
            text(
                "server_firewall_fail",
                "SirinVPN firewall hooks or tunnel isolation rules are missing. Use server repair to restore its owned rules.",
            ),
        ),
        "server_nat4" => (
            "VPS IPv4 NAT",
            text(
                "server_nat4_pass",
                "A source masquerade rule exists for the configured tunnel subnet.",
            ),
            text(
                "server_nat4_fail",
                "The configured tunnel subnet has no source masquerade rule. Use server repair to restore IPv4 NAT.",
            ),
        ),
        "server_nat6" => (
            "VPS IPv6 NAT",
            text(
                "server_nat6_pass",
                "A source masquerade rule exists for the private IPv6 tunnel subnet.",
            ),
            text(
                "server_nat6_fail",
                "The private IPv6 subnet has no source masquerade rule. Use server repair to restore IPv6 NAT.",
            ),
        ),
        "server_ports" => (
            "VPS listening ports",
            text(
                "server_ports_pass",
                "Configured VPN transport, private management and DNS listening sockets are present. This does not verify the provider firewall.",
            ),
            text(
                "server_ports_fail",
                "A configured transport, private management or DNS listener is missing. Check server services or use server repair.",
            ),
        ),
        "server_mtu" => (
            "VPS interface MTU",
            text(
                "server_mtu_pass",
                "The VPS interface MTU meets the IP protocol minimum. Client probes determine the usable path MTU.",
            ),
            text(
                "server_mtu_fail",
                "The VPS tunnel interface MTU is below the IP protocol minimum. Use server repair.",
            ),
        ),
        "server_cpu" | "server_memory" | "server_disk" => return Some(resource(value)),
        "external_reachability" => {
            return Some(check(
                "external_reachability",
                "Provider firewall and public reachability",
                DiagnosticLevel::Warning,
                text(
                    "external_reachability",
                    "Local listeners cannot establish public reachability. If a transport fails, check the VPS provider firewall and configured public ports.",
                ),
            ));
        }
        "dns_blocklist" => {
            return Some(check(
                "dns_blocklist",
                "VPS DNS blocking",
                if value.level == DiagnosticLevel::Pass {
                    DiagnosticLevel::Pass
                } else {
                    DiagnosticLevel::Warning
                },
                if value.level == DiagnosticLevel::Pass {
                    text(
                        "dns_blocklist_pass",
                        "DNS blocking uses the latest refreshed list.",
                    )
                } else {
                    text(
                        "dns_blocklist_failed",
                        "The latest blocklist refresh failed, so DNS blocking keeps the last good list. Check the list addresses and the VPS internet access.",
                    )
                },
            ));
        }
        "os_security_updates" => {
            let on = value.level == DiagnosticLevel::Pass;
            return Some(check(
                "os_security_updates",
                "VPS security updates",
                if on {
                    DiagnosticLevel::Pass
                } else {
                    DiagnosticLevel::Warning
                },
                if on {
                    text(
                        "os_security_updates_on",
                        "Automatic security updates for the VPS operating system are on.",
                    )
                } else {
                    text(
                        "os_security_updates_off",
                        "Automatic security updates are off or could not be confirmed. Repair VPS with “Turn on automatic security updates” selected switches them on.",
                    )
                },
            ));
        }
        "os_reboot_required" => {
            let current = value.level == DiagnosticLevel::Pass;
            return Some(check(
                "os_reboot_required",
                "VPS restart",
                if current {
                    DiagnosticLevel::Pass
                } else {
                    DiagnosticLevel::Warning
                },
                if current {
                    text(
                        "os_reboot_current",
                        "The VPS runs its newest installed kernel.",
                    )
                } else {
                    text(
                        "os_reboot_pending",
                        "An installed update may wait for a VPS restart. Restart the VPS when a short VPN interruption is acceptable.",
                    )
                },
            ));
        }
        "diagnostics_busy" => {
            return Some(check(
                "diagnostics_busy",
                "VPS current diagnostics",
                DiagnosticLevel::Warning,
                text(
                    "diagnostics_busy",
                    "Another current-state check is running. Try again in a few seconds.",
                ),
            ));
        }
        _ => return None,
    };
    Some(match value.level {
        DiagnosticLevel::Pass => check(&value.code, label, DiagnosticLevel::Pass, success),
        DiagnosticLevel::Fail => check(&value.code, label, DiagnosticLevel::Fail, failure),
        DiagnosticLevel::Warning | DiagnosticLevel::NotApplicable => caused(
            check(
                &value.code,
                label,
                value.level.clone(),
                text(
                    "state_unreadable",
                    "This current state could not be read. Check server tools and service permissions, then rerun diagnostics.",
                ),
            ),
            "not_measured",
        ),
    })
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
            if number >= 90 {
                text("resource_limited", "Current usage: {percent}%. Capacity is limited. Free resources or increase the VPS capacity.")
            } else {
                text("resource_available", "Current usage: {percent}%. Capacity is available.")
            }
            .with("percent", number),
        ),
        None => caused(
            check(
                &value.code,
                label,
                DiagnosticLevel::Warning,
                text("resource_unavailable", "A current resource reading is unavailable."),
            ),
            "not_measured",
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

fn dns_success(message: &str) -> Option<Text> {
    let millis = message
        .strip_prefix("Valid DNS response in ")?
        .strip_suffix(" ms. No query history is retained.")?
        .parse::<u16>()
        .ok()?;
    (millis <= 5000).then(|| {
        text(
            "dns_valid_time",
            "Valid DNS response in {millis} ms. No query history is retained.",
        )
        .with("millis", millis)
    })
}

/// The VPS's DNS failure causes the app shows, with the key it translates each by.
const DNS_ERRORS: &[(&str, &str)] = &[
    (
        "dns_error_tcp",
        "TCP connection failed. Check the resolver address, route and port 53 firewall.",
    ),
    (
        "dns_error_https",
        "Authenticated HTTPS DNS failed. Check the resolver address, TLS name, HTTPS path and outbound port 443.",
    ),
    (
        "dns_error_timeout",
        "No DNS reply within three seconds. Check upstream reachability and firewall rules; DNS protection remains enabled.",
    ),
    (
        "dns_error_trust_unavailable",
        "The VPS certificate trust bundle is unavailable. Repair the CA certificates package.",
    ),
    (
        "dns_error_trust_invalid",
        "The VPS certificate trust bundle is invalid.",
    ),
    (
        "dns_error_tls_name",
        "The TLS resolver authentication name is invalid.",
    ),
    (
        "dns_error_tls_unreachable",
        "The TLS resolver could not be reached. Check its IP, route and outbound port 853.",
    ),
    (
        "dns_error_tls_auth",
        "TLS authentication failed. Check the resolver's certificate, configured TLS name and VPS clock.",
    ),
    ("dns_error_send", "The DNS request could not be sent."),
    (
        "dns_error_closed",
        "The DNS resolver closed the connection without a reply.",
    ),
    ("dns_error_size", "The DNS response had an invalid size."),
    ("dns_error_incomplete", "The DNS reply was incomplete."),
    (
        "dns_error_mismatch",
        "The DNS reply did not match the request or was truncated.",
    ),
    (
        "dns_error_servfail",
        "The resolver returned SERVFAIL. Check its upstream reachability, DNSSEC validation and clock.",
    ),
    (
        "dns_error_refused",
        "The resolver refused this query. Check its client access policy and zone forwarding rules.",
    ),
    (
        "dns_error_other",
        "The resolver returned a DNS error. Check its configured zone and upstream policy.",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// A check as the VPS words it: free text, no message key.
    fn check(code: &str, label: &str, level: DiagnosticLevel, message: &str) -> DiagnosticCheck {
        DiagnosticCheck {
            code: code.into(),
            label: label.into(),
            level,
            message: message.into(),
            cause: None,
            message_key: None,
            message_params: Default::default(),
        }
    }
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
            check("dns_blocklist", secret, DiagnosticLevel::Fail, secret),
            check("os_security_updates", secret, DiagnosticLevel::Fail, secret),
            check("os_reboot_required", secret, DiagnosticLevel::Pass, secret),
            check("dns", secret, DiagnosticLevel::NotApplicable, secret),
            check("leak_dns", secret, DiagnosticLevel::Pass, secret),
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
        // The VPS can neither fake a local leak result nor mark its own check not applicable.
        assert!(
            !report
                .checks
                .iter()
                .any(|c| c.code == "leak_dns" || c.code == "dns")
        );
        let blocklist = report
            .checks
            .iter()
            .find(|c| c.code == "dns_blocklist")
            .unwrap();
        assert_eq!(blocklist.level, DiagnosticLevel::Warning);
        assert!(blocklist.message.contains("last good list"));
        let level = |code: &str| {
            report
                .checks
                .iter()
                .find(|c| c.code == code)
                .unwrap()
                .level
                .clone()
        };
        // Update state never escalates to a failure: the tunnel itself is unaffected.
        assert_eq!(level("os_security_updates"), DiagnosticLevel::Warning);
        assert_eq!(level("os_reboot_required"), DiagnosticLevel::Pass);
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
            check(
                "dns_tls_0",
                "ignored",
                DiagnosticLevel::Fail,
                DNS_ERRORS[7].1,
            ),
            check(
                "dns_resolver_response",
                "ignored",
                DiagnosticLevel::Pass,
                "Valid DNS response in 82 ms. No query history is retained.",
            ),
        ]));
        assert_eq!(report.checks[0].level, DiagnosticLevel::Warning);
        assert_eq!(report.checks[1].message, DNS_ERRORS[7].1);
        assert_eq!(
            report.checks[1].message_key.as_deref(),
            Some(DNS_ERRORS[7].0)
        );
        assert!(report.checks[2].message.contains("82 ms"));
        assert!(dns_label("dns_zone_01").is_none());
        assert!(dns_label("dns_zone_32").is_none());
    }
}
