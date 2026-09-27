//! Explicit, bounded inspection of current state. Raw command output never leaves this module.
use crate::{ServerConfiguration, metrics, service_metrics};
use sirinvpn_protocol::{API_VERSION, DiagnosticCheck, DiagnosticLevel, DiagnosticReport};
use std::{fs, path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command, sync::Mutex};

mod network;

static RUNNING: Mutex<()> = Mutex::const_new(());
const OUTPUT_LIMIT: u64 = 128 * 1024;

pub async fn collect_diagnostics(configuration: &ServerConfiguration) -> DiagnosticReport {
    let Ok(_guard) = RUNNING.try_lock() else {
        return report(vec![check(
            "diagnostics_busy",
            "Current diagnostics",
            DiagnosticLevel::Warning,
            "Another current-state check is running. Try again in a few seconds.",
        )]);
    };
    let (dns_active, dns, network, resources, service) = tokio::join!(
        metrics::dns_services_active(configuration),
        crate::dns_diagnostics::diagnose(configuration),
        network::inspect(configuration),
        resources(),
        output(
            "systemctl",
            &[
                "show",
                "--property=ActiveState",
                "--value",
                "sirinvpn-server.service"
            ]
        ),
    );
    let interface = metrics::interface_exists(&configuration.interface_name);
    let mut checks = vec![
        condition(
            "interface",
            "VPS VPN interface",
            Some(interface),
            "The configured VPS VPN interface exists.",
            "The VPS VPN interface is missing. Use server repair to restore it.",
        ),
        condition(
            "dns",
            "VPS DNS service",
            Some(dns_active),
            "The configured private resolver services are active.",
            "A private resolver service is inactive. Use server repair, then rerun diagnostics.",
        ),
        condition(
            "forwarding",
            "VPS IPv4 forwarding",
            flag("/proc/sys/net/ipv4/ip_forward"),
            "IPv4 forwarding is enabled.",
            "IPv4 forwarding is disabled. Use server repair to restore forwarding.",
        ),
        condition(
            "server_process",
            "VPS service",
            service.as_deref().map(|value| value.trim() == "active"),
            "The SirinVPN system service is active.",
            "The SirinVPN system service is inactive. Check its installation or use server repair.",
        ),
    ];
    if configuration.ipv6_tunnel_enabled {
        checks.push(condition(
            "ipv6",
            "VPS IPv6 tunnel",
            flag("/proc/sys/net/ipv6/conf/all/forwarding").map(|forwarding| {
                forwarding && metrics::interface_has_private_ipv6(&configuration.interface_name)
            }),
            "IPv6 forwarding and the private tunnel address are present.",
            "IPv6 forwarding or tunnel addressing is unavailable. Use server repair.",
        ));
    }
    checks.extend(network);
    checks.extend(resources);
    checks.extend(dns);
    report(checks)
}

fn report(checks: Vec<DiagnosticCheck>) -> DiagnosticReport {
    DiagnosticReport {
        api_version: API_VERSION.into(),
        checks,
    }
}

fn flag(path: &str) -> Option<bool> {
    match fs::read_to_string(path).ok()?.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

fn check(code: &str, label: &str, level: DiagnosticLevel, message: &str) -> DiagnosticCheck {
    DiagnosticCheck {
        code: code.into(),
        label: label.into(),
        level,
        message: message.into(),
    }
}

fn condition(
    code: &str,
    label: &str,
    value: Option<bool>,
    success: &str,
    failure: &str,
) -> DiagnosticCheck {
    match value {
        Some(true) => check(code, label, DiagnosticLevel::Pass, success),
        Some(false) => check(code, label, DiagnosticLevel::Fail, failure),
        None => check(
            code,
            label,
            DiagnosticLevel::Warning,
            "This current state could not be read. Check the server tools and service permissions.",
        ),
    }
}

pub(super) async fn output(program: &str, arguments: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(arguments)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let result = tokio::time::timeout(Duration::from_secs(1), async {
        let mut bytes = Vec::new();
        child
            .stdout
            .take()?
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .await
            .ok()?;
        if bytes.len() as u64 > OUTPUT_LIMIT {
            return None;
        }
        let status = child.wait().await.ok()?;
        if !status.success() {
            return None;
        }
        String::from_utf8(bytes).ok()
    })
    .await
    .ok()
    .flatten();
    if result.is_none() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

async fn resources() -> Vec<DiagnosticCheck> {
    let first = metrics::read_system_metric_snapshot("sirinvpn0");
    let disk = service_metrics::root_disk_usage().await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let last = metrics::read_system_metric_snapshot("sirinvpn0");
    let cpu = first
        .cpu
        .zip(last.cpu)
        .and_then(|(a, b)| metrics::cpu_usage_basis_points(a, b));
    vec![
        usage(
            "server_cpu",
            "VPS CPU",
            cpu.map(u64::from).map(|used| (used, 10_000)),
            90,
        ),
        usage(
            "server_memory",
            "VPS memory",
            last.memory.map(|m| {
                (
                    m.total_bytes.saturating_sub(m.available_bytes),
                    m.total_bytes,
                )
            }),
            90,
        ),
        usage("server_disk", "VPS disk", disk, 90),
    ]
}

fn usage(code: &str, label: &str, counters: Option<(u64, u64)>, threshold: u64) -> DiagnosticCheck {
    let Some((used, total)) = counters.filter(|(used, total)| *total > 0 && used <= total) else {
        return check(
            code,
            label,
            DiagnosticLevel::Warning,
            "A current resource reading is unavailable.",
        );
    };
    let percent = (u128::from(used) * 100 / u128::from(total)) as u64;
    check(
        code,
        label,
        if percent >= threshold {
            DiagnosticLevel::Warning
        } else {
            DiagnosticLevel::Pass
        },
        &format!(
            "Current usage: {percent}%. {}",
            if percent >= threshold {
                "Capacity is limited. Free resources or increase the VPS capacity."
            } else {
                "Capacity is available."
            }
        ),
    )
}

fn read_current(path: impl AsRef<Path>) -> Option<String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > OUTPUT_LIMIT {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_readings_are_unknown_and_resource_pressure_is_not_a_tunnel_failure() {
        assert_eq!(
            condition("routes", "Routes", None, "yes", "no").level,
            DiagnosticLevel::Warning
        );
        assert_eq!(
            usage("server_cpu", "CPU", Some((90, 100)), 90).level,
            DiagnosticLevel::Warning
        );
        assert_eq!(
            usage("server_cpu", "CPU", Some((89, 100)), 90).level,
            DiagnosticLevel::Pass
        );
        assert_eq!(
            usage("server_memory", "RAM", Some((u64::MAX, u64::MAX)), 90).message,
            "Current usage: 100%. Capacity is limited. Free resources or increase the VPS capacity."
        );
        assert_eq!(
            usage("server_disk", "Disk", Some((2, 1)), 90).level,
            DiagnosticLevel::Warning
        );
    }
}
