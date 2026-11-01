//! Explicit, bounded inspection of current state. Raw command output never leaves this module.
use crate::{ServerConfiguration, metrics, service_metrics};
use sirinvpn_protocol::{API_VERSION, DiagnosticCheck, DiagnosticLevel, DiagnosticReport};
use std::{fs, path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command, sync::Mutex};

mod network;
pub(crate) use network::ports;

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
    let (dns_active, dns, network, resources, os, service) = tokio::join!(
        metrics::dns_services_active(configuration),
        crate::dns_diagnostics::diagnose(configuration),
        network::inspect(configuration),
        resources(),
        operating_system_updates(),
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
    checks.extend(os);
    checks.extend(dns);
    let blocklist = crate::dns_blocklist::read_status();
    if blocklist.active || blocklist.failure.is_some() {
        checks.push(if blocklist.failure.is_some() {
            check(
                "dns_blocklist",
                "VPS DNS blocking",
                DiagnosticLevel::Warning,
                "The latest blocklist refresh failed. DNS blocking keeps the last good list.",
            )
        } else {
            check(
                "dns_blocklist",
                "VPS DNS blocking",
                DiagnosticLevel::Pass,
                "DNS blocking uses the latest refreshed list.",
            )
        });
    }
    report(checks)
}

fn report(checks: Vec<DiagnosticCheck>) -> DiagnosticReport {
    DiagnosticReport {
        api_version: API_VERSION.into(),
        checks,
    }
}

pub(crate) fn flag(path: &str) -> Option<bool> {
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

/// Whether automatic distribution security updates run, and whether an installed update
/// still waits for a reboot (`None` when that cannot be read). Updates are the Owner's to manage.
pub(crate) async fn update_state() -> (bool, Option<bool>) {
    let (setting, timer) = tokio::join!(
        output(
            "apt-config",
            &["shell", "VALUE", "APT::Periodic::Unattended-Upgrade"]
        ),
        output("systemctl", &["is-enabled", "apt-daily-upgrade.timer"]),
    );
    let automatic = Path::new("/usr/bin/unattended-upgrade").exists()
        && setting.as_deref().is_some_and(periodic_enabled)
        && timer
            .as_deref()
            .is_some_and(|state| state.trim() == "enabled");
    let kernels = fs::read_dir("/boot").map(|entries| {
        entries
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("vmlinuz-"))
            .filter_map(|entry| entry.metadata().ok())
            .map(|metadata| std::os::unix::fs::MetadataExt::ctime(&metadata))
            .collect::<Vec<_>>()
    });
    let boot = read_current("/proc/stat").and_then(|stat| {
        stat.lines()
            .find_map(|line| line.strip_prefix("btime "))?
            .trim()
            .parse::<i64>()
            .ok()
    });
    (
        automatic,
        reboot_required(
            Path::new("/run/reboot-required").exists(),
            boot,
            kernels.ok().as_deref(),
        ),
    )
}

async fn operating_system_updates() -> Vec<DiagnosticCheck> {
    let (automatic, reboot) = update_state().await;
    vec![
        if automatic {
            check(
                "os_security_updates",
                "VPS security updates",
                DiagnosticLevel::Pass,
                "Automatic security updates are on.",
            )
        } else {
            check(
                "os_security_updates",
                "VPS security updates",
                DiagnosticLevel::Warning,
                "Automatic security updates are off or could not be confirmed.",
            )
        },
        match reboot {
            Some(false) => check(
                "os_reboot_required",
                "VPS restart",
                DiagnosticLevel::Pass,
                "The VPS runs its newest installed kernel.",
            ),
            Some(true) => check(
                "os_reboot_required",
                "VPS restart",
                DiagnosticLevel::Warning,
                "An installed update waits for a VPS restart.",
            ),
            None => check(
                "os_reboot_required",
                "VPS restart",
                DiagnosticLevel::Warning,
                "This current state could not be read. Check the server tools and service permissions.",
            ),
        },
    ]
}

/// `apt-config shell VALUE key` prints `VALUE='1'`; the value is a period in days, 0 is off.
fn periodic_enabled(output: &str) -> bool {
    output
        .trim()
        .strip_prefix("VALUE='")
        .and_then(|value| value.strip_suffix('\''))
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|days| days > 0)
}

/// dpkg keeps a package's build time as the file's mtime, so a kernel installed since boot
/// shows only in its inode change time.
fn reboot_required(flagged: bool, boot: Option<i64>, kernels: Option<&[i64]>) -> Option<bool> {
    if flagged {
        return Some(true);
    }
    let boot = boot?;
    Some(kernels?.iter().any(|changed| *changed > boot))
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
    fn update_readings_need_an_enabled_period_and_a_kernel_change_after_boot() {
        assert!(periodic_enabled("VALUE='1'\n"));
        assert!(periodic_enabled("VALUE='7'"));
        assert!(!periodic_enabled("VALUE='0'"));
        assert!(!periodic_enabled("VALUE=''"));
        assert!(!periodic_enabled("VALUE='always'"));
        assert_eq!(reboot_required(true, None, None), Some(true));
        assert_eq!(
            reboot_required(false, Some(100), Some(&[50, 90])),
            Some(false)
        );
        assert_eq!(
            reboot_required(false, Some(100), Some(&[50, 150])),
            Some(true)
        );
        assert_eq!(reboot_required(false, None, Some(&[150])), None);
        assert_eq!(reboot_required(false, Some(100), None), None);
    }

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
