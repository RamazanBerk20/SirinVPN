//! Metrics.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CpuCounters {
    pub(super) total: u64,
    pub(super) idle: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MemoryCounters {
    pub(super) total_bytes: u64,
    pub(super) available_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SystemMetricSnapshot {
    pub(super) recorded_at: Instant,
    pub(super) cpu: Option<CpuCounters>,
    pub(super) memory: Option<MemoryCounters>,
    pub(super) network: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct LiveMetricSample {
    pub(super) cpu_usage_basis_points: Option<u16>,
    pub(super) memory_used_bytes: Option<u64>,
    pub(super) memory_total_bytes: Option<u64>,
    pub(super) rx_bytes_per_second: Option<u64>,
    pub(super) tx_bytes_per_second: Option<u64>,
}

#[derive(Default)]
pub(super) struct LiveMetricSampler {
    pub(super) previous: Option<SystemMetricSnapshot>,
}

impl LiveMetricSampler {
    pub(super) fn sample(&mut self, current: SystemMetricSnapshot) -> LiveMetricSample {
        let memory_total_bytes = current.memory.map(|memory| memory.total_bytes);
        let memory_used_bytes = current
            .memory
            .map(|memory| memory.total_bytes.saturating_sub(memory.available_bytes));
        let previous = self.previous.replace(current);
        let Some(previous) = previous else {
            return LiveMetricSample {
                memory_used_bytes,
                memory_total_bytes,
                ..LiveMetricSample::default()
            };
        };
        let Some(elapsed) = current
            .recorded_at
            .checked_duration_since(previous.recorded_at)
            .filter(|elapsed| {
                *elapsed >= MIN_LIVE_METRIC_INTERVAL && *elapsed <= MAX_LIVE_METRIC_INTERVAL
            })
        else {
            return LiveMetricSample {
                memory_used_bytes,
                memory_total_bytes,
                ..LiveMetricSample::default()
            };
        };
        let cpu_usage_basis_points = previous
            .cpu
            .zip(current.cpu)
            .and_then(|(previous, current)| cpu_usage_basis_points(previous, current));
        let (rx_bytes_per_second, tx_bytes_per_second) = previous
            .network
            .zip(current.network)
            .map(|(previous, current)| {
                (
                    bytes_per_second(previous.0, current.0, elapsed),
                    bytes_per_second(previous.1, current.1, elapsed),
                )
            })
            .unwrap_or_default();
        LiveMetricSample {
            cpu_usage_basis_points,
            memory_used_bytes,
            memory_total_bytes,
            rx_bytes_per_second,
            tx_bytes_per_second,
        }
    }
}

pub async fn collect_status(configuration: &ServerConfiguration) -> ServerStatus {
    let sampler = Mutex::new(LiveMetricSampler::default());
    collect_status_with_peer_count(configuration, 1, &sampler).await
}

pub(super) async fn collect_status_with_peer_count(
    configuration: &ServerConfiguration,
    authorized_peer_count: u32,
    live_metrics: &Mutex<LiveMetricSampler>,
) -> ServerStatus {
    let interface_up = interface_exists(&configuration.interface_name);
    let (dns_healthy, disk) = tokio::join!(
        dns_services_active(configuration),
        super::service_metrics::root_disk_usage(),
    );
    let system_metrics = read_system_metric_snapshot(&configuration.interface_name);
    let (rx_bytes, tx_bytes) = system_metrics.network.unwrap_or_default();
    let live_sample = live_metrics
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .sample(system_metrics);
    let uptime_seconds = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|contents| contents.split_whitespace().next()?.parse::<f64>().ok())
        .map(|value| value as u64)
        .unwrap_or_default();

    ServerStatus {
        api_version: API_VERSION.to_owned(),
        server_name: configuration.server_name.clone(),
        connection_state: if interface_up {
            ConnectionState::Connected
        } else {
            ConnectionState::Degraded
        },
        interface_up,
        dns_healthy,
        dns_upstream: configuration.dns_upstream.clone(),
        private_dns_records: configuration.private_dns_records.clone(),
        transport: TransportKind::DirectUdp,
        peer_count: authorized_peer_count,
        peer_activity_supported: true,
        recently_active_peer_count: None,
        rx_bytes,
        tx_bytes,
        uptime_seconds,
        cpu_usage_basis_points: live_sample.cpu_usage_basis_points,
        memory_used_bytes: live_sample.memory_used_bytes,
        memory_total_bytes: live_sample.memory_total_bytes,
        rx_bytes_per_second: live_sample.rx_bytes_per_second,
        tx_bytes_per_second: live_sample.tx_bytes_per_second,
        disk_used_bytes: disk.map(|(used, _)| used),
        disk_total_bytes: disk.map(|(_, total)| total),
        rx_packets: super::service_metrics::packet_counter(
            &configuration.interface_name,
            "rx_packets",
        ),
        tx_packets: super::service_metrics::packet_counter(
            &configuration.interface_name,
            "tx_packets",
        ),
        caller_role: None,
        caller_administrator: false,
        caller_device_id: None,
        caller_identity_fingerprint: String::new(),
    }
}

pub(super) async fn dns_services_active(configuration: &ServerConfiguration) -> bool {
    command_succeeds("systemctl", &["is-active", "--quiet", "unbound"]).await
        && (configuration.dns_upstream.doh_endpoints().is_none()
            || command_succeeds("systemctl", &["is-active", "--quiet", "sirinvpn-doh"]).await)
}

pub(super) fn interface_has_private_ipv6(interface: &str) -> bool {
    fs::read_to_string("/proc/net/if_inet6")
        .ok()
        .is_some_and(|contents| interface_list_has_private_ipv6(&contents, interface))
}

pub(super) fn interface_list_has_private_ipv6(contents: &str, interface: &str) -> bool {
    contents.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields
            .next()
            .is_some_and(|address| address.len() == 32 && address.starts_with("fd"))
            && fields.nth(4) == Some(interface)
    })
}

pub(super) async fn command_succeeds(program: &str, arguments: &[&str]) -> bool {
    tokio::time::timeout(
        Duration::from_secs(1),
        Command::new(program)
            .args(arguments)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .map(|output| output.status.success())
    .unwrap_or(false)
}

pub(super) fn interface_exists(interface: &str) -> bool {
    Path::new("/sys/class/net").join(interface).is_dir()
}

pub(super) fn read_system_metric_snapshot(interface: &str) -> SystemMetricSnapshot {
    let cpu = fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|contents| parse_cpu_counters(&contents));
    let memory = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|contents| parse_memory_counters(&contents));
    let network = fs::read_to_string("/proc/net/dev")
        .ok()
        .and_then(|contents| parse_interface_counters(&contents, interface));
    SystemMetricSnapshot {
        recorded_at: Instant::now(),
        cpu,
        memory,
        network,
    }
}

pub(super) fn parse_cpu_counters(contents: &str) -> Option<CpuCounters> {
    let mut fields = contents
        .lines()
        .find(|line| line.starts_with("cpu "))?
        .split_whitespace()
        .skip(1)
        .map(str::parse::<u64>);
    let user = fields.next()?.ok()?;
    let nice = fields.next()?.ok()?;
    let system = fields.next()?.ok()?;
    let idle = fields.next()?.ok()?;
    let io_wait = fields.next()?.ok()?;
    let irq = fields.next()?.ok()?;
    let soft_irq = fields.next()?.ok()?;
    let steal = fields.next()?.ok()?;
    let total = [user, nice, system, idle, io_wait, irq, soft_irq, steal]
        .into_iter()
        .try_fold(0_u64, |sum, value| sum.checked_add(value))?;
    Some(CpuCounters {
        total,
        idle: idle.checked_add(io_wait)?,
    })
}

pub(super) fn parse_memory_counters(contents: &str) -> Option<MemoryCounters> {
    let mut total_bytes = None;
    let mut available_bytes = None;
    for line in contents.lines() {
        let (name, value) = line.split_once(':')?;
        if name != "MemTotal" && name != "MemAvailable" {
            continue;
        }
        let mut fields = value.split_whitespace();
        let kibibytes = fields.next()?.parse::<u64>().ok()?;
        if fields.next()? != "kB" || fields.next().is_some() {
            return None;
        }
        let bytes = kibibytes.checked_mul(1024)?;
        if name == "MemTotal" {
            total_bytes = Some(bytes);
        } else {
            available_bytes = Some(bytes);
        }
    }
    let total_bytes = total_bytes?;
    Some(MemoryCounters {
        total_bytes,
        available_bytes: available_bytes?.min(total_bytes),
    })
}

pub(super) fn cpu_usage_basis_points(previous: CpuCounters, current: CpuCounters) -> Option<u16> {
    let total = current.total.checked_sub(previous.total)?;
    let idle = current.idle.checked_sub(previous.idle)?;
    let busy = total.checked_sub(idle)?;
    if total == 0 {
        return None;
    }
    let basis_points = (u128::from(busy) * 10_000 / u128::from(total)).min(10_000);
    u16::try_from(basis_points).ok()
}

pub(super) fn bytes_per_second(previous: u64, current: u64, elapsed: Duration) -> Option<u64> {
    let delta = current.checked_sub(previous)?;
    let elapsed_nanos = elapsed.as_nanos();
    if elapsed_nanos == 0 {
        return None;
    }
    let rate = (u128::from(delta) * 1_000_000_000 / elapsed_nanos).min(u128::from(u64::MAX));
    u64::try_from(rate).ok()
}

pub(super) fn parse_interface_counters(contents: &str, interface: &str) -> Option<(u64, u64)> {
    contents.lines().find_map(|line| {
        let (name, counters) = line.split_once(':')?;
        if name.trim() != interface {
            return None;
        }
        let counters: Vec<_> = counters.split_whitespace().collect();
        let received = counters.first()?.parse().ok()?;
        let sent = counters.get(8)?.parse().ok()?;
        Some((received, sent))
    })
}
