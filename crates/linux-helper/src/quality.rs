//! Observations never replace a working tunnel. Candidate probes use a separate peer.
use super::*;
use sirinvpn_protocol::{QualitySelection, TransportQualitySample, TransportQualityStatus};

const SAMPLE_INTERVAL: u64 = 30;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct PathHealth {
    rx: Option<u64>,
    handshake: Option<u64>,
    progress_at: u64,
    failed_since: Option<u64>,
    failures: u8,
    checked_at: u64,
}

impl PathHealth {
    pub(super) fn record(
        &mut self,
        now: u64,
        rx: Option<u64>,
        handshake: Option<u64>,
        reply: bool,
    ) {
        // A resume or stalled observer starts a new evidence window. Old failed
        // checks cannot become a confirmed failure on the first wake-up sample.
        if now < self.checked_at
            || now.saturating_sub(self.checked_at) > 30
            || rx.zip(self.rx).is_some_and(|(new, old)| new < old)
        {
            *self = Self::default();
        }
        let progress = reply
            || rx.zip(self.rx).is_some_and(|(new, old)| new > old)
            || handshake
                .zip(self.handshake)
                .is_some_and(|(new, old)| new > old);
        let initialized = self.checked_at != 0;
        self.rx = rx;
        self.handshake = handshake;
        self.checked_at = now;
        if progress {
            self.progress_at = now;
            self.failed_since = None;
            self.failures = 0;
        } else if initialized {
            self.failed_since.get_or_insert(now);
            self.failures = self.failures.saturating_add(1);
        }
    }
    pub(super) fn failed(&self, now: u64) -> bool {
        self.failures >= 3
            && self
                .failed_since
                .is_some_and(|at| now.saturating_sub(at) >= 15)
            && now >= self.checked_at
            && now - self.checked_at <= 10
    }
    pub(super) fn receiving(&self, now: u64) -> bool {
        self.progress_at > 0 && now >= self.progress_at && now - self.progress_at <= 15
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct QualityController {
    pub status: TransportQualityStatus,
    #[serde(default)]
    pub health: PathHealth,
    sampled_at: u64,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub network_changed_at_unix: u64,
}

impl QualityController {
    pub(super) fn snapshot(&self, active: bool) -> TransportQualityStatus {
        let mut status = self.status.clone();
        if !active || now_unix().saturating_sub(self.sampled_at) > 90 {
            status.sample = None;
            status.selection = QualitySelection::Pending;
        }
        status
    }
    pub(super) fn valid(&self) -> bool {
        self.status.sample.is_none_or(|sample| sample.valid())
            && self.status.candidates_checked <= 4
    }
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    /// A bounded worker reads a snapshot without keeping the operation lock over IO.
    /// Revalidate the session, interface and network before publishing any result.
    pub(super) fn measure_current_path(&self) -> Result<()> {
        let desired = self.read_persistent()?;
        let snapshot = self.read_state()?;
        if snapshot.waiting_for_user || !snapshot.has_connected {
            return Ok(());
        }
        let request = current_persistent_request(&desired, Some(&snapshot));
        let route = self.physical_default_route_fingerprint();
        if route == Some(None) {
            return Ok(());
        }
        let interface = fs::read_to_string(format!("/sys/class/net/{INTERFACE_NAME}/ifindex")).ok();
        let reply = self
            .runner
            .tunnel_probe(request.client_address, request.dns_address);
        let rx = self
            .runner
            .output("wg", &["show", INTERFACE_NAME, "transfer"])
            .ok()
            .and_then(|bytes| receive_counter(&bytes));
        let handshake = self.latest_handshake_timestamp();
        let checked_at = now_unix();
        let sample_due = snapshot
            .quality
            .as_ref()
            .is_none_or(|q| now_unix().saturating_sub(q.sampled_at) >= SAMPLE_INTERVAL);
        let sample = (sample_due && !snapshot.reconnecting).then(|| self.sample_quality(&request));
        let mtu = (!snapshot.reconnecting)
            .then(|| self.measure_mtu(&request, &snapshot))
            .flatten();
        let _lock = self.lock_operations()?;
        let mut current = self.read_state()?;
        if current.server_id != snapshot.server_id
            || current.applied_at_unix != snapshot.applied_at_unix
            || current.transport != snapshot.transport
            || current.waiting_for_user
            || current.reconnecting != snapshot.reconnecting
            || current
                .quality
                .as_ref()
                .map(|q| (q.generation, q.network_changed_at_unix))
                .unwrap_or_default()
                != snapshot
                    .quality
                    .as_ref()
                    .map(|q| (q.generation, q.network_changed_at_unix))
                    .unwrap_or_default()
            || self.read_persistent()?.request != desired.request
            || self.physical_default_route_fingerprint() != route
            || fs::read_to_string(format!("/sys/class/net/{INTERFACE_NAME}/ifindex")).ok()
                != interface
        {
            return Ok(());
        }
        let quality = current
            .quality
            .get_or_insert_with(QualityController::default);
        quality.health.record(checked_at, rx, handshake, reply);
        if let Some(sample) = sample {
            quality.sampled_at = now_unix();
            quality.status.sample = sample;
            quality.status.selection = if sample.is_some() {
                QualitySelection::Observing
            } else {
                QualitySelection::IcmpUnavailable
            };
            quality.status.candidates_checked = 1;
        }
        if let Some(mtu) = mtu {
            self.commit_mtu(&request, &mut current, mtu);
        }
        self.write_state(&current)?;
        Ok(())
    }

    pub(super) fn sample_quality(
        &self,
        request: &TunnelConnectRequest,
    ) -> Option<TransportQualitySample> {
        self.sample_quality_on(INTERFACE_NAME, request.dns_address, request.transport)
    }

    pub(super) fn sample_quality_on(
        &self,
        interface: &str,
        destination: Ipv4Addr,
        transport: TransportKind,
    ) -> Option<TransportQualitySample> {
        let output = self
            .runner
            .output_with_timeout(
                "ping",
                &[
                    "-n",
                    "-4",
                    "-c",
                    "8",
                    "-i",
                    "0.2",
                    "-W",
                    "1",
                    "-w",
                    "3",
                    "-s",
                    "32",
                    "-I",
                    interface,
                    &destination.to_string(),
                ],
                Duration::from_millis(3500),
            )
            .ok()?;
        parse_sample(&output, transport)
    }
}

fn receive_counter(output: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(output).ok()?;
    let mut total = None;
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return None;
        }
        total = Some(
            total
                .unwrap_or(0_u64)
                .checked_add(fields[1].parse().ok()?)?,
        );
    }
    total
}

pub(super) fn transfer_counter(output: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(output).ok()?;
    let mut sum = 0_u64;
    let mut found = false;
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return None;
        }
        sum = sum
            .checked_add(fields[1].parse().ok()?)?
            .checked_add(fields[2].parse().ok()?)?;
        found = true;
    }
    found.then_some(sum)
}

fn parse_sample(output: &[u8], transport: TransportKind) -> Option<TransportQualitySample> {
    if output.len() > 8192 {
        return None;
    }
    let output = std::str::from_utf8(output).ok()?;
    let packets = output
        .lines()
        .find(|line| line.contains("packets transmitted"))?;
    let mut counts = packets.split(',');
    let sent = counts.next()?.split_whitespace().next()?.parse().ok()?;
    let received = counts.next()?.split_whitespace().next()?.parse().ok()?;
    let rtt = output.lines().find(|line| line.starts_with("rtt "))?;
    let values = rtt
        .split_once(" = ")?
        .1
        .split_whitespace()
        .next()?
        .split('/')
        .collect::<Vec<_>>();
    if values.len() != 4 {
        return None;
    }
    let micros = |value: &str| {
        let ms = value.parse::<f64>().ok()?;
        (ms.is_finite() && (0.0..=3000.0).contains(&ms)).then_some((ms * 1000.0).round() as u32)
    };
    let sample = TransportQualitySample {
        transport,
        probes_sent: sent,
        probes_received: received,
        latency_micros: micros(values[1])?,
        jitter_micros: micros(values[3])?,
    };
    sample.valid().then_some(sample)
}

#[cfg(test)]
mod tests;
