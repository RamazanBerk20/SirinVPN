use super::*;
use crate::probes;
use sirinvpn_protocol::{MtuPolicy, MtuProbeOutcome, MtuStatus, TransportKind};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

impl Controller {
    pub(super) async fn inspect_measurements(&mut self) -> io::Result<()> {
        let Some(active) = &self.active else {
            return Ok(());
        };
        if active
            .connected_at
            .is_none_or(|at| at.elapsed() < Duration::from_secs(3))
        {
            return Ok(());
        }
        let source = active.request.client_address;
        let destination = active.request.dns_address;
        let ipv6 = active.request.client_ipv6_address.is_some();
        let transport = active.request.transport;
        let kill = active.request.connection_policy().kill_switch;
        let counter = active
            .stats
            .and_then(|stats| stats.rx_bytes.checked_add(stats.tx_bytes));
        let cancel = Arc::clone(&self.cancel);
        let epoch = self.operation_epoch;
        if active.mtu.outcome == MtuProbeOutcome::Pending {
            let current = active.mtu;
            let result = tokio::select! {
                biased;
                _ = cancel.changed(epoch) => return Err(io::ErrorKind::Interrupted.into()),
                result = detect_mtu(source, destination, ipv6, current) => result,
            };
            let active = self.active.as_mut().expect("measured adapter");
            active.mtu = result;
            if result.policy == MtuPolicy::Automatic
                && let Some(value) = result.suggested
                && value != result.configured
            {
                let luid = active.adapter.luid();
                let apply = network::set_mtu(luid, AF_INET, value).and_then(|()| {
                    if ipv6 {
                        network::set_mtu(luid, AF_INET6, value)
                    } else {
                        Ok(())
                    }
                });
                if apply.is_ok() {
                    active.mtu.configured = value;
                    active.request.mtu = value;
                } else {
                    let _ = network::set_mtu(luid, AF_INET, result.configured);
                    if ipv6 {
                        let _ = network::set_mtu(luid, AF_INET6, result.configured);
                    }
                    active.mtu.outcome = MtuProbeOutcome::ApplyFailed;
                }
            }
            // Measurement work is separated across controller passes so a pause
            // cannot sit behind both an MTU search and eight quality probes.
            return Ok(());
        }
        if !self.quality.due() {
            return Ok(());
        }
        let idle = self.quality.idle(counter);
        let sample = tokio::select! {
            biased;
            _ = cancel.changed(epoch) => return Err(io::ErrorKind::Interrupted.into()),
            sample = probes::sample(source, destination, transport) => sample,
        };
        let kinds = self
            .saved
            .as_ref()
            .expect("measured session")
            .request
            .reconnect_candidates
            .iter()
            .map(|candidate| candidate.transport)
            .collect::<Vec<_>>();
        if let Some(kind) = self.quality.record(transport, sample, &kinds, kill, idle) {
            self.change_quality_transport(kind).await?;
        }
        Ok(())
    }

    pub(super) async fn change_quality_transport(&mut self, kind: TransportKind) -> io::Result<()> {
        let saved = self.saved.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
        if !saved.request.connection_policy().kill_switch {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let count = saved.request.reconnect_candidates.len();
        let offset = saved
            .request
            .reconnect_candidates
            .iter()
            .position(|candidate| candidate.transport == kind)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let index = self.attempt_index / count.max(1) * count + offset;
        self.close_guard()?;
        self.stop_active().await?;
        self.cleanup_routes()?;
        self.saved.as_mut().expect("saved session").phase = SessionPhase::Connecting;
        self.persist()?;
        self.attempt_index = index;
        self.next_attempt = Instant::now();
        self.pass_started = Instant::now();
        self.quality.changing();
        Ok(())
    }
}

async fn detect_mtu(
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    ipv6: bool,
    mut status: MtuStatus,
) -> MtuStatus {
    if probes::ping(source, destination, 32, 1000).await.is_none() {
        status.outcome = MtuProbeOutcome::IcmpUnavailable;
        return status;
    }
    let minimum = if ipv6 { 1280 } else { 576 };
    let ceiling = status.configured;
    let candidates = std::iter::once(ceiling).chain(
        [1380, 1320, 1280, 1200, 1024, 768, 576]
            .into_iter()
            .filter(|value| *value >= minimum && *value < ceiling),
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    for candidate in candidates {
        if Instant::now() >= deadline {
            break;
        }
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, 700) as u32;
        if probes::ping(source, destination, candidate - 28, timeout)
            .await
            .is_some()
            && Instant::now() < deadline
            && probes::ping(source, destination, candidate - 28, 700)
                .await
                .is_some()
        {
            status.suggested = Some(candidate);
            status.outcome = MtuProbeOutcome::Measured;
            return status;
        }
    }
    status.outcome = MtuProbeOutcome::NoUsableMtu;
    status
}
