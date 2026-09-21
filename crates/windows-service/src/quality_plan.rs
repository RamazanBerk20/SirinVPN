//! Current measurements and reversible transport trials; never serialized.
use sirinvpn_protocol::{
    QualitySelection, TransportKind, TransportQualitySample, TransportQualityStatus,
};
use std::time::{Duration, Instant};

pub(crate) struct QualityMonitor {
    pub status: TransportQualityStatus,
    sampled: Option<Instant>,
    cycle: Instant,
    checked: Vec<TransportKind>,
    best: Option<TransportQualitySample>,
    rollback: Option<TransportKind>,
    idle_counter: Option<(Instant, u64)>,
}
impl Default for QualityMonitor {
    fn default() -> Self {
        Self {
            status: TransportQualityStatus::default(),
            sampled: None,
            cycle: Instant::now(),
            checked: Vec::new(),
            best: None,
            rollback: None,
            idle_counter: None,
        }
    }
}
impl QualityMonitor {
    pub(crate) fn due(&mut self) -> bool {
        if self.rollback.is_none() && self.cycle.elapsed() >= Duration::from_secs(600) {
            *self = Self::default();
        }
        self.sampled
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(30))
    }
    pub(crate) fn idle(&mut self, counter: Option<u64>) -> bool {
        let Some(counter) = counter else {
            self.idle_counter = None;
            return false;
        };
        let previous = self.idle_counter.replace((Instant::now(), counter));
        previous.is_some_and(|(at, before)| {
            at.elapsed() >= Duration::from_secs(10)
                && at.elapsed() <= Duration::from_secs(90)
                && counter >= before
                && counter - before <= 32 * 1024
        })
    }
    pub(crate) fn record(
        &mut self,
        transport: TransportKind,
        sample: Option<TransportQualitySample>,
        candidates: &[TransportKind],
        kill_switch: bool,
        idle: bool,
    ) -> Option<TransportKind> {
        self.sampled = Some(Instant::now());
        if !self.checked.contains(&transport) {
            self.checked.push(transport);
        }
        self.status.sample = sample;
        self.status.candidates_checked = self.checked.len().min(4) as u8;
        if let Some(sample) = sample
            && sample.valid()
            && self
                .best
                .is_none_or(|best| sample.transport == best.transport || sample.improves(best))
        {
            self.best = Some(sample);
        }
        if self.rollback.take().is_some()
            && let Some(best) = self.best
            && best.transport != transport
        {
            self.status.selection = QualitySelection::Comparing;
            return Some(best.transport);
        }
        self.status.selection = if sample.is_none() {
            QualitySelection::IcmpUnavailable
        } else if candidates.len() < 2 {
            QualitySelection::Observing
        } else if !kill_switch {
            QualitySelection::ProtectionRequired
        } else if let Some(next) = candidates.iter().find(|kind| !self.checked.contains(kind)) {
            if idle {
                self.rollback = self.best.map(|best| best.transport);
                self.status.selection = QualitySelection::Comparing;
                return Some(*next);
            }
            QualitySelection::WaitingForIdle
        } else {
            QualitySelection::Selected
        };
        None
    }
    pub(crate) fn failed_trial(&mut self, transport: TransportKind) -> Option<TransportKind> {
        let previous = self.rollback.take()?;
        if !self.checked.contains(&transport) {
            self.checked.push(transport);
        }
        self.status.candidates_checked = self.checked.len().min(4) as u8;
        self.status.sample = None;
        self.status.selection = QualitySelection::Comparing;
        Some(previous)
    }
    pub(crate) fn changing(&mut self) {
        self.sampled = None;
        self.idle_counter = None;
        self.status.sample = None;
        self.status.selection = QualitySelection::Comparing;
    }
    pub(crate) fn snapshot(&self, connected: bool) -> TransportQualityStatus {
        let mut status = self.status.clone();
        if !connected
            || self
                .sampled
                .is_none_or(|at| at.elapsed() > Duration::from_secs(90))
        {
            status.sample = None;
            if status.selection != QualitySelection::Comparing {
                status.selection = QualitySelection::Pending;
            }
        }
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const KINDS: [TransportKind; 2] = [TransportKind::DirectUdp, TransportKind::ObfuscatedUdp];
    fn sample(kind: TransportKind, received: u8, latency: u32) -> TransportQualitySample {
        TransportQualitySample {
            transport: kind,
            probes_sent: 8,
            probes_received: received,
            latency_micros: latency,
            jitter_micros: 1000,
        }
    }
    #[test]
    fn trials_require_protection_and_idle_then_roll_back_after_failure() {
        let mut quality = QualityMonitor::default();
        assert_eq!(
            quality.record(
                KINDS[0],
                Some(sample(KINDS[0], 8, 80_000)),
                &KINDS,
                false,
                true
            ),
            None
        );
        assert_eq!(
            quality.status.selection,
            QualitySelection::ProtectionRequired
        );
        assert_eq!(
            quality.record(
                KINDS[0],
                Some(sample(KINDS[0], 8, 80_000)),
                &KINDS,
                true,
                false
            ),
            None
        );
        assert_eq!(quality.status.selection, QualitySelection::WaitingForIdle);
        assert_eq!(
            quality.record(
                KINDS[0],
                Some(sample(KINDS[0], 8, 80_000)),
                &KINDS,
                true,
                true
            ),
            Some(KINDS[1])
        );
        assert_eq!(quality.failed_trial(KINDS[1]), Some(KINDS[0]));
        assert_eq!(quality.failed_trial(KINDS[1]), None);
    }
    #[test]
    fn a_worse_trial_returns_to_the_measured_winner() {
        let mut quality = QualityMonitor::default();
        quality.record(
            KINDS[0],
            Some(sample(KINDS[0], 8, 80_000)),
            &KINDS,
            true,
            true,
        );
        assert_eq!(
            quality.record(
                KINDS[1],
                Some(sample(KINDS[1], 7, 20_000)),
                &KINDS,
                true,
                true
            ),
            Some(KINDS[0])
        );
        assert!(quality.snapshot(false).sample.is_none());
        assert_eq!(quality.status.candidates_checked, 2);
    }
    #[test]
    fn stale_samples_and_counter_resets_cannot_trigger_an_idle_trial() {
        let mut quality = QualityMonitor::default();
        assert!(quality.due());
        assert!(!quality.idle(Some(100)));
        quality.idle_counter = Some((Instant::now() - Duration::from_secs(15), 100));
        assert!(quality.idle(Some(200)));
        quality.idle_counter = Some((Instant::now() - Duration::from_secs(15), 200));
        assert!(!quality.idle(Some(50)));
        assert!(!quality.idle(None));
        quality.record(KINDS[0], Some(sample(KINDS[0], 8, 1000)), &[], false, false);
        assert!(!quality.due());
        quality.sampled = Some(Instant::now() - Duration::from_secs(91));
        assert!(quality.snapshot(true).sample.is_none());
        quality.changing();
        assert!(quality.due());
        assert!(quality.idle_counter.is_none());
        quality.cycle = Instant::now() - Duration::from_secs(601);
        assert!(quality.due());
        assert!(quality.checked.is_empty());
    }
}
