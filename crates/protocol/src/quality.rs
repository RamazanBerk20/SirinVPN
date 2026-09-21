//! A bounded sample of the current private tunnel, never a traffic log.
use crate::TransportKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransportQualitySample {
    pub transport: TransportKind,
    pub probes_sent: u8,
    pub probes_received: u8,
    pub latency_micros: u32,
    pub jitter_micros: u32,
}

impl TransportQualitySample {
    pub fn valid(self) -> bool {
        self.probes_sent == 8
            && self.probes_received > 0
            && self.probes_received <= self.probes_sent
            && self.latency_micros <= 3_000_000
            && self.jitter_micros <= 3_000_000
    }

    pub fn stable(self) -> bool {
        self.valid() && self.probes_received == self.probes_sent
    }

    /// Prefer complete delivery, then latency with a jitter penalty. Hysteresis
    /// prevents switching for timer noise or an imperceptible latency difference.
    pub fn improves(self, current: Self) -> bool {
        if !self.valid() {
            return false;
        }
        if self.probes_received != current.probes_received {
            return self.probes_received > current.probes_received;
        }
        let score = |s: Self| u64::from(s.latency_micros) + 2 * u64::from(s.jitter_micros);
        let old = score(current);
        old.saturating_sub(score(self)) >= (old / 5).max(5_000)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualitySelection {
    #[default]
    Pending,
    Observing,
    WaitingForIdle,
    Comparing,
    Selected,
    IcmpUnavailable,
    ProtectionRequired,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransportQualityStatus {
    #[serde(default)]
    pub isolated_measurement_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_switch_reason: Option<TransportSwitchReason>,
    pub sample: Option<TransportQualitySample>,
    pub selection: QualitySelection,
    pub candidates_checked: u8,
}

/// Temporary, isolated measurement access; never a second application session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementLeaseRequest {
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementLease {
    pub public_key: String,
    pub client_address: std::net::Ipv4Addr,
    pub expires_at_unix: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportSwitchReason {
    ConfirmedFailure,
    QualityImprovement,
    Rollback,
}
