//! Probe only the current private VPN path; no external address or traffic history.
use super::*;
use sirinvpn_protocol::{
    MIN_IPV4_TUNNEL_MTU, MIN_IPV6_TUNNEL_MTU, MtuPolicy, MtuProbeOutcome, MtuStatus,
};

pub(super) fn session_mtu(request: &TunnelConnectRequest) -> u16 {
    // TCP negotiates MSS when the socket opens. Lowering the interface later
    // cannot shrink the remote peer's established segments for another carrier.
    request
        .reconnect_candidates
        .iter()
        .fold(request.mtu, |mtu, candidate| mtu.min(candidate.mtu))
}

pub(super) fn initial_mtu(request: &TunnelConnectRequest) -> Option<MtuStatus> {
    request.mtu_policy.map(|policy| MtuStatus {
        policy,
        configured: session_mtu(request),
        suggested: None,
        outcome: MtuProbeOutcome::Pending,
    })
}

fn probe_candidates(ceiling: u16, minimum: u16) -> Vec<u16> {
    let mut result = vec![ceiling];
    for value in [1380, 1320, 1280, 1200, 1024, 768, 576] {
        if (minimum..ceiling).contains(&value) {
            result.push(value);
        }
    }
    result
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    #[cfg(test)]
    pub(super) fn inspect_mtu(
        &self,
        request: &TunnelConnectRequest,
        state: &mut RuntimeState,
        route: Option<RouteTransition>,
    ) {
        let Some(_) = request.mtu_policy else {
            return;
        };
        if route.is_some_and(|transition| {
            state
                .mtu_sampled_at_unix
                .is_some_and(|at| at < transition.detected_at_unix)
        }) {
            if let Some(mtu) = state.mtu.as_mut() {
                mtu.outcome = MtuProbeOutcome::Pending;
                mtu.suggested = None;
            }
            state.mtu_sampled_at_unix = None;
        }
        if state
            .mtu
            .is_some_and(|mtu| mtu.outcome != MtuProbeOutcome::Pending)
        {
            return;
        }
        if let Some(result) = self.measure_mtu(request, state) {
            self.commit_mtu(request, state, result);
        }
    }

    pub(super) fn measure_mtu(
        &self,
        request: &TunnelConnectRequest,
        state: &RuntimeState,
    ) -> Option<MtuStatus> {
        request.mtu_policy?;
        if state
            .mtu
            .is_some_and(|mtu| mtu.outcome != MtuProbeOutcome::Pending)
        {
            return None;
        }
        let minimum = if request.client_ipv6_address.is_some() {
            MIN_IPV6_TUNNEL_MTU
        } else {
            MIN_IPV4_TUNNEL_MTU
        };
        let mut result = state
            .mtu
            .unwrap_or_else(|| initial_mtu(request).expect("MTU policy exists"));
        let destination = request.dns_address.to_string();
        let ping = |size: u16| {
            self.runner
                .output_with_timeout(
                    "ping",
                    &[
                        "-n",
                        "-4",
                        "-c",
                        "1",
                        "-W",
                        "1",
                        "-w",
                        "1",
                        "-M",
                        "do",
                        "-I",
                        INTERFACE_NAME,
                        "-s",
                        &size.to_string(),
                        &destination,
                    ],
                    Duration::from_millis(1250),
                )
                .is_ok()
        };
        // No conclusion can be drawn from large packets if this server does not answer ICMP.
        if !ping(32) {
            result.outcome = MtuProbeOutcome::IcmpUnavailable;
        } else {
            let ceiling = result.configured.min(request.mtu);
            let deadline = std::time::Instant::now() + Duration::from_secs(8);
            let safe = probe_candidates(ceiling, minimum)
                .into_iter()
                .find(|candidate| {
                    std::time::Instant::now() < deadline
                        && ping(candidate - 28)
                        && ping(candidate - 28)
                });
            result.suggested = safe;
            result.outcome = if let Some(value) = safe {
                let _ = value;
                MtuProbeOutcome::Measured
            } else {
                MtuProbeOutcome::NoUsableMtu
            };
        }
        Some(result)
    }

    pub(super) fn commit_mtu(
        &self,
        request: &TunnelConnectRequest,
        state: &mut RuntimeState,
        mut result: MtuStatus,
    ) {
        if result.policy == MtuPolicy::Automatic
            && let Some(value) = result.suggested
            && value != result.configured
        {
            if self
                .runner
                .run(
                    "ip",
                    &[
                        "link",
                        "set",
                        "dev",
                        INTERFACE_NAME,
                        "mtu",
                        &value.to_string(),
                    ],
                    None,
                )
                .is_ok()
            {
                result.configured = value;
            } else {
                result.outcome = MtuProbeOutcome::ApplyFailed;
            }
        }
        let _ = request;
        state.mtu = Some(result);
        state.mtu_sampled_at_unix = Some(now_unix());
    }
}

#[cfg(test)]
mod tests;
