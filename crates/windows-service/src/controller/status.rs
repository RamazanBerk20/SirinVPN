use super::*;
use crate::link::{Observation, tunnel_phase};
use sirinvpn_protocol::{MtuPolicy, MtuProbeOutcome, MtuStatus};
use sirinvpn_tunnel_model::{KillSwitchState, TunnelPhase, TunnelRoutingMode};

impl Controller {
    pub(super) fn publish(&mut self) {
        let mut status = idle();
        status.application_routing_supported = self.application_driver_ready();
        let mut owner = None;
        if let Some(saved) = &self.saved {
            owner = Some(saved.owner_sid.clone());
            let request = self
                .link
                .active()
                .map_or(&saved.request, |active| &active.request);
            let policy = request.connection_policy();
            let registered = crate::install::registered_auto_start();
            status.supervisor_status_known = Some(registered.is_ok());
            let held = saved.phase == SessionPhase::Held;
            let verified = (if held && !policy.kill_switch {
                self.firewall.absent().unwrap_or(false)
            } else {
                self.firewall.verified().unwrap_or(false)
            }) && (!policy.kill_switch
                || registered.as_ref().is_ok_and(|enabled| *enabled));
            let carrying = self.link.connected().is_some_and(|active| {
                active.stats.is_some() && !active.carrier.as_ref().is_some_and(Carrier::finished)
            });
            let phase = tunnel_phase(
                request.server_id,
                saved.phase,
                &self.link,
                Observation { verified, carrying },
            );
            let connected = matches!(phase, TunnelPhase::Connected { .. });
            status.set_phase(phase);
            status.policy = Some(policy);
            status.kill_switch_enabled = policy.kill_switch;
            status.kill_switch_state = Some(if !verified {
                KillSwitchState::Failed
            } else if !policy.kill_switch {
                KillSwitchState::Off
            } else if connected {
                KillSwitchState::Armed
            } else {
                KillSwitchState::Blocking
            });
            status.auto_reconnect_enabled = policy.automatic_reconnect;
            status.connect_on_startup = policy.connect_on_startup;
            status.startup_service_enabled = registered
                .ok()
                .map(|enabled| enabled && policy.connect_on_startup);
            status.transport_fallback_enabled = !request.reconnect_candidates.is_empty();
            status.transport = Some(request.transport);
            status.endpoint_checkpoint = saved.request.endpoint_checkpoint.clone();
            status.transport_quality = Some(self.quality.snapshot(connected));
            status.routing_mode = request.routing.mode;
            status.application_routing_ready =
                // Connected implies verified, not held and no enforcement failure.
                (request.routing.mode == TunnelRoutingMode::SelectedApplications)
                    .then_some(connected && status.application_routing_supported);
            status.allow_lan = request.routing.allow_lan;
            status.included_routes = Some(request.routing.included_routes.clone());
            status.ipv6_tunneled = connected
                && verified
                && request.client_ipv6_address.is_some()
                && request.routing.mode != TunnelRoutingMode::SelectedApplications;
            status.ipv6_blocked = verified
                && (request.client_ipv6_address.is_none()
                    || request.routing.mode == TunnelRoutingMode::SelectedApplications)
                && (!held || policy.kill_switch);
            status.mtu = Some(MtuStatus {
                policy: request.mtu_policy.unwrap_or(MtuPolicy::Automatic),
                configured: request.mtu,
                suggested: None,
                outcome: MtuProbeOutcome::Pending,
            });
            if let Some(active) = self.link.active() {
                status.mtu = Some(active.mtu);
                if let Some(stats) = active.stats {
                    status.rx_bytes = stats.rx_bytes;
                    status.tx_bytes = stats.tx_bytes;
                    status.byte_counters_available = Some(true);
                }
                status.tunnel_uptime_seconds = active
                    .connected_at
                    .map(|instant| instant.elapsed().as_secs());
                status.counter_epoch = Some(active.epoch.to_string());
            }
        }
        crate::published::publish(&self.published, owner, status);
    }
}

pub(super) fn idle() -> LocalTunnelStatus {
    let mut status = LocalTunnelStatus {
        application_routing_backend: Some(
            sirinvpn_tunnel_model::ApplicationRoutingBackend::WindowsBindRedirect,
        ),
        application_routing_supported: false,
        application_routing_ready: None,
        endpoint_updates_supported: true,
        endpoint_checkpoint: None,
        transport_quality_supported: true,
        transport_quality: None,
        mtu_detection_supported: true,
        https_transport_supported: true,
        mtu: None,
        connection_control_supported: true,
        recovery_in_progress: false,
        startup_service_enabled: Some(false),
        supervisor_status_known: Some(true),
        policy: None,
        independent_policy_supported: true,
        kill_switch_state: Some(KillSwitchState::Off),
        connect_on_startup: false,
        waiting_for_user: false,
        traffic_metrics_supported: true,
        byte_counters_available: Some(false),
        included_routes: None,
        state: ConnectionState::Disconnected,
        interface_name: "SirinVPN".into(),
        server_id: None,
        rx_bytes: 0,
        tx_bytes: 0,
        rx_packets: None,
        tx_packets: None,
        tunnel_uptime_seconds: None,
        counter_epoch: None,
        ipv6_blocked: false,
        ipv6_tunneled: false,
        transport: None,
        kill_switch_enabled: false,
        auto_reconnect_enabled: false,
        transport_fallback_enabled: false,
        routing_mode: TunnelRoutingMode::FullTunnel,
        allow_lan: false,
    };
    status.set_phase(TunnelPhase::Idle);
    status
}
