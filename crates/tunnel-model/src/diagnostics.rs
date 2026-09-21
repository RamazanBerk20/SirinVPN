use crate::{KillSwitchState, LocalTunnelStatus, TunnelRoutingMode};
use sirinvpn_core::diagnostics::{CurrentConnection, Protection};
use sirinvpn_protocol::ServerId;

impl LocalTunnelStatus {
    pub fn diagnostic_connection(&self, selected: ServerId) -> CurrentConnection {
        CurrentConnection {
            state: self.state.clone(),
            selected_server: self.server_id == Some(selected),
            another_server: self.server_id.is_some_and(|id| id != selected),
            recovering: self.recovery_in_progress,
            waiting_for_user: self.waiting_for_user,
            protection: match self.kill_switch_state {
                Some(KillSwitchState::Off) => Protection::Off,
                Some(KillSwitchState::Armed) => Protection::Armed,
                Some(KillSwitchState::Blocking) => Protection::Blocking,
                Some(KillSwitchState::Failed) => Protection::Failed,
                Some(KillSwitchState::Unknown) => Protection::Unknown,
                None if self.kill_switch_enabled => Protection::Unknown,
                None => Protection::Off,
            },
            transport: self.transport,
            split_routes: self.routing_mode == TunnelRoutingMode::SelectedRoutes,
            split_applications: self.routing_mode == TunnelRoutingMode::SelectedApplications,
            ipv6_tunneled: self.ipv6_tunneled,
            ipv6_blocked: self.ipv6_blocked,
            mtu: self.mtu,
            quality: self
                .transport_quality
                .as_ref()
                .and_then(|quality| quality.sample),
        }
    }
}
