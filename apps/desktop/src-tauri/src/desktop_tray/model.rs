//! Pure menu presentation. A selection is never evidence of an active tunnel.
use super::{Action, Destination};
use sirinvpn_protocol::{ConnectionState, ServerId, ServerProfile};
use sirinvpn_tunnel_model::{KillSwitchState, LocalTunnelStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IconState {
    Disconnected,
    Connected,
    Progress,
    Blocked,
    Attention,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerItem {
    pub id: ServerId,
    pub name: String,
    pub connected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub status: String,
    pub protection: String,
    pub icon: IconState,
    pub primary: Option<(String, Action)>,
    pub reconnect: bool,
    pub extra_disconnect: bool,
    pub active: Option<ServerId>,
    pub selected: Option<ServerId>,
    pub servers: Vec<ServerItem>,
    pub can_switch: bool,
    pub needs_update: bool,
    pub legacy_session: bool,
    pub quit: String,
    pub busy: bool,
}

// Native menus interpret ampersands as mnemonics. Escape names and remove control
// characters; long labels cannot make the collection menu unbounded.
pub fn menu_name(name: &str) -> String {
    let clean: String = name.chars().filter(|c| !c.is_control()).take(48).collect();
    let suffix = if name.chars().count() > 48 { "…" } else { "" };
    format!("{}{suffix}", clean.replace('&', "&&"))
}

pub fn project(
    local: Option<&LocalTunnelStatus>,
    profiles: Option<&[ServerProfile]>,
    selected: Option<ServerId>,
    busy: bool,
) -> Model {
    let active = local.and_then(|s| s.server_id);
    let list = profiles.unwrap_or_default();
    let selected = selected
        .filter(|id| list.iter().any(|p| p.id == *id))
        .or_else(|| {
            list.iter()
                .find(|p| p.favorite)
                .or_else(|| list.first())
                .map(|p| p.id)
        });
    let name = |id| {
        list.iter()
            .find(|p| p.id == id)
            .map(|p| menu_name(&p.name))
            .unwrap_or_else(|| "current server".into())
    };
    let mut model = Model {
        status: "Connection status unavailable".into(),
        protection: "Kill switch: Status unknown".into(),
        icon: IconState::Attention,
        primary: None,
        reconnect: false,
        extra_disconnect: false,
        active,
        selected,
        servers: vec![],
        can_switch: false,
        needs_update: false,
        legacy_session: false,
        quit: "Quit app (VPN status unknown)…".into(),
        busy,
    };
    if let Some(s) = local {
        let verified = s.supervisor_status_known == Some(true);
        model.protection = match s.kill_switch_state {
            Some(KillSwitchState::Armed) if verified => "Kill switch: Armed",
            Some(KillSwitchState::Blocking) if verified => "Kill switch: Blocking traffic",
            Some(KillSwitchState::Off) if s.server_id.is_none() || verified => "Kill switch: Off",
            Some(KillSwitchState::Failed) => "Kill switch: Enforcement failed",
            _ => "Kill switch: Status unknown",
        }
        .into();
        if s.kill_switch_enabled
            && s.supervisor_status_known == Some(true)
            && matches!(
                s.kill_switch_state,
                Some(KillSwitchState::Armed | KillSwitchState::Blocking)
            )
            && s.routing_mode == sirinvpn_tunnel_model::TunnelRoutingMode::FullTunnel
            && !s.ipv6_blocked
            && !s.ipv6_tunneled
        {
            model
                .protection
                .push_str(" · IPv6 verification unavailable");
        }
        if let Some(id) = active {
            model.needs_update = !s.connection_control_supported;
            model.legacy_session = s.policy.is_none();
            let connected = s.state == ConnectionState::Connected;
            model.status = if connected {
                format!("Connected to {}", name(id))
            } else if s.waiting_for_user {
                format!("Connection paused · {}", name(id))
            } else if s.recovery_in_progress {
                format!("Reconnecting to {}", name(id))
            } else if s.state == ConnectionState::Connecting {
                format!("Connecting to {}", name(id))
            } else {
                format!("Connection interrupted · {}", name(id))
            };
            model.icon = if connected {
                IconState::Connected
            } else {
                IconState::Progress
            };
            let (label, action) = if connected || model.legacy_session {
                ("Disconnect…", Action::Disconnect(id))
            } else if s.waiting_for_user {
                ("Resume connection", Action::Reconnect(id))
            } else if s.recovery_in_progress {
                ("Stop reconnecting…", Action::Pause(id))
            } else {
                ("Cancel connection…", Action::Pause(id))
            };
            if !model.needs_update {
                model.primary = Some((label.into(), action));
            }
            model.extra_disconnect = !connected && !model.needs_update && !model.legacy_session;
            model.reconnect = connected && !model.needs_update && !model.legacy_session;
            model.can_switch = !model.needs_update && !model.legacy_session && profiles.is_some();
            model.quit = if s.waiting_for_user {
                "Quit app (connection stays paused)"
            } else if s.recovery_in_progress {
                "Quit app (recovery keeps running)"
            } else if connected {
                "Quit app (VPN keeps running)"
            } else {
                "Quit app (connection service keeps running)"
            }
            .into();
        } else if s.state == ConnectionState::Disconnected
            && !s.kill_switch_enabled
            && !s.auto_reconnect_enabled
            && !s.recovery_in_progress
            && s.kill_switch_state == Some(KillSwitchState::Off)
        {
            model.status = "Disconnected".into();
            model.icon = IconState::Disconnected;
            model.quit = "Quit app".into();
            model.can_switch = profiles.is_some();
            model.primary = if let Some(id) = selected {
                Some((format!("Connect to {}", name(id)), Action::Connect(id)))
            } else if profiles.is_some() {
                Some((
                    "Add server…".into(),
                    Action::Navigate(Destination::AddServer, None),
                ))
            } else {
                None
            };
        }
        if s.kill_switch_state == Some(KillSwitchState::Blocking) && verified {
            model.icon = IconState::Blocked;
            model.quit = "Quit app (traffic block stays active)".into();
        } else if model.protection.contains("unknown")
            || model.protection.contains("failed")
            || model.protection.contains("unavailable")
        {
            model.icon = IconState::Attention;
            if active.is_some() && !verified {
                model.quit = "Quit app (protection status unknown)…".into();
            }
        }
    }
    let mut ordered = list
        .iter()
        .filter(|p| list.len() <= 6 || p.favorite || Some(p.id) == active || Some(p.id) == selected)
        .collect::<Vec<_>>();
    ordered.sort_by_key(|p| {
        (
            Some(p.id) != active,
            Some(p.id) != selected,
            !p.favorite,
            p.name.to_lowercase(),
        )
    });
    model.servers = ordered
        .into_iter()
        .take(6)
        .map(|p| ServerItem {
            id: p.id,
            name: menu_name(&p.name),
            connected: local.is_some_and(|s| {
                s.state == ConnectionState::Connected && s.server_id == Some(p.id)
            }),
        })
        .collect();
    if profiles.is_none() && active.is_none() {
        model.status.push_str(" · Saved servers unavailable");
    }
    model
}
