//! Pure menu presentation. A selection is never evidence of an active tunnel.
use super::{Action, Destination};
use crate::native_text::{self, text, text_with};
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

/// What quitting the app leaves running; the menu label is derived from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quit {
    Plain,
    StatusUnknown,
    Paused,
    Reconnecting,
    Connected,
    Service,
    Blocking,
    KillSwitchUnknown,
}

impl Quit {
    /// An unknown exit outcome always asks before quitting.
    pub fn needs_consent(self) -> bool {
        matches!(self, Self::StatusUnknown | Self::KillSwitchUnknown)
    }

    pub fn label(self) -> String {
        text(match self {
            Self::Plain => "native.tray.quit.plain",
            Self::StatusUnknown => "native.tray.quit.statusUnknown",
            Self::Paused => "native.tray.quit.paused",
            Self::Reconnecting => "native.tray.quit.reconnecting",
            Self::Connected => "native.tray.quit.connected",
            Self::Service => "native.tray.quit.service",
            Self::Blocking => "native.tray.quit.blocking",
            Self::KillSwitchUnknown => "native.tray.quit.killSwitchUnknown",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KillSwitch {
    On,
    Blocking,
    Off,
    Failed,
    Unknown,
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
    pub quit: Quit,
    pub busy: bool,
    /// Text changes rebuild the menu even when the connection state is unchanged.
    pub text_revision: u64,
}

// Remove control characters; long names cannot make the collection menu unbounded.
fn short_name(name: &str) -> String {
    let clean: String = name.chars().filter(|c| !c.is_control()).take(48).collect();
    let suffix = if name.chars().count() > 48 { "…" } else { "" };
    format!("{clean}{suffix}")
}

/// Native menus interpret ampersands as mnemonics.
pub fn escape(label: &str) -> String {
    label.replace('&', "&&")
}

pub fn menu_name(name: &str) -> String {
    escape(&short_name(name))
}

pub fn project(
    local: Option<&LocalTunnelStatus>,
    profiles: Option<&[ServerProfile]>,
    selected: Option<ServerId>,
    busy: bool,
) -> Model {
    // Read before any text so a concurrent language change is never missed.
    let text_revision = native_text::revision();
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
    // Without a saved name, the text falls back to a message that needs none.
    let named = |id: ServerId, with_name: &str, without_name: &str| {
        list.iter()
            .find(|p| p.id == id)
            .map(|p| text_with(with_name, &[("name", short_name(&p.name).as_str())]))
            .unwrap_or_else(|| text(without_name))
    };
    let mut model = Model {
        status: text("native.tray.status.unknown"),
        protection: text("native.tray.killSwitch.unknown"),
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
        quit: Quit::StatusUnknown,
        busy,
        text_revision,
    };
    if let Some(s) = local {
        let verified = s.supervisor_status_known == Some(true);
        let kill_switch = match s.kill_switch_state {
            Some(KillSwitchState::Armed) if verified => KillSwitch::On,
            Some(KillSwitchState::Blocking) if verified => KillSwitch::Blocking,
            Some(KillSwitchState::Off) if s.server_id.is_none() || verified => KillSwitch::Off,
            Some(KillSwitchState::Failed) => KillSwitch::Failed,
            _ => KillSwitch::Unknown,
        };
        let ipv6_unverified = s.kill_switch_enabled
            && s.supervisor_status_known == Some(true)
            && matches!(
                s.kill_switch_state,
                Some(KillSwitchState::Armed | KillSwitchState::Blocking)
            )
            && s.routing_mode == sirinvpn_tunnel_model::TunnelRoutingMode::FullTunnel
            && !s.ipv6_blocked
            && !s.ipv6_tunneled;
        model.protection = text(match (kill_switch, ipv6_unverified) {
            (KillSwitch::On, false) => "native.tray.killSwitch.on",
            (KillSwitch::On, true) => "native.tray.killSwitch.onIpv6Unverified",
            (KillSwitch::Blocking, false) => "native.tray.killSwitch.blocking",
            (KillSwitch::Blocking, true) => "native.tray.killSwitch.blockingIpv6Unverified",
            (KillSwitch::Off, _) => "native.tray.killSwitch.off",
            (KillSwitch::Failed, _) => "native.tray.killSwitch.failed",
            (KillSwitch::Unknown, _) => "native.tray.killSwitch.unknown",
        });
        let attention =
            matches!(kill_switch, KillSwitch::Unknown | KillSwitch::Failed) || ipv6_unverified;
        if let Some(id) = active {
            model.needs_update = !s.connection_control_supported;
            model.legacy_session = s.policy.is_none();
            let connected = s.state == ConnectionState::Connected;
            model.status = if connected {
                named(
                    id,
                    "native.tray.status.connectedTo",
                    "native.tray.status.connected",
                )
            } else if s.waiting_for_user {
                named(
                    id,
                    "native.tray.status.pausedOn",
                    "native.tray.status.paused",
                )
            } else if s.recovery_in_progress {
                named(
                    id,
                    "native.tray.status.reconnectingTo",
                    "native.tray.status.reconnecting",
                )
            } else if s.state == ConnectionState::Connecting {
                named(
                    id,
                    "native.tray.status.connectingTo",
                    "native.tray.status.connecting",
                )
            } else {
                named(
                    id,
                    "native.tray.status.interruptedOn",
                    "native.tray.status.interrupted",
                )
            };
            model.icon = if connected {
                IconState::Connected
            } else {
                IconState::Progress
            };
            let (label, action) = if connected || model.legacy_session {
                ("native.tray.menu.disconnect", Action::Disconnect(id))
            } else if s.waiting_for_user {
                ("native.tray.menu.resume", Action::Reconnect(id))
            } else if s.recovery_in_progress {
                ("native.tray.menu.stopReconnecting", Action::Pause(id))
            } else {
                ("native.tray.menu.stopConnecting", Action::Pause(id))
            };
            if !model.needs_update {
                model.primary = Some((text(label), action));
            }
            model.extra_disconnect = !connected && !model.needs_update && !model.legacy_session;
            model.reconnect = connected && !model.needs_update && !model.legacy_session;
            model.can_switch = !model.needs_update && !model.legacy_session && profiles.is_some();
            model.quit = if s.waiting_for_user {
                Quit::Paused
            } else if s.recovery_in_progress {
                Quit::Reconnecting
            } else if connected {
                Quit::Connected
            } else {
                Quit::Service
            };
        } else if s.state == ConnectionState::Disconnected
            && !s.kill_switch_enabled
            && !s.auto_reconnect_enabled
            && !s.recovery_in_progress
            && s.kill_switch_state == Some(KillSwitchState::Off)
        {
            model.status = text("native.tray.status.disconnected");
            model.icon = IconState::Disconnected;
            model.quit = Quit::Plain;
            model.can_switch = profiles.is_some();
            model.primary = if let Some(id) = selected {
                Some((
                    named(
                        id,
                        "native.tray.menu.connectTo",
                        "native.tray.menu.connectServer",
                    ),
                    Action::Connect(id),
                ))
            } else if profiles.is_some() {
                Some((
                    text("native.tray.menu.addServer"),
                    Action::Navigate(Destination::AddServer, None),
                ))
            } else {
                None
            };
        }
        if s.kill_switch_state == Some(KillSwitchState::Blocking) && verified {
            model.icon = IconState::Blocked;
            model.quit = Quit::Blocking;
        } else if attention {
            model.icon = IconState::Attention;
            if active.is_some() && !verified {
                model.quit = Quit::KillSwitchUnknown;
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
        model.status = text_with(
            "native.tray.status.serversUnavailable",
            &[("status", model.status.as_str())],
        );
    }
    model
}
