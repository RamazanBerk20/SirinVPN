use super::*;
use crate::connection_controller::Gate;
use sirinvpn_protocol::ConnectionState;
use crate::native_text::text_with;
use sirinvpn_protocol::ServerProfile;
use sirinvpn_tunnel_model::{ConnectionPolicy, KillSwitchState, LocalTunnelStatus};

fn id(n: u8) -> ServerId {
    format!("123e4567-e89b-42d3-a456-4266141740{n:02}")
        .parse()
        .unwrap()
}
fn profile(n: u8) -> ServerProfile {
    serde_json::from_value(serde_json::json!({
        "schema_version":1,"id":id(n),"name":format!("Server {n}"),"role":"owner",
        "endpoint":{"host":"example.invalid","wireguard_port":51820},
        "client_tunnel_address":"10.77.0.2","server_tunnel_address":"10.77.0.1",
        "server_wireguard_public_key":"fixture","identity_reference":"fixture",
        "pinned_server_certificate_pem":"fixture","client_management_certificate_pem":"fixture"
    }))
    .unwrap()
}
fn status() -> LocalTunnelStatus {
    serde_json::from_value(serde_json::json!({
        "state":"connected","interface_name":"sirinvpn0","server_id":id(1),
        "rx_bytes":0,"tx_bytes":0,"ipv6_blocked":true,"ipv6_tunneled":false,
        "kill_switch_enabled":true,"auto_reconnect_enabled":true,"transport_fallback_enabled":false,
        "routing_mode":"full_tunnel","allow_lan":false,"included_routes":[],
        "kill_switch_state":"armed","supervisor_status_known":true,"connection_control_supported":true,
        "policy":{"kill_switch":true,"automatic_reconnect":true,"connect_on_startup":false}
    })).unwrap()
}

#[test]
fn active_server_wins_over_gui_selection_and_only_connected_server_is_checked() {
    let local = status();
    let profiles = [profile(1), profile(2)];
    let m = model::project(Some(&local), Some(&profiles), Some(id(2)), Gate::Idle);
    assert_eq!(m.primary.as_ref().unwrap().1, Action::Disconnect(id(1)));
    assert_eq!(m.servers.iter().find(|s| s.connected).unwrap().id, id(1));
    assert_eq!(m.active, Some(id(1)));
    assert_eq!(m.selected, Some(id(2)));
    assert_eq!(m.protection, text("native.tray.killSwitch.on"));
    assert_eq!(
        m.status,
        text_with("native.tray.status.connectedTo", &[("name", "Server 1")])
    );
    assert_eq!(m.quit, model::Quit::Connected);
}

#[test]
fn saved_selection_does_not_claim_connection_and_absence_is_not_unknown() {
    let mut local = status();
    local.state = ConnectionState::Disconnected;
    local.server_id = None;
    local.kill_switch_state = Some(KillSwitchState::Off);
    local.kill_switch_enabled = false;
    local.auto_reconnect_enabled = false;
    local.policy = None;
    let profiles = [profile(1), profile(2)];
    let m = model::project(Some(&local), Some(&profiles), Some(id(2)), Gate::Idle);
    assert_eq!(m.primary.unwrap().1, Action::Connect(id(2)));
    assert!(m.servers.iter().all(|s| !s.connected));
    assert_eq!(m.quit, model::Quit::Plain);
    assert_eq!(m.status, text("native.tray.status.disconnected"));
    let unknown = model::project(None, Some(&profiles), Some(id(2)), Gate::Idle);
    assert!(unknown.primary.is_none());
    assert!(!unknown.can_switch);
    assert_eq!(unknown.icon, model::IconState::Attention);
    assert!(unknown.quit.needs_consent());
    let unloaded = model::project(None, None, None, Gate::Idle);
    assert_eq!(
        unloaded.status,
        text_with(
            "native.tray.status.serversUnavailable",
            &[("status", text("native.tray.status.unknown").as_str())]
        )
    );
    let empty = model::project(Some(&local), Some(&[]), None, Gate::Idle);
    assert_eq!(
        empty.primary.unwrap().1,
        Action::Navigate(Destination::AddServer, None)
    );
}

#[test]
fn pauses_keep_a_block_distinct_from_an_error_and_retries_have_explicit_actions() {
    let mut local = status();
    local.state = ConnectionState::Connecting;
    local.kill_switch_state = Some(KillSwitchState::Blocking);
    let m = model::project(Some(&local), None, None, Gate::Idle);
    assert_eq!(
        m.primary.unwrap().0,
        text("native.tray.menu.stopConnecting")
    );
    // No saved name: the status reads without one instead of inventing it.
    assert_eq!(m.status, text("native.tray.status.connecting"));
    local.recovery_in_progress = true;
    let m = model::project(Some(&local), None, None, Gate::Idle);
    assert_eq!(
        m.primary.unwrap().0,
        text("native.tray.menu.stopReconnecting")
    );
    assert_eq!(m.icon, model::IconState::Blocked);
    local.state = ConnectionState::Degraded;
    local.waiting_for_user = true;
    local.recovery_in_progress = false;
    let m = model::project(Some(&local), None, None, Gate::Idle);
    assert_eq!(m.primary.unwrap().1, Action::Reconnect(id(1)));
    assert!(m.extra_disconnect);
    assert_eq!(m.quit, model::Quit::Blocking);
    local.supervisor_status_known = Some(false);
    let m = model::project(Some(&local), None, None, Gate::Idle);
    assert_eq!(m.icon, model::IconState::Attention);
    assert_eq!(m.protection, text("native.tray.killSwitch.unknown"));
    assert_eq!(m.quit, model::Quit::KillSwitchUnknown);
}

#[test]
fn old_helpers_do_not_advertise_safe_handoffs_or_invent_ipv6_evidence() {
    let mut local = status();
    local.connection_control_supported = false;
    local.ipv6_blocked = false;
    let m = model::project(Some(&local), None, None, Gate::Idle);
    assert!(m.needs_update);
    assert!(!m.reconnect);
    assert!(!m.can_switch);
    assert_eq!(
        m.protection,
        text("native.tray.killSwitch.onIpv6Unverified")
    );
    assert_eq!(m.icon, model::IconState::Attention);
    local.policy = Some(ConnectionPolicy::default());
    local.kill_switch_state = None;
    assert_eq!(
        model::project(Some(&local), None, None, Gate::Idle).protection,
        text("native.tray.killSwitch.unknown")
    );
    local.connection_control_supported = true;
    local.policy = None;
    let legacy = model::project(Some(&local), None, None, Gate::Idle);
    assert!(!legacy.needs_update && legacy.legacy_session);
    assert!(!legacy.reconnect && !legacy.can_switch);
    assert_eq!(legacy.primary.unwrap().1, Action::Disconnect(id(1)));
}

#[test]
fn collection_is_bounded_and_favorites_follow_the_active_server() {
    let local = status();
    let mut profiles = (1..=20).map(profile).collect::<Vec<_>>();
    profiles[18].favorite = true;
    profiles[19].favorite = true;
    profiles[19].name = "İş & Ev\nVPN".into();
    let m = model::project(Some(&local), Some(&profiles), Some(id(2)), Gate::Idle);
    assert!(m.servers.len() <= 6);
    assert_eq!(m.servers[0].id, id(1));
    assert!(m.servers.iter().any(|s| s.id == id(19)));
    assert!(m.servers.iter().any(|s| s.name == "İş && EvVPN"));
    // Labels are escaped once, when the menu is built.
    profiles[0].name = "A & B".into();
    let m = model::project(Some(&local), Some(&profiles), None, Gate::Idle);
    assert_eq!(
        m.status,
        text_with("native.tray.status.connectedTo", &[("name", "A & B")])
    );
    assert_eq!(
        model::escape(&m.status),
        text_with("native.tray.status.connectedTo", &[("name", "A && B")])
    );
}

#[test]
fn contradictory_flags_read_as_unknown_and_offer_only_disconnect() {
    let mut local = status();
    // No phase produces Connected while waiting for the user.
    local.waiting_for_user = true;
    assert!(local.phase().is_none());
    let m = model::project(Some(&local), None, None, Gate::Idle);
    assert_eq!(m.status, text("native.tray.status.unknown"));
    assert_eq!(m.primary.unwrap().1, Action::Disconnect(id(1)));
    assert!(!m.reconnect && !m.can_switch && !m.extra_disconnect);
    assert!(m.quit.needs_consent());
    assert_eq!(m.icon, model::IconState::Attention);
    assert!(m.servers.iter().all(|s| !s.connected));
    assert!(notification_phase(Some(&local)) == Phase::Unavailable);
    assert!(notification_phase(None) == Phase::Unavailable);
    local.waiting_for_user = false;
    assert!(notification_phase(Some(&local)) == Phase::Connected);
    local.state = ConnectionState::Degraded;
    local.recovery_in_progress = true;
    assert!(notification_phase(Some(&local)) == Phase::Recovering);
}

#[test]
fn a_starting_connect_keeps_disconnect_available() {
    let mut local = status();
    local.state = ConnectionState::Connecting;
    let starting = model::project(Some(&local), None, None, Gate::Connecting);
    assert!(starting.busy && starting.cancellable);
    let protected = model::project(Some(&local), None, None, Gate::Protected);
    assert!(protected.busy && !protected.cancellable);
    let idle = model::project(Some(&local), None, None, Gate::Idle);
    assert!(!idle.busy && !idle.cancellable);
}
