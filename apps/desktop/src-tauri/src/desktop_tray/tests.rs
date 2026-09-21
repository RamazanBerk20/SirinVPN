use super::*;
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
    let m = model::project(Some(&local), Some(&profiles), Some(id(2)), false);
    assert_eq!(m.primary.as_ref().unwrap().1, Action::Disconnect(id(1)));
    assert_eq!(m.servers.iter().find(|s| s.connected).unwrap().id, id(1));
    assert_eq!(m.active, Some(id(1)));
    assert_eq!(m.selected, Some(id(2)));
    assert_eq!(m.protection, "Kill switch: Armed");
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
    let m = model::project(Some(&local), Some(&profiles), Some(id(2)), false);
    assert_eq!(m.primary.unwrap().1, Action::Connect(id(2)));
    assert!(m.servers.iter().all(|s| !s.connected));
    assert_eq!(m.quit, "Quit app");
    let unknown = model::project(None, Some(&profiles), Some(id(2)), false);
    assert!(unknown.primary.is_none());
    assert!(!unknown.can_switch);
    assert_eq!(unknown.icon, model::IconState::Attention);
    let empty = model::project(Some(&local), Some(&[]), None, false);
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
    let m = model::project(Some(&local), None, None, false);
    assert_eq!(m.primary.unwrap().0, "Cancel connection…");
    local.recovery_in_progress = true;
    let m = model::project(Some(&local), None, None, false);
    assert_eq!(m.primary.unwrap().0, "Stop reconnecting…");
    assert_eq!(m.icon, model::IconState::Blocked);
    local.waiting_for_user = true;
    local.recovery_in_progress = false;
    let m = model::project(Some(&local), None, None, false);
    assert_eq!(m.primary.unwrap().1, Action::Reconnect(id(1)));
    assert!(m.extra_disconnect);
    assert!(m.quit.contains("block stays active"));
    local.supervisor_status_known = Some(false);
    let m = model::project(Some(&local), None, None, false);
    assert_eq!(m.icon, model::IconState::Attention);
    assert!(m.protection.contains("unknown"));
}

#[test]
fn old_helpers_do_not_advertise_safe_handoffs_or_invent_ipv6_evidence() {
    let mut local = status();
    local.connection_control_supported = false;
    local.ipv6_blocked = false;
    let m = model::project(Some(&local), None, None, false);
    assert!(m.needs_update);
    assert!(!m.reconnect);
    assert!(!m.can_switch);
    assert!(m.protection.contains("IPv6 verification unavailable"));
    local.policy = Some(ConnectionPolicy::default());
    local.kill_switch_state = None;
    assert!(
        model::project(Some(&local), None, None, false)
            .protection
            .contains("unknown")
    );
    local.connection_control_supported = true;
    local.policy = None;
    let legacy = model::project(Some(&local), None, None, false);
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
    let m = model::project(Some(&local), Some(&profiles), Some(id(2)), false);
    assert!(m.servers.len() <= 6);
    assert_eq!(m.servers[0].id, id(1));
    assert!(m.servers.iter().any(|s| s.id == id(19)));
    assert!(m.servers.iter().any(|s| s.name == "İş && EvVPN"));
}
