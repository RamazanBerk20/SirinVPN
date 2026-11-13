//! Native connection controls; no WebView event is required to change networking.
mod actions;
mod icon;
pub(crate) mod model;
pub(crate) mod navigation;
#[cfg(test)]
mod tests;

use crate::{
    AppState,
    connection_notifications::{self, Phase},
    desktop_lifecycle::show_main,
    native_text::text,
};
use serde::Serialize;
use sirinvpn_protocol::ServerId;
use sirinvpn_tunnel_model::{LocalTunnelStatus, TunnelPhase};
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    time::Duration,
};
use tauri::{
    AppHandle, Manager,
    menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::TrayIconBuilder,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    Home,
    Servers,
    AddServer,
    Settings,
    Connection,
    Diagnostics,
    ComponentUpdate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Open,
    Connect(ServerId),
    Disconnect(ServerId),
    /// Cancel a connect that has no active session yet.
    Cancel,
    Reconnect(ServerId),
    Pause(ServerId),
    Switch(ServerId),
    Navigate(Destination, Option<ServerId>),
    Quit,
    DisconnectQuit(ServerId),
}

#[derive(Clone, Serialize)]
pub struct NavigationRequest {
    pub sequence: u64,
    pub destination: Destination,
    pub server_id: Option<ServerId>,
}

#[derive(Default)]
struct Inner {
    selected: Option<ServerId>,
    pending: Option<NavigationRequest>,
    sequence: u64,
    model: Option<model::Model>,
    actions: HashMap<String, Action>,
}
pub struct TrayState {
    inner: Mutex<Inner>,
    /// Drops repeated menu clicks while a tray action runs; not shown as busy.
    busy: AtomicBool,
    refresh: SyncSender<()>,
}

pub fn create(app: &tauri::App) -> tauri::Result<()> {
    let (sender, receiver) = mpsc::sync_channel(1);
    app.manage(TrayState {
        inner: Mutex::new(Inner::default()),
        busy: AtomicBool::new(false),
        refresh: sender,
    });
    let handle = app.handle().clone();
    std::thread::spawn(move || {
        loop {
            refresh(&handle);
            // Native changes arrive through `request_refresh`; the timer is a fallback.
            let fallback = if crate::local_status_stream::watching() { 15 } else { 4 };
            if receiver.recv_timeout(Duration::from_secs(fallback))
                == Err(mpsc::RecvTimeoutError::Disconnected)
            {
                break;
            }
        }
    });
    let initial = model::project(None, None, None, crate::connection_controller::Gate::Idle);
    let (menu, actions) = build_menu(app.handle(), &initial, 0)?;
    if let Ok(mut inner) = app.state::<TrayState>().inner.lock() {
        inner.actions = actions;
    }
    let mut tray = TrayIconBuilder::with_id("sirinvpn")
        .menu(&menu)
        .on_menu_event(|app, event| {
            let action = app
                .state::<TrayState>()
                .inner
                .lock()
                .ok()
                .and_then(|s| s.actions.get(event.id.as_ref()).cloned());
            if let Some(action) = action {
                actions::dispatch(app.clone(), action);
            }
        });
    if let Some(base) = app.default_window_icon() {
        tray = tray.icon(icon::render(base, model::IconState::Attention));
    }
    tray.build(app)?;
    Ok(())
}

pub fn request_refresh(app: &AppHandle) {
    if let Some(state) = app.try_state::<TrayState>() {
        let _ = state.refresh.try_send(());
    }
}

fn refresh(app: &AppHandle) {
    let local = crate::helper::invoke_helper("status", None).ok();
    let profiles = app.state::<AppState>().paths.profile_store().load().ok();
    let state = app.state::<TrayState>();
    let selected = state.inner.lock().ok().and_then(|s| s.selected);
    let model = model::project(
        local.as_ref(),
        profiles.as_deref(),
        selected,
        crate::connection_controller::gate(),
    );
    connection_notifications::observe(app, notification_phase(local.as_ref()));
    let sequence = {
        let Ok(mut inner) = state.inner.lock() else {
            return;
        };
        if inner.model.as_ref() == Some(&model) {
            return;
        }
        inner.sequence += 1;
        inner.sequence
    };
    let Some(tray) = app.tray_by_id("sirinvpn") else {
        return;
    };
    if let Ok((menu, actions)) = build_menu(app, &model, sequence) {
        // Never hold the mutex while awaiting GTK's main thread. Callbacks use it.
        if tray.set_menu(Some(menu)).is_ok()
            && let Ok(mut inner) = state.inner.lock()
        {
            inner.actions = actions;
            inner.model = Some(model.clone());
        }
    }
    if let Some(base) = app.default_window_icon() {
        let _ = tray.set_icon(Some(icon::render(base, model.icon)));
    }
}

/// An unreadable status and contradictory lifecycle flags are both "unknown".
fn notification_phase(local: Option<&LocalTunnelStatus>) -> Phase {
    match local.and_then(LocalTunnelStatus::phase) {
        Some(TunnelPhase::Idle) => Phase::Disconnected,
        Some(TunnelPhase::Connecting { .. }) => Phase::Connecting,
        Some(TunnelPhase::Connected { .. }) => Phase::Connected,
        Some(TunnelPhase::Paused { .. }) => Phase::Paused,
        Some(TunnelPhase::Recovering { .. } | TunnelPhase::Unhealthy { recovering: true, .. }) => {
            Phase::Recovering
        }
        Some(TunnelPhase::Unhealthy { recovering: false, .. }) | None => Phase::Unavailable,
    }
}

fn build_menu(
    app: &AppHandle,
    m: &model::Model,
    sequence: u64,
) -> tauri::Result<(Menu<tauri::Wry>, HashMap<String, Action>)> {
    let menu = Menu::new(app)?;
    let mut actions = HashMap::new();
    let mut item = |label: &str,
                    action: Option<Action>,
                    enabled: bool|
     -> tauri::Result<MenuItem<tauri::Wry>> {
        let id = format!("tray:{sequence}:{}", actions.len());
        let label = model::escape(label);
        if let Some(action) = action {
            actions.insert(id.clone(), action);
            MenuItem::with_id(app, id, label, enabled, None::<&str>)
        } else {
            MenuItem::new(app, label, false, None::<&str>)
        }
    };
    // Native menus dim disabled text. Status rows open their details on Home,
    // which keeps them readable without replacing the platform menu.
    menu.append(&item(
        &m.status,
        Some(Action::Navigate(Destination::Home, m.active)),
        true,
    )?)?;
    menu.append(&item(
        &m.protection,
        Some(Action::Navigate(Destination::Home, m.active)),
        true,
    )?)?;
    if m.legacy_session && !m.needs_update {
        menu.append(&item(
            &text("native.tray.status.legacySession"),
            None,
            false,
        )?)?;
    }
    if m.busy {
        menu.append(&item(&text("native.tray.status.busy"), None, false)?)?;
    }
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&item(
        &text("native.tray.menu.open"),
        Some(Action::Open),
        true,
    )?)?;
    // Disconnect stays available while a connect is starting: it cancels it.
    let can_disconnect = !m.busy || m.cancellable;
    if let Some((label, action)) = &m.primary {
        let enabled = if matches!(action, Action::Disconnect(_)) {
            can_disconnect
        } else {
            !m.busy
        };
        menu.append(&item(label, Some(action.clone()), enabled)?)?;
    }
    if m.cancellable && m.active.is_none() {
        menu.append(&item(
            &text("native.tray.menu.stopConnecting"),
            Some(Action::Cancel),
            true,
        )?)?;
    }
    if let Some(id) = m.active {
        if m.extra_disconnect {
            menu.append(&item(
                &text("native.tray.menu.disconnect"),
                Some(Action::Disconnect(id)),
                can_disconnect,
            )?)?;
        }
        if m.reconnect {
            menu.append(&item(
                &text("native.tray.menu.reconnect"),
                Some(Action::Reconnect(id)),
                !m.busy,
            )?)?;
        }
    }
    if m.needs_update {
        menu.append(&item(
            &text("native.tray.menu.updateComponent"),
            Some(Action::Navigate(Destination::ComponentUpdate, m.active)),
            true,
        )?)?;
    }
    let servers = Submenu::new(
        app,
        model::escape(&text(if m.active.is_some() {
            "native.tray.menu.switchServer"
        } else {
            "native.tray.menu.connectServer"
        })),
        true,
    )?;
    for server in &m.servers {
        // Check items need their own ID but all actions share the same generation.
        let control = item(
            &server.name,
            Some(Action::Switch(server.id)),
            m.can_switch && !m.busy && Some(server.id) != m.active,
        )?;
        let check = CheckMenuItem::with_id(
            app,
            control.id().clone(),
            &server.name,
            control.is_enabled()?,
            server.connected,
            None::<&str>,
        )?;
        servers.append(&check)?;
    }
    if !m.servers.is_empty() {
        servers.append(&PredefinedMenuItem::separator(app)?)?;
    }
    servers.append(&item(
        &text("native.tray.menu.manageServers"),
        Some(Action::Navigate(Destination::Servers, None)),
        true,
    )?)?;
    menu.append(&servers)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    let target = m.active.or(m.selected);
    if target.is_some() {
        menu.append(&item(
            &text("native.tray.menu.connectionSettings"),
            Some(Action::Navigate(Destination::Connection, target)),
            true,
        )?)?;
    }
    menu.append(&item(
        &text("native.tray.menu.settings"),
        Some(Action::Navigate(Destination::Settings, None)),
        true,
    )?)?;
    if target.is_some() {
        menu.append(&item(
            &text("native.tray.menu.diagnostics"),
            Some(Action::Navigate(Destination::Diagnostics, target)),
            true,
        )?)?;
    }
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&item(&m.quit.label(), Some(Action::Quit), !m.busy)?)?;
    if let Some(id) = m.active {
        menu.append(&item(
            &text("native.tray.menu.disconnectQuit"),
            Some(Action::DisconnectQuit(id)),
            can_disconnect && !m.needs_update,
        )?)?;
    }
    Ok((menu, actions))
}
