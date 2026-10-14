use super::*;
use crate::{
    connection_controller, connection_policy,
    connection_preferences::ConnectionPreferenceStore,
    native_text::{text, text_with},
};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

pub(super) fn dispatch(app: AppHandle, action: Action) {
    match action {
        Action::Open => show_main(&app),
        Action::Navigate(destination, server) => navigation::open(&app, destination, server),
        action => {
            if app.state::<TrayState>().busy.swap(true, Ordering::AcqRel) {
                return;
            }
            request_refresh(&app);
            tauri::async_runtime::spawn_blocking(move || {
                let result = run(&app, action);
                app.state::<TrayState>()
                    .busy
                    .store(false, Ordering::Release);
                request_refresh(&app);
                if let Err(error) = result {
                    show_main(&app);
                    app.dialog()
                        .message(error)
                        .title(text("native.tray.error.title"))
                        .kind(MessageDialogKind::Error)
                        .blocking_show();
                }
            });
        }
    }
}

fn confirm(app: &AppHandle, title: &str, message: &str, button: &str) -> bool {
    app.dialog()
        .message(message)
        .title(title)
        .buttons(MessageDialogButtons::OkCancelCustom(
            button.into(),
            text("native.tray.confirm.cancel"),
        ))
        .blocking_show()
}

fn run(app: &AppHandle, action: Action) -> Result<(), String> {
    // Connect and Switch stay cancellable from the window's Disconnect.
    let _operation = if matches!(action, Action::Connect(_) | Action::Switch(_)) {
        connection_controller::acquire_connection()
    } else {
        connection_controller::acquire()
    }?;
    let status = crate::helper::invoke_helper("status", None).map_err(crate::safe_error);
    if action == Action::Quit {
        let state = app.state::<TrayState>();
        let expected = state
            .inner
            .lock()
            .ok()
            .and_then(|i| i.model.as_ref().map(|m| m.quit));
        // Saved servers aren't loaded here; an empty list keeps the status line to the state.
        let current = model::project(status.as_ref().ok(), Some(&[]), None, false);
        // Re-read at click time. A changed/unknown exit outcome needs fresh consent.
        if (status.is_err() || expected != Some(current.quit) || current.quit.needs_consent())
            && !confirm(
                app,
                &text("native.tray.confirm.quit.title"),
                &text_with(
                    "native.tray.confirm.quit.message",
                    &[("status", current.status.as_str())],
                ),
                &text("native.tray.confirm.quit.confirm"),
            )
        {
            return Ok(());
        }
        app.exit(0);
        return Ok(());
    }
    let current = status?;
    let paths = app.state::<AppState>().paths.clone();
    match action {
        Action::Connect(id) | Action::Switch(id) => {
            let profile = crate::identity::find_profile(&paths, &id.to_string())?;
            let active = current.server_id;
            if matches!(action, Action::Connect(_)) && active.is_some() {
                return Err(text("native.tray.error.alreadyConnected"));
            }
            if active == Some(id) {
                return Ok(());
            }
            if active.is_none() && !connection_controller::confirmed_disconnected(&current) {
                return Err(text("native.tray.error.statusUnverified"));
            }
            let preferences = app.state::<ConnectionPreferenceStore>().get(id)?;
            if let Some(active_id) = active {
                connection_controller::require_finished_rotation(&paths, active_id)?;
                if !current.connection_control_supported || current.policy.is_none() {
                    return Err(text("native.tray.error.updateToSwitch"));
                }
                let message = text(if current.kill_switch_enabled {
                    "native.tray.confirm.switch.messageKillSwitchOn"
                } else {
                    "native.tray.confirm.switch.messageKillSwitchOff"
                });
                if !confirm(
                    app,
                    &text_with(
                        "native.tray.confirm.switch.title",
                        &[("name", profile.name.as_str())],
                    ),
                    &message,
                    &text("native.tray.confirm.switch.confirm"),
                ) {
                    return Ok(());
                }
            }
            let next = connection_policy::connect_native(
                paths,
                &id.to_string(),
                preferences,
                active.map(|_| &current),
                true,
            )?;
            if next.server_id != Some(id) {
                return Err(text("native.tray.error.serverUnconfirmed"));
            }
            // Keep selection useful when the window is next opened, without opening it.
            navigation::queue(app, Destination::Home, Some(id), false);
        }
        Action::Reconnect(id) => {
            connection_controller::require_finished_rotation(&paths, id)?;
            connection_controller::session_action("reconnect-session", id)?;
        }
        Action::Pause(id) => {
            if current.server_id != Some(id) {
                return Err(text("native.tray.error.connectionChanged"));
            }
            let message = text(if current.kill_switch_enabled {
                "native.tray.confirm.stop.messageKillSwitchOn"
            } else {
                "native.tray.confirm.stop.messageKillSwitchOff"
            });
            if !confirm(
                app,
                &text("native.tray.confirm.stop.title"),
                &message,
                &text("native.tray.confirm.stop.confirm"),
            ) {
                return Ok(());
            }
            let paused = connection_controller::session_action("pause-session", id)?;
            if !paused.waiting_for_user || paused.server_id != Some(id) {
                return Err(text("native.tray.error.stopUnconfirmed"));
            }
        }
        Action::Disconnect(id) | Action::DisconnectQuit(id) => {
            if current.server_id != Some(id) {
                return Err(text("native.tray.error.connectionChanged"));
            }
            let quitting = matches!(action, Action::DisconnectQuit(_));
            let (title, button) = if quitting {
                (
                    "native.tray.confirm.disconnectQuit.title",
                    "native.tray.confirm.disconnectQuit.confirm",
                )
            } else {
                (
                    "native.tray.confirm.disconnect.title",
                    "native.tray.confirm.disconnect.confirm",
                )
            };
            if !confirm(
                app,
                &text(title),
                &text("native.tray.confirm.disconnect.message"),
                &text(button),
            ) {
                return Ok(());
            }
            let result = connection_controller::session_action("disconnect-session", id)?;
            if !connection_controller::confirmed_disconnected(&result) {
                return Err(text("native.tray.error.disconnectUnconfirmed"));
            }
            if quitting {
                let verified =
                    crate::helper::invoke_helper("status", None).map_err(crate::safe_error)?;
                if !connection_controller::confirmed_disconnected(&verified) {
                    return Err(text("native.tray.error.quitUnconfirmed"));
                }
                app.exit(0);
            }
        }
        _ => {}
    }
    Ok(())
}
