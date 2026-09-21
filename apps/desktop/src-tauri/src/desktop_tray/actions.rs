use super::*;
use crate::{
    connection_controller, connection_policy, connection_preferences::ConnectionPreferenceStore,
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
                        .title("SirinVPN · Connection action failed")
                        .kind(MessageDialogKind::Error)
                        .blocking_show();
                }
            });
        }
    }
}

fn confirm(app: &AppHandle, message: &str, button: &str) -> bool {
    app.dialog()
        .message(message)
        .title("SirinVPN")
        .buttons(MessageDialogButtons::OkCancelCustom(
            button.into(),
            "Cancel".into(),
        ))
        .blocking_show()
}

fn run(app: &AppHandle, action: Action) -> Result<(), String> {
    let _operation = connection_controller::acquire()?;
    let status = crate::helper::invoke_helper("status", None).map_err(crate::safe_error);
    if action == Action::Quit {
        let state = app.state::<TrayState>();
        let expected = state
            .inner
            .lock()
            .ok()
            .and_then(|i| i.model.as_ref().map(|m| m.quit.clone()));
        let current = model::project(status.as_ref().ok(), None, None, false);
        // Re-read at click time. A changed/unknown exit outcome needs fresh consent.
        if (status.is_err()
            || expected.as_deref() != Some(current.quit.as_str())
            || current.quit.contains("unknown"))
            && !confirm(
                app,
                &format!(
                    "{}\n\nClosing the app does not stop the VPN service, recovery, or an active traffic block. Quit the interface?",
                    current.status
                ),
                "Quit app",
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
                return Err(
                    "A connection is already active. Use Switch server to review a handoff.".into(),
                );
            }
            if active == Some(id) {
                return Ok(());
            }
            if active.is_none() && !connection_controller::confirmed_disconnected(&current) {
                return Err("The local connection state could not be verified. Open Home before connecting.".into());
            }
            let preferences = app.state::<ConnectionPreferenceStore>().get(id)?;
            if let Some(active_id) = active {
                connection_controller::require_finished_rotation(&paths, active_id)?;
                if !current.connection_control_supported || current.policy.is_none() {
                    return Err("Update the local VPN component before switching servers.".into());
                }
                let protection = if current.kill_switch_enabled {
                    "The kill switch remains in place during the change."
                } else {
                    "The kill switch is off; traffic is not blocked during the change."
                };
                let message = format!(
                    "Switch this device's connection to {}?\n\n{protection}\n\nCurrent reconnect, startup and routing choices carry across. This server's saved protection and routing preferences apply when you start a fresh connection. Other members stay connected.",
                    profile.name
                );
                if !confirm(app, &message, "Switch server") {
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
                return Err("The helper did not acknowledge the selected server. Check Home for its current state.".into());
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
                return Err("The active connection changed. Reopen the tray menu.".into());
            }
            let protection = if current.kill_switch_enabled {
                "The kill switch stays active. Internet access may remain blocked until you resume or explicitly Disconnect."
            } else {
                "The kill switch is off. Traffic will not be blocked by SirinVPN."
            };
            if !confirm(
                app,
                &format!(
                    "Stop this connection's attempts and wait for manual action?\n\n{protection}\n\nThe saved startup preference is unchanged."
                ),
                "Stop attempts",
            ) {
                return Ok(());
            }
            let paused = connection_controller::session_action("pause-session", id)?;
            if !paused.waiting_for_user || paused.server_id != Some(id) {
                return Err(
                    "The helper did not confirm that recovery paused. Check the current status."
                        .into(),
                );
            }
        }
        Action::Disconnect(id) | Action::DisconnectQuit(id) => {
            if current.server_id != Some(id) {
                return Err("The active connection changed. Reopen the tray menu.".into());
            }
            let quitting = matches!(action, Action::DisconnectQuit(_));
            let button = if quitting {
                "Disconnect and quit"
            } else {
                "Disconnect"
            };
            if !confirm(
                app,
                "Disconnect this device from its active VPN server?\n\nThis releases the traffic block, stops connection attempts, and pauses startup connection until you Connect again. Other devices stay connected.",
                button,
            ) {
                return Ok(());
            }
            let result = connection_controller::session_action("disconnect-session", id)?;
            if !connection_controller::confirmed_disconnected(&result) {
                return Err("Disconnection was not confirmed. The app will stay open; check the tunnel and traffic block.".into());
            }
            if quitting {
                let verified =
                    crate::helper::invoke_helper("status", None).map_err(crate::safe_error)?;
                if !connection_controller::confirmed_disconnected(&verified) {
                    return Err(
                        "The final status did not confirm disconnection. The app will stay open."
                            .into(),
                    );
                }
                app.exit(0);
            }
        }
        _ => {}
    }
    Ok(())
}
