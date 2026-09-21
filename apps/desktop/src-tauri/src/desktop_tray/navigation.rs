use super::*;
use tauri::Emitter;

pub(super) fn queue(
    app: &AppHandle,
    destination: Destination,
    server_id: Option<ServerId>,
    show: bool,
) {
    if let Ok(mut inner) = app.state::<TrayState>().inner.lock() {
        inner.sequence += 1;
        if server_id.is_some() {
            inner.selected = server_id;
        }
        inner.pending = Some(NavigationRequest {
            sequence: inner.sequence,
            destination,
            server_id,
        });
    }
    // The pending request is consumed after the WebView subscribes, including
    // reload/startup. An event alone could be lost while it is still loading.
    let _ = app.emit("desktop-navigation", ());
    if show {
        show_main(app);
    }
    request_refresh(app);
}

pub(super) fn open(app: &AppHandle, destination: Destination, server_id: Option<ServerId>) {
    queue(app, destination, server_id, true);
}

#[tauri::command]
pub fn desktop_navigation(app: AppHandle) -> Option<NavigationRequest> {
    app.try_state::<TrayState>()?
        .inner
        .lock()
        .ok()?
        .pending
        .clone()
}

#[tauri::command]
pub fn desktop_navigation_ack(app: AppHandle, sequence: u64) {
    if let Some(state) = app.try_state::<TrayState>()
        && let Ok(mut inner) = state.inner.lock()
        && inner
            .pending
            .as_ref()
            .is_some_and(|request| request.sequence == sequence)
    {
        inner.pending = None;
    }
}

#[tauri::command]
pub fn desktop_selection(app: AppHandle, server_id: Option<String>) -> Result<(), String> {
    let Some(state) = app.try_state::<TrayState>() else {
        return Ok(());
    };
    let id = if let Some(id) = server_id {
        Some(crate::identity::find_profile(&app.state::<AppState>().paths, &id)?.id)
    } else {
        None
    };
    let mut inner = state
        .inner
        .lock()
        .map_err(|_| "The tray selection is unavailable.")?;
    inner.selected = id;
    drop(inner);
    request_refresh(&app);
    Ok(())
}
