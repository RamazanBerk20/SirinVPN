//! Local status notifications contain no server addresses, names, or identity material.
use crate::{app_preferences::PreferencesState, native_text::text};
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Connecting,
    Paused,
    Connected,
    Disconnected,
    Recovering,
    Unavailable,
}

#[derive(Default)]
pub struct ConnectionNotifications(Mutex<Option<Phase>>);

/// The message key for a change, if it deserves a notification.
fn message(previous: Option<Phase>, next: Phase) -> Option<&'static str> {
    if previous.is_none() || previous == Some(next) {
        return None;
    }
    match next {
        Phase::Connecting | Phase::Paused => None,
        Phase::Connected => Some("native.notification.connected"),
        Phase::Disconnected => Some("native.notification.disconnected"),
        Phase::Recovering => Some("native.notification.reconnecting"),
        Phase::Unavailable => Some("native.notification.statusUnknown"),
    }
}

pub fn observe(app: &AppHandle, next: Phase) {
    let state = app.state::<ConnectionNotifications>();
    let Ok(mut previous) = state.0.lock() else {
        return;
    };
    let key = message(*previous, next);
    *previous = Some(next);
    drop(previous);
    if app.state::<PreferencesState>().current().notifications
        && let Some(key) = key
    {
        let body = text(key);
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = crate::app_notifications::show(handle, 7400, body).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_and_repeated_polling_are_silent() {
        for phase in [
            Phase::Connected,
            Phase::Disconnected,
            Phase::Recovering,
            Phase::Unavailable,
        ] {
            assert!(message(None, phase).is_none());
            assert!(message(Some(phase), phase).is_none());
        }
    }

    #[test]
    fn lost_status_never_claims_a_disconnect_or_protection() {
        assert_eq!(
            message(Some(Phase::Connected), Phase::Unavailable),
            Some("native.notification.statusUnknown")
        );
        assert_eq!(
            message(Some(Phase::Recovering), Phase::Connected),
            Some("native.notification.connected")
        );
        let unknown = text("native.notification.statusUnknown").to_lowercase();
        assert!(!unknown.contains("disconnected") && !unknown.contains("protect"));
    }
}
