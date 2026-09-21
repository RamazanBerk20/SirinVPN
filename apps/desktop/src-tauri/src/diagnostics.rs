//! Explicit current-condition report. A timed-out native read cannot queue more diagnostic work.
use sirinvpn_core::SecretStore;
use sirinvpn_core::diagnostics::{self as core, CurrentConnection, check};
use sirinvpn_protocol::{API_VERSION, DiagnosticLevel, DiagnosticReport};
use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicBool, Ordering},
};
use tauri::Manager;

static RUNNING: LazyLock<Arc<tokio::sync::Mutex<()>>> =
    LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

pub(super) async fn run(
    app: tauri::AppHandle,
    server_id: String,
) -> Result<DiagnosticReport, String> {
    server_id
        .parse::<sirinvpn_protocol::ServerId>()
        .map_err(|_| "The local server ID is invalid.")?;
    let Ok(guard) = RUNNING.clone().try_lock_owned() else {
        return Ok(message(
            "local_diagnostics_busy",
            "Current diagnostics",
            "A previous native status check is still finishing. Cancel an active connection attempt if needed, then retry.",
        ));
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancellation = cancelled.clone();
    let worker = tauri::async_runtime::spawn(async move {
        let _guard = guard;
        collect(app, server_id, cancellation).await
    });
    match tokio::time::timeout(std::time::Duration::from_secs(16), worker).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Ok(message(
            "local_diagnostics_unavailable",
            "Current diagnostics",
            "The diagnostic worker could not finish. Refresh connection state and try again.",
        )),
        Err(_) => {
            cancelled.store(true, Ordering::Release);
            Ok(message(
                "local_diagnostics_timeout",
                "Current diagnostics",
                "The current checks did not finish within sixteen seconds. A connection, recovery or private server request may still be running. Wait briefly or cancel the connection attempt, then retry.",
            ))
        }
    }
}

fn message(code: &str, label: &str, text: &str) -> DiagnosticReport {
    DiagnosticReport {
        api_version: API_VERSION.into(),
        checks: vec![check(code, label, DiagnosticLevel::Warning, text)],
    }
}

async fn collect(
    app: tauri::AppHandle,
    server_id: String,
    cancelled: Arc<AtomicBool>,
) -> Result<DiagnosticReport, String> {
    let paths = app.state::<crate::AppState>().paths.clone();
    let (profile, identity, current) = tauri::async_runtime::spawn_blocking(move || {
        let profile = crate::find_profile(&paths, &server_id)
            .map_err(|_| "The selected server profile could not be opened.".to_owned())?;
        let current = crate::invoke_helper("status", None)
            .ok()
            .map(|status| status.diagnostic_connection(profile.id));
        let identity = paths.secret_store().get(&profile.identity_reference).ok();
        Ok::<_, String>((profile, identity, current))
    })
    .await
    .map_err(|_| "The local status worker was interrupted.")??;
    if cancelled.load(Ordering::Acquire) {
        return Ok(DiagnosticReport {
            api_version: API_VERSION.into(),
            checks: core::local_checks(current.as_ref()),
        });
    }
    let (mut report, dns) = tokio::join!(
        core::diagnose(&profile, identity.as_ref(), current.as_ref()),
        async {
            if current.as_ref().is_some_and(CurrentConnection::can_probe) {
                Some(
                    core::probe_private_dns(
                        profile.client_tunnel_address,
                        profile.server_tunnel_address,
                    )
                    .await,
                )
            } else {
                None
            }
        },
    );
    if let Some(dns) = dns {
        report.checks.insert(0, dns);
    }
    Ok(report)
}
