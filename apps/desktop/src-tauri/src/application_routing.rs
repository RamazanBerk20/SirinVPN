//! Explicit launches as the ordinary desktop user. Arguments are never saved.
use sirinvpn_tunnel_model::{ApplicationLaunchRequest, ApplicationLaunchResult};
use std::{collections::BTreeMap, path::PathBuf};

#[tauri::command]
pub async fn launch_vpn_application(
    server_id: String,
    executable: String,
    arguments: Vec<String>,
) -> Result<ApplicationLaunchResult, String> {
    let server_id = server_id
        .parse()
        .map_err(|_| "The local server ID is invalid.")?;
    let environment: BTreeMap<_, _> = [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "LANG",
        "LC_ALL",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect();
    let launch = ApplicationLaunchRequest {
        server_id,
        executable: PathBuf::from(executable),
        arguments,
        environment,
    };
    launch
        .validate()
        .map_err(|_| "Choose an executable and at most 64 arguments. Each line is one argument.")?;
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(windows)]
        {
            use std::process::{Command, Stdio};
            let request = sirinvpn_windows_service::ApplicationRouteRequest { server_id: launch.server_id,
                executable: launch.executable.to_str().ok_or("Choose a native Windows executable.")?.to_owned() };
            let input = serde_json::to_vec(&request).map_err(|_| "The routing request could not be prepared.")?;
            let status = crate::helper::invoke_helper("route-application", Some(&input)).map_err(|error| error.to_string())?;
            if status.server_id != Some(launch.server_id) || status.application_routing_ready != Some(true) {
                return Err("The application routing guard is not ready. Refresh the connection.".into());
            }
            // No shell, elevation or service-side process creation. Every process
            // using this executable path under this account matches the WFP guard.
            let mut child = Command::new(&launch.executable).args(&launch.arguments)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                .spawn().map_err(|_| "The executable could not start. Its routing selection remains protected until Disconnect.".to_owned())?;
            let id = child.id();
            std::thread::spawn(move || { let _ = child.wait(); });
            Ok(ApplicationLaunchResult { process_id: Some(id), completed: false })
        }
        #[cfg(not(windows))]
        {
        let input = serde_json::to_vec(&launch).map_err(|_| "The launch request could not be prepared.")?;
        let bytes = crate::helper::invoke_helper_payload("launch-application", Some(&input))
            .map_err(|_| "Launch did not complete. Check VPS DNS and host forwarding rules, close existing instances, and choose a native executable. Flatpak, Snap and desktop-service launchers are unsupported.")?;
        serde_json::from_slice(&bytes).map_err(|_| "The launch result could not be verified.".into())
        }
    }).await.map_err(|_| "The application launcher did not respond.")?
}
