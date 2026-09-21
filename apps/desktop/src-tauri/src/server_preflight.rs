use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerPreflightInput {
    ssh: crate::ssh_login::SshLoginInput,
    transport: sirinvpn_installer::TransportSetup,
    #[serde(default)]
    endpoint_discovery_port: Option<u16>,
}

#[tauri::command]
pub(crate) async fn inspect_server_network(
    input: ServerPreflightInput,
) -> Result<sirinvpn_installer::NetworkPreflight, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let target = crate::ssh_login::resolve_target(input.ssh)?;
        sirinvpn_installer::Provisioner::inspect_server(
            &target,
            &input.transport,
            input.endpoint_discovery_port,
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "The VPS network inspection was interrupted.".to_owned())?
}
