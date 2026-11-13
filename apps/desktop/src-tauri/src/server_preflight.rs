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
) -> Result<sirinvpn_installer::NetworkPreflight, crate::CommandError> {
    tauri::async_runtime::spawn_blocking(move || {
        let target = crate::ssh_login::resolve_target(input.ssh)?;
        sirinvpn_installer::Provisioner::inspect_server(
            &target,
            &input.transport,
            input.endpoint_discovery_port,
        )
        .map_err(crate::command_error)
    })
    .await
    .map_err(|_| crate::CommandError::from("The server network check was interrupted. Try again."))?
}
