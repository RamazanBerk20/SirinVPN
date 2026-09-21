use super::*;

pub(super) fn invoke_helper(command: &str, input: Option<&[u8]>) -> Result<LocalTunnelStatus> {
    Ok(sirinvpn_windows_service::ipc::call_blocking(
        command, input,
    )?)
}
pub(super) fn invoke_helper_payload(command: &str, input: Option<&[u8]>) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&invoke_helper(command, input)?)?)
}
pub(super) fn resolve_server_binary(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path);
        }
        bail!("the selected Linux server binary is unavailable");
    }
    #[cfg(debug_assertions)]
    if let Some(path) = env::var_os("SIRINVPN_SERVER_BINARY") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }
    let executable = env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or_else(|| anyhow!("application directory unavailable"))?;
    for path in [
        directory.join("sirinvpn-server"),
        directory.join("resources/vps/sirinvpn-server"),
    ] {
        if path.is_file() {
            return Ok(path);
        }
    }
    bail!("the packaged Linux server binary is unavailable; repair the Windows installation")
}
