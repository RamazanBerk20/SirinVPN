//! The desktop remains an ordinary user process. The installed LocalSystem
//! service authenticates the caller and owns the entire tunnel lifecycle.
use super::*;

pub(super) fn invoke_helper(command: &str, input: Option<&[u8]>) -> Result<LocalTunnelStatus> {
    Ok(sirinvpn_windows_service::ipc::call_blocking(
        command, input,
    )?)
}

/// The server payload is a Linux ELF file shipped as a resource for VPS setup.
/// It is read for SSH upload; it is never executed by the Windows desktop.
pub(super) fn resolve_binary(
    environment: &str,
    _installed: &str,
    sibling_name: &str,
) -> Result<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(path) = env::var_os(environment) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = environment;
    let executable = env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or_else(|| anyhow!("application directory is unavailable"))?;
    for path in [
        directory.join(sibling_name),
        directory.join("resources").join(sibling_name),
        directory.join("resources/vps").join(sibling_name),
    ] {
        if path.is_file() {
            return Ok(path);
        }
    }
    bail!("The packaged SirinVPN component is unavailable. Repair the Windows installation.")
}
