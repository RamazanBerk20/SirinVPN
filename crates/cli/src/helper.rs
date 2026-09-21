//! Helper.

use super::*;
use sirinvpn_tunnel_model::HELPER_PROTOCOL_VERSION;
use std::{
    io::Write,
    process::{Command, Stdio},
};

pub(super) fn invoke_helper(command_name: &str, input: Option<&[u8]>) -> Result<LocalTunnelStatus> {
    serde_json::from_slice(&invoke_helper_payload(command_name, input)?)
        .context("the privileged helper returned invalid status")
}

pub(super) fn invoke_helper_payload(command_name: &str, input: Option<&[u8]>) -> Result<Vec<u8>> {
    let installed_helper = PathBuf::from("/usr/lib/sirinvpn/sirinvpn-helper");
    let packaged_helper = resolve_packaged_helper_binary()?;
    let mut helper = if installed_helper.is_file() {
        installed_helper.clone()
    } else {
        packaged_helper.clone()
    };
    if command_name != "status" && !helper_protocol_is_current(&installed_helper) {
        install_helper(&packaged_helper)?;
        if !helper_protocol_is_current(&installed_helper) {
            bail!("the installed privileged helper is incompatible");
        }
        helper = installed_helper.clone();
    }
    let mut command = if nix::unistd::Uid::effective().is_root() || command_name == "status" {
        Command::new(&helper)
    } else {
        let mut command = Command::new("pkexec");
        command.arg(&helper);
        command
    };
    command
        .arg(command_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command
        .spawn()
        .context("could not start the privileged helper")?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("privileged helper input is unavailable"))?
            .write_all(input)?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!("the privileged networking operation was not authorized or failed safely");
    }
    Ok(output.stdout)
}

pub(super) fn helper_protocol_is_current(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    Command::new(path)
        .arg("version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).trim()
                    == HELPER_PROTOCOL_VERSION.to_string()
        })
}

pub(super) fn install_helper(source: &Path) -> Result<()> {
    let mut command = if nix::unistd::Uid::effective().is_root() {
        Command::new(source)
    } else {
        let mut command = Command::new("pkexec");
        command.arg(source);
        command
    };
    let status = command
        .arg("install-system")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        bail!("the privileged helper installation was not authorized");
    }
    Ok(())
}

pub(super) fn resolve_packaged_helper_binary() -> Result<PathBuf> {
    #[cfg(debug_assertions)]
    {
        if let Some(path) = env::var_os("SIRINVPN_HELPER_PATH") {
            let path = PathBuf::from(path);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    let current = env::current_exe()?;
    let sibling = current
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent directory"))?
        .join("sirinvpn-helper");
    if sibling.is_file() {
        return Ok(sibling);
    }
    let appimage_relative = current
        .parent()
        .and_then(|directory| directory.parent())
        .map(|directory| directory.join("lib/sirinvpn/sirinvpn-helper"));
    if let Some(path) = appimage_relative
        && path.is_file()
    {
        return Ok(path);
    }
    let installed = PathBuf::from("/usr/lib/sirinvpn/sirinvpn-helper");
    if installed.is_file() {
        return Ok(installed);
    }
    bail!("the packaged SirinVPN helper is unavailable")
}

pub(super) fn resolve_server_binary(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "the selected SirinVPN server binary is unavailable: {}",
            path.display()
        );
    }
    #[cfg(debug_assertions)]
    if let Some(path) = env::var_os("SIRINVPN_SERVER_BINARY") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }
    let current = env::current_exe()?;
    let sibling = current
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent directory"))?
        .join("sirinvpn-server");
    if sibling.is_file() {
        return Ok(sibling);
    }
    let packaged = current
        .parent()
        .and_then(|directory| directory.parent())
        .map(|directory| directory.join("lib/sirinvpn/sirinvpn-server"));
    if let Some(path) = packaged
        && path.is_file()
    {
        return Ok(path);
    }
    let installed = PathBuf::from("/usr/lib/sirinvpn/sirinvpn-server");
    if installed.is_file() {
        return Ok(installed);
    }
    bail!("the packaged SirinVPN server binary is unavailable")
}
