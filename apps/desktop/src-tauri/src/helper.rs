//! Helper.

use super::*;
use sirinvpn_tunnel_model::HELPER_PROTOCOL_VERSION;
use std::fs;
use std::{
    io::Write,
    process::{Command, Stdio},
};

const INSTALLED_HELPER: &str = "/usr/lib/sirinvpn/sirinvpn-helper";

pub(super) fn packaged_helper_update_required() -> Result<bool> {
    let packaged = resolve_packaged_helper_binary()?;
    if !helper_protocol_is_current(&packaged) {
        bail!(
            "The bundled VPN component does not match this app. Reopen the current SirinVPN package."
        );
    }
    Ok(!helper_protocol_is_current(Path::new(INSTALLED_HELPER))
        || !helper_artifact_matches(Path::new(INSTALLED_HELPER), &packaged))
}

/// A connection must refresh an old component before reading its capabilities.
/// Read-only status polling never requests installation or administrator access.
pub(super) fn prepare_helper_for_connection(interactive: bool) -> Result<()> {
    if packaged_helper_update_required()? {
        if !interactive {
            bail!("Connect once from Home to finish local VPN setup.");
        }
        let current = invoke_helper("status", None)?;
        if !crate::connection_controller::confirmed_disconnected(&current) {
            bail!(
                "Disconnect the VPN and release its traffic protection before updating the local VPN component."
            );
        }
        install_verified_helper(
            Path::new(INSTALLED_HELPER),
            &resolve_packaged_helper_binary()?,
            install_helper,
        )?;
    }
    ensure_vpn_authorization("connect-managed", interactive)
}

fn install_verified_helper(
    installed: &Path,
    packaged: &Path,
    install: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    if !helper_protocol_is_current(packaged) {
        bail!("The bundled VPN component does not match this app.");
    }
    install(packaged)?;
    if !helper_protocol_is_current(installed) || !helper_artifact_matches(installed, packaged) {
        bail!(
            "The local VPN component could not be verified after installation. Reopen the current SirinVPN package and try again."
        );
    }
    Ok(())
}

pub(super) fn invoke_helper(command_name: &str, input: Option<&[u8]>) -> Result<LocalTunnelStatus> {
    invoke_helper_with_interaction(command_name, input, true)
}

pub(super) fn invoke_helper_with_interaction(
    command_name: &str,
    input: Option<&[u8]>,
    interactive: bool,
) -> Result<LocalTunnelStatus> {
    let output = invoke_helper_payload_with_interaction(command_name, input, interactive)?;
    let mut status: LocalTunnelStatus = serde_json::from_slice(&output)?;
    if command_name == "status" && status.startup_service_enabled.is_none() {
        status.startup_service_enabled =
            sirinvpn_linux_helper::startup_service_enabled(&sirinvpn_linux_helper::SystemRunner);
    }
    Ok(status)
}

pub(super) fn invoke_helper_payload(command_name: &str, input: Option<&[u8]>) -> Result<Vec<u8>> {
    invoke_helper_payload_with_interaction(command_name, input, true)
}

fn invoke_helper_payload_with_interaction(
    command_name: &str,
    input: Option<&[u8]>,
    interactive: bool,
) -> Result<Vec<u8>> {
    let installed_helper = PathBuf::from(INSTALLED_HELPER);
    let packaged_helper = resolve_packaged_helper_binary()?;
    let mut helper = if installed_helper.is_file() {
        installed_helper.clone()
    } else {
        packaged_helper.clone()
    };
    let starts_connection = matches!(
        command_name,
        "connect"
            | "connect-managed"
            | "resume"
            | "reconnect-session"
            | "switch-session"
            | "apply-endpoint-checkpoint"
            | "publish-endpoint-checkpoint"
            | "launch-application"
    );
    if command_name != "status"
        && (!helper_protocol_is_current(&installed_helper)
            || starts_connection && !helper_artifact_matches(&installed_helper, &packaged_helper))
    {
        if !interactive {
            bail!("Connect once from Home to finish local VPN setup.");
        }
        install_verified_helper(&installed_helper, &packaged_helper, install_helper)?;
        helper = installed_helper.clone();
    }
    ensure_vpn_authorization(command_name, interactive)?;
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
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn()?;
    if let Some(bytes) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("privileged helper input is unavailable"))?
            .write_all(bytes)?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "The local network operation did not complete. Refresh to verify the tunnel and kill switch state."
        );
    }
    Ok(output.stdout)
}

fn vpn_authorization_granted(action: &str) -> bool {
    Command::new("pkcheck")
        .args([
            "--action-id",
            action,
            "--process",
            &std::process::id().to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_for_vpn_authorization(action: &str) -> bool {
    // Polkit reloads rules asynchronously after their atomic replacement.
    for _ in 0..40 {
        if vpn_authorization_granted(action) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

fn ensure_vpn_authorization(command: &str, interactive: bool) -> Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    let Some(action) = sirinvpn_linux_helper::vpn_control_action(command) else {
        return Ok(());
    };
    if vpn_authorization_granted(&action) {
        return Ok(());
    }
    if !interactive {
        bail!("Connect once from Home to authorize VPN controls for this account.");
    }
    let granted = Command::new("pkexec")
        .args([INSTALLED_HELPER, "authorize-user"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !granted.success() || !wait_for_vpn_authorization(&action) {
        bail!(
            "VPN-control authorization was not granted. Connect from an active local session to try again."
        );
    }
    Ok(())
}

// Compatible protocol versions can still contain older recovery behavior.
// Refresh on connection start; status and disconnect never install just for a
// newer build, so leaving a tunnel does not depend on an optional update.
fn helper_artifact_matches(installed: &Path, packaged: &Path) -> bool {
    let (Ok(installed_meta), Ok(packaged_meta)) = (fs::metadata(installed), fs::metadata(packaged))
    else {
        return false;
    };
    if installed_meta.len() != packaged_meta.len() {
        return false;
    }
    match (fs::read(installed), fs::read(packaged)) {
        (Ok(installed), Ok(packaged)) => installed == packaged,
        _ => false,
    }
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
        bail!("privileged helper installation was not authorized");
    }
    if !nix::unistd::Uid::effective().is_root() {
        let action = sirinvpn_linux_helper::vpn_control_action("connect-managed").unwrap();
        if !wait_for_vpn_authorization(&action) {
            bail!(
                "The VPN component was installed, but this account's control permission is unavailable. Connect from an active local session."
            );
        }
    }
    Ok(())
}

pub(super) fn resolve_packaged_helper_binary() -> Result<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(path) = env::var_os("SIRINVPN_HELPER_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }
    let executable = env::current_exe()?;
    let sibling = executable
        .parent()
        .ok_or_else(|| anyhow!("application executable has no parent directory"))?
        .join("sirinvpn-helper");
    if sibling.is_file() {
        return Ok(sibling);
    }
    let appimage_relative = executable
        .parent()
        .and_then(|directory| directory.parent())
        .map(|directory| directory.join("lib/sirinvpn/sirinvpn-helper"));
    if let Some(path) = appimage_relative
        && path.is_file()
    {
        return Ok(path);
    }
    bail!("the packaged SirinVPN helper is unavailable")
}

pub(super) fn resolve_binary(
    environment: &str,
    installed: &str,
    sibling_name: &str,
) -> Result<PathBuf> {
    #[cfg(debug_assertions)]
    {
        if let Some(path) = env::var_os(environment) {
            let path = PathBuf::from(path);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = environment;
    let executable = env::current_exe()?;
    let sibling = executable
        .parent()
        .ok_or_else(|| anyhow!("application executable has no parent directory"))?
        .join(sibling_name);
    if sibling.is_file() {
        return Ok(sibling);
    }
    let appimage_relative = executable
        .parent()
        .and_then(|directory| directory.parent())
        .map(|directory| directory.join("lib/sirinvpn").join(sibling_name));
    if let Some(path) = appimage_relative
        && path.is_file()
    {
        return Ok(path);
    }
    let installed = PathBuf::from(installed);
    if installed.is_file() {
        return Ok(installed);
    }
    bail!("required SirinVPN component is not installed")
}

#[cfg(test)]
mod artifact_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn component(path: &Path, protocol: u16) {
        fs::write(
            path,
            format!("#!/bin/sh\n[ \"$1\" = version ] || exit 1\nprintf '%s\\n' '{protocol}'\n"),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn an_old_component_is_replaced_and_verified_before_it_can_be_used() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("installed");
        let packaged = dir.path().join("packaged");
        component(&installed, 13);
        component(&packaged, HELPER_PROTOCOL_VERSION);
        assert!(!helper_protocol_is_current(&installed));
        install_verified_helper(&installed, &packaged, |source| {
            fs::copy(source, &installed)?;
            Ok(())
        })
        .unwrap();
        assert!(helper_protocol_is_current(&installed));
        assert!(helper_artifact_matches(&installed, &packaged));
    }

    #[test]
    fn cancelled_or_incomplete_installation_never_claims_a_current_component() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("installed");
        let packaged = dir.path().join("packaged");
        component(&installed, 13);
        component(&packaged, HELPER_PROTOCOL_VERSION);
        assert!(install_verified_helper(&installed, &packaged, |_| bail!("cancelled")).is_err());
        assert!(install_verified_helper(&installed, &packaged, |_| Ok(())).is_err());
        assert!(!helper_protocol_is_current(&installed));
    }

    #[test]
    fn a_compatible_but_older_helper_is_not_the_packaged_build() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("installed");
        let packaged = dir.path().join("packaged");
        fs::write(&installed, b"protocol 13, build a").unwrap();
        fs::write(&packaged, b"protocol 13, build b").unwrap();
        assert!(!helper_artifact_matches(&installed, &packaged));
        fs::copy(&packaged, &installed).unwrap();
        assert!(helper_artifact_matches(&installed, &packaged));
        fs::remove_file(&installed).unwrap();
        assert!(!helper_artifact_matches(&installed, &packaged));
    }
}
