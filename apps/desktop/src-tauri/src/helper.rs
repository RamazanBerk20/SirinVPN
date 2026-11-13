//! Helper.

use super::*;
use sirinvpn_tunnel_model::HELPER_PROTOCOL_VERSION;
use std::fs;
use std::{
    io::Write,
    os::unix::fs::MetadataExt,
    process::{Command, Stdio},
};

const INSTALLED_HELPER: &str = "/usr/lib/sirinvpn/sirinvpn-helper";

// The same two rules as the CLI's helper module.

/// Routine elevation runs only the packaged helper, or a copy whose whole path (the
/// file and every directory above it) is root-owned and closed to group and others.
fn escalation_target(helper: &Path) -> Result<PathBuf> {
    if helper == Path::new(INSTALLED_HELPER) {
        return Ok(helper.to_owned());
    }
    // Run the resolved path, so a link swapped in later cannot redirect pkexec.
    if let Ok(real) = helper.canonicalize()
        && real.ancestors().all(|path| {
            fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
        })
    {
        return Ok(real);
    }
    bail!("The VPN component isn’t in a location only the administrator can change. Reinstall SirinVPN.")
}

/// `install-system` from a user-owned copy (an AppImage stage or a source build): only a
/// file this user owns and nobody else can write. Returns its resolved path and SHA-256,
/// hashed through one open handle; refuses a file that changed while it was read.
fn user_owned_install_source(helper: &Path) -> Result<(PathBuf, String)> {
    use sha2::{Digest, Sha256};
    let unchecked = || anyhow!("Couldn’t verify the VPN component at {}.", helper.display());
    let real = helper.canonicalize().map_err(|_| unchecked())?;
    let mut file = fs::File::open(&real).map_err(|_| unchecked())?;
    let before = file.metadata().map_err(|_| unchecked())?;
    if !before.is_file()
        || before.uid() != nix::unistd::Uid::effective().as_raw()
        || before.mode() & 0o022 != 0
    {
        bail!(
            "The VPN component at {} could be changed by another account. Reinstall SirinVPN.",
            real.display()
        );
    }
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|_| unchecked())?;
    let after = file.metadata().map_err(|_| unchecked())?;
    let now = fs::metadata(&real).map_err(|_| unchecked())?;
    let same = |a: &fs::Metadata, b: &fs::Metadata| {
        (a.dev(), a.ino(), a.size(), a.mtime(), a.mtime_nsec(), a.ctime(), a.ctime_nsec())
            == (b.dev(), b.ino(), b.size(), b.mtime(), b.mtime_nsec(), b.ctime(), b.ctime_nsec())
    };
    if !same(&before, &after) || !same(&after, &now) {
        bail!("The VPN component at {} changed while it was being checked.", real.display());
    }
    Ok((real, format!("{:x}", hasher.finalize())))
}

/// SHA-256 of a file, or `None` when it cannot be read.
fn file_sha256(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    std::io::copy(&mut fs::File::open(path).ok()?, &mut hasher).ok()?;
    Some(format!("{:x}", hasher.finalize()))
}

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
                "Disconnect and turn off the kill switch before updating the VPN component."
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
            "Couldn’t verify the VPN component after installing it. Reopen the current SirinVPN package and try again."
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
        command.arg(escalation_target(&helper)?);
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
            "The VPN action didn’t finish. Refresh to check the connection and kill switch."
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
            "VPN control wasn’t authorized. Connect again from your active desktop session."
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
    let mut busy_retries = 5;
    let output = loop {
        match Command::new(path)
            .arg("version")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            // A just-written file is busy until another thread's forked child drops its write handle.
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy && busy_retries > 0 =>
            {
                busy_retries -= 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            output => break output,
        }
    };
    output.is_ok_and(|output| {
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).trim() == HELPER_PROTOCOL_VERSION.to_string()
    })
}

/// Root can't read an AppImage's FUSE mount, so pkexec would fail before asking.
/// The helper is copied to a private directory outside the mount first.
fn stage_outside_appimage(source: &Path, appdir: Option<&Path>) -> Result<Option<tempfile::TempDir>> {
    if !appdir.is_some_and(|appdir| source.starts_with(appdir)) {
        return Ok(None);
    }
    // Hardened systems often mount /tmp noexec; the session's runtime directory stays executable.
    let parent = env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|directory| directory.is_dir())
        .unwrap_or_else(env::temp_dir);
    let directory = tempfile::Builder::new().prefix("sirinvpn-helper.").tempdir_in(parent)?;
    fs::copy(source, directory.path().join("sirinvpn-helper"))?;
    Ok(Some(directory))
}

pub(super) fn install_helper(source: &Path) -> Result<()> {
    let staged = stage_outside_appimage(source, env::var_os("APPDIR").as_deref().map(Path::new))?;
    let staged_helper = staged.as_ref().map(|directory| directory.path().join("sirinvpn-helper"));
    let source = staged_helper.as_deref().unwrap_or(source);
    // A user-owned copy is named with its hash, so what runs as root is on record.
    let mut shown = None;
    let mut command = if nix::unistd::Uid::effective().is_root() {
        Command::new(source)
    } else {
        let target = match escalation_target(source) {
            Ok(target) => target,
            Err(_) => {
                let (target, digest) = user_owned_install_source(source)?;
                eprintln!(
                    "Installing the VPN component as root from {} (SHA-256 {digest}); it is not in a root-only location.",
                    target.display()
                );
                shown = Some((target.clone(), digest));
                target
            }
        };
        let mut command = Command::new("pkexec");
        command.arg(target);
        command
    };
    let named = shown
        .as_ref()
        .map(|(path, digest)| format!(" Component: {} (SHA-256 {digest}).", path.display()))
        .unwrap_or_default();
    let status = command
        .arg("install-system")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        bail!("The VPN component wasn’t installed. Approve the administrator prompt and try again.{named}");
    }
    // Fail closed if what root installed is not the file that was named.
    if let Some((_, digest)) = &shown
        && file_sha256(Path::new(INSTALLED_HELPER)).as_ref() != Some(digest)
    {
        bail!("The installed VPN component doesn’t match the one approved.{named} Reinstall SirinVPN.");
    }
    if !nix::unistd::Uid::effective().is_root() {
        let action = sirinvpn_linux_helper::vpn_control_action("connect-managed").unwrap();
        if !wait_for_vpn_authorization(&action) {
            bail!(
                "The VPN component was installed, but this account can’t control it yet. Connect from your active desktop session."
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
    bail!("The bundled VPN component is missing. Reinstall SirinVPN.")
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
    bail!("A required SirinVPN component is missing. Reinstall SirinVPN.")
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
    fn an_appimage_helper_is_staged_outside_the_mount_for_pkexec() {
        let appdir = tempfile::tempdir().unwrap();
        let packaged = appdir.path().join("usr/lib/sirinvpn/sirinvpn-helper");
        fs::create_dir_all(packaged.parent().unwrap()).unwrap();
        component(&packaged, HELPER_PROTOCOL_VERSION);
        let staged = stage_outside_appimage(&packaged, Some(appdir.path()))
            .unwrap()
            .unwrap();
        let copy = staged.path().join("sirinvpn-helper");
        assert!(!copy.starts_with(appdir.path()));
        assert!(helper_artifact_matches(&copy, &packaged));
        assert!(helper_protocol_is_current(&copy));
        assert!(stage_outside_appimage(&packaged, None).unwrap().is_none());
        let elsewhere = tempfile::tempdir().unwrap();
        assert!(stage_outside_appimage(&packaged, Some(elsewhere.path())).unwrap().is_none());
    }

    #[test]
    fn install_system_takes_a_user_owned_closed_copy_only_with_its_hash() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("sirinvpn-helper");
        fs::write(&helper, b"abc").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        // Routine elevation refuses a user-owned copy; only `install-system` may take it.
        assert!(escalation_target(&helper).is_err());
        assert_eq!(
            escalation_target(Path::new(INSTALLED_HELPER)).unwrap(),
            Path::new(INSTALLED_HELPER)
        );
        let (real, digest) = user_owned_install_source(&helper).unwrap();
        assert_eq!(real, helper.canonicalize().unwrap());
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(file_sha256(&helper), Some(digest));
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o722)).unwrap();
        assert!(user_owned_install_source(&helper).is_err());
        assert!(user_owned_install_source(&dir.path().join("missing")).is_err());
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
