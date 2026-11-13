//! Helper.

use super::*;
use sirinvpn_installer::ServerBinarySource;
use sirinvpn_tunnel_model::HELPER_PROTOCOL_VERSION;
use std::{
    io::Write,
    os::unix::fs::MetadataExt,
    process::{Command, Stdio},
};

const INSTALLED_HELPER: &str = "/usr/lib/sirinvpn/sirinvpn-helper";

/// The only helper pkexec may run as root: the packaged one, or a copy whose whole path
/// (the file and every directory above it) is root-owned and closed to group and others.
/// Anything else could be a user-writable file that would run as root.
fn escalation_target(helper: &Path) -> Result<PathBuf> {
    if helper == Path::new(INSTALLED_HELPER) {
        return Ok(helper.to_owned());
    }
    // Run the resolved path, so a link swapped in later cannot redirect pkexec.
    if let Ok(real) = helper.canonicalize()
        && real.ancestors().all(|path| {
            std::fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
        })
    {
        return Ok(real);
    }
    bail!(
        "the privileged helper at {} is not in a location only root can change, so it was not run with elevated rights; install the SirinVPN package and try again",
        helper.display()
    )
}

/// `install-system` from a source build or unpacked tarball, where no root-owned copy
/// exists yet: only a file this user owns and nobody else can write. Returns its resolved
/// path and SHA-256, hashed through one open handle; refuses a file that changed while
/// it was read or that the path no longer names.
fn user_owned_install_source(helper: &Path) -> Result<(PathBuf, String)> {
    use sha2::{Digest, Sha256};
    let unchecked = || {
        anyhow!(
            "could not verify the privileged helper at {}",
            helper.display()
        )
    };
    let real = helper.canonicalize().map_err(|_| unchecked())?;
    let mut file = std::fs::File::open(&real).map_err(|_| unchecked())?;
    let before = file.metadata().map_err(|_| unchecked())?;
    if !before.is_file()
        || before.uid() != nix::unistd::Uid::effective().as_raw()
        || before.mode() & 0o022 != 0
    {
        bail!(
            "the privileged helper at {} is neither in a root-only location nor a file only you can change; install the SirinVPN package and try again",
            real.display()
        );
    }
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|_| unchecked())?;
    let after = file.metadata().map_err(|_| unchecked())?;
    let now = std::fs::metadata(&real).map_err(|_| unchecked())?;
    let same = |a: &std::fs::Metadata, b: &std::fs::Metadata| {
        (
            a.dev(),
            a.ino(),
            a.size(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.dev(),
            b.ino(),
            b.size(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        )
    };
    if !same(&before, &after) || !same(&after, &now) {
        bail!(
            "the privileged helper at {} changed while it was being checked",
            real.display()
        );
    }
    Ok((real, format!("{:x}", hasher.finalize())))
}

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
        command.arg(escalation_target(&helper)?);
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
    let mut shown = None;
    let mut command = if nix::unistd::Uid::effective().is_root() {
        Command::new(source)
    } else {
        let target = match escalation_target(source) {
            Ok(target) => target,
            Err(_) => {
                let (target, digest) = user_owned_install_source(source)?;
                eprintln!(
                    "Installing the privileged helper as root from {}",
                    target.display()
                );
                eprintln!("SHA-256: {digest}");
                eprintln!(
                    "Warning: this file is not in a root-only location; approve only if you built or unpacked it yourself."
                );
                shown = Some(digest);
                target
            }
        };
        let mut command = Command::new("pkexec");
        command.arg(target);
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
    // Fail closed if what root installed is not the file that was shown.
    if let Some(digest) = shown
        && file_sha256(Path::new(INSTALLED_HELPER)).as_deref() != Some(&digest)
    {
        bail!(
            "the installed privileged helper does not match SHA-256 {digest}; remove {INSTALLED_HELPER} and install the SirinVPN package"
        );
    }
    Ok(())
}

/// SHA-256 of a file, or `None` when it cannot be read.
fn file_sha256(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    std::io::copy(&mut std::fs::File::open(path).ok()?, &mut hasher).ok()?;
    Some(format!("{:x}", hasher.finalize()))
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

/// Both packaged payloads, so a VPS of either architecture gets its own binary.
fn packaged_by_architecture(directory: &Path) -> Option<ServerBinarySource> {
    let x86_64 = directory.join("sirinvpn-server-x86_64");
    let aarch64 = directory.join("sirinvpn-server-aarch64");
    (x86_64.is_file() && aarch64.is_file())
        .then(|| ServerBinarySource::by_architecture(x86_64, aarch64))
}

pub(super) fn resolve_server_binary(explicit: Option<PathBuf>) -> Result<ServerBinarySource> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path.into());
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
            return Ok(path.into());
        }
    }
    let current = env::current_exe()?;
    let sibling = current
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent directory"))?
        .join("sirinvpn-server");
    if sibling.is_file() {
        return Ok(sibling.into());
    }
    if let Some(both) = packaged_by_architecture(Path::new("/usr/lib/sirinvpn")) {
        return Ok(both);
    }
    let packaged = current
        .parent()
        .and_then(|directory| directory.parent())
        .map(|directory| directory.join("lib/sirinvpn/sirinvpn-server"));
    if let Some(path) = packaged
        && path.is_file()
    {
        return Ok(path.into());
    }
    let installed = PathBuf::from("/usr/lib/sirinvpn/sirinvpn-server");
    if installed.is_file() {
        return Ok(installed.into());
    }
    bail!("the packaged SirinVPN server binary is unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_packaged_helper_or_a_root_only_path_may_be_elevated() {
        assert_eq!(
            escalation_target(Path::new(INSTALLED_HELPER)).unwrap(),
            Path::new(INSTALLED_HELPER)
        );
        // A user-writable directory (a temp directory is, or sits under one) never qualifies.
        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("sirinvpn-helper");
        std::fs::write(&helper, b"#!/bin/sh\n").unwrap();
        let error = escalation_target(&helper).unwrap_err().to_string();
        assert!(error.contains("install the SirinVPN package"));
        // A path that does not exist, or climbs out of the installed directory, is no exception.
        assert!(escalation_target(&directory.path().join("missing")).is_err());
        assert!(
            escalation_target(Path::new("/usr/lib/sirinvpn/../../../tmp/sirinvpn-helper")).is_err()
        );
    }

    #[test]
    fn install_system_accepts_only_a_user_owned_closed_file_and_names_its_hash() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("sirinvpn-helper");
        std::fs::write(&helper, b"abc").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Routine elevation still refuses it; only `install-system` may take it.
        assert!(escalation_target(&helper).is_err());
        let (real, digest) = user_owned_install_source(&helper).unwrap();
        assert_eq!(real, helper.canonicalize().unwrap());
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(file_sha256(&helper).as_deref(), Some(digest.as_str()));
        // Writable by others, or missing: refused, never hashed and run.
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(user_owned_install_source(&helper).is_err());
        assert!(user_owned_install_source(&directory.path().join("missing")).is_err());
        assert!(file_sha256(&directory.path().join("missing")).is_none());
    }

    #[test]
    fn a_root_owned_closed_path_is_accepted() {
        // Needs a root-owned tree, which a test cannot create; use the system's own.
        let env = Path::new("/usr/bin/env");
        let root_only = env.canonicalize().is_ok_and(|real| {
            real.ancestors().all(|path| {
                std::fs::symlink_metadata(path)
                    .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
            })
        });
        if root_only {
            assert_eq!(escalation_target(env).unwrap(), env.canonicalize().unwrap());
        }
    }

    #[test]
    fn both_packaged_architectures_select_a_per_architecture_source() {
        let directory = tempfile::tempdir().unwrap();
        assert!(packaged_by_architecture(directory.path()).is_none());
        std::fs::write(directory.path().join("sirinvpn-server-x86_64"), b"x").unwrap();
        assert!(packaged_by_architecture(directory.path()).is_none());
        std::fs::write(directory.path().join("sirinvpn-server-aarch64"), b"a").unwrap();
        assert!(matches!(
            packaged_by_architecture(directory.path()),
            Some(ServerBinarySource::ByArchitecture { x86_64, aarch64 })
                if x86_64.ends_with("sirinvpn-server-x86_64")
                    && aarch64.ends_with("sirinvpn-server-aarch64")
        ));
    }

    #[test]
    fn an_explicit_server_binary_stays_one_exact_file() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("sirinvpn-server");
        std::fs::write(&binary, b"x").unwrap();
        assert!(matches!(
            resolve_server_binary(Some(binary.clone())).unwrap(),
            ServerBinarySource::Exact(path) if path == binary
        ));
        assert!(resolve_server_binary(Some(directory.path().join("missing"))).is_err());
    }
}
