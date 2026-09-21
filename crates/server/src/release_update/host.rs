use super::*;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use sirinvpn_release::{ReleaseError, ReleaseManifest, ServerReleaseHost};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub const SERVER_BINARY: &str = "/usr/local/lib/sirinvpn/sirinvpn-server";
pub const UPDATER_BINARY: &str = "/usr/local/lib/sirinvpn/sirinvpn-updater";
pub const MAINTENANCE_LOCK: &str = "/run/sirinvpn-maintenance.lock";

#[cfg(test)]
mod tests;

pub struct SystemServerHost {
    pub paths: crate::ServerPaths,
    maintenance: File,
}

impl SystemServerHost {
    pub fn acquire(paths: crate::ServerPaths) -> Result<Self, ReleaseError> {
        require_root()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(MAINTENANCE_LOCK)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(ReleaseError::UnsafeInstalledState);
        }
        FileExt::try_lock_exclusive(&file).map_err(|_| {
            ReleaseError::ServerOperation("another installation or update is running")
        })?;
        require_no_ssh_transaction()?;
        Ok(Self {
            paths,
            maintenance: file,
        })
    }
}

impl ServerReleaseHost for SystemServerHost {
    fn lock(&self) -> Result<Box<dyn Send>, ReleaseError> {
        // Duplicated descriptors share the same flock. Dropping the library's
        // guard cannot release the outer lease or race an SSH transaction.
        Ok(Box::new(self.maintenance.try_clone()?))
    }
    fn installed_binary(&self) -> &Path {
        Path::new(SERVER_BINARY)
    }
    fn preflight(&self, executable: &Path, manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
        validate_live_compatibility(&self.paths, manifest)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".sirinvpn-check-")
            .tempfile_in(RELEASE_DIRECTORY)?;
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(executable)?;
        std::io::copy(&mut source, &mut temporary)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o700))?;
        temporary.as_file().sync_all()?;
        // Close the writable descriptor before executing an ELF (ETXTBSY).
        let executable = temporary.into_temp_path();
        run_command(
            Command::new(&executable)
                .arg("--state-directory")
                .arg(&self.paths.state_directory)
                .arg("validate-state"),
            Duration::from_secs(20),
            "candidate state validation",
        )?;
        let capabilities = run_command(
            Command::new(&executable).args(["release", "capabilities"]),
            Duration::from_secs(5),
            "candidate recovery coordinator validation",
        )?;
        let capabilities: ReleaseCapabilities = serde_json::from_str(&capabilities)
            .map_err(|_| ReleaseError::ServerUpdateUnsupported)?;
        if capabilities != release_capabilities()? {
            return Err(ReleaseError::ServerUpdateUnsupported);
        }
        Ok(())
    }
    fn stop(&self) -> Result<(), ReleaseError> {
        systemctl(&["stop", "sirinvpn-server.service"])?;
        if uses_doh(&self.paths)? {
            systemctl(&["stop", "sirinvpn-doh.service"])?;
        }
        Ok(())
    }
    fn replace(&self, executable: &Path) -> Result<(), ReleaseError> {
        replace_binary(executable, Path::new(SERVER_BINARY))
    }
    fn start(&self) -> Result<(), ReleaseError> {
        if uses_doh(&self.paths)? {
            systemctl(&["start", "sirinvpn-doh.service"])?;
        }
        systemctl(&["start", "sirinvpn-server.service"])?;
        Ok(())
    }
    fn health(&self) -> Result<(), ReleaseError> {
        let configuration = crate::load_configuration(&self.paths)
            .map_err(|_| ReleaseError::ServerOperation("server configuration validation"))?;
        crate::validate_state(&self.paths).map_err(|_| {
            ReleaseError::ServerOperation("installed identity and access validation")
        })?;
        // Require a stable service process and the actual management/transport
        // listeners owned by it, not merely systemd's initial 'active' state.
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut stable = 0;
        let mut previous_pid = None;
        while Instant::now() < deadline {
            if let Ok(pid) = service_pid()
                && listeners_healthy(&configuration, pid).is_ok()
                && ["sirinvpn-network", "sirinvpn-firewall", "unbound"]
                    .into_iter()
                    .all(|unit| systemctl(&["is-active", "--quiet", unit]).is_ok())
                && (!uses_doh(&self.paths)?
                    || systemctl(&["is-active", "--quiet", "sirinvpn-doh"]).is_ok())
            {
                stable = if previous_pid == Some(pid) {
                    stable + 1
                } else {
                    1
                };
                previous_pid = Some(pid);
                if stable >= 4 {
                    return Ok(());
                }
            } else {
                stable = 0;
                previous_pid = None;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Err(ReleaseError::ServerOperation(
            "server health did not stabilize",
        ))
    }
    fn complete(&self) -> Result<(), ReleaseError> {
        replace_binary(Path::new(SERVER_BINARY), Path::new(UPDATER_BINARY))
    }
}

pub fn require_no_ssh_transaction() -> Result<(), ReleaseError> {
    for directory in ["/run", "/var/lib/sirinvpn-maintenance"] {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if (name.starts_with("sirinvpn-install-") || name.starts_with("sirinvpn-uninstall-"))
                && name.ends_with(".backup")
            {
                return Err(ReleaseError::ServerOperation(
                    "an SSH installation or removal is awaiting its final checks",
                ));
            }
        }
    }
    Ok(())
}

pub fn validate_live_compatibility(
    paths: &crate::ServerPaths,
    manifest: &ReleaseManifest,
) -> Result<(), ReleaseError> {
    let configuration = crate::load_configuration(paths)
        .map_err(|_| ReleaseError::ServerOperation("current configuration is invalid"))?;
    require_reads(
        manifest,
        "server_configuration",
        configuration.schema_version,
    )?;
    if paths.authorization.exists() {
        let authorization = crate::authorization::load_authorization(&paths.authorization)
            .map_err(|_| ReleaseError::ServerOperation("current authorization is invalid"))?;
        require_reads(
            manifest,
            "server_authorization",
            authorization.schema_version,
        )?;
    }
    if paths.operational_configuration.exists() {
        require_reads(manifest, "server_operational_configuration", 1)?;
    }
    for state in [
        "server_handoff_guard",
        "server_maintenance_guard",
        "server_release_transaction",
        "server_security_update_policy",
    ] {
        require_reads(manifest, state, 1)?;
    }
    Ok(())
}

fn require_reads(manifest: &ReleaseManifest, name: &str, schema: u16) -> Result<(), ReleaseError> {
    if manifest.state_compatibility.iter().any(|state| {
        state.state == name && state.reads.minimum <= schema && state.reads.maximum >= schema
    }) {
        Ok(())
    } else {
        Err(ReleaseError::ForwardIncompatible(name.to_owned()))
    }
}

pub fn require_root() -> Result<(), ReleaseError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(ReleaseError::ServerOperation(
            "VPS release management requires root",
        ));
    }
    Ok(())
}

fn uses_doh(paths: &crate::ServerPaths) -> Result<bool, ReleaseError> {
    let configuration = crate::load_configuration(paths)
        .map_err(|_| ReleaseError::ServerOperation("DNS configuration validation"))?;
    Ok(matches!(
        configuration.dns_upstream.default_upstream(),
        sirinvpn_protocol::DnsUpstream::DnsOverHttps { .. }
    ))
}

fn service_pid() -> Result<u32, ReleaseError> {
    let text = systemctl(&[
        "show",
        "--property=MainPID",
        "--value",
        "sirinvpn-server.service",
    ])?;
    let pid: u32 = text
        .trim()
        .parse()
        .map_err(|_| ReleaseError::ServerOperation("server PID is unavailable"))?;
    if pid <= 1 || fs::read_link(format!("/proc/{pid}/exe"))? != Path::new(SERVER_BINARY) {
        return Err(ReleaseError::ServerOperation(
            "the server process is not running the installed executable",
        ));
    }
    Ok(pid)
}

fn listeners_healthy(
    configuration: &crate::ServerConfiguration,
    pid: u32,
) -> Result<(), ReleaseError> {
    let mut ports = vec![configuration.management_port];
    if let Some(endpoint) = &configuration.tcp_fallback {
        ports.push(endpoint.port);
    }
    if let Some(port) = configuration.endpoint_discovery_port {
        ports.push(port);
    }
    ports.sort_unstable();
    ports.dedup();
    for port in ports {
        let output = run_command(
            Command::new("/usr/bin/ss").args(["-H", "-lntp", &format!("sport = :{port}")]),
            Duration::from_secs(3),
            "server listener verification",
        )?;
        if !output.lines().any(|line| {
            line.contains(&format!("pid={pid},"))
                && (port != configuration.management_port
                    || line.contains(&format!("10.77.0.1:{port}")))
        }) {
            return Err(ReleaseError::ServerOperation(
                "a server listener is unavailable",
            ));
        }
    }
    if let Some(endpoint) = &configuration.obfuscated_udp {
        let output = run_command(
            Command::new("/usr/bin/ss").args([
                "-H",
                "-lnup",
                &format!("sport = :{}", endpoint.port),
            ]),
            Duration::from_secs(3),
            "wrapped UDP listener verification",
        )?;
        if !output.contains(&format!("pid={pid},")) {
            return Err(ReleaseError::ServerOperation(
                "the wrapped UDP listener is unavailable",
            ));
        }
    }
    let port = run_command(
        Command::new("/usr/bin/wg").args(["show", "sirinvpn0", "listen-port"]),
        Duration::from_secs(3),
        "WireGuard listener verification",
    )?;
    if port.trim().parse::<u16>().ok() != Some(configuration.wireguard_port) {
        return Err(ReleaseError::ServerOperation(
            "the WireGuard listener is unavailable",
        ));
    }
    Ok(())
}

pub fn systemctl(arguments: &[&str]) -> Result<String, ReleaseError> {
    run_command(
        Command::new("/usr/bin/systemctl").args(arguments),
        Duration::from_secs(45),
        "systemd service operation",
    )
}

pub fn run_command(
    command: &mut Command,
    timeout: Duration,
    phase: &'static str,
) -> Result<String, ReleaseError> {
    let mut output = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ReleaseError::ServerOperation(phase))?;
    let deadline = Instant::now() + timeout;
    loop {
        if output.metadata()?.len() > 64 * 1024 || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ReleaseError::ServerOperation(phase));
        }
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(ReleaseError::ServerOperation(phase));
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    use std::io::{Seek, SeekFrom};
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    output.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err(ReleaseError::ServerOperation(phase));
    }
    String::from_utf8(bytes).map_err(|_| ReleaseError::ServerOperation(phase))
}

pub fn replace_binary(source: &Path, destination: &Path) -> Result<(), ReleaseError> {
    let parent = destination
        .parent()
        .ok_or(ReleaseError::UnsafeInstalledState)?;
    for path in [parent.to_path_buf(), destination.to_path_buf()] {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Err(ReleaseError::UnsafeInstalledState);
        }
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".sirinvpn-replace-")
        .tempfile_in(parent)?;
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(source)?;
    std::io::copy(&mut source, &mut temporary)?;
    temporary.flush()?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn binary_digest(path: &Path) -> Result<String, ReleaseError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.file_type().is_file()
        || file.metadata()?.len() > sirinvpn_release::MAX_ARTIFACT_BYTES
    {
        return Err(ReleaseError::ServerInstalledMismatch);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let len = file.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        hasher.update(&buffer[..len]);
    }
    Ok(hex::encode(hasher.finalize()))
}
