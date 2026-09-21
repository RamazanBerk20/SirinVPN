//! Ssh.

use super::*;

pub(super) fn connect_transport(target: &SshTarget) -> anyhow::Result<Session> {
    validate_host(&target.host)?;
    if target.port == 0 {
        bail!("SSH port must be non-zero");
    }
    let address = (target.host.as_str(), target.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("server address did not resolve"))?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    let mut session = Session::new()?;
    session.set_tcp_stream(stream);
    session.set_timeout(SSH_OPERATION_TIMEOUT_MS);
    session.handshake()?;
    Ok(session)
}

pub(super) fn fingerprint(session: &Session) -> anyhow::Result<String> {
    let (host_key, _) = session
        .host_key()
        .ok_or_else(|| anyhow!("server did not present an SSH host key"))?;
    Ok(format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(host_key))
    ))
}

pub(super) fn verify_host_key(
    session: &Session,
    expected: Option<&str>,
) -> Result<(), InstallerError> {
    let actual = fingerprint(session).map_err(|error| phase_error("host key", error))?;
    match expected {
        None => Err(InstallerError::HostKeyUnknown {
            fingerprint: actual,
        }),
        Some(expected)
            if bool::from(subtle::ConstantTimeEq::ct_eq(
                expected.as_bytes(),
                actual.as_bytes(),
            )) =>
        {
            Ok(())
        }
        Some(_) => Err(InstallerError::HostKeyMismatch),
    }
}

pub(super) fn authenticate(session: &Session, target: &SshTarget) -> Result<(), InstallerError> {
    let result = match &target.authentication {
        SshAuthentication::Agent => authenticate_agent(session, &target.username),
        SshAuthentication::Password(password) => session
            .userauth_password(&target.username, password.as_str())
            .map_err(anyhow::Error::from),
        SshAuthentication::PrivateKey { path, passphrase } => session
            .userauth_pubkey_file(
                &target.username,
                None,
                path,
                passphrase.as_ref().map(|value| value.as_str()),
            )
            .map_err(anyhow::Error::from),
        SshAuthentication::PrivateKeyMemory {
            private_key_pem,
            passphrase,
        } => session
            .userauth_pubkey_memory(
                &target.username,
                None,
                private_key_pem.as_str(),
                passphrase.as_ref().map(|value| value.as_str()),
            )
            .map_err(anyhow::Error::from),
    };
    if result.is_err() || !session.authenticated() {
        return Err(InstallerError::AuthenticationFailed);
    }
    Ok(())
}

pub(super) fn authenticate_agent(session: &Session, username: &str) -> anyhow::Result<()> {
    let mut agent = session.agent()?;
    agent.connect()?;
    agent.list_identities()?;
    for identity in agent.identities()? {
        if agent.userauth(username, &identity).is_ok() && session.authenticated() {
            return Ok(());
        }
    }
    bail!("no SSH agent identity was accepted")
}

pub(super) fn discover(session: &Session) -> Result<ServerDiscovery, InstallerError> {
    let command = r#"set -eu
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
. /etc/os-release
printf 'os_id=%s\n' "$ID"
printf 'os_version=%s\n' "$VERSION_ID"
printf 'architecture=%s\n' "$(uname -m)"
IPV4_INTERFACE=$(ip -4 route show default | awk 'NR==1 {for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
printf 'default_interface=%s\n' "$IPV4_INTERFACE"
IPV6_INTERFACE=$(ip -6 route show default | awk 'NR==1 {for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
printf 'ipv6_default_interface=%s\n' "$IPV6_INTERFACE"
printf 'ssh_server_port=%s\n' "$(printf '%s' "$SSH_CONNECTION" | awk '{print $4}')"
[ -n "$IPV4_INTERFACE" ] && printf 'ipv4_available=1\n' || printf 'ipv4_available=0\n'
[ -n "$IPV6_INTERFACE" ] && ip -o -6 address show dev "$IPV6_INTERFACE" scope global | awk '{print $4}' | grep -Eq '^[23][0-9A-Fa-f]*:' && printf 'ipv6_available=1\n' || printf 'ipv6_available=0\n'
command -v nft >/dev/null 2>&1 && printf 'nftables_available=1\n' || printf 'nftables_available=0\n'
command -v wg >/dev/null 2>&1 && printf 'wireguard_available=1\n' || printf 'wireguard_available=0\n'
command -v unbound >/dev/null 2>&1 && printf 'unbound_installed=1\n' || printf 'unbound_installed=0\n'
test -x /usr/local/lib/sirinvpn/sirinvpn-server && printf 'sirinvpn_installed=1\n' || printf 'sirinvpn_installed=0\n'"#;
    let output = run(session, command).map_err(|error| phase_error("discovery", error))?;
    parse_discovery(&output).map_err(|error| phase_error("discovery", error))
}

pub(super) fn parse_discovery(output: &str) -> anyhow::Result<ServerDiscovery> {
    let value = |key: &str| -> anyhow::Result<&str> {
        output
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .ok_or_else(|| anyhow!("missing discovery field"))
    };
    let boolean = |key: &str| -> anyhow::Result<bool> { Ok(value(key)? == "1") };
    let valid_interface = |interface: &str| {
        !interface.is_empty()
            && interface.len() <= 15
            && interface
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_.:-".contains(character))
    };
    let default_interface = value("default_interface")?.to_owned();
    if default_interface.is_empty() && !boolean("ipv4_available")? {
        bail!("the VPS has no IPv4 default route for Internet forwarding");
    }
    if !valid_interface(&default_interface) {
        bail!("default network interface is invalid");
    }
    let ipv6_default_interface = match value("ipv6_default_interface")? {
        "" => None,
        interface if valid_interface(interface) => Some(interface.to_owned()),
        _ => bail!("IPv6 default network interface is invalid"),
    };
    let ipv6_available = boolean("ipv6_available")?;
    if ipv6_available && ipv6_default_interface.is_none() {
        bail!("IPv6 availability requires a default network interface");
    }
    Ok(ServerDiscovery {
        os_id: value("os_id")?.to_owned(),
        os_version: value("os_version")?.to_owned(),
        architecture: value("architecture")?.to_owned(),
        default_interface,
        ipv6_default_interface,
        ssh_server_port: value("ssh_server_port")?.parse()?,
        ipv4_available: boolean("ipv4_available")?,
        ipv6_available,
        nftables_available: boolean("nftables_available")?,
        wireguard_available: boolean("wireguard_available")?,
        unbound_installed: boolean("unbound_installed")?,
        sirinvpn_installed: boolean("sirinvpn_installed")?,
    })
}

pub(super) fn check_compatibility(discovery: &ServerDiscovery) -> Result<(), InstallerError> {
    if discovery.os_id != "debian" || discovery.os_version != "13" {
        return Err(InstallerError::Incompatible(
            "P0 supports Debian 13 only".to_owned(),
        ));
    }
    if !matches!(discovery.architecture.as_str(), "x86_64" | "aarch64") {
        return Err(InstallerError::Incompatible(
            "P0 supports amd64 and arm64 servers only".to_owned(),
        ));
    }
    if !discovery.ipv4_available {
        return Err(InstallerError::Incompatible(
            "an IPv4 default route is required for P0".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_repair_ipv6_compatible(
    previously_enabled: bool,
    currently_available: bool,
) -> Result<(), InstallerError> {
    if previously_enabled && !currently_available {
        return Err(InstallerError::Incompatible(
            "the VPS no longer exposes the IPv6 route required by its existing dual-stack configuration; repair will not disable IPv6 implicitly"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_restore_ipv6_compatible(
    backup_enabled: bool,
    target_available: bool,
) -> Result<(), InstallerError> {
    if backup_enabled && !target_available {
        return Err(InstallerError::Incompatible(
            "the backup requires the IPv6 route used by its dual-stack server configuration, but the restore VPS does not provide one"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_dns_upstream_compatible(
    dns_upstream: &DnsUpstream,
    ipv6_available: bool,
) -> Result<(), InstallerError> {
    let requires_ipv6 = match dns_upstream {
        DnsUpstream::Split { default, zones } => {
            ensure_dns_upstream_compatible(default, ipv6_available)?;
            zones
                .iter()
                .flat_map(|zone| zone.addresses())
                .any(|address| address.is_ipv6())
        }
        DnsUpstream::Recursive => false,
        DnsUpstream::DnsOverTls { endpoints } => {
            endpoints.iter().any(|endpoint| endpoint.address.is_ipv6())
        }
        DnsUpstream::DnsOverHttps { endpoints } => {
            endpoints.iter().any(|endpoint| endpoint.address.is_ipv6())
        }
    };
    if !ipv6_available && requires_ipv6 {
        return Err(InstallerError::Incompatible(
            "an IPv6 secure-DNS endpoint requires a usable IPv6 route on the VPS".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn run_privileged(
    session: &Session,
    target: &SshTarget,
    command: &str,
) -> anyhow::Result<String> {
    if target.username == "root" {
        return run(session, command);
    }
    let wrapped = format!("sudo -S -p '' /bin/sh -lc {}", shell_quote(command));
    let mut channel = session.channel_session()?;
    channel.exec(&wrapped)?;
    if let Some(password) = &target.sudo_password {
        channel.write_all(password.as_bytes())?;
        channel.write_all(b"\n")?;
        channel.flush()?;
    }
    channel.send_eof()?;
    read_channel(channel)
}

pub(super) fn run_privileged_bytes(
    session: &Session,
    target: &SshTarget,
    command: &str,
    max_stdout_bytes: usize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if target.username == "root" {
        return run_bytes(session, command, max_stdout_bytes);
    }
    let wrapped = format!("sudo -S -p '' /bin/sh -lc {}", shell_quote(command));
    let mut channel = session.channel_session()?;
    channel.exec(&wrapped)?;
    if let Some(password) = &target.sudo_password {
        channel.write_all(password.as_bytes())?;
        channel.write_all(b"\n")?;
        channel.flush()?;
    }
    channel.send_eof()?;
    read_channel_bytes(channel, max_stdout_bytes)
}

pub(super) fn run_privileged_with_input(
    session: &Session,
    target: &SshTarget,
    command: &str,
    input: &[u8],
) -> anyhow::Result<String> {
    if target.username == "root" {
        return run_with_input(session, command, input);
    }
    const STREAM_MARKER: &str = "SIRINVPN_RESTORE_STREAM_V1";
    let relay = format!(
        "while IFS= read -r line; do [ \"$line\" = {} ] && break; done; exec /bin/sh -lc {}",
        shell_quote(STREAM_MARKER),
        shell_quote(command),
    );
    let wrapped = format!("sudo -S -p '' /bin/sh -lc {}", shell_quote(&relay));
    let mut channel = session.channel_session()?;
    channel.exec(&wrapped)?;
    if let Some(password) = &target.sudo_password {
        channel.write_all(password.as_bytes())?;
        channel.write_all(b"\n")?;
    }
    channel.write_all(STREAM_MARKER.as_bytes())?;
    channel.write_all(b"\n")?;
    channel.write_all(input)?;
    channel.flush()?;
    channel.send_eof()?;
    read_channel(channel)
}

pub(super) fn run(session: &Session, command: &str) -> anyhow::Result<String> {
    let mut channel = session.channel_session()?;
    channel.exec(command)?;
    read_channel(channel)
}

pub(super) fn run_bytes(
    session: &Session,
    command: &str,
    max_stdout_bytes: usize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut channel = session.channel_session()?;
    channel.exec(command)?;
    read_channel_bytes(channel, max_stdout_bytes)
}

pub(super) fn run_with_input(
    session: &Session,
    command: &str,
    input: &[u8],
) -> anyhow::Result<String> {
    let mut channel = session.channel_session()?;
    channel.exec(command)?;
    channel.write_all(input)?;
    channel.flush()?;
    channel.send_eof()?;
    read_channel(channel)
}

pub(super) fn rollback_now(session: &Session, target: &SshTarget, nonce: &str) {
    run_rollback_now(session, target, &maintenance::rollback_path(nonce, false));
}

pub(super) fn run_rollback_now(session: &Session, target: &SshTarget, path: &str) {
    let path = shell_quote(path);
    let command = format!("test -x {path} && /bin/sh {path} || true");
    for _ in 0..3 {
        if run_privileged(session, target, &command).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let Ok(recovery_session) = connect_transport(target) else {
        return;
    };
    if verify_host_key(
        &recovery_session,
        target.expected_host_key_sha256.as_deref(),
    )
    .is_err()
        || authenticate(&recovery_session, target).is_err()
    {
        return;
    }
    let _ = run_privileged(&recovery_session, target, &command);
}

// Bound memory before allocation, even when the SSH peer sends an endless response.
const MAX_COMMAND_STDOUT_BYTES: usize = 1024 * 1024;

pub(super) fn read_bounded_output(
    reader: impl Read,
    limit: usize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("remote command returned an oversized response");
    }
    Ok(bytes)
}

pub(super) fn read_channel(mut channel: ssh2::Channel) -> anyhow::Result<String> {
    let stdout = read_bounded_output(&mut channel, MAX_COMMAND_STDOUT_BYTES)?;
    // Remote stderr may contain echoed credentials; never include it in an error,
    // including debug APKs and desktop development builds.
    let _stderr = read_bounded_output(channel.stderr(), MAX_SERVER_BACKUP_STDERR_SIZE)?;
    channel.wait_close()?;
    let status = channel.exit_status()?;
    if status != 0 {
        if let Some(failure) = crate::install_failure::InstallFailure::from_output(&stdout, status)
        {
            return Err(failure.into());
        }
        bail!("remote command exited with status {status}");
    }
    Ok(std::str::from_utf8(&stdout)?.to_owned())
}

pub(super) fn read_channel_bytes(
    mut channel: ssh2::Channel,
    max_stdout_bytes: usize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let stdout = read_bounded_output(&mut channel, max_stdout_bytes)?;
    if stdout.is_empty() {
        bail!("remote command returned an empty binary response");
    }
    let _stderr = read_bounded_output(channel.stderr(), MAX_SERVER_BACKUP_STDERR_SIZE)?;
    channel.wait_close()?;
    let status = channel.exit_status()?;
    if status != 0 {
        bail!("remote command exited with status {status}");
    }
    Ok(stdout)
}

pub(super) fn upload(
    session: &Session,
    remote_path: &Path,
    bytes: &[u8],
    mode: i32,
) -> anyhow::Result<()> {
    let mut channel = session.scp_send(remote_path, mode, bytes.len() as u64, None)?;
    channel.write_all(bytes)?;
    channel.send_eof()?;
    channel.wait_eof()?;
    channel.close()?;
    channel.wait_close()?;
    Ok(())
}

pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub(super) fn elf_architecture(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return None;
    }
    match u16::from_le_bytes([bytes[18], bytes[19]]) {
        62 => Some("x86_64"),
        183 => Some("aarch64"),
        _ => None,
    }
}

pub(super) fn event(phase: InstallPhase, message: &str) -> InstallEvent {
    InstallEvent {
        phase,
        message: message.to_owned(),
    }
}

pub(super) fn phase_error(phase: &'static str, error: anyhow::Error) -> InstallerError {
    if let Some(failure) = error.downcast_ref::<crate::install_failure::InstallFailure>() {
        return InstallerError::PhaseFailed {
            phase,
            message: failure.to_string(),
        };
    }
    #[cfg(debug_assertions)]
    let message = format!("Debug-only detail: {error:#}");
    #[cfg(not(debug_assertions))]
    let message = {
        let _ = error;
        "The operation did not complete. Run Diagnose and retry; no secret details were retained."
            .to_owned()
    };
    InstallerError::PhaseFailed { phase, message }
}
