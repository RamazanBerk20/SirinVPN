//! System.

use super::*;

pub trait CommandRunner {
    fn kick_tunnel(&self, _: Ipv4Addr, _: Ipv4Addr) {}
    fn optimize_session(&self) {}
    fn measure_candidate(
        &self,
        _: &TunnelConnectRequest,
        _: IpAddr,
        _: &MeasureSessionRequest,
    ) -> Option<sirinvpn_protocol::TransportQualitySample> {
        None
    }
    fn tunnel_probe(&self, _: Ipv4Addr, _: Ipv4Addr) -> bool {
        false
    }
    fn endpoint_checkpoint(
        &self,
        _: &sirinvpn_protocol::EndpointIdentity,
        _: &str,
        _: IpAddr,
    ) -> Result<Option<sirinvpn_protocol::EndpointTransitionResponse>> {
        Ok(None)
    }

    fn offer_endpoint_checkpoint(
        &self,
        _: &sirinvpn_protocol::EndpointIdentity,
        _: &sirinvpn_protocol::EndpointTransitionResponse,
        _: &str,
        _: IpAddr,
    ) -> Result<bool> {
        Ok(false)
    }
    fn endpoint_addresses(&self, host: &str, _: &[SocketAddr]) -> Vec<IpAddr> {
        host.parse().ok().into_iter().collect()
    }
    fn endpoint_addresses_for_hosts(
        &self,
        hosts: &[&str],
        servers: &[SocketAddr],
    ) -> Vec<Vec<IpAddr>> {
        hosts
            .iter()
            .map(|host| self.endpoint_addresses(host, servers))
            .collect()
    }
    fn run(&self, program: &str, arguments: &[&str], stdin: Option<&[u8]>) -> Result<()>;

    fn output(&self, program: &str, arguments: &[&str]) -> Result<Vec<u8>> {
        self.run(program, arguments, None)?;
        Ok(Vec::new())
    }

    fn succeeds(&self, program: &str, arguments: &[&str]) -> bool {
        self.run(program, arguments, None).is_ok()
    }

    fn output_with_timeout(
        &self,
        program: &str,
        arguments: &[&str],
        _: Duration,
    ) -> Result<Vec<u8>> {
        self.output(program, arguments)
    }
}

#[derive(Clone, Copy)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn kick_tunnel(&self, source: Ipv4Addr, destination: Ipv4Addr) {
        let send = || -> io::Result<()> {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            socket.bind_device(Some(INTERFACE_NAME.as_bytes()))?;
            socket.bind(&SocketAddr::new(source.into(), 0).into())?;
            socket.send_to(&[0_u8; 12], &SocketAddr::new(destination.into(), 53).into())?;
            Ok(())
        };
        let _ = send();
    }
    fn optimize_session(&self) {
        let _ = LinuxNetworkHelper::system().optimize_session();
    }
    fn measure_candidate(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
        probe: &MeasureSessionRequest,
    ) -> Option<sirinvpn_protocol::TransportQualitySample> {
        measurement::sample_candidate(request, endpoint, probe)
    }
    fn tunnel_probe(&self, source: Ipv4Addr, destination: Ipv4Addr) -> bool {
        // A successful TCP exchange also works when the VPS drops ICMP. The
        // source and interface binding keep this check inside the encrypted path.
        let probe = || -> io::Result<()> {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            socket.bind_device(Some(INTERFACE_NAME.as_bytes()))?;
            socket.bind(&SocketAddr::new(source.into(), 0).into())?;
            socket.connect_timeout(
                &SocketAddr::new(destination.into(), 8443).into(),
                Duration::from_millis(700),
            )
        };
        probe().is_ok()
    }
    fn endpoint_checkpoint(
        &self,
        known: &sirinvpn_protocol::EndpointIdentity,
        private_key: &str,
        address: IpAddr,
    ) -> Result<Option<sirinvpn_protocol::EndpointTransitionResponse>> {
        Ok(tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(sirinvpn_core::discover_endpoint_checkpoint_at(
                known,
                private_key,
                address,
                Some(51_820),
            ))?)
    }

    fn offer_endpoint_checkpoint(
        &self,
        known: &sirinvpn_protocol::EndpointIdentity,
        head: &sirinvpn_protocol::EndpointTransitionResponse,
        private_key: &str,
        source: IpAddr,
    ) -> Result<bool> {
        Ok(tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(sirinvpn_core::offer_endpoint_checkpoint_at(
                known,
                head,
                private_key,
                source,
                Some(51_820),
            ))?)
    }
    fn endpoint_addresses_for_hosts(
        &self,
        hosts: &[&str],
        servers: &[SocketAddr],
    ) -> Vec<Vec<IpAddr>> {
        endpoint_resolution::resolve_hosts(hosts, servers)
    }
    fn endpoint_addresses(&self, host: &str, servers: &[SocketAddr]) -> Vec<IpAddr> {
        endpoint_resolution::resolve(host, servers)
    }
    fn output_with_timeout(
        &self,
        program: &str,
        arguments: &[&str],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        // Used only for the small service-state response. A stalled system bus
        // must not hold the app's status request indefinitely.
        let mut child = Command::new(program)
            .args(arguments)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        bail!("service status query failed");
                    }
                    let mut output = Vec::new();
                    io::Read::read_to_end(
                        &mut child
                            .stdout
                            .take()
                            .ok_or_else(|| anyhow!("missing query output"))?,
                        &mut output,
                    )?;
                    return Ok(output);
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!("service status query did not complete");
                }
            }
        }
    }
    fn run(&self, program: &str, arguments: &[&str], stdin: Option<&[u8]>) -> Result<()> {
        let mut command = Command::new(program);
        command
            .args(arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn()?;
        if let Some(bytes) = stdin {
            child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("command stdin is unavailable"))?
                .write_all(bytes)?;
        }
        let status = child.wait()?;
        if !status.success() {
            bail!("network command failed")
        }
        Ok(())
    }

    fn output(&self, program: &str, arguments: &[&str]) -> Result<Vec<u8>> {
        let output = Command::new(program)
            .args(arguments)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if !output.status.success() {
            bail!("network query failed")
        }
        Ok(output.stdout)
    }
}

pub fn require_root() -> Result<(), HelperError> {
    if nix::unistd::Uid::effective().is_root() {
        Ok(())
    } else {
        Err(HelperError::PermissionDenied)
    }
}

pub fn install_system_integration() -> Result<()> {
    require_root().map_err(anyhow::Error::from)?;
    let source = std::env::current_exe()?;
    let destination_directory = Path::new("/usr/lib/sirinvpn");
    fs::create_dir_all(destination_directory)?;
    fs::set_permissions(destination_directory, fs::Permissions::from_mode(0o755))?;
    let destination = destination_directory.join("sirinvpn-helper");
    let same_file = source.canonicalize().ok() == destination.canonicalize().ok();
    if !same_file {
        let temporary = destination.with_extension("new");
        fs::copy(&source, &temporary)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))?;
        fs::rename(temporary, &destination)?;
    }

    write_system_file(
        Path::new("/usr/share/polkit-1/actions/org.sirinvpn.network.policy"),
        POLKIT_POLICY,
    )?;
    write_system_file(
        Path::new("/usr/lib/NetworkManager/conf.d/90-sirinvpn-probe.conf"),
        include_str!("../../../packaging/networkmanager/90-sirinvpn-probe.conf"),
    )?;
    // Reload the new device rule without interrupting the physical network.
    // NetworkManager is optional (e.g. systemd-networkd installations).
    let _ = Command::new("systemctl")
        .args(["reload", "NetworkManager.service"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    write_system_file(
        Path::new("/usr/lib/systemd/system/sirinvpn-killswitch.service"),
        KILL_SWITCH_SERVICE,
    )?;
    write_system_file(
        Path::new("/usr/lib/systemd/system/sirinvpn-reconnect.service"),
        RECONNECT_SERVICE,
    )?;
    write_system_file(
        Path::new("/usr/lib/systemd/system/sirinvpn-transport.service"),
        TRANSPORT_SERVICE,
    )?;
    write_system_file(
        Path::new("/usr/lib/systemd/system/sirinvpn-transport@.service"),
        include_str!("../../../packaging/systemd/sirinvpn-transport@.service"),
    )?;
    let daemon_reload = Command::new("systemctl")
        .arg("daemon-reload")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !daemon_reload.success() {
        bail!("systemd did not accept the SirinVPN service definitions");
    }
    let runtime_state = Path::new("/run/sirinvpn/client-state.json");
    if runtime_state.exists() {
        fs::set_permissions(runtime_state, fs::Permissions::from_mode(0o644))?;
    }
    if Path::new("/var/lib/sirinvpn/desired-connection.json").exists() {
        let _ = Command::new("systemctl")
            .args(["try-restart", RECONNECT_UNIT])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    if std::env::var_os("PKEXEC_UID").is_some() {
        authorize_invoking_user()?;
    }
    Ok(())
}

pub fn run_transport_relay() -> Result<()> {
    run_transport_relay_for(None)
}

pub fn run_transport_relay_for(kind: Option<TransportKind>) -> Result<()> {
    require_root().map_err(anyhow::Error::from)?;
    let path = kind.map_or_else(
        || PathBuf::from("/run/sirinvpn/transport.json"),
        |kind| LinuxNetworkHelper::system().carrier_config_path(kind),
    );
    let bytes = Zeroizing::new(fs::read(path)?);
    let config: ClientTransportConfig = serde_json::from_slice(&bytes)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ready = || {
        let _ = Command::new("systemd-notify")
            .args(["--ready", "--status=Authenticated transport ready"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };
    match config {
        ClientTransportConfig::LegacyObfuscatedUdp(config) => {
            runtime.block_on(run_client_relay(config, ready))?
        }
        ClientTransportConfig::Current(CurrentClientTransportConfig::TcpFallback(config)) => {
            runtime.block_on(run_tcp_client_relay(config, ready))?
        }
        ClientTransportConfig::Current(CurrentClientTransportConfig::TlsLike(config)) => {
            runtime.block_on(run_tls_like_client_relay(config, ready))?
        }
    }
    Ok(())
}

pub(super) fn write_system_file(path: &Path, contents: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("system integration path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&temporary)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub fn read_connect_request() -> Result<TunnelConnectRequest> {
    let mut bytes = Zeroizing::new(Vec::new());
    io::Read::read_to_end(&mut io::stdin(), &mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub const POLKIT_POLICY: &str =
    include_str!("../../../packaging/polkit/org.sirinvpn.network.policy");

pub const KILL_SWITCH_SERVICE: &str =
    include_str!("../../../packaging/systemd/sirinvpn-killswitch.service");

pub const RECONNECT_SERVICE: &str =
    include_str!("../../../packaging/systemd/sirinvpn-reconnect.service");

pub const TRANSPORT_SERVICE: &str =
    include_str!("../../../packaging/systemd/sirinvpn-transport.service");
