//! Network policy.

use super::*;

pub(super) async fn sync_wireguard_peers(
    configuration: &ServerConfiguration,
    authorization: &AuthorizationDocument,
) -> Result<()> {
    let desired = authorization.desired_peers(unix_time());
    for peer in &desired {
        validate_wireguard_public_key(&peer.public_key)?;
        let IpAddr::V4(address) = peer.address else {
            bail!("only IPv4 SirinVPN peer addresses are supported");
        };
        let probe = authorization.measurement_leases.iter().any(|lease| {
            lease.public_key == peer.public_key
                && lease.address == address
                && lease.active(authorization, unix_time())
        });
        if !probe && (address.octets()[..3] != [10, 77, 0] || address.octets()[3] < 2) {
            bail!("WireGuard peer address is outside the SirinVPN tunnel");
        }
    }

    let output = diagnostics::output("wg", &["show", &configuration.interface_name, "peers"])
        .await
        .context("could not inspect WireGuard peers within its bounds")?;
    let current: HashSet<_> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    let desired_keys: HashSet<_> = desired.iter().map(|peer| peer.public_key.clone()).collect();

    let mut arguments = vec!["set".to_owned(), configuration.interface_name.clone()];
    let mut removed: Vec<_> = current.difference(&desired_keys).cloned().collect();
    removed.sort();
    for public_key in removed {
        arguments.extend(["peer".to_owned(), public_key, "remove".to_owned()]);
    }
    for peer in desired {
        let IpAddr::V4(address) = peer.address else {
            bail!("only IPv4 SirinVPN peer addresses are supported");
        };
        let allowed_ips = if address.octets()[..3] == [10, 77, 1] {
            format!("{address}/32")
        } else {
            peer_allowed_ips(
                authorization.server_id,
                address,
                configuration.ipv6_tunnel_enabled,
            )?
        };
        arguments.extend([
            "peer".to_owned(),
            peer.public_key,
            "allowed-ips".to_owned(),
            allowed_ips,
        ]);
    }
    if arguments.len() == 2 {
        return Ok(());
    }
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    diagnostics::output("wg", &arguments)
        .await
        .context("could not update WireGuard peers within its bounds")?;
    Ok(())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct PeerIsolationState {
    pub(super) ipv4: Vec<Ipv4Addr>,
    pub(super) ipv6: Vec<Ipv6Addr>,
}

pub(super) fn peer_isolation_state(
    configuration: &ServerConfiguration,
    authorization: &AuthorizationDocument,
) -> Result<PeerIsolationState> {
    let mut state = PeerIsolationState::default();
    for device in authorization.devices.iter().filter(|device| {
        device.peer_communication_enabled && authorization.access_for_device(device).is_some()
    }) {
        let IpAddr::V4(address) = device.client_tunnel_address else {
            bail!("only IPv4 SirinVPN peer addresses are supported");
        };
        state.ipv4.push(address);
        if configuration.ipv6_tunnel_enabled {
            state.ipv6.push(
                ipv6_tunnel_address(authorization.server_id, address)
                    .context("could not derive the peer IPv6 tunnel address")?,
            );
        }
    }
    state.ipv4.sort_unstable();
    state.ipv4.dedup();
    state.ipv6.sort_unstable();
    state.ipv6.dedup();
    Ok(state)
}

pub(super) fn peer_isolation_nft_batch(state: &PeerIsolationState) -> String {
    let mut batch = concat!(
        "flush set inet sirinvpn_filter peer_communication4\n",
        "flush set inet sirinvpn_filter peer_communication6\n",
    )
    .to_owned();
    if !state.ipv4.is_empty() {
        let addresses = state
            .ipv4
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        batch.push_str(&format!(
            "add element inet sirinvpn_filter peer_communication4 {{ {addresses} }}\n"
        ));
    }
    if !state.ipv6.is_empty() {
        let addresses = state
            .ipv6
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        batch.push_str(&format!(
            "add element inet sirinvpn_filter peer_communication6 {{ {addresses} }}\n"
        ));
    }
    batch
}

pub(super) async fn sync_peer_isolation(
    configuration: &ServerConfiguration,
    authorization: &AuthorizationDocument,
) -> Result<()> {
    let mut batch = enrollment_quarantine_nft_batch(configuration, authorization.server_id);
    batch.push_str(&handoff_guard_nft_batch(
        configuration,
        authorization.endpoint_transition_source,
    ));
    batch.push_str(&peer_isolation_nft_batch(&peer_isolation_state(
        configuration,
        authorization,
    )?));
    apply_nft_batch(&batch, "peer-isolation policy").await
}

/// A migrated source retains the pinned control channels for offline clients,
/// but cannot continue serving traffic with its frozen authorization snapshot.
/// A separate table survives replacement of the normal firewall rules.
pub(super) fn handoff_guard_nft_batch(configuration: &ServerConfiguration, source: bool) -> String {
    let mut batch = concat!(
        "add table inet sirinvpn_handoff\n",
        "add chain inet sirinvpn_handoff input { type filter hook input priority -31; policy accept; }\n",
        "add chain inet sirinvpn_handoff forward { type filter hook forward priority -31; policy accept; }\n",
        "flush chain inet sirinvpn_handoff input\n",
        "flush chain inet sirinvpn_handoff forward\n",
    ).to_owned();
    if source {
        let interface = &configuration.interface_name;
        let address = configuration.server_tunnel_address;
        let port = configuration.management_port;
        batch.push_str(&format!(concat!(
            "add rule inet sirinvpn_handoff input iifname \"{interface}\" ip daddr {address} tcp dport {port} accept\n",
            "add rule inet sirinvpn_handoff input iifname \"{interface}\" drop\n",
            "add rule inet sirinvpn_handoff forward iifname \"{interface}\" drop\n",
            "add rule inet sirinvpn_handoff forward oifname \"{interface}\" drop\n",
        ), interface = interface, address = address, port = port));
    }
    batch
}

/// Install before bringing up WireGuard, including on a migrated source reboot.
pub async fn install_network_guard(paths: &ServerPaths) -> Result<()> {
    let configuration = load_configuration(paths)?;
    if paths.authorization_required.exists() || fs::symlink_metadata(&paths.authorization).is_ok() {
        apply_nft_batch(
            &authorization_transaction::containment(&configuration, true),
            "startup authorization containment",
        )
        .await?;
    }
    let authorization = load_runtime_authorization(paths)?;
    let source = authorization
        .as_ref()
        .is_some_and(|document| document.endpoint_transition_source);
    apply_nft_batch(
        &handoff_guard_nft_batch(&configuration, source),
        "handoff guard",
    )
    .await
}

/// Temporary bearer identities can reach only enrollment over private mTLS.
/// Separate base chains also secure installations upgraded from older versions.
pub(super) fn enrollment_quarantine_nft_batch(
    configuration: &ServerConfiguration,
    server_id: ServerId,
) -> String {
    let interface = &configuration.interface_name;
    let server = configuration.server_tunnel_address;
    let port = configuration.management_port;
    let v6 = sirinvpn_protocol::ipv6_tunnel_address(server_id, Ipv4Addr::new(10, 77, 0, 224))
        .expect("fixed bootstrap address");
    format!(
        concat!(
            "add chain inet sirinvpn_filter enrollment_input {{ type filter hook input priority -30; policy accept; }}\n",
            "flush chain inet sirinvpn_filter enrollment_input\n",
            "add rule inet sirinvpn_filter enrollment_input iifname \"{interface}\" ip saddr 10.77.0.224/27 ip daddr {server} tcp dport {port} accept\n",
            "add rule inet sirinvpn_filter enrollment_input iifname \"{interface}\" ip saddr 10.77.0.224/27 drop\n",
            "add rule inet sirinvpn_filter enrollment_input iifname \"{interface}\" ip6 saddr {v6}/123 drop\n",
            "add chain inet sirinvpn_filter enrollment_forward {{ type filter hook forward priority -30; policy accept; }}\n",
            "flush chain inet sirinvpn_filter enrollment_forward\n",
            "add rule inet sirinvpn_filter enrollment_forward iifname \"{interface}\" ip saddr 10.77.0.224/27 drop\n",
            "add rule inet sirinvpn_filter enrollment_forward oifname \"{interface}\" ip daddr 10.77.0.224/27 drop\n",
            "add rule inet sirinvpn_filter enrollment_forward iifname \"{interface}\" ip6 saddr {v6}/123 drop\n",
            "add rule inet sirinvpn_filter enrollment_forward oifname \"{interface}\" ip6 daddr {v6}/123 drop\n",
        ),
        interface = interface,
        server = server,
        port = port,
        v6 = v6
    )
}

pub(super) fn validate_port_forward(
    configuration: &ServerConfiguration,
    operational: &OperationalConfiguration,
    forward: &PortForward,
) -> Result<()> {
    if forward.public_port < MIN_PORT_FORWARD_PUBLIC_PORT || forward.device_port == 0 {
        bail!("public ports must be 1024-65535 and device ports must be 1-65535");
    }
    if forward.public_port == DOH_PROXY_PORT {
        bail!("that public protocol and port is reserved by SirinVPN DNS");
    }
    let reserved = match forward.protocol {
        PortForwardProtocol::Tcp => {
            forward.public_port == operational.ssh_port
                || forward.public_port == configuration.management_port
                || configuration.endpoint_discovery_port == Some(forward.public_port)
                || configuration
                    .tcp_fallback
                    .as_ref()
                    .is_some_and(|endpoint| endpoint.port == forward.public_port)
                || configuration
                    .tls_like
                    .as_ref()
                    .is_some_and(|endpoint| endpoint.port == forward.public_port)
        }
        PortForwardProtocol::Udp => {
            forward.public_port == configuration.wireguard_port
                || configuration
                    .obfuscated_udp
                    .as_ref()
                    .is_some_and(|endpoint| endpoint.port == forward.public_port)
        }
    };
    if reserved {
        bail!("that public protocol and port is reserved by SSH or SirinVPN");
    }
    Ok(())
}

pub(super) fn port_forward_nft_batch(
    configuration: &ServerConfiguration,
    operational: Option<&OperationalConfiguration>,
    authorization: &AuthorizationDocument,
) -> Result<Option<String>> {
    let Some(operational) = operational else {
        if authorization.port_forwards.is_empty() {
            return Ok(None);
        }
        bail!("port forwarding requires repaired server operational configuration");
    };
    let mut forwards = authorization.port_forwards.clone();
    forwards.sort_by_key(|forward| (forward.protocol, forward.public_port));
    let mark = format!("{PORT_FORWARD_MARK:#x}");
    let mut batch = concat!(
        "flush chain inet sirinvpn_filter port_forward\n",
        "flush chain ip sirinvpn_nat port_forward_prerouting\n",
    )
    .to_owned();
    for forward in forwards
        .into_iter()
        .filter(|_| !authorization.endpoint_transition_source)
    {
        validate_port_forward(configuration, operational, &forward)?;
        let device = authorization
            .devices
            .iter()
            .find(|device| device.id == forward.device_id)
            .context("port forward references an unavailable device")?;
        if authorization.access_for_device(device).is_none() {
            continue;
        }
        let IpAddr::V4(address) = device.client_tunnel_address else {
            bail!("only IPv4 SirinVPN port-forward targets are supported");
        };
        batch.push_str(&format!(
            "add rule ip sirinvpn_nat port_forward_prerouting iifname \"{}\" {} dport {} ct mark set {mark} dnat to {address}:{}\n",
            operational.external_interface,
            forward.protocol,
            forward.public_port,
            forward.device_port,
        ));
        batch.push_str(&format!(
            "add rule inet sirinvpn_filter port_forward iifname \"{}\" oifname \"{}\" ct mark {mark} ip daddr {address} {} dport {} ct original proto-dst {} meta mark set {mark} accept\n",
            operational.external_interface,
            configuration.interface_name,
            forward.protocol,
            forward.device_port,
            forward.public_port,
        ));
    }
    Ok(Some(batch))
}

pub(super) async fn sync_port_forwards(
    configuration: &ServerConfiguration,
    operational: Option<&OperationalConfiguration>,
    authorization: &AuthorizationDocument,
) -> Result<()> {
    if let Some(batch) = port_forward_nft_batch(configuration, operational, authorization)? {
        apply_nft_batch(&batch, "port-forward policy").await?;
    }
    Ok(())
}

pub(super) async fn apply_nft_batch(batch: &str, description: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("could not stage {description}"))?;
        let mut stdin = child
            .stdin
            .take()
            .with_context(|| format!("could not open {description} input"))?;
        stdin
            .write_all(batch.as_bytes())
            .await
            .with_context(|| format!("could not apply {description}"))?;
        drop(stdin);
        let status = child
            .wait()
            .await
            .with_context(|| format!("could not finish {description}"))?;
        if !status.success() {
            bail!("could not apply {description}");
        }
        Ok(())
    })
    .await
    .context("firewall operation timed out")?
}

pub(super) fn peer_allowed_ips(
    server_id: ServerId,
    address: Ipv4Addr,
    ipv6_enabled: bool,
) -> Result<String> {
    if !ipv6_enabled {
        return Ok(format!("{address}/32"));
    }
    let ipv6_address = ipv6_tunnel_address(server_id, address)
        .context("could not derive the peer IPv6 tunnel address")?;
    Ok(format!("{address}/32,{ipv6_address}/128"))
}
