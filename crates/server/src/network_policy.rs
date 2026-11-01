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
    for peer in &desired {
        arguments.extend([
            "peer".to_owned(),
            peer.public_key.clone(),
            "allowed-ips".to_owned(),
            desired_allowed_ips(
                peer,
                authorization.server_id,
                configuration.ipv6_tunnel_enabled,
            )?,
        ]);
    }
    if arguments.len() > 2 {
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        diagnostics::output("wg", &arguments)
            .await
            .context("could not update WireGuard peers within its bounds")?;
    }
    sync_subnet_kernel_routes(&configuration.interface_name, &desired).await?;
    sync_preshared_keys(&configuration.interface_name, &desired).await
}

/// A router peer also carries its live LAN ranges, so WireGuard sends them to it.
pub(super) fn desired_allowed_ips(
    peer: &DesiredPeer,
    server_id: ServerId,
    ipv6_enabled: bool,
) -> Result<String> {
    let IpAddr::V4(address) = peer.address else {
        bail!("only IPv4 SirinVPN peer addresses are supported");
    };
    let mut allowed_ips = if address.octets()[..3] == [10, 77, 1] {
        format!("{address}/32")
    } else {
        peer_allowed_ips(server_id, address, ipv6_enabled)?
    };
    for route in &peer.subnet_routes {
        allowed_ips.push(',');
        allowed_ips.push_str(route);
    }
    Ok(allowed_ips)
}

/// Ranges whose kernel route the last sync could not add. It mirrors the one VPS kernel.
static INACTIVE_SUBNET_ROUTES: std::sync::Mutex<BTreeSet<String>> =
    std::sync::Mutex::new(BTreeSet::new());

pub(super) fn inactive_subnet_routes() -> BTreeSet<String> {
    INACTIVE_SUBNET_ROUTES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// AllowedIPs pick the router peer; these routes send the LAN ranges into the tunnel at all.
/// `proto static` marks them as ours; `add` never takes over a route on another interface.
pub(super) async fn sync_subnet_kernel_routes(
    interface: &str,
    desired: &[DesiredPeer],
) -> Result<()> {
    let output = diagnostics::output(
        "ip",
        &["-4", "route", "show", "dev", interface, "proto", "static"],
    )
    .await
    .context("could not inspect subnet routes within its bounds")?;
    let (stale, missing) = subnet_kernel_route_changes(&output, desired);
    for route in &stale {
        diagnostics::output(
            "ip",
            &[
                "-4", "route", "delete", route, "dev", interface, "proto", "static",
            ],
        )
        .await
        .context("could not remove a subnet route within its bounds")?;
    }
    let mut inactive = BTreeSet::new();
    for route in missing {
        // A range that later collides with a VPS route stays inactive instead of failing
        // every commit and recovery, which would leave it impossible to remove.
        if diagnostics::output(
            "ip",
            &[
                "-4", "route", "add", &route, "dev", interface, "proto", "static",
            ],
        )
        .await
        .is_none()
        {
            inactive.insert(route);
        }
    }
    *INACTIVE_SUBNET_ROUTES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = inactive;
    Ok(())
}

/// Stale and missing routes, given `ip -4 route show dev <if> proto static`.
pub(super) fn subnet_kernel_route_changes(
    current: &str,
    desired: &[DesiredPeer],
) -> (Vec<String>, Vec<String>) {
    let current: BTreeSet<String> = current
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(|route| {
            if route.contains('/') {
                route.to_owned()
            } else {
                format!("{route}/32")
            }
        })
        .collect();
    let desired: BTreeSet<String> = desired
        .iter()
        .flat_map(|peer| peer.subnet_routes.iter().cloned())
        .collect();
    (
        current.difference(&desired).cloned().collect(),
        desired.difference(&current).cloned().collect(),
    )
}

/// A LAN range the VPS already routes elsewhere would be taken over or would hide the LAN.
pub(super) async fn vps_route_conflict(
    interface: &str,
    routes: &[String],
) -> Result<Option<String>> {
    if routes.is_empty() {
        return Ok(None);
    }
    let output = diagnostics::output("ip", &["-4", "-j", "route", "show", "table", "main"])
        .await
        .context("could not inspect VPS routes within its bounds")?;
    vps_route_overlap(&output, interface, routes)
}

pub(super) fn vps_route_overlap(
    output: &str,
    interface: &str,
    routes: &[String],
) -> Result<Option<String>> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(output).context("VPS routes are unreadable")?;
    Ok(entries
        .iter()
        .filter(|entry| entry["dev"].as_str() != Some(interface))
        .filter_map(|entry| entry["dst"].as_str())
        .find_map(|destination| sirinvpn_protocol::overlapping_subnet_route(destination, routes))
        .map(str::to_owned))
}

/// Keys travel on stdin, never in arguments visible to other local processes.
async fn sync_preshared_keys(interface: &str, desired: &[DesiredPeer]) -> Result<()> {
    if desired.is_empty() {
        return Ok(());
    }
    let current = Zeroizing::new(
        diagnostics::output("wg", &["show", interface, "preshared-keys"])
            .await
            .context("could not inspect WireGuard preshared keys within its bounds")?,
    );
    for (public_key, preshared_key) in preshared_key_updates(&current, desired) {
        let (path, input) = match preshared_key {
            Some(key) => ("/dev/stdin", Zeroizing::new(format!("{key}\n"))),
            None => ("/dev/null", Zeroizing::new(String::new())),
        };
        run_with_input(
            "wg",
            &["set", interface, "peer", public_key, "preshared-key", path],
            input.as_bytes(),
            "WireGuard preshared key update",
        )
        .await?;
    }
    Ok(())
}

/// Desired peers whose kernel preshared key differs, given `wg show <if> preshared-keys`.
pub(super) fn preshared_key_updates<'a>(
    current: &str,
    desired: &'a [DesiredPeer],
) -> Vec<(&'a str, Option<&'a str>)> {
    let current: HashMap<&str, &str> = current
        .lines()
        .filter_map(|line| line.trim().split_once('\t'))
        .collect();
    desired
        .iter()
        .filter(|peer| {
            let kernel = current
                .get(peer.public_key.as_str())
                .copied()
                .filter(|key| *key != "(none)");
            kernel != peer.preshared_key.as_deref()
        })
        .map(|peer| (peer.public_key.as_str(), peer.preshared_key.as_deref()))
        .collect()
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
///
/// It also confines tunnel sources outside the tunnel range (a subnet router's LAN
/// hosts) to answers back into the tunnel, also while the server is stopped.
pub(super) fn handoff_guard_nft_batch(configuration: &ServerConfiguration, source: bool) -> String {
    let interface = &configuration.interface_name;
    // The tunnel and its measurement probes (10.77.1.0/24); subnet routes never overlap it.
    let tunnel = "10.77.0.0/23";
    let mut batch = format!(
        concat!(
            "add table inet sirinvpn_handoff\n",
            "add chain inet sirinvpn_handoff input {{ type filter hook input priority -31; policy accept; }}\n",
            "add chain inet sirinvpn_handoff forward {{ type filter hook forward priority -31; policy accept; }}\n",
            "flush chain inet sirinvpn_handoff input\n",
            "flush chain inet sirinvpn_handoff forward\n",
            "add rule inet sirinvpn_handoff input iifname \"{interface}\" ip saddr != {tunnel} ct state != {{ established, related }} drop\n",
            "add rule inet sirinvpn_handoff forward iifname \"{interface}\" ip saddr != {tunnel} oifname != \"{interface}\" drop\n",
            "add rule inet sirinvpn_handoff forward iifname \"{interface}\" ip saddr != {tunnel} ct state != {{ established, related }} drop\n",
        ),
        interface = interface,
        tunnel = tunnel
    );
    if source {
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
                || configuration
                    .tls_like
                    .as_ref()
                    .is_some_and(|endpoint| endpoint.quic && endpoint.port == forward.public_port)
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
    let subnet_routes = subnet_route_nft_rules(configuration, authorization);
    let Some(operational) = operational else {
        if !authorization.port_forwards.is_empty() {
            bail!("port forwarding requires repaired server operational configuration");
        }
        return Ok(Some(format!(
            "flush chain inet sirinvpn_filter port_forward\n{subnet_routes}"
        )));
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
        // A forward that later collides with a reserved port stays inactive instead of failing
        // every commit and recovery, which would leave it impossible to remove.
        if validate_port_forward(configuration, operational, &forward).is_err() {
            continue;
        }
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
    batch.push_str(&subnet_routes);
    Ok(Some(batch))
}

/// `port_forward` is the runtime chain every installed forward chain jumps to before peer
/// isolation drops tunnel-to-tunnel traffic, so routes work without a firewall rewrite.
/// Peers that may reach each other reach the routers' LANs; LAN hosts only answer.
pub(super) fn subnet_route_nft_rules(
    configuration: &ServerConfiguration,
    authorization: &AuthorizationDocument,
) -> String {
    let mut routes: Vec<_> = authorization
        .devices
        .iter()
        .flat_map(|device| authorization.live_subnet_routes(device))
        .map(String::as_str)
        .collect();
    if routes.is_empty() {
        return String::new();
    }
    routes.sort_unstable();
    let routes = routes.join(", ");
    format!(
        concat!(
            "add rule inet sirinvpn_filter port_forward iifname \"{interface}\" oifname \"{interface}\" ip saddr @peer_communication4 ip daddr {{ {routes} }} accept\n",
            "add rule inet sirinvpn_filter port_forward iifname \"{interface}\" oifname \"{interface}\" ip saddr {{ {routes} }} ip daddr @peer_communication4 ct state established,related accept\n",
        ),
        interface = configuration.interface_name,
        routes = routes
    )
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
    run_with_input("nft", &["-f", "-"], batch.as_bytes(), description).await
}

async fn run_with_input(
    program: &str,
    arguments: &[&str],
    input: &[u8],
    description: &str,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut child = Command::new(program)
            .args(arguments)
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
            .write_all(input)
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
    .with_context(|| format!("{description} timed out"))?
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_peers_whose_kernel_preshared_key_differs_are_updated() {
        let peer = |name: &str, key: Option<&str>| DesiredPeer {
            public_key: name.to_owned(),
            address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
            preshared_key: key.map(str::to_owned),
            subnet_routes: Vec::new(),
        };
        let desired = [
            peer("same", Some("kept")),
            peer("changed", Some("new")),
            peer("added", Some("fresh")),
            peer("removed", None),
            peer("keyless", None),
            peer("unlisted", Some("late")),
        ];
        let current = "same\tkept\nchanged\told\nadded\t(none)\nremoved\tstale\nkeyless\t(none)\n";
        assert_eq!(
            preshared_key_updates(current, &desired),
            [
                ("changed", Some("new")),
                ("added", Some("fresh")),
                ("removed", None),
                ("unlisted", Some("late")),
            ]
        );
        assert!(preshared_key_updates("same\tkept\n", &desired[..1]).is_empty());
    }

    #[test]
    fn router_peers_carry_their_routes_and_the_kernel_routes_follow_them() {
        let server_id = ServerId::new();
        let router = DesiredPeer {
            public_key: "router".into(),
            address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
            preshared_key: None,
            subnet_routes: vec!["192.168.1.0/24".into(), "192.168.7.7/32".into()],
        };
        assert_eq!(
            desired_allowed_ips(&router, server_id, false).unwrap(),
            "10.77.0.2/32,192.168.1.0/24,192.168.7.7/32"
        );
        let ipv6 = ipv6_tunnel_address(server_id, Ipv4Addr::new(10, 77, 0, 2)).unwrap();
        assert_eq!(
            desired_allowed_ips(&router, server_id, true).unwrap(),
            format!("10.77.0.2/32,{ipv6}/128,192.168.1.0/24,192.168.7.7/32")
        );
        // `ip route show` prints host routes without /32.
        let current = "192.168.7.7 scope link\n10.20.0.0/20 scope link\n";
        assert_eq!(
            subnet_kernel_route_changes(current, std::slice::from_ref(&router)),
            (
                vec!["10.20.0.0/20".to_owned()],
                vec!["192.168.1.0/24".to_owned()]
            )
        );
        assert_eq!(
            subnet_kernel_route_changes("", &[]),
            (Vec::new(), Vec::new())
        );
    }

    #[test]
    fn existing_vps_routes_on_other_interfaces_conflict() {
        let output = r#"[{"dst":"default","gateway":"203.0.113.1","dev":"eth0"},
            {"dst":"203.0.113.0/24","dev":"eth0"},{"dst":"10.77.0.0/24","dev":"sirinvpn0"},
            {"dst":"192.168.5.0/24","dev":"sirinvpn0"},{"dst":"172.17.0.0/16","dev":"docker0"},
            {"type":"blackhole","dst":"10.9.9.9"}]"#;
        let routes = |list: &[&str]| {
            list.iter()
                .map(|route| route.to_string())
                .collect::<Vec<_>>()
        };
        let conflict =
            |list: &[&str]| vps_route_overlap(output, "sirinvpn0", &routes(list)).unwrap();
        assert_eq!(conflict(&["192.168.1.0/24", "192.168.5.0/24"]), None);
        assert_eq!(
            conflict(&["172.17.3.0/24"]).as_deref(),
            Some("172.17.3.0/24")
        );
        assert_eq!(conflict(&["10.9.0.0/20"]).as_deref(), Some("10.9.0.0/20"));
        assert!(vps_route_overlap("not json", "sirinvpn0", &routes(&["10.9.0.0/20"])).is_err());
    }
}
