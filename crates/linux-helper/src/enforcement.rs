//! Atomic, scoped nftables policy and short-lived privileged enforcement observations.
use super::*;
use serde_json::{Value, json};

const TABLE: &str = "sirinvpn_guard";

fn eq(left: Value, right: Value) -> Value {
    json!({"match": {"op": "==", "left": left, "right": right}})
}
fn meta(key: &str) -> Value {
    json!({"meta": {"key": key}})
}
fn payload(protocol: &str, field: &str) -> Value {
    json!({"payload": {"protocol": protocol, "field": field}})
}
fn prefix(cidr: &str) -> Value {
    let network: IpNet = cidr.parse().expect("validated CIDR");
    if matches!(network, IpNet::V4(_)) && network.prefix_len() == 32 {
        return json!(network.addr().to_string());
    }
    if matches!(network, IpNet::V6(_)) && network.prefix_len() == 128 {
        return json!(network.addr().to_string());
    }
    json!({"prefix": {"addr": network.addr().to_string(), "len": network.prefix_len()}})
}

/// These objects are both the installation plan and the exact inspection contract.
/// Extra rules/chains, reordered rules, changed verdicts, or inspection failure do
/// not pass verification. Handles and nft's version metadata are not policy.
pub(super) fn guard_objects(request: &TunnelConnectRequest, endpoint: IpAddr) -> Vec<Value> {
    guard_objects_with_controls(request, endpoint, &[])
}

fn guard_objects_with_controls(
    request: &TunnelConnectRequest,
    endpoint: IpAddr,
    controls: &[SocketAddr],
) -> Vec<Value> {
    // The forward chain always exists so every mode can add and flush it in the
    // same transaction; only full-tunnel mode gives it rules.
    let mut objects = vec![
        json!({"table": {"family": "inet", "name": TABLE}}),
        json!({"chain": {"family": "inet", "table": TABLE, "name": "output", "type": "filter",
            "hook": "output", "prio": 0, "policy": if request.routing.mode == TunnelRoutingMode::FullTunnel {"drop"} else {"accept"}}}),
        json!({"chain": {"family": "inet", "table": TABLE, "name": "forward", "type": "filter",
            "hook": "forward", "prio": 0, "policy": "accept"}}),
    ];
    let mut rule = |mut expressions: Vec<Value>, verdict: &str| {
        expressions.push(json!({verdict: null}));
        objects.push(json!({"rule": {"family": "inet", "table": TABLE, "chain": "output", "expr": expressions}}));
    };
    rule(vec![eq(meta("oifname"), json!("lo"))], "accept");
    rule(vec![eq(meta("oifname"), json!(INTERFACE_NAME))], "accept");
    // This separate peer can emit only private echo probes. It has no default
    // route and its source address cannot route ordinary application traffic.
    rule(
        vec![
            eq(meta("oifname"), json!("sirinprobe0")),
            eq(payload("ip", "saddr"), prefix("10.77.1.0/24")),
            eq(
                payload("ip", "daddr"),
                json!(request.dns_address.to_string()),
            ),
            eq(payload("icmp", "type"), json!("echo-request")),
        ],
        "accept",
    );
    // Only privileged, marked carrier sockets can use these exact validated
    // destinations. Keeping the configured candidates allows preparation without
    // replacing the active firewall or interrupting the old carrier.
    // HTTPS through a CDN may reach only the CDN address resolved for its signed name.
    let mut carriers = Vec::new();
    for (kind, port, https) in
        std::iter::once((request.transport, request.endpoint_port, &request.https)).chain(
            request.reconnect_candidates.iter().map(|candidate| {
                (
                    candidate.transport,
                    candidate.endpoint_port,
                    &candidate.https,
                )
            }),
        )
    {
        let destination = if https.as_ref().is_some_and(|https| https.cdn) {
            request.cdn_address
        } else {
            Some(endpoint)
        };
        if let Some(value) = destination.map(|address| (kind, port, address))
            && !carriers.contains(&value)
        {
            carriers.push(value);
        }
    }
    for (kind, port, destination) in carriers {
        let protocol = match kind {
            TransportKind::TcpFallback | TransportKind::TlsLike => "tcp",
            TransportKind::DirectUdp | TransportKind::ObfuscatedUdp | TransportKind::Quic => "udp",
        };
        rule(
            vec![
                eq(meta("mark"), json!(51820)),
                eq(
                    payload(if destination.is_ipv6() { "ip6" } else { "ip" }, "daddr"),
                    json!(destination.to_string()),
                ),
                eq(payload(protocol, "dport"), json!(port)),
            ],
            "accept",
        );
    }
    if let Some(identity) = &request.endpoint_identity {
        // While the session runs through a CDN, discovery goes there too (carrier rule).
        if let Some(port) = identity
            .descriptor
            .discovery_port(false)
            .filter(|_| !request.https.as_ref().is_some_and(|https| https.cdn))
        {
            rule(
                vec![
                    eq(meta("mark"), json!(51820)),
                    eq(
                        payload(if endpoint.is_ipv6() { "ip6" } else { "ip" }, "daddr"),
                        json!(endpoint.to_string()),
                    ),
                    eq(payload("tcp", "dport"), json!(port)),
                ],
                "accept",
            );
        }
        for server in &request.endpoint_dns_servers {
            for protocol in ["udp", "tcp"] {
                rule(
                    vec![
                        eq(meta("mark"), json!(51820)),
                        eq(
                            payload(if server.is_ipv6() { "ip6" } else { "ip" }, "daddr"),
                            json!(server.ip().to_string()),
                        ),
                        eq(payload(protocol, "dport"), json!(53)),
                    ],
                    "accept",
                );
            }
        }
    }
    for control in controls {
        rule(
            vec![
                eq(meta("mark"), json!(51820)),
                eq(
                    payload(if control.is_ipv6() { "ip6" } else { "ip" }, "daddr"),
                    json!(control.ip().to_string()),
                ),
                eq(payload("tcp", "dport"), json!(control.port())),
            ],
            "accept",
        );
    }
    // IPv6 link maintenance is necessary even when only the outer endpoint uses
    // IPv6. Restrict it to local discovery/router messages with the required hop limit.
    if endpoint.is_ipv6()
        || request.cdn_address.is_some_and(|address| address.is_ipv6())
        || request.endpoint_dns_servers.iter().any(SocketAddr::is_ipv6)
        || controls.iter().any(SocketAddr::is_ipv6)
    {
        rule(
            vec![
                eq(payload("ip6", "hoplimit"), json!(255)),
                eq(
                    payload("icmpv6", "type"),
                    json!({"set": ["nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert"]}),
                ),
            ],
            "accept",
        );
        rule(
            vec![
                eq(payload("udp", "sport"), json!(546)),
                eq(payload("udp", "dport"), json!(547)),
                eq(payload("ip6", "daddr"), json!("ff02::1:2")),
            ],
            "accept",
        );
    }
    rule(
        vec![
            eq(payload("udp", "sport"), json!(68)),
            eq(payload("udp", "dport"), json!(67)),
        ],
        "accept",
    );
    let subnet_routes = &request.subnet_routes;
    if request.routing.mode != TunnelRoutingMode::SelectedApplications
        && (request.routing.mode == TunnelRoutingMode::SelectedRoutes
            || request.routing.allow_lan
            || !subnet_routes.announced.is_empty())
    {
        rule(
            vec![eq(
                payload("ip", "daddr"),
                json!(request.dns_address.to_string()),
            )],
            "drop",
        );
        for protocol in ["udp", "tcp"] {
            for port in [53, 853] {
                rule(vec![eq(payload(protocol, "dport"), json!(port))], "drop");
            }
        }
    }
    // Another device's LAN never leaves locally; an announced LAN is this device's own.
    for route in &subnet_routes.reachable {
        rule(vec![eq(payload("ip", "daddr"), prefix(route))], "drop");
    }
    for route in &subnet_routes.announced {
        rule(vec![eq(payload("ip", "daddr"), prefix(route))], "accept");
    }
    if request.routing.allow_lan && request.routing.mode != TunnelRoutingMode::SelectedApplications
    {
        for (family, routes) in [
            ("ip", IPV4_LAN_ROUTES.as_slice()),
            ("ip6", IPV6_LAN_ROUTES.as_slice()),
        ] {
            for route in routes {
                rule(vec![eq(payload(family, "daddr"), prefix(route))], "accept");
            }
        }
    }
    if request.routing.mode == TunnelRoutingMode::SelectedRoutes {
        for route in &request.routing.included_routes {
            let family = if route.contains(':') { "ip6" } else { "ip" };
            rule(vec![eq(payload(family, "daddr"), prefix(route))], "drop");
        }
    }
    if request.routing.mode == TunnelRoutingMode::FullTunnel {
        // Containers, VMs and shared connections are forwarded, not output. Apply
        // the same tunnel-or-allowed-LAN policy to them while the tunnel is down.
        let mut forward = |mut expressions: Vec<Value>, verdict: &str| {
            expressions.push(json!({verdict: null}));
            objects.push(json!({"rule": {"family": "inet", "table": TABLE, "chain": "forward", "expr": expressions}}));
        };
        forward(vec![eq(meta("oifname"), json!(INTERFACE_NAME))], "accept");
        for state in ["established", "related"] {
            forward(
                vec![
                    eq(meta("iifname"), json!(INTERFACE_NAME)),
                    eq(json!({"ct": {"key": "state"}}), json!(state)),
                ],
                "accept",
            );
        }
        // The VPS sends only peers allowed to reach this router; it forwards them to its LAN.
        for route in &subnet_routes.announced {
            forward(
                vec![
                    eq(meta("iifname"), json!(INTERFACE_NAME)),
                    eq(payload("ip", "daddr"), prefix(route)),
                ],
                "accept",
            );
        }
        for route in &subnet_routes.reachable {
            forward(vec![eq(payload("ip", "daddr"), prefix(route))], "drop");
        }
        if request.routing.allow_lan {
            forward(
                vec![eq(
                    payload("ip", "daddr"),
                    json!(request.dns_address.to_string()),
                )],
                "drop",
            );
            for protocol in ["udp", "tcp"] {
                for port in [53, 853] {
                    forward(vec![eq(payload(protocol, "dport"), json!(port))], "drop");
                }
            }
            for (family, routes) in [
                ("ip", IPV4_LAN_ROUTES.as_slice()),
                ("ip6", IPV6_LAN_ROUTES.as_slice()),
            ] {
                for route in routes {
                    forward(vec![eq(payload(family, "daddr"), prefix(route))], "accept");
                }
            }
        }
        forward(Vec::new(), "drop");
    }
    objects
}

/// The boot guard's own small record, saved next to the full request. Boot protection
/// must not depend on the full request still validating after a helper upgrade.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct GuardSpec {
    schema_version: u16,
    pub(super) server_id: ServerId,
    pub(super) policy: ConnectionPolicy,
    pub(super) routing_mode: TunnelRoutingMode,
    pub(super) allow_lan: bool,
    /// Only for SelectedRoutes. Absent in specs from older helpers, whose boot fallback
    /// then blocks the whole host as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_routes: Option<SelectedRoutesGuard>,
}

/// What a SelectedRoutes guard drops; everything else it accepts. Both are already in the
/// world-readable runtime state, so the 0644 spec reveals nothing new. Other devices' LANs
/// are not, so a request that reaches any gets no record and blocks the whole host at boot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SelectedRoutesGuard {
    dns_address: Ipv4Addr,
    included_routes: Vec<String>,
}

impl GuardSpec {
    pub(super) fn for_request(request: &TunnelConnectRequest) -> Self {
        Self {
            schema_version: 1,
            server_id: request.server_id,
            policy: request.connection_policy(),
            routing_mode: request.routing.mode,
            allow_lan: request.routing.allow_lan,
            selected_routes: (request.routing.mode == TunnelRoutingMode::SelectedRoutes
                && request.subnet_routes.reachable.is_empty())
            .then(|| SelectedRoutesGuard {
                dns_address: request.dns_address,
                included_routes: request.routing.included_routes.clone(),
            }),
        }
    }

    pub(super) fn blocks_at_boot(&self) -> bool {
        self.policy.kill_switch && self.policy.connect_on_startup
    }
}

/// Used only when the saved request cannot be used: no carrier can be started, so no
/// carrier destination is allowed. Without a readable spec it blocks a full tunnel
/// without LAN. Selected applications never block the host, as their guard does not.
/// Selected routes drop only what their guard drops; a spec without those routes (from
/// an older helper) or with an unparsable one blocks the whole host instead.
pub(super) fn deny_all_guard_objects(spec: Option<&GuardSpec>) -> Option<Vec<Value>> {
    let (mode, allow_lan) = spec.map_or((TunnelRoutingMode::FullTunnel, false), |spec| {
        (spec.routing_mode, spec.allow_lan)
    });
    if mode == TunnelRoutingMode::SelectedApplications {
        return None;
    }
    if mode == TunnelRoutingMode::SelectedRoutes
        && let Some(routes) = spec.and_then(|spec| spec.selected_routes.as_ref())
        && let Some(objects) = selected_routes_boot_objects(routes, allow_lan)
    {
        return Some(objects);
    }
    let mut objects = vec![
        json!({"table": {"family": "inet", "name": TABLE}}),
        json!({"chain": {"family": "inet", "table": TABLE, "name": "output", "type": "filter",
            "hook": "output", "prio": 0, "policy": "drop"}}),
        json!({"chain": {"family": "inet", "table": TABLE, "name": "forward", "type": "filter",
            "hook": "forward", "prio": 0, "policy": "accept"}}),
    ];
    let mut rule = |chain: &str, mut expressions: Vec<Value>, verdict: &str| {
        expressions.push(json!({verdict: null}));
        objects.push(json!({"rule": {"family": "inet", "table": TABLE, "chain": chain, "expr": expressions}}));
    };
    rule("output", vec![eq(meta("oifname"), json!("lo"))], "accept");
    rule(
        "output",
        vec![eq(meta("oifname"), json!(INTERFACE_NAME))],
        "accept",
    );
    rule(
        "output",
        vec![
            eq(payload("ip6", "hoplimit"), json!(255)),
            eq(
                payload("icmpv6", "type"),
                json!({"set": ["nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert"]}),
            ),
        ],
        "accept",
    );
    rule(
        "output",
        vec![
            eq(payload("udp", "sport"), json!(546)),
            eq(payload("udp", "dport"), json!(547)),
            eq(payload("ip6", "daddr"), json!("ff02::1:2")),
        ],
        "accept",
    );
    rule(
        "output",
        vec![
            eq(payload("udp", "sport"), json!(68)),
            eq(payload("udp", "dport"), json!(67)),
        ],
        "accept",
    );
    if allow_lan {
        for (family, routes) in [
            ("ip", IPV4_LAN_ROUTES.as_slice()),
            ("ip6", IPV6_LAN_ROUTES.as_slice()),
        ] {
            for route in routes {
                rule(
                    "output",
                    vec![eq(payload(family, "daddr"), prefix(route))],
                    "accept",
                );
            }
        }
    }
    rule(
        "forward",
        vec![eq(meta("oifname"), json!(INTERFACE_NAME))],
        "accept",
    );
    rule("forward", Vec::new(), "drop");
    Some(objects)
}

/// The SelectedRoutes guard without any carrier: output accepts by default, the forward
/// chain stays empty, and DNS and the included routes are dropped
/// in the same order as `guard_objects`. Announced routes are not kept, so an overlap
/// with an included route is dropped: stricter, never more open.
fn selected_routes_boot_objects(
    routes: &SelectedRoutesGuard,
    allow_lan: bool,
) -> Option<Vec<Value>> {
    let valid = |list: &[String]| list.iter().all(|route| route.parse::<IpNet>().is_ok());
    if routes.included_routes.is_empty() || !valid(&routes.included_routes) {
        return None;
    }
    let family = |route: &str| if route.contains(':') { "ip6" } else { "ip" };
    let mut objects = vec![
        json!({"table": {"family": "inet", "name": TABLE}}),
        json!({"chain": {"family": "inet", "table": TABLE, "name": "output", "type": "filter",
            "hook": "output", "prio": 0, "policy": "accept"}}),
        json!({"chain": {"family": "inet", "table": TABLE, "name": "forward", "type": "filter",
            "hook": "forward", "prio": 0, "policy": "accept"}}),
    ];
    let mut rule = |mut expressions: Vec<Value>, verdict: &str| {
        expressions.push(json!({verdict: null}));
        objects.push(json!({"rule": {"family": "inet", "table": TABLE, "chain": "output", "expr": expressions}}));
    };
    rule(vec![eq(meta("oifname"), json!("lo"))], "accept");
    rule(vec![eq(meta("oifname"), json!(INTERFACE_NAME))], "accept");
    rule(
        vec![eq(
            payload("ip", "daddr"),
            json!(routes.dns_address.to_string()),
        )],
        "drop",
    );
    for protocol in ["udp", "tcp"] {
        for port in [53, 853] {
            rule(vec![eq(payload(protocol, "dport"), json!(port))], "drop");
        }
    }
    if allow_lan {
        for route in IPV4_LAN_ROUTES.iter().chain(IPV6_LAN_ROUTES.iter()) {
            rule(
                vec![eq(payload(family(route), "daddr"), prefix(route))],
                "accept",
            );
        }
    }
    for route in &routes.included_routes {
        rule(
            vec![eq(payload(family(route), "daddr"), prefix(route))],
            "drop",
        );
    }
    Some(objects)
}

pub(super) fn normalize_guard(output: &[u8]) -> Option<Vec<Value>> {
    let value: Value = serde_json::from_slice(output).ok()?;
    let mut objects = Vec::new();
    for object in value.get("nftables")?.as_array()? {
        if object.get("metainfo").is_some() {
            continue;
        }
        let mut object = object.clone();
        let map = object.as_object_mut()?;
        if map.len() != 1 {
            return None;
        }
        let (kind, value) = map.iter_mut().next()?;
        if !["table", "chain", "rule"].contains(&kind.as_str()) {
            return None;
        }
        let inner = value.as_object_mut()?;
        inner.remove("handle");
        objects.push(object);
    }
    Some(objects)
}

pub(super) fn boot_seconds() -> Option<u64> {
    fs::read_to_string("/proc/uptime")
        .ok()?
        .split('.')
        .next()?
        .parse()
        .ok()
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub(super) fn guard_is_absent(&self) -> Result<bool, HelperError> {
        let bytes = self
            .runner
            .output("nft", &["-j", "list", "tables"])
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| HelperError::NetworkOperationFailed)?;
        let objects = value
            .get("nftables")
            .and_then(Value::as_array)
            .ok_or(HelperError::NetworkOperationFailed)?;
        Ok(!objects.iter().any(|object| {
            object.get("table").is_some_and(|table| {
                table.get("family").and_then(Value::as_str) == Some("inet")
                    && table.get("name").and_then(Value::as_str) == Some(TABLE)
            })
        }))
    }

    pub(super) fn guard_is_verified(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
    ) -> bool {
        self.runner
            .output("nft", &["-j", "list", "table", "inet", TABLE])
            .ok()
            .and_then(|output| normalize_guard(&output))
            .is_some_and(|objects| objects == guard_objects(request, endpoint))
    }

    pub(super) fn apply_policy_guard(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
    ) -> Result<(), HelperError> {
        self.apply_policy_guard_with_controls(request, endpoint, &[])
    }

    pub(super) fn apply_policy_guard_with_controls(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
        controls: &[SocketAddr],
    ) -> Result<(), HelperError> {
        self.install_guard(guard_objects_with_controls(request, endpoint, controls))
    }

    /// The one installation path for every JSON guard: one transaction on the same base
    /// chains, then an exact read-back.
    pub(super) fn install_guard(&self, objects: Vec<Value>) -> Result<(), HelperError> {
        let expected = objects.clone();
        // Adding an existing table/base chain keeps its hook registered. Never
        // delete/recreate a base chain during recovery: hook registration can
        // otherwise leave a packet gap despite an atomic ruleset transaction.
        let mut commands = vec![
            json!({"add": objects[0]}),
            json!({"add": objects[1]}),
            json!({"add": objects[2]}),
            json!({"flush": {"chain": {"family":"inet", "table":TABLE, "name":"output"}}}),
            json!({"flush": {"chain": {"family":"inet", "table":TABLE, "name":"forward"}}}),
        ];
        commands.extend(
            objects
                .into_iter()
                .skip(3)
                .map(|object| json!({"add":object})),
        );
        let input = serde_json::to_vec(&json!({"nftables": commands}))
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        // One rule transaction on the same base chains. Failure retains the old rules.
        self.runner
            .run("nft", &["-j", "-f", "-"], Some(&input))
            .map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        if !self
            .runner
            .output("nft", &["-j", "list", "table", "inet", TABLE])
            .ok()
            .and_then(|output| normalize_guard(&output))
            .is_some_and(|objects| objects == expected)
        {
            return Err(HelperError::PersistentProtectionUnavailable);
        }
        Ok(())
    }

    pub(super) fn guard_spec_path(&self) -> PathBuf {
        self.persistent_directory.join("guard-spec.json")
    }

    /// Readable without privilege: status reports a saved session from it after reboot.
    /// It holds nothing the world-readable runtime state does not already show.
    pub(super) fn read_guard_spec(&self) -> Option<GuardSpec> {
        let bytes = fs::read(self.guard_spec_path()).ok()?;
        serde_json::from_slice::<GuardSpec>(&bytes)
            .ok()
            .filter(|spec| spec.schema_version == 1)
    }

    pub(super) fn observe_policy(
        &self,
        state: &mut RuntimeState,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
    ) {
        state.application_guard_verified = (request.routing.mode
            == TunnelRoutingMode::SelectedApplications)
            .then(|| self.application_configuration_exists(request));
        state.enforcement = Some(if !request.connection_policy().kill_switch {
            if self.guard_is_absent().unwrap_or(false) {
                KillSwitchState::Off
            } else {
                KillSwitchState::Unknown
            }
        } else if self.guard_is_verified(request, endpoint) {
            if state.has_connected && !state.reconnecting && !state.waiting_for_user {
                KillSwitchState::Armed
            } else {
                KillSwitchState::Blocking
            }
        } else {
            KillSwitchState::Failed
        });
        state.observed_at_boot_seconds = boot_seconds();
    }
}

impl RuntimeState {
    pub(super) fn effective_kill_switch(&self) -> KillSwitchState {
        if !self.observation_is_fresh() {
            return KillSwitchState::Unknown;
        }
        self.enforcement.unwrap_or(KillSwitchState::Unknown)
    }
    pub(super) fn observation_is_fresh(&self) -> bool {
        self.observed_at_boot_seconds
            .zip(boot_seconds())
            .is_some_and(|(observed, now)| now.checked_sub(observed).is_some_and(|age| age <= 15))
    }
}
