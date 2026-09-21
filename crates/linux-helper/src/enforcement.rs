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
    let mut objects = vec![
        json!({"table": {"family": "inet", "name": TABLE}}),
        json!({"chain": {"family": "inet", "table": TABLE, "name": "output", "type": "filter",
            "hook": "output", "prio": 0, "policy": if request.routing.mode == TunnelRoutingMode::FullTunnel {"drop"} else {"accept"}}}),
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
    let mut carriers = vec![(request.transport, request.endpoint_port)];
    for candidate in &request.reconnect_candidates {
        let value = (candidate.transport, candidate.endpoint_port);
        if !carriers.contains(&value) {
            carriers.push(value);
        }
    }
    for (kind, port) in carriers {
        let protocol = match kind {
            TransportKind::TcpFallback | TransportKind::TlsLike => "tcp",
            _ => "udp",
        };
        rule(
            vec![
                eq(meta("mark"), json!(51820)),
                eq(
                    payload(if endpoint.is_ipv6() { "ip6" } else { "ip" }, "daddr"),
                    json!(endpoint.to_string()),
                ),
                eq(payload(protocol, "dport"), json!(port)),
            ],
            "accept",
        );
    }
    if let Some(identity) = &request.endpoint_identity {
        if let Some(port) = identity
            .descriptor
            .endpoint_discovery_port
            .or_else(|| identity.descriptor.tls_like.as_ref().map(|tls| tls.port))
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
    if request.routing.mode != TunnelRoutingMode::SelectedApplications
        && (request.routing.mode == TunnelRoutingMode::SelectedRoutes || request.routing.allow_lan)
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
    objects
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
        let objects = guard_objects_with_controls(request, endpoint, controls);
        let expected = objects.clone();
        // Adding an existing table/base chain keeps its hook registered. Never
        // delete/recreate a base chain during recovery: hook registration can
        // otherwise leave a packet gap despite an atomic ruleset transaction.
        let mut commands = vec![
            json!({"add": objects[0]}),
            json!({"add": objects[1]}),
            json!({"flush": {"chain": {"family":"inet", "table":TABLE, "name":"output"}}}),
        ];
        commands.extend(
            objects
                .into_iter()
                .skip(2)
                .map(|object| json!({"add":object})),
        );
        let input = serde_json::to_vec(&json!({"nftables": commands}))
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        // One rule transaction on the same base chain. Failure retains the old rules.
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
