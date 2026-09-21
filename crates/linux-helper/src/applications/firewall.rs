use super::*;
use serde_json::{Value, json};

pub(super) const TABLE: &str = "sirinvpn_apps";

fn compare(left: Value, right: Value, op: &str) -> Value {
    json!({"match":{"op":op,"left":left,"right":right}})
}
fn interface(key: &str, value: &str) -> Value {
    compare(json!({"meta":{"key":key}}), json!(value), "==")
}
fn address(protocol: &str, field: &str, value: &str, op: &str) -> Value {
    compare(
        json!({"payload":{"protocol":protocol,"field":field}}),
        json!(value),
        op,
    )
}
fn chain(name: &str, kind: &str, hook: &str, priority: i32) -> Value {
    json!({"chain":{"family":"inet","table":TABLE,"name":name,
        "type":kind,"hook":hook,"prio":priority,"policy":"accept"}})
}
fn rule(objects: &mut Vec<Value>, chain: &str, mut expressions: Vec<Value>, verdict: Value) {
    expressions.push(verdict);
    objects.push(json!({"rule":{"family":"inet","table":TABLE,"chain":chain,"expr":expressions}}));
}

pub(super) fn objects(request: &TunnelConnectRequest) -> Vec<Value> {
    let mut out = vec![
        json!({"table":{"family":"inet","name":TABLE}}),
        chain("input", "filter", "input", -5),
        chain("forward", "filter", "forward", -5),
        chain("postrouting", "nat", "postrouting", 100),
    ];
    // Permit only IPv6 neighbour maintenance to the host itself. Its DNS stub,
    // proxies and other network services must not become an escape path.
    for kind in ["nd-neighbor-solicit", "nd-neighbor-advert"] {
        rule(
            &mut out,
            "input",
            vec![
                interface("iifname", HOST_LINK),
                compare(
                    json!({"payload":{"protocol":"ip6","field":"hoplimit"}}),
                    json!(255),
                    "==",
                ),
                compare(
                    json!({"payload":{"protocol":"icmpv6","field":"type"}}),
                    json!(kind),
                    "==",
                ),
            ],
            json!({"accept":null}),
        );
    }
    rule(
        &mut out,
        "input",
        vec![interface("iifname", HOST_LINK)],
        json!({"drop":null}),
    );
    for (family, source) in [("ip", APP4), ("ip6", APP6)] {
        rule(
            &mut out,
            "forward",
            vec![
                interface("iifname", HOST_LINK),
                address(family, "saddr", source, "!="),
            ],
            json!({"drop":null}),
        );
    }
    if request.client_ipv6_address.is_none() || !ipv6_forwarding_available() {
        rule(
            &mut out,
            "forward",
            vec![
                interface("iifname", HOST_LINK),
                compare(json!({"meta":{"key":"nfproto"}}), json!("ipv6"), "=="),
            ],
            json!({"drop":null}),
        );
    }
    rule(
        &mut out,
        "forward",
        vec![
            interface("iifname", HOST_LINK),
            interface("oifname", INTERFACE_NAME),
        ],
        json!({"accept":null}),
    );
    // A stale VPS address or resolver port must never fall back to an allowed LAN.
    rule(
        &mut out,
        "forward",
        vec![
            interface("iifname", HOST_LINK),
            address("ip", "daddr", &request.dns_address.to_string(), "=="),
        ],
        json!({"drop":null}),
    );
    for protocol in ["udp", "tcp"] {
        for port in [53, 853] {
            rule(
                &mut out,
                "forward",
                vec![
                    interface("iifname", HOST_LINK),
                    compare(
                        json!({"payload":{"protocol":protocol,"field":"dport"}}),
                        json!(port),
                        "==",
                    ),
                ],
                json!({"drop":null}),
            );
        }
    }
    if request.routing.allow_lan {
        for route in IPV4_LAN_ROUTES {
            let network: IpNet = route.parse().expect("static LAN CIDR");
            let destination = if network.prefix_len() == 32 {
                json!(network.addr().to_string())
            } else {
                json!({"prefix":{"addr":network.addr().to_string(),"len":network.prefix_len()}})
            };
            rule(
                &mut out,
                "forward",
                vec![
                    interface("iifname", HOST_LINK),
                    compare(
                        json!({"payload":{"protocol":"ip","field":"daddr"}}),
                        destination,
                        "==",
                    ),
                ],
                json!({"accept":null}),
            );
        }
    }
    rule(
        &mut out,
        "forward",
        vec![interface("iifname", HOST_LINK)],
        json!({"drop":null}),
    );
    for state in ["established", "related"] {
        rule(
            &mut out,
            "forward",
            vec![
                interface("oifname", HOST_LINK),
                compare(json!({"ct":{"key":"state"}}), json!(state), "=="),
            ],
            json!({"accept":null}),
        );
    }
    rule(
        &mut out,
        "forward",
        vec![interface("oifname", HOST_LINK)],
        json!({"drop":null}),
    );
    rule(
        &mut out,
        "postrouting",
        vec![
            interface("iifname", HOST_LINK),
            interface("oifname", INTERFACE_NAME),
            address("ip", "saddr", APP4, "=="),
        ],
        json!({"snat":{"family":"ip","addr":request.client_address.to_string()}}),
    );
    if let Some(address6) = request.client_ipv6_address {
        rule(
            &mut out,
            "postrouting",
            vec![
                interface("iifname", HOST_LINK),
                interface("oifname", INTERFACE_NAME),
                address("ip6", "saddr", APP6, "=="),
            ],
            json!({"snat":{"family":"ip6","addr":address6.to_string()}}),
        );
    }
    if request.routing.allow_lan {
        rule(
            &mut out,
            "postrouting",
            vec![
                interface("iifname", HOST_LINK),
                address("ip", "saddr", APP4, "=="),
            ],
            json!({"masquerade":null}),
        );
    }
    out
}

pub(super) fn transaction(objects: &[Value]) -> Vec<Value> {
    let mut commands = Vec::new();
    for object in objects {
        commands.push(json!({"add":object}));
        if let Some(chain) = object.get("chain") {
            commands.push(
                json!({"flush":{"chain":{"family":"inet","table":TABLE,"name":chain["name"]}}}),
            );
        }
    }
    commands
}
