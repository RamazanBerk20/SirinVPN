use super::{check, condition, output, read_current};
use crate::ServerConfiguration;
use serde_json::Value;
use sirinvpn_protocol::{DiagnosticCheck, DiagnosticLevel};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) async fn inspect(config: &ServerConfiguration) -> Vec<DiagnosticCheck> {
    let port_args = ["show", &config.interface_name, "listen-port"];
    let key_args = ["show", &config.interface_name, "public-key"];
    let (port, key, routes, filter, nat4, nat6) = tokio::join!(
        output("wg", &port_args),
        output("wg", &key_args),
        output("ip", &["-j", "-4", "route", "show", "table", "main"]),
        output("nft", &["-j", "list", "table", "inet", "sirinvpn_filter"]),
        output("nft", &["-j", "list", "table", "ip", "sirinvpn_nat"]),
        async {
            if config.ipv6_tunnel_enabled {
                output("nft", &["-j", "list", "table", "ip6", "sirinvpn_nat6"]).await
            } else {
                None
            }
        },
    );
    let wireguard = port
        .as_deref()
        .and_then(|port| port.trim().parse::<u16>().ok())
        .zip(key.as_deref())
        .map(|(port, key)| {
            port == config.wireguard_port && key.trim() == config.wireguard_public_key
        });
    let routes = json(routes)
        .and_then(|value| route_state(&value, &config.interface_name, &config.tunnel_cidr));
    let filter = json(filter).and_then(|value| filter_state(&value, &config.interface_name));
    let nat4 =
        json(nat4).and_then(|value| nat_state(&value, "ip", "sirinvpn_nat", &config.tunnel_cidr));
    let mtu = read_current(format!("/sys/class/net/{}/mtu", config.interface_name))
        .and_then(|text| text.trim().parse::<u32>().ok());
    let min_mtu = if config.ipv6_tunnel_enabled {
        1280
    } else {
        576
    };
    let mut checks = vec![
        condition(
            "wireguard",
            "VPS WireGuard identity and port",
            wireguard,
            "The running WireGuard interface has the configured public identity and listening port.",
            "The running WireGuard identity or port differs from the saved configuration. Use server repair.",
        ),
        condition(
            "server_routes",
            "VPS routes",
            routes,
            "The main routing table has an external default route and the configured tunnel subnet route.",
            "The external default route or tunnel subnet route is missing. Check VPS networking and use server repair for the tunnel route.",
        ),
        condition(
            "server_firewall",
            "VPS firewall structure",
            filter,
            "SirinVPN input and forwarding hooks and tunnel isolation rules are present. Other firewall policies can still affect connectivity.",
            "SirinVPN firewall hooks or tunnel isolation rules are missing. Use server repair to restore its owned rules.",
        ),
        condition(
            "server_nat4",
            "VPS IPv4 NAT",
            nat4,
            "The source NAT hook contains a masquerade rule for the configured tunnel subnet.",
            "The configured tunnel subnet has no source masquerade rule. Use server repair to restore IPv4 NAT.",
        ),
        condition(
            "server_ports",
            "VPS listening ports",
            ports(config),
            "The configured VPN transports, private management and DNS ports have listening sockets. Provider firewall reachability requires a client connection.",
            "A configured VPN transport, private management or DNS listener is missing. Check server services or use server repair.",
        ),
        condition(
            "server_mtu",
            "VPS interface MTU",
            mtu.map(|mtu| (min_mtu..=65535).contains(&mtu)),
            "The VPS tunnel interface MTU meets the IP protocol minimum. Client path measurements determine the usable end-to-end MTU.",
            "The VPS tunnel interface MTU is below the IP protocol minimum. Use server repair.",
        ),
    ];
    if config.ipv6_tunnel_enabled {
        let state = ipv6_prefix(&config.interface_name)
            .zip(json(nat6))
            .and_then(|(prefix, value)| nat_state(&value, "ip6", "sirinvpn_nat6", &prefix));
        checks.push(condition("server_nat6", "VPS IPv6 NAT", state,
            "The source NAT hook contains a masquerade rule for the private IPv6 tunnel subnet.",
            "The private IPv6 tunnel subnet has no source masquerade rule. Use server repair to restore IPv6 NAT."));
    }
    checks.push(check("external_reachability", "Provider firewall and public reachability", DiagnosticLevel::Warning,
        "Listening sockets and local rules cannot establish public reachability. If a transport fails, check the VPS provider firewall and the configured public ports."));
    checks
}

fn json(text: Option<String>) -> Option<Value> {
    serde_json::from_str(&text?).ok()
}

fn ipv6_prefix(interface: &str) -> Option<String> {
    let text = read_current("/proc/net/if_inet6")?;
    text.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if *fields.get(5)? != interface || !fields.first()?.starts_with("fd") {
            return None;
        }
        let mut bytes: [u8; 16] = hex::decode(fields[0]).ok()?.try_into().ok()?;
        bytes[8..].fill(0);
        Some(format!("{}/64", Ipv6Addr::from(bytes)))
    })
}

fn route_state(value: &Value, interface: &str, subnet: &str) -> Option<bool> {
    let routes = value.as_array()?;
    let unicast = |row: &&Value| {
        row.get("type").is_none_or(|kind| kind == "unicast")
            && row
                .get("flags")
                .and_then(Value::as_array)
                .is_none_or(|flags| !flags.iter().any(|flag| flag == "linkdown"))
    };
    let default = routes.iter().filter(unicast).any(|row| {
        row["dst"] == "default"
            && row["dev"]
                .as_str()
                .is_some_and(|dev| dev != interface && dev != "lo")
    });
    let tunnel = routes
        .iter()
        .filter(unicast)
        .any(|row| row["dst"] == subnet && row["dev"] == interface);
    Some(default && tunnel)
}

fn hook(rows: &[Value], family: &str, table: &str, name: &str, kind: &str) -> bool {
    rows.iter().filter_map(|row| row.get("chain")).any(|chain| {
        chain["family"] == family
            && chain["table"] == table
            && chain["name"] == name
            && chain["hook"] == name
            && chain["type"] == kind
    })
}

fn matches(expr: &[Value], left: Value, op: &str, right: Value) -> bool {
    expr.iter().any(|item| {
        item.get("match")
            .is_some_and(|item| item["left"] == left && item["op"] == op && item["right"] == right)
    })
}

fn filter_state(value: &Value, interface: &str) -> Option<bool> {
    use serde_json::json;
    let rows = value["nftables"].as_array()?;
    let isolation = rows.iter().filter_map(|row| row.get("rule")).any(|rule| {
        let Some(expr) = rule["expr"].as_array() else {
            return false;
        };
        rule["family"] == "inet"
            && rule["table"] == "sirinvpn_filter"
            && rule["chain"] == "forward"
            && expr.iter().any(|item| item.get("drop").is_some())
            && matches(
                expr,
                json!({"meta":{"key":"iifname"}}),
                "==",
                json!(interface),
            )
            && matches(
                expr,
                json!({"meta":{"key":"oifname"}}),
                "==",
                json!(interface),
            )
    });
    Some(
        hook(rows, "inet", "sirinvpn_filter", "input", "filter")
            && hook(rows, "inet", "sirinvpn_filter", "forward", "filter")
            && isolation,
    )
}

fn nat_state(value: &Value, family: &str, table: &str, subnet: &str) -> Option<bool> {
    use serde_json::json;
    let rows = value["nftables"].as_array()?;
    let (address, prefix) = subnet.split_once('/')?;
    let prefix = prefix.parse::<u8>().ok()?;
    let masquerade = rows.iter().filter_map(|row| row.get("rule")).any(|rule| {
        let Some(expr) = rule["expr"].as_array() else {
            return false;
        };
        rule["family"] == family
            && rule["table"] == table
            && rule["chain"] == "postrouting"
            && expr.iter().any(|item| item.get("masquerade").is_some())
            && matches(
                expr,
                json!({"payload":{"protocol":family,"field":"saddr"}}),
                "==",
                json!({"prefix":{"addr":address,"len":prefix}}),
            )
    });
    Some(hook(rows, family, table, "postrouting", "nat") && masquerade)
}

fn ports(config: &ServerConfiguration) -> Option<bool> {
    let tcp = listeners("tcp", "0A")?;
    let udp = listeners("udp", "07")?;
    let private =
        |rows: &[(IpAddr, u16)], port| rows.contains(&(config.server_tunnel_address, port));
    let public = |rows: &[(IpAddr, u16)], port| {
        rows.iter().any(|(address, bound)| {
            *bound == port
                && (address.is_unspecified()
                    || (!address.is_loopback() && *address != config.server_tunnel_address))
        })
    };
    Some(
        private(&tcp, config.management_port)
            && private(&tcp, 53)
            && private(&udp, 53)
            && public(&udp, config.wireguard_port)
            && config
                .obfuscated_udp
                .as_ref()
                .is_none_or(|endpoint| public(&udp, endpoint.port))
            && config
                .tcp_fallback
                .as_ref()
                .is_none_or(|endpoint| public(&tcp, endpoint.port))
            && config
                .tls_like
                .as_ref()
                .is_none_or(|endpoint| public(&tcp, endpoint.port))
            && config
                .endpoint_discovery_port
                .is_none_or(|port| public(&tcp, port)),
    )
}

fn listeners(protocol: &str, state: &str) -> Option<Vec<(IpAddr, u16)>> {
    let v4 = read_current(format!("/proc/net/{protocol}"))?;
    let v6 = read_current(format!("/proc/net/{protocol}6"));
    let mut rows = parse_listeners(&v4, state)?;
    if let Some(v6) = v6 {
        rows.extend(parse_listeners(&v6, state)?);
    }
    Some(rows)
}

fn parse_listeners(text: &str, state: &str) -> Option<Vec<(IpAddr, u16)>> {
    let mut listeners = Vec::new();
    for line in text.lines().skip(1).filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if *fields.get(3)? != state {
            continue;
        }
        let (address, port) = fields.get(1)?.split_once(':')?;
        let mut address = hex::decode(address).ok()?;
        // Linux exposes each native-endian 32-bit address word in hexadecimal.
        if cfg!(target_endian = "little") {
            for word in address.chunks_exact_mut(4) {
                word.reverse();
            }
        }
        let ip = match address.len() {
            4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(address).ok()?)),
            16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(address).ok()?)),
            _ => return None,
        };
        listeners.push((ip, u16::from_str_radix(port, 16).ok()?));
    }
    Some(listeners)
}

#[cfg(test)]
mod tests;
