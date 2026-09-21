use super::*;
use std::collections::HashMap;

pub(super) fn inspection_command(ports: &[RequiredPort]) -> String {
    let mut numbers = ports
        .iter()
        .map(|port| port.port)
        .chain([53, 8443])
        .collect::<Vec<_>>();
    numbers.sort_unstable();
    numbers.dedup();
    let filter = format!(
        "( {} )",
        numbers
            .iter()
            .map(|port| format!("sport = :{port}"))
            .collect::<Vec<_>>()
            .join(" or ")
    );
    format!(
        r#"set -eu
printf '\036ssh\n'
printf '%s' "${{SSH_CONNECTION:-}}" | awk '{{print $3}}'
printf '\036addresses\n'
ip -j address show
printf '\036routes\n'
ip -j -4 route show table main
printf '\036links\n'
ip -j -details link show
printf '\036listeners\n'
ss -H -lntup {filter}
printf '\036wireguard\n'
if command -v wg >/dev/null 2>&1; then wg show all listen-port; fi
printf '\036nftables\n'
if command -v nft >/dev/null 2>&1; then nft -j list tables; else printf '{{"nftables":[]}}\n'; fi
printf '\036firewall_services\n'
for service in docker ufw firewalld; do
  if systemctl is-active --quiet "$service"; then printf '%s\n' "$service"; fi
done
printf '\036legacy_policies\n'
for program in iptables ip6tables; do
  if command -v "$program" >/dev/null 2>&1; then
    "$program" -S INPUT | head -n 1
    "$program" -S FORWARD | head -n 1
  fi
done
printf '\036end\n'
"#,
        filter = shell_quote(&filter)
    )
}

pub(super) fn sections(output: &str) -> anyhow::Result<HashMap<&str, &str>> {
    if output.len() > 512 * 1024 {
        bail!("network inspection exceeded its size limit");
    }
    let names = [
        "ssh",
        "addresses",
        "routes",
        "links",
        "listeners",
        "wireguard",
        "nftables",
        "firewall_services",
        "legacy_policies",
        "end",
    ];
    let mut parsed = HashMap::new();
    for section in output
        .split('\x1e')
        .filter(|section| !section.trim().is_empty())
    {
        let (name, body) = section
            .split_once('\n')
            .ok_or_else(|| anyhow!("invalid inspection framing"))?;
        if !names.contains(&name) || parsed.insert(name, body.trim()).is_some() {
            bail!("invalid or duplicate inspection section");
        }
    }
    if parsed.len() != names.len() {
        bail!("incomplete network inspection");
    }
    Ok(parsed)
}

pub(super) fn check_firewalls_and_links(
    discovery: &ServerDiscovery,
    report: &mut NetworkPreflight,
    sections: &HashMap<&str, &str>,
) -> anyhow::Result<()> {
    let links: serde_json::Value = serde_json::from_str(sections["links"])?;
    for link in links
        .as_array()
        .ok_or_else(|| anyhow!("invalid network links"))?
    {
        let Some(name) = field(link, "ifname") else {
            continue;
        };
        if !valid_interface(name) {
            bail!("invalid network link name");
        }
        if name == INTERFACE_NAME {
            if !discovery.sirinvpn_installed {
                report.issue(true, "reserved_interface", "The interface sirinvpn0 already exists without an installed SirinVPN server. Resolve its ownership before installing.".into());
            }
        } else if link
            .get("linkinfo")
            .and_then(|info| field(info, "info_kind"))
            .is_some_and(|kind| ["wireguard", "tun", "tap"].contains(&kind))
        {
            report.issue(false, "existing_vpn", format!("VPN interface {name} is already present. Its routes and firewall rules are preserved; check coexistence with SirinVPN."));
        }
    }
    let tables: serde_json::Value = serde_json::from_str(sections["nftables"])?;
    let foreign = tables
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("invalid firewall table response"))?
        .iter()
        .filter_map(|entry| entry.get("table"))
        .any(|table| {
            field(table, "name").is_none_or(|name| {
                ![
                    "sirinvpn_filter",
                    "sirinvpn_nat",
                    "sirinvpn_nat6",
                    "sirinvpn_handoff",
                ]
                .contains(&name)
            })
        });
    if foreign {
        report.issue(false, "existing_firewall", "Other nftables tables are active. SirinVPN preserves them; existing input or forwarding restrictions may also need to permit the listed ports and tunnel network.".into());
    }
    for service in sections["firewall_services"]
        .lines()
        .filter(|line| !line.is_empty())
    {
        if !["docker", "ufw", "firewalld"].contains(&service) {
            bail!("invalid firewall service response");
        }
        report.issue(false, "firewall_service", format!("{service} is active. Its configuration is preserved. SirinVPN adds scoped Docker forwarding rules when DOCKER-USER exists; verify any additional firewall policy."));
    }
    if sections["legacy_policies"]
        .lines()
        .any(|line| ["-P INPUT DROP", "-P FORWARD DROP"].contains(&line.trim()))
    {
        report.issue(false, "firewall_drop_policy", "An existing IPv4/IPv6 input or forwarding policy drops traffic by default. Add matching allowances in that firewall if the provider ports are open but VPN traffic remains blocked.".into());
    }
    Ok(())
}
