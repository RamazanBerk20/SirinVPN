//! Verification.

use super::*;

pub(super) fn install_verification_command(
    expected_binary_sha256: &str,
    bootstrap: &BootstrapOutput,
    server_id: ServerId,
    discovery: &ServerDiscovery,
) -> String {
    let obfuscated_udp = bootstrap
        .obfuscated_udp
        .as_ref()
        .expect("validated bootstrap output includes Obfuscated UDP");
    let tcp_fallback = bootstrap
        .tcp_fallback
        .as_ref()
        .expect("validated bootstrap output includes TCP fallback");
    let expected_certificate_sha256 = hex::encode(Sha256::digest(
        bootstrap.management_certificate_pem.as_bytes(),
    ));
    let dns_verification =
        unbound_dns_verification(&bootstrap.dns_upstream, &bootstrap.private_dns_records);
    let expected_operational_configuration = shell_quote(&format!(
        r#"{{"schema_version":1,"external_interface":"{}","ssh_port":{}}}"#,
        discovery.default_interface, discovery.ssh_server_port
    ));
    let doh_runtime_conditions = match bootstrap.dns_upstream.default_upstream() {
        DnsUpstream::DnsOverHttps { .. } => format!(
            r#"systemctl is-active --quiet sirinvpn-doh &&
  systemctl is-enabled --quiet sirinvpn-doh &&
  ss -H -lun 'sport = :{DOH_PROXY_PORT}' | grep -q '127.0.0.1:{DOH_PROXY_PORT}' &&
  ss -H -lnt 'sport = :{DOH_PROXY_PORT}' | grep -q '127.0.0.1:{DOH_PROXY_PORT}' &&"#,
        ),
        DnsUpstream::Recursive | DnsUpstream::DnsOverTls { .. } | DnsUpstream::Split { .. } => {
            format!(
                r#"! systemctl is-active --quiet sirinvpn-doh &&
  ! systemctl is-enabled --quiet sirinvpn-doh &&
  [ ! -e /etc/systemd/system/sirinvpn-doh.service ] &&
  ! ss -H -lun 'sport = :{DOH_PROXY_PORT}' | grep -q '127.0.0.1:{DOH_PROXY_PORT}' &&
  ! ss -H -lnt 'sport = :{DOH_PROXY_PORT}' | grep -q '127.0.0.1:{DOH_PROXY_PORT}' &&"#,
            )
        }
    };
    let ipv6_verification = if bootstrap.ipv6_tunnel_enabled {
        let server_ipv6 = ipv6_tunnel_address(server_id, Ipv4Addr::new(10, 77, 0, 1))
            .expect("built-in server address has an IPv6 mapping");
        let owner_ipv6 = ipv6_tunnel_address(server_id, Ipv4Addr::new(10, 77, 0, 2))
            .expect("built-in owner address has an IPv6 mapping");
        format!(
            r#"ip -o -6 address show dev sirinvpn0 | grep -Fq 'inet6 {server_ipv6}/64 '
nft list table ip6 sirinvpn_nat6 >/dev/null 2>&1
[ "$(sysctl -n net.ipv6.conf.all.forwarding)" = "1" ]
wg show sirinvpn0 allowed-ips | grep -Fq '{owner_ipv6}/128'"#,
        )
    } else {
        "! nft list table ip6 sirinvpn_nat6 >/dev/null 2>&1".to_owned()
    };
    format!(
        r#"set -eu
EXPECTED_BINARY_SHA256={expected_binary_sha256}
EXPECTED_CERTIFICATE_SHA256={expected_certificate_sha256}
EXPECTED_WIREGUARD_PUBLIC_KEY={expected_wireguard_public_key}
EXPECTED_WIREGUARD_PORT={expected_wireguard_port}
EXPECTED_OBFUSCATED_UDP_PORT={expected_obfuscated_udp_port}
EXPECTED_TCP_FALLBACK_PORT={expected_tcp_fallback_port}
EXPECTED_ENDPOINT_DISCOVERY_PORT={expected_endpoint_discovery_port}

/usr/local/lib/sirinvpn/sirinvpn-server --state-directory /etc/sirinvpn validate-state
unbound-checkconf /etc/unbound/unbound.conf >/dev/null
{dns_verification}
[ "$(sha256sum /usr/local/lib/sirinvpn/sirinvpn-server | cut -d' ' -f1)" = "$EXPECTED_BINARY_SHA256" ]
[ "$(sha256sum /etc/sirinvpn/management.crt | cut -d' ' -f1)" = "$EXPECTED_CERTIFICATE_SHA256" ]
[ "$(stat -c '%a:%U:%G' /usr/local/lib/sirinvpn/sirinvpn-server)" = "755:root:root" ]
[ "$(stat -c '%a:%U:%G' /etc/sirinvpn)" = "750:root:sirinvpn" ]
[ "$(stat -c '%a:%U:%G' /etc/sirinvpn/wireguard.key)" = "600:root:root" ]
for path in /etc/sirinvpn/server.json /etc/sirinvpn/management.crt /etc/sirinvpn/management.key /etc/sirinvpn/transport.key /etc/sirinvpn/authorization/authorization.json; do
  [ "$(stat -c '%a:%U:%G' "$path")" = "600:sirinvpn:sirinvpn" ]
done
if [ -e /etc/sirinvpn/https.key ]; then
  [ "$(stat -c '%a:%U:%G' /etc/sirinvpn/https.key)" = "600:sirinvpn:sirinvpn" ]
fi
[ "$(stat -c '%a:%U:%G' /etc/sirinvpn/authorization)" = "750:sirinvpn:sirinvpn" ]
[ "$(stat -c '%a:%U:%G' /etc/sirinvpn/authorization-required)" = "600:root:root" ]
[ "$(stat -c '%a:%U:%G' /etc/sirinvpn/owner.crt)" = "640:root:sirinvpn" ]
[ "$(stat -c '%a:%U:%G' /etc/sirinvpn/operational.json)" = "640:root:sirinvpn" ]
[ "$(cat /etc/sirinvpn/operational.json)" = {expected_operational_configuration} ]

attempt=0
until systemctl is-active --quiet sirinvpn-network sirinvpn-firewall unbound sirinvpn-server &&
  systemctl is-enabled --quiet sirinvpn-network sirinvpn-firewall unbound sirinvpn-server &&
  {doh_runtime_conditions}
  ip -o -4 address show dev sirinvpn0 | grep -q 'inet 10.77.0.1/24 ' &&
  [ "$(wg show sirinvpn0 public-key)" = "$EXPECTED_WIREGUARD_PUBLIC_KEY" ] &&
  [ "$(wg show sirinvpn0 listen-port)" = "$EXPECTED_WIREGUARD_PORT" ] &&
  nft list table inet sirinvpn_filter >/dev/null 2>&1 &&
  nft list table inet sirinvpn_handoff >/dev/null 2>&1 &&
  nft list set inet sirinvpn_filter peer_communication4 >/dev/null 2>&1 &&
  nft list set inet sirinvpn_filter peer_communication6 >/dev/null 2>&1 &&
  nft list chain inet sirinvpn_filter port_forward >/dev/null 2>&1 &&
  nft list chain ip sirinvpn_nat port_forward_prerouting >/dev/null 2>&1 &&
  nft list chain inet sirinvpn_filter input | grep -Fq "udp dport $EXPECTED_OBFUSCATED_UDP_PORT accept" &&
  nft list chain inet sirinvpn_filter input | grep -Fq "tcp dport $EXPECTED_TCP_FALLBACK_PORT accept" &&
  nft list chain inet sirinvpn_filter input | grep -Fq "tcp dport $EXPECTED_ENDPOINT_DISCOVERY_PORT accept" &&
  nft list chain inet sirinvpn_filter forward | grep -Fq 'jump port_forward' &&
  nft list chain inet sirinvpn_filter forward | grep -Fq 'ct mark 0x5356504e drop' &&
  nft list chain inet sirinvpn_filter forward | grep -Fq 'iifname "{verification_external_interface}" meta nfproto ipv4 oifname "sirinvpn0" drop' &&
  nft list chain inet sirinvpn_filter forward | grep -Fq 'ip saddr @peer_communication4 ip daddr @peer_communication4 accept' &&
  nft list chain inet sirinvpn_filter forward | grep -Fq 'ip6 saddr @peer_communication6 ip6 daddr @peer_communication6 accept' &&
  grep -Fxq 'ExecStopPost=+/etc/sirinvpn/firewall.sh isolate-runtime' /etc/systemd/system/sirinvpn-server.service &&
  nft list table ip sirinvpn_nat >/dev/null 2>&1 &&
  nft list chain ip sirinvpn_nat postrouting | grep -Fq 'ct mark 0x5356504e masquerade' &&
  [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ] &&
  ss -H -lun 'sport = :53' | grep -q '10.77.0.1:53' &&
  ss -H -lun "sport = :$EXPECTED_OBFUSCATED_UDP_PORT" | grep -q ":$EXPECTED_OBFUSCATED_UDP_PORT" &&
  ss -H -lnt "sport = :$EXPECTED_TCP_FALLBACK_PORT" | grep -q ":$EXPECTED_TCP_FALLBACK_PORT" &&
  ss -H -lnt "sport = :$EXPECTED_ENDPOINT_DISCOVERY_PORT" | grep -q ":$EXPECTED_ENDPOINT_DISCOVERY_PORT" &&
  ss -H -lnt 'sport = :8443' | grep -q '10.77.0.1:8443'; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 15 ] || exit 1
  sleep 1
done

{ipv6_verification}"#,
        expected_binary_sha256 = shell_quote(expected_binary_sha256),
        expected_certificate_sha256 = shell_quote(&expected_certificate_sha256),
        expected_wireguard_public_key = shell_quote(&bootstrap.wireguard_public_key),
        expected_wireguard_port = bootstrap.wireguard_port,
        expected_obfuscated_udp_port = obfuscated_udp.port,
        expected_tcp_fallback_port = tcp_fallback.port,
        expected_endpoint_discovery_port = bootstrap
            .endpoint_transition
            .as_ref()
            .and_then(|head| head.claims.endpoint_discovery_port)
            .unwrap_or(tcp_fallback.port),
        dns_verification = dns_verification,
        doh_runtime_conditions = doh_runtime_conditions,
        ipv6_verification = ipv6_verification,
        expected_operational_configuration = expected_operational_configuration,
        verification_external_interface = discovery.default_interface,
    )
}
