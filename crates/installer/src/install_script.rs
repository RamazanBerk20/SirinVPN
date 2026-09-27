//! Install script.

use super::*;

pub(super) fn install_script(
    request: &InstallRequest,
    discovery: &ServerDiscovery,
    remote_binary: &str,
    remote_owner: &str,
    nonce: &str,
    transaction: InstallTransaction<'_>,
    artifact: &release_guard::PreparedArtifact,
) -> String {
    let transport_init_arguments = format!(
        "{}{}",
        request.transport.init_arguments(),
        request
            .transport
            .endpoint_arguments(&request.target.host, transaction.expected_profile)
    );
    let discovery_port = transaction
        .endpoint_discovery_port
        .unwrap_or(request.transport.tcp_tls_port);
    let discovery_firewall_rule = if discovery_port == request.transport.tcp_tls_port {
        String::new()
    } else {
        format!("    tcp dport {discovery_port} accept\n")
    };
    let client_public_key = shell_quote(&request.identity.wireguard_public_key);
    let dns_init_arguments =
        server_dns_init_arguments(&request.dns_upstream, &request.private_dns_records);
    let (unbound_tls_configuration, unbound_forward_zone) =
        unbound_dns_configuration(&request.dns_upstream, &request.private_dns_records);
    let doh_endpoints = request.dns_upstream.doh_endpoints();
    let doh_service_network_policy = doh_endpoints.map_or_else(
        || "IPAddressDeny=any\nIPAddressAllow=127.0.0.1".to_owned(),
        |endpoints| {
            let mut lines = vec![
                "IPAddressDeny=any".to_owned(),
                "IPAddressAllow=127.0.0.1".to_owned(),
            ];
            for endpoint in endpoints {
                lines.push(format!("IPAddressAllow={}", endpoint.address));
            }
            lines.join("\n")
        },
    );
    let doh_service_unit = doh_endpoints.map_or_else(String::new, |_| {
        format!(
            r#"cat >/etc/systemd/system/sirinvpn-doh.service <<'UNIT'
[Unit]
Description=SirinVPN DNS-over-HTTPS upstream proxy
Requires=sirinvpn-network.service
After=sirinvpn-network.service
Before=unbound.service
[Service]
Type=simple
User=sirinvpn
Group=sirinvpn
ExecStart=/usr/local/lib/sirinvpn/sirinvpn-server doh-proxy
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
{doh_service_network_policy}
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
UNIT"#,
        )
    });
    let unbound_unit_dependencies = if doh_endpoints.is_some() {
        "Requires=sirinvpn-network.service sirinvpn-doh.service\nAfter=sirinvpn-network.service sirinvpn-doh.service"
    } else {
        "Requires=sirinvpn-network.service\nAfter=sirinvpn-network.service"
    };
    let doh_service_activation = if doh_endpoints.is_some() {
        "systemctl enable sirinvpn-doh >/dev/null\nsystemctl restart sirinvpn-doh"
    } else {
        "systemctl disable --now sirinvpn-doh >/dev/null 2>&1 || true\nrm -f /etc/systemd/system/sirinvpn-doh.service\nsystemctl daemon-reload"
    };
    let doh_port_preflight = if doh_endpoints.is_some() {
        format!(
            r#"if ss -H -lun "sport = :{DOH_PROXY_PORT}" | grep -q . || ss -H -lnt "sport = :{DOH_PROXY_PORT}" | grep -q .; then
  if ! systemctl is-active --quiet sirinvpn-doh; then
    echo "DNS-over-HTTPS loopback port {DOH_PROXY_PORT} is already owned by another service; refusing to replace it" >&2
    exit 1
  fi
fi"#,
        )
    } else {
        String::new()
    };
    let external_interface = format!("\"{}\"", discovery.default_interface);
    let ipv6_interface = discovery
        .ipv6_default_interface
        .as_deref()
        .unwrap_or(&discovery.default_interface);
    let ipv6_external_interface = format!("\"{ipv6_interface}\"");
    let ipv6_cidr = ipv6_tunnel_cidr(request.server_id);
    let server_ipv6_address = ipv6_tunnel_address(request.server_id, Ipv4Addr::new(10, 77, 0, 1))
        .expect("built-in server address has an IPv6 mapping");
    let bootstrap_ipv6_address =
        ipv6_tunnel_address(request.server_id, Ipv4Addr::new(10, 77, 0, 224))
            .expect("built-in bootstrap address has an IPv6 mapping");
    let IpAddr::V4(owner_ipv4_address) = transaction.owner_client_tunnel_address else {
        unreachable!("validated owner tunnel address must be IPv4")
    };
    let owner_ipv6_address = ipv6_tunnel_address(request.server_id, owner_ipv4_address)
        .expect("built-in owner address has an IPv6 mapping");
    let ipv6_enabled = if transaction.ipv6_tunnel_enabled {
        "1"
    } else {
        "0"
    };
    let ipv6_init_argument = if transaction.ipv6_tunnel_enabled {
        "--ipv6-tunnel-enabled true"
    } else {
        ""
    };
    let owner_allowed_ips = if transaction.ipv6_tunnel_enabled {
        format!("{owner_ipv4_address}/32,{owner_ipv6_address}/128")
    } else {
        format!("{owner_ipv4_address}/32")
    };
    let ipv6_network_address = if transaction.ipv6_tunnel_enabled {
        format!("    ip -6 address replace {server_ipv6_address}/64 dev sirinvpn0 nodad")
    } else {
        String::new()
    };
    let ipv6_input_rules = if transaction.ipv6_tunnel_enabled {
        format!(
            r#"    iifname != "sirinvpn0" ip6 daddr {server_ipv6_address} udp dport 53 drop
    iifname != "sirinvpn0" ip6 daddr {server_ipv6_address} tcp dport 53 drop"#,
        )
    } else {
        String::new()
    };
    let ipv6_forward_rules = if transaction.ipv6_tunnel_enabled {
        format!(
            r#"    iifname "sirinvpn0" meta nfproto ipv6 oifname {ipv6_external_interface} accept
    iifname {ipv6_external_interface} meta nfproto ipv6 oifname "sirinvpn0" ct state established,related accept"#,
        )
    } else {
        String::new()
    };
    let ipv6_nat_table = if transaction.ipv6_tunnel_enabled {
        format!(
            r#"table ip6 sirinvpn_nat6 {{
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip6 saddr {ipv6_cidr} oifname {ipv6_external_interface} masquerade
  }}
}}"#,
        )
    } else {
        String::new()
    };
    let ipv6_unbound = if transaction.ipv6_tunnel_enabled {
        format!(
            "  interface: {server_ipv6_address}\n  access-control: ::/0 refuse\n  access-control: {ipv6_cidr} allow"
        )
    } else {
        String::new()
    };
    let ipv6_sysctl = if transaction.ipv6_tunnel_enabled {
        format!("net/ipv6/conf/{ipv6_interface}/accept_ra=2\nnet.ipv6.conf.all.forwarding=1")
    } else {
        String::new()
    };
    let ipv6_accept_ra_backup = if transaction.ipv6_tunnel_enabled {
        format!(
            "cat /proc/sys/net/ipv6/conf/{ipv6_interface}/accept_ra >\"$BACKUP_DIR/ipv6_accept_ra\""
        )
    } else {
        String::new()
    };
    let ipv6_accept_ra_restore = if transaction.ipv6_tunnel_enabled {
        format!(
            r#"if [ -s "$BACKUP_DIR/ipv6_accept_ra" ]; then
  sysctl -q -w "net/ipv6/conf/{ipv6_interface}/accept_ra=$(cat "$BACKUP_DIR/ipv6_accept_ra")"
fi"#,
        )
    } else {
        String::new()
    };
    let binary = "\"$STAGED_BINARY\"";
    let owner = shell_quote(remote_owner);
    let server_name = shell_quote(&request.server_name);
    let server_id = shell_quote(&request.server_id.to_string());
    let manage_existing_user =
        if request.replace_existing_installation || discovery.sirinvpn_installed {
            "1"
        } else {
            "0"
        };
    let replacement = if request.replace_existing_installation {
        r#"# Explicit SSH-authorized SirinVPN identity replacement.
for unit in sirinvpn-server sirinvpn-doh sirinvpn-firewall sirinvpn-network; do
  if systemctl cat "$unit.service" >/dev/null 2>&1; then
    systemctl stop "$unit.service"
  fi
done
rm -f -- /etc/sirinvpn/server.json /etc/sirinvpn/management.crt /etc/sirinvpn/management.key /etc/sirinvpn/wireguard.key /etc/sirinvpn/transport.key /etc/sirinvpn/https.key /etc/sirinvpn/authorization-required
rm -rf -- /etc/sirinvpn/authorization
"#
    } else {
        ""
    };
    let restore_stdin_setup = if transaction.restore_snapshot.is_some() {
        "exec 3<&0\nexec </dev/null"
    } else {
        ""
    };
    let restore_state = if transaction.restore_snapshot.is_some() {
        format!(
            "/usr/local/lib/sirinvpn/sirinvpn-server restore-state --server-id {server_id} --owner-certificate /etc/sirinvpn/owner.crt <&3\nexec 3<&-"
        )
    } else {
        String::new()
    };

    format!(
        r#"#!/bin/sh
set -eu
umask 077
{restore_stdin_setup}

printf '%s\n' 'SIRINVPN_INSTALL_STEP=recovery'
for pending in /run/sirinvpn-rollback-*.sh /run/sirinvpn-uninstall-rollback-*.sh /var/lib/sirinvpn-maintenance/sirinvpn-rollback-*.sh /var/lib/sirinvpn-maintenance/sirinvpn-uninstall-rollback-*.sh; do
  [ -f "$pending" ] || continue
  /bin/sh "$pending"
done

printf '%s\n' 'SIRINVPN_INSTALL_STEP=guards'
{maintenance_begin}
printf '%s\n' 'SIRINVPN_INSTALL_STEP=staged_server'
{artifact_preflight}

printf '%s\n' 'SIRINVPN_INSTALL_STEP=dependencies'
set --
command -v wg >/dev/null 2>&1 || set -- "$@" wireguard-tools
command -v nft >/dev/null 2>&1 || set -- "$@" nftables
command -v unbound >/dev/null 2>&1 || set -- "$@" unbound
test -s /usr/share/dns/root.key || set -- "$@" dns-root-data
command -v ip >/dev/null 2>&1 || set -- "$@" iproute2
test -s /etc/ssl/certs/ca-certificates.crt || set -- "$@" ca-certificates
if [ "$#" -gt 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "$@"
fi

printf '%s\n' 'SIRINVPN_INSTALL_STEP=ports'
if ss -H -lnt "sport = :{tcp_fallback_port}" | grep -q .; then
  if ! systemctl is-active --quiet sirinvpn-server ||
    ! ss -H -lntp "sport = :{tcp_fallback_port}" | grep -Fq 'sirinvpn-server'; then
    echo "TCP port {tcp_fallback_port} is already owned by another service; refusing to replace it" >&2
    exit 1
  fi
fi

{doh_port_preflight}

printf '%s\n' 'SIRINVPN_INSTALL_STEP=snapshot'
BACKUP_DIR=/var/lib/sirinvpn-maintenance/sirinvpn-install-{nonce}.backup.preparing
MANAGED_PATHS="{managed_paths} {update_managed_paths}"
install -d -m 0700 "$BACKUP_DIR"
: >"$BACKUP_DIR/existing"
for path in $MANAGED_PATHS; do
  [ -e "/$path" ] && printf '%s\n' "$path" >>"$BACKUP_DIR/existing"
done
for unit in sirinvpn-network sirinvpn-firewall sirinvpn-doh unbound sirinvpn-server sirinvpn-security-update.timer; do
  systemctl is-active --quiet "$unit" && : >"$BACKUP_DIR/active.$unit" || true
  systemctl is-enabled --quiet "$unit" && : >"$BACKUP_DIR/enabled.$unit" || true
done
cat /proc/sys/net/ipv4/ip_forward >"$BACKUP_DIR/ip_forward"
cat /proc/sys/net/ipv6/conf/all/forwarding >"$BACKUP_DIR/ipv6_forwarding"
{ipv6_accept_ra_backup}

ROLLBACK_SCRIPT=/var/lib/sirinvpn-maintenance/sirinvpn-rollback-{nonce}.sh
cat >"$ROLLBACK_SCRIPT.preparing" <<'ROLLBACK'
{rollback_begin}
MANAGED_PATHS="{managed_paths} {update_managed_paths}"
if [ -f "$BACKUP_DIR/backup-ready" ]; then
if [ "$BEFORE_START" -eq 0 ]; then
  for unit in sirinvpn-server sirinvpn-doh sirinvpn-firewall sirinvpn-network; do
    if systemctl cat "$unit" >/dev/null 2>&1; then systemctl stop "$unit"; fi
  done
fi
{preserve_authorization}
if command -v iptables >/dev/null 2>&1 && iptables -w 5 -n -L DOCKER-USER >/dev/null 2>&1; then
  while iptables -w 5 -C DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s 10.77.0.0/24 -d 10.77.0.0/24 -m comment --comment sirinvpn-forward-peers -j ACCEPT >/dev/null 2>&1; do
    iptables -w 5 -D DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s 10.77.0.0/24 -d 10.77.0.0/24 -m comment --comment sirinvpn-forward-peers -j ACCEPT || break
  done
  while iptables -w 5 -C DOCKER-USER -i sirinvpn0 -o {external_interface} -s 10.77.0.0/24 -m comment --comment sirinvpn-forward-out -j ACCEPT >/dev/null 2>&1; do
    iptables -w 5 -D DOCKER-USER -i sirinvpn0 -o {external_interface} -s 10.77.0.0/24 -m comment --comment sirinvpn-forward-out -j ACCEPT || break
  done
  while iptables -w 5 -C DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward-in -j ACCEPT >/dev/null 2>&1; do
    iptables -w 5 -D DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward-in -j ACCEPT || break
  done
  while iptables -w 5 -C DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m mark --mark 0x5356504e/0xffffffff -m comment --comment sirinvpn-forward-ports -j ACCEPT >/dev/null 2>&1; do
    iptables -w 5 -D DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m mark --mark 0x5356504e/0xffffffff -m comment --comment sirinvpn-forward-ports -j ACCEPT || break
  done
fi
if command -v ip6tables >/dev/null 2>&1 && ip6tables -w 5 -n -L DOCKER-USER >/dev/null 2>&1; then
  while ip6tables -w 5 -C DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s {ipv6_cidr} -d {ipv6_cidr} -m comment --comment sirinvpn-forward6-peers -j ACCEPT >/dev/null 2>&1; do
    ip6tables -w 5 -D DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s {ipv6_cidr} -d {ipv6_cidr} -m comment --comment sirinvpn-forward6-peers -j ACCEPT || break
  done
  while ip6tables -w 5 -C DOCKER-USER -i sirinvpn0 -o {ipv6_external_interface} -s {ipv6_cidr} -m comment --comment sirinvpn-forward6-out -j ACCEPT >/dev/null 2>&1; do
    ip6tables -w 5 -D DOCKER-USER -i sirinvpn0 -o {ipv6_external_interface} -s {ipv6_cidr} -m comment --comment sirinvpn-forward6-out -j ACCEPT || break
  done
  while ip6tables -w 5 -C DOCKER-USER -i {ipv6_external_interface} -o sirinvpn0 -d {ipv6_cidr} -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward6-in -j ACCEPT >/dev/null 2>&1; do
    ip6tables -w 5 -D DOCKER-USER -i {ipv6_external_interface} -o sirinvpn0 -d {ipv6_cidr} -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward6-in -j ACCEPT || break
  done
fi
nft list table inet sirinvpn_filter >/dev/null 2>&1 && nft delete table inet sirinvpn_filter
nft list table ip sirinvpn_nat >/dev/null 2>&1 && nft delete table ip sirinvpn_nat
nft list table ip6 sirinvpn_nat6 >/dev/null 2>&1 && nft delete table ip6 sirinvpn_nat6
ip link show sirinvpn0 >/dev/null 2>&1 && ip link delete sirinvpn0
{runtime_table_cleanup}
for path in $MANAGED_PATHS; do
  rm -rf -- "/$path"
done
if [ -s "$BACKUP_DIR/existing" ]; then
  tar -C / -xpf "$BACKUP_DIR/managed.tar"
fi
{restore_authorization}
{restore_committed_binary}
fi
if [ -s "$BACKUP_DIR/ip_forward" ]; then
  sysctl -q -w "net.ipv4.ip_forward=$(cat "$BACKUP_DIR/ip_forward")"
fi
if [ -s "$BACKUP_DIR/ipv6_forwarding" ]; then
  sysctl -q -w "net.ipv6.conf.all.forwarding=$(cat "$BACKUP_DIR/ipv6_forwarding")"
fi
{ipv6_accept_ra_restore}
if [ -f "$BACKUP_DIR/created-user" ]; then
  userdel sirinvpn >/dev/null 2>&1 || true
  groupdel sirinvpn >/dev/null 2>&1 || true
fi
if [ -f "$BACKUP_DIR/created-update-fetch-user" ]; then
  userdel sirinvpn-update-fetch >/dev/null 2>&1 || true
  groupdel sirinvpn-update-fetch >/dev/null 2>&1 || true
fi
{rollback_finish}
ROLLBACK
printf '%s\n' 'SIRINVPN_INSTALL_STEP=recovery_guard'
{arm_recovery}
{save_committed_binary}

{replacement}
printf '%s\n' 'SIRINVPN_INSTALL_STEP=accounts'
SIRINVPN_USER_CREATED=0
if ! getent passwd sirinvpn >/dev/null 2>&1; then
  : >"$BACKUP_DIR/created-user"
  useradd --system --home /nonexistent --shell /usr/sbin/nologin sirinvpn
  SIRINVPN_USER_CREATED=1
fi
install -d -o root -g sirinvpn -m 0750 /etc/sirinvpn
install -d -o root -g root -m 0755 /usr/local/lib/sirinvpn
if [ "$SIRINVPN_USER_CREATED" -eq 1 ] || [ "{manage_existing_user}" -eq 1 ]; then
  : >/etc/sirinvpn/installer-managed-user
  chmod 0600 /etc/sirinvpn/installer-managed-user
fi
printf '%s\n' 'SIRINVPN_INSTALL_STEP=server_files'
install -o root -g root -m 0755 {binary} /usr/local/lib/sirinvpn/sirinvpn-server
{update_setup}
install -o root -g sirinvpn -m 0640 {owner} /etc/sirinvpn/owner.crt
{restore_state}

printf '%s\n' 'SIRINVPN_INSTALL_STEP=initialize'
/usr/local/lib/sirinvpn/sirinvpn-server init --name {server_name} --owner-certificate /etc/sirinvpn/owner.crt --server-id {server_id} --owner-wireguard-public-key {client_public_key}{transport_init_arguments} {ipv6_init_argument}{dns_init_arguments} >/dev/null
printf '%s\n' 'SIRINVPN_INSTALL_STEP=permissions'
chown sirinvpn:sirinvpn /etc/sirinvpn/server.json /etc/sirinvpn/management.crt /etc/sirinvpn/management.key
chown sirinvpn:sirinvpn /etc/sirinvpn/transport.key
if [ -f /etc/sirinvpn/https.key ]; then
  chown sirinvpn:sirinvpn /etc/sirinvpn/https.key
  chmod 0600 /etc/sirinvpn/https.key
fi
chown root:root /etc/sirinvpn/wireguard.key
chown root:root /etc/sirinvpn/authorization-required
chown -R sirinvpn:sirinvpn /etc/sirinvpn/authorization
chmod 0750 /etc/sirinvpn/authorization
chmod 0600 /etc/sirinvpn/authorization-required
chmod 0600 /etc/sirinvpn/authorization/authorization.json
chmod 0600 /etc/sirinvpn/server.json /etc/sirinvpn/management.crt /etc/sirinvpn/management.key /etc/sirinvpn/wireguard.key /etc/sirinvpn/transport.key

printf '%s\n' 'SIRINVPN_INSTALL_STEP=network_configuration'
cat >/etc/sirinvpn/operational.json <<'OPERATIONAL'
{{"schema_version":1,"external_interface":"{operational_external_interface}","ssh_port":{ssh_server_port}}}
OPERATIONAL
chown root:sirinvpn /etc/sirinvpn/operational.json
chmod 0640 /etc/sirinvpn/operational.json

cat >/etc/sirinvpn/network.sh <<'NETWORK'
#!/bin/sh
set -eu
case "${{1:-}}" in
  up)
    if [ -f /var/lib/sirinvpn-server-release/server-transaction.json ]; then
      /usr/local/lib/sirinvpn/sirinvpn-updater release recover --before-start >/dev/null
    fi
    /usr/local/lib/sirinvpn/sirinvpn-server network-guard
    ip link show sirinvpn0 >/dev/null 2>&1 || ip link add sirinvpn0 type wireguard
    ip address replace 10.77.0.1/24 dev sirinvpn0
{ipv6_network_address}
    wg set sirinvpn0 private-key /etc/sirinvpn/wireguard.key listen-port {wireguard_port}
    if [ ! -e /etc/sirinvpn/authorization-required ] && [ ! -e /etc/sirinvpn/authorization/authorization.json ]; then
      wg set sirinvpn0 peer {client_public_key} allowed-ips {owner_allowed_ips}
    fi
    ip link set mtu 1420 up dev sirinvpn0
    ;;
  down)
    if ip link show sirinvpn0 >/dev/null 2>&1; then ip link delete sirinvpn0; fi
{runtime_table_cleanup}
    ;;
  *) exit 2 ;;
esac
NETWORK
chmod 0750 /etc/sirinvpn/network.sh

cat >/etc/sirinvpn/nftables.conf <<'NFTABLES'
table inet sirinvpn_filter {{
  set peer_communication4 {{
    type ipv4_addr
  }}
  set peer_communication6 {{
    type ipv6_addr
  }}
  chain port_forward {{
  }}
  chain input {{
    type filter hook input priority -20; policy accept;
    iifname "sirinvpn0" ip saddr 10.77.0.224/27 ip daddr 10.77.0.1 tcp dport 8443 accept
    iifname "sirinvpn0" ip saddr 10.77.0.224/27 drop
    iifname "sirinvpn0" ip6 saddr {bootstrap_ipv6_address}/123 drop
    iifname != "sirinvpn0" ip daddr 10.77.0.1 tcp dport 8443 drop
    iifname != "sirinvpn0" ip daddr 10.77.0.1 udp dport 53 drop
    iifname != "sirinvpn0" ip daddr 10.77.0.1 tcp dport 53 drop
{ipv6_input_rules}
    udp dport {wireguard_port} accept
    udp dport {obfuscated_udp_port} accept
    tcp dport {tcp_fallback_port} accept
{discovery_firewall_rule}
  }}
  chain forward {{
    type filter hook forward priority -20; policy accept;
    iifname "sirinvpn0" ip saddr 10.77.0.224/27 drop
    oifname "sirinvpn0" ip daddr 10.77.0.224/27 drop
    iifname "sirinvpn0" ip6 saddr {bootstrap_ipv6_address}/123 drop
    oifname "sirinvpn0" ip6 daddr {bootstrap_ipv6_address}/123 drop
    jump port_forward
    iifname {external_interface} oifname "sirinvpn0" ip daddr 10.77.0.0/24 ct mark 0x5356504e drop
    iifname "sirinvpn0" oifname "sirinvpn0" meta nfproto ipv4 ip saddr @peer_communication4 ip daddr @peer_communication4 accept
    iifname "sirinvpn0" oifname "sirinvpn0" meta nfproto ipv6 ip6 saddr @peer_communication6 ip6 daddr @peer_communication6 accept
    iifname "sirinvpn0" oifname "sirinvpn0" drop
    iifname "sirinvpn0" meta nfproto ipv4 oifname {external_interface} accept
    iifname {external_interface} meta nfproto ipv4 oifname "sirinvpn0" ct state established,related accept
    iifname {external_interface} meta nfproto ipv4 oifname "sirinvpn0" drop
{ipv6_forward_rules}
  }}
}}
table ip sirinvpn_nat {{
  chain port_forward_prerouting {{
  }}
  chain prerouting {{
    type nat hook prerouting priority dstnat - 10; policy accept;
    jump port_forward_prerouting
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    iifname {external_interface} oifname "sirinvpn0" ip daddr 10.77.0.0/24 ct mark 0x5356504e masquerade
    ip saddr 10.77.0.0/24 oifname {external_interface} masquerade
  }}
}}
{ipv6_nat_table}
NFTABLES
chmod 0640 /etc/sirinvpn/nftables.conf

cat >/etc/sirinvpn/firewall.sh <<'FIREWALL'
#!/bin/sh
set -eu
IPV6_ENABLED={ipv6_enabled}

docker_user_available() {{
  command -v iptables >/dev/null 2>&1 &&
    iptables -w 5 -n -L DOCKER-USER >/dev/null 2>&1
}}

docker_user6_available() {{
  command -v ip6tables >/dev/null 2>&1 &&
    ip6tables -w 5 -n -L DOCKER-USER >/dev/null 2>&1
}}

remove_docker_forwarding() {{
  docker_user_available || return 0
  while iptables -w 5 -C DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s 10.77.0.0/24 -d 10.77.0.0/24 -m comment --comment sirinvpn-forward-peers -j ACCEPT >/dev/null 2>&1; do
    iptables -w 5 -D DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s 10.77.0.0/24 -d 10.77.0.0/24 -m comment --comment sirinvpn-forward-peers -j ACCEPT || return 1
  done
  while iptables -w 5 -C DOCKER-USER -i sirinvpn0 -o {external_interface} -s 10.77.0.0/24 -m comment --comment sirinvpn-forward-out -j ACCEPT >/dev/null 2>&1; do
    iptables -w 5 -D DOCKER-USER -i sirinvpn0 -o {external_interface} -s 10.77.0.0/24 -m comment --comment sirinvpn-forward-out -j ACCEPT || return 1
  done
  while iptables -w 5 -C DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward-in -j ACCEPT >/dev/null 2>&1; do
    iptables -w 5 -D DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward-in -j ACCEPT || return 1
  done
  while iptables -w 5 -C DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m mark --mark 0x5356504e/0xffffffff -m comment --comment sirinvpn-forward-ports -j ACCEPT >/dev/null 2>&1; do
    iptables -w 5 -D DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m mark --mark 0x5356504e/0xffffffff -m comment --comment sirinvpn-forward-ports -j ACCEPT || return 1
  done
}}

remove_docker6_forwarding() {{
  docker_user6_available || return 0
  while ip6tables -w 5 -C DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s {ipv6_cidr} -d {ipv6_cidr} -m comment --comment sirinvpn-forward6-peers -j ACCEPT >/dev/null 2>&1; do
    ip6tables -w 5 -D DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s {ipv6_cidr} -d {ipv6_cidr} -m comment --comment sirinvpn-forward6-peers -j ACCEPT || return 1
  done
  while ip6tables -w 5 -C DOCKER-USER -i sirinvpn0 -o {ipv6_external_interface} -s {ipv6_cidr} -m comment --comment sirinvpn-forward6-out -j ACCEPT >/dev/null 2>&1; do
    ip6tables -w 5 -D DOCKER-USER -i sirinvpn0 -o {ipv6_external_interface} -s {ipv6_cidr} -m comment --comment sirinvpn-forward6-out -j ACCEPT || return 1
  done
  while ip6tables -w 5 -C DOCKER-USER -i {ipv6_external_interface} -o sirinvpn0 -d {ipv6_cidr} -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward6-in -j ACCEPT >/dev/null 2>&1; do
    ip6tables -w 5 -D DOCKER-USER -i {ipv6_external_interface} -o sirinvpn0 -d {ipv6_cidr} -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward6-in -j ACCEPT || return 1
  done
}}

add_docker_forwarding() {{
  docker_user_available || return 0
  iptables -w 5 -C DOCKER-USER -i sirinvpn0 -o {external_interface} -s 10.77.0.0/24 -m comment --comment sirinvpn-forward-out -j ACCEPT >/dev/null 2>&1 ||
    iptables -w 5 -I DOCKER-USER 1 -i sirinvpn0 -o {external_interface} -s 10.77.0.0/24 -m comment --comment sirinvpn-forward-out -j ACCEPT
  iptables -w 5 -C DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward-in -j ACCEPT >/dev/null 2>&1 ||
    iptables -w 5 -I DOCKER-USER 1 -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward-in -j ACCEPT
  iptables -w 5 -C DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s 10.77.0.0/24 -d 10.77.0.0/24 -m comment --comment sirinvpn-forward-peers -j ACCEPT >/dev/null 2>&1 ||
    iptables -w 5 -I DOCKER-USER 1 -i sirinvpn0 -o sirinvpn0 -s 10.77.0.0/24 -d 10.77.0.0/24 -m comment --comment sirinvpn-forward-peers -j ACCEPT
  iptables -w 5 -C DOCKER-USER -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m mark --mark 0x5356504e/0xffffffff -m comment --comment sirinvpn-forward-ports -j ACCEPT >/dev/null 2>&1 ||
    iptables -w 5 -I DOCKER-USER 1 -i {external_interface} -o sirinvpn0 -d 10.77.0.0/24 -m mark --mark 0x5356504e/0xffffffff -m comment --comment sirinvpn-forward-ports -j ACCEPT
}}

add_docker6_forwarding() {{
  [ "$IPV6_ENABLED" -eq 1 ] || return 0
  docker_user6_available || return 0
  ip6tables -w 5 -C DOCKER-USER -i sirinvpn0 -o {ipv6_external_interface} -s {ipv6_cidr} -m comment --comment sirinvpn-forward6-out -j ACCEPT >/dev/null 2>&1 ||
    ip6tables -w 5 -I DOCKER-USER 1 -i sirinvpn0 -o {ipv6_external_interface} -s {ipv6_cidr} -m comment --comment sirinvpn-forward6-out -j ACCEPT
  ip6tables -w 5 -C DOCKER-USER -i {ipv6_external_interface} -o sirinvpn0 -d {ipv6_cidr} -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward6-in -j ACCEPT >/dev/null 2>&1 ||
    ip6tables -w 5 -I DOCKER-USER 1 -i {ipv6_external_interface} -o sirinvpn0 -d {ipv6_cidr} -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sirinvpn-forward6-in -j ACCEPT
  ip6tables -w 5 -C DOCKER-USER -i sirinvpn0 -o sirinvpn0 -s {ipv6_cidr} -d {ipv6_cidr} -m comment --comment sirinvpn-forward6-peers -j ACCEPT >/dev/null 2>&1 ||
    ip6tables -w 5 -I DOCKER-USER 1 -i sirinvpn0 -o sirinvpn0 -s {ipv6_cidr} -d {ipv6_cidr} -m comment --comment sirinvpn-forward6-peers -j ACCEPT
}}

delete_owned_tables() {{
  nft list table inet sirinvpn_filter >/dev/null 2>&1 && nft delete table inet sirinvpn_filter || true
  nft list table ip sirinvpn_nat >/dev/null 2>&1 && nft delete table ip sirinvpn_nat || true
  nft list table ip6 sirinvpn_nat6 >/dev/null 2>&1 && nft delete table ip6 sirinvpn_nat6 || true
}}

isolate_runtime() {{
  if nft list table inet sirinvpn_filter >/dev/null 2>&1; then
    nft -f - <<'RUNTIME_POLICY'
flush set inet sirinvpn_filter peer_communication4
flush set inet sirinvpn_filter peer_communication6
flush chain inet sirinvpn_filter port_forward
RUNTIME_POLICY
  fi
  if nft list chain ip sirinvpn_nat port_forward_prerouting >/dev/null 2>&1; then
    nft flush chain ip sirinvpn_nat port_forward_prerouting
  fi
}}

case "${{1:-}}" in
  up)
    remove_docker_forwarding || true
    remove_docker6_forwarding || true
    delete_owned_tables
    nft -f /etc/sirinvpn/nftables.conf
    if ! add_docker_forwarding || ! add_docker6_forwarding; then
      remove_docker_forwarding || true
      remove_docker6_forwarding || true
      delete_owned_tables
      exit 1
    fi
    ;;
  down)
    remove_docker_forwarding || true
    remove_docker6_forwarding || true
    delete_owned_tables
    ;;
  isolate-runtime|isolate-peers)
    isolate_runtime
    ;;
  *) exit 2 ;;
esac
FIREWALL
chmod 0750 /etc/sirinvpn/firewall.sh

printf '%s\n' 'SIRINVPN_INSTALL_STEP=dns_configuration'
cat >/etc/unbound/unbound.conf.d/sirinvpn.conf <<'UNBOUND'
server:
  interface: 127.0.0.1
  interface: 10.77.0.1
  access-control: 0.0.0.0/0 refuse
  access-control: 127.0.0.0/8 allow
  access-control: 10.77.0.0/24 allow
{ipv6_unbound}
{unbound_tls_configuration}
  verbosity: 0
  use-syslog: no
  logfile: ""
  hide-identity: yes
  hide-version: yes
  qname-minimisation: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  unwanted-reply-threshold: 100000
{unbound_forward_zone}
UNBOUND
printf '%s\n' 'SIRINVPN_INSTALL_STEP=dns_validation'
unbound-checkconf /etc/unbound/unbound.conf >/dev/null
printf '%s\n' 'SIRINVPN_INSTALL_STEP=service_configuration'

cat >/etc/sysctl.d/90-sirinvpn.conf <<'SYSCTL'
net.ipv4.ip_forward=1
{ipv6_sysctl}
SYSCTL
sysctl -q -p /etc/sysctl.d/90-sirinvpn.conf

cat >/etc/systemd/system/sirinvpn-network.service <<'UNIT'
[Unit]
Description=SirinVPN network data plane
Before=sirinvpn-doh.service unbound.service sirinvpn-firewall.service sirinvpn-server.service
[Service]
Type=oneshot
ExecStart=/etc/sirinvpn/network.sh up
ExecStop=/etc/sirinvpn/network.sh down
RemainAfterExit=yes
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/sirinvpn-firewall.service <<'UNIT'
[Unit]
Description=SirinVPN isolated firewall rules
Requires=sirinvpn-network.service
After=sirinvpn-network.service docker.service
Before=sirinvpn-server.service
[Service]
Type=oneshot
ExecStart=/etc/sirinvpn/firewall.sh up
ExecStop=/etc/sirinvpn/firewall.sh down
RemainAfterExit=yes
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
UNIT

{doh_service_unit}

mkdir -p /etc/systemd/system/unbound.service.d
cat >/etc/systemd/system/unbound.service.d/sirinvpn.conf <<'UNIT'
[Unit]
{unbound_unit_dependencies}
UNIT

cat >/etc/systemd/system/sirinvpn-server.service <<'UNIT'
[Unit]
Description=SirinVPN private management service
Requires=sirinvpn-network.service sirinvpn-firewall.service unbound.service
After=sirinvpn-network.service sirinvpn-firewall.service unbound.service
[Service]
Type=simple
User=sirinvpn
Group=sirinvpn
ExecStart=/usr/local/lib/sirinvpn/sirinvpn-server serve
ExecStopPost=+/etc/sirinvpn/firewall.sh isolate-runtime
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/etc/sirinvpn/authorization
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
UNIT

printf '%s\n' 'SIRINVPN_INSTALL_STEP=service_registration'
systemctl daemon-reload
systemctl enable sirinvpn-network sirinvpn-firewall unbound sirinvpn-server >/dev/null
printf '%s\n' 'SIRINVPN_INSTALL_STEP=restart_network'
systemctl restart sirinvpn-network
printf '%s\n' 'SIRINVPN_INSTALL_STEP=restart_firewall'
systemctl restart sirinvpn-firewall
printf '%s\n' 'SIRINVPN_INSTALL_STEP=restart_dns_proxy'
{doh_service_activation}
printf '%s\n' 'SIRINVPN_INSTALL_STEP=restart_dns'
systemctl restart unbound
printf '%s\n' 'SIRINVPN_INSTALL_STEP=restart_server'
systemctl restart sirinvpn-server
"#,
        nonce = nonce,
        binary = binary,
        owner = owner,
        server_name = server_name,
        server_id = server_id,
        wireguard_port = request.transport.wireguard_port,
        obfuscated_udp_port = request.transport.obfuscated_udp_port,
        tcp_fallback_port = request.transport.tcp_tls_port,
        client_public_key = client_public_key,
        external_interface = external_interface,
        operational_external_interface = discovery.default_interface,
        ssh_server_port = discovery.ssh_server_port,
        ipv6_external_interface = ipv6_external_interface,
        ipv6_enabled = ipv6_enabled,
        ipv6_init_argument = ipv6_init_argument,
        dns_init_arguments = dns_init_arguments,
        doh_port_preflight = doh_port_preflight,
        doh_service_unit = doh_service_unit,
        unbound_unit_dependencies = unbound_unit_dependencies,
        doh_service_activation = doh_service_activation,
        ipv6_cidr = ipv6_cidr,
        ipv6_network_address = ipv6_network_address,
        ipv6_input_rules = ipv6_input_rules,
        ipv6_forward_rules = ipv6_forward_rules,
        ipv6_nat_table = ipv6_nat_table,
        ipv6_unbound = ipv6_unbound,
        unbound_tls_configuration = unbound_tls_configuration,
        unbound_forward_zone = unbound_forward_zone,
        ipv6_sysctl = ipv6_sysctl,
        ipv6_accept_ra_backup = ipv6_accept_ra_backup,
        ipv6_accept_ra_restore = ipv6_accept_ra_restore,
        restore_stdin_setup = restore_stdin_setup,
        restore_state = restore_state,
        owner_allowed_ips = owner_allowed_ips,
        replacement = replacement,
        manage_existing_user = manage_existing_user,
        managed_paths = MANAGED_SERVER_PATHS,
        update_managed_paths = super::updates::UPDATE_MANAGED_PATHS,
        maintenance_begin = super::updates::MAINTENANCE_BEGIN,
        update_setup = super::updates::UPDATE_SETUP,
        artifact_preflight =
            artifact.root_preflight(remote_binary, nonce, transaction.expected_profile.is_some()),
        rollback_begin = maintenance::rollback_begin(nonce, false),
        rollback_finish = maintenance::rollback_finish(),
        arm_recovery = maintenance::arm(nonce, false),
        preserve_authorization = if transaction.expected_profile.is_some() {
            maintenance::PRESERVE_AUTHORIZATION
        } else {
            ""
        },
        restore_authorization = if transaction.expected_profile.is_some() {
            maintenance::RESTORE_AUTHORIZATION
        } else {
            ""
        },
        save_committed_binary = artifact.save_committed_binary(),
        restore_committed_binary = artifact.restore_committed_binary(),
        runtime_table_cleanup = super::uninstall::RUNTIME_TABLE_CLEANUP,
    )
}
