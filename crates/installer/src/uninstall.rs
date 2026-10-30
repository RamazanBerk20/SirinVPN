//! Uninstall.

use super::*;

// Network teardown, rollback and uninstall share ownership of these runtime
// tables. Keep quarantine until the tunnel is gone; never delete foreign tables.
pub(super) const RUNTIME_TABLE_CLEANUP: &str = r#"nft list tables >/dev/null
for table in sirinvpn_handoff sirinvpn_measurement; do
  if nft list table inet "$table" >/dev/null 2>&1; then
    nft delete table inet "$table"
  fi
done"#;

/// Kernel values found before SirinVPN first changed each key. Install adds a
/// key only before its first change and never rewrites one, so later repairs
/// cannot replace an original with SirinVPN's own value. An installation
/// without this record predates it; uninstall then leaves forwarding as-is.
pub(super) const ORIGINAL_SYSCTL_RECORD: &str = "/etc/sirinvpn/installer-original-sysctl";

pub(super) fn record_original_sysctl(accept_ra_interface: Option<&str>) -> String {
    let accept_ra = accept_ra_interface
        .map(|interface| format!(" net/ipv6/conf/{interface}/accept_ra"))
        .unwrap_or_default();
    format!(
        r#"if [ -f {record} ] || [ ! -e /etc/sysctl.d/90-sirinvpn.conf ]; then
  for key in net/ipv4/ip_forward net/ipv6/conf/all/forwarding{accept_ra}; do
    # IPv6 keys are absent when the kernel was booted with ipv6.disable=1.
    [ -r "/proc/sys/$key" ] || continue
    if [ -f {record} ] && cut -d= -f1 {record} | grep -Fqx -- "$key"; then continue; fi
    printf '%s=%s\n' "$key" "$(cat "/proc/sys/$key")" >>{record}
  done
  if [ -f {record} ]; then chmod 0600 {record}; fi
fi"#,
        record = ORIGINAL_SYSCTL_RECORD,
    )
}

/// Copies the validated original entries into the uninstall backup, with the
/// current values of the same keys so a failed uninstall can return to them.
pub(super) fn snapshot_original_sysctl() -> String {
    format!(
        r#": >"$BACKUP_DIR/original-sysctl"
: >"$BACKUP_DIR/sysctl"
if [ -f {record} ]; then
  while IFS='=' read -r key value; do
    case "$key" in
      net/ipv4/ip_forward|net/ipv6/conf/all/forwarding) ;;
      net/ipv6/conf/*/accept_ra)
        interface=${{key#net/ipv6/conf/}}
        interface=${{interface%/accept_ra}}
        case "$interface" in ''|*[!A-Za-z0-9_.:-]*) continue ;; esac
        ;;
      *) continue ;;
    esac
    case "$value" in ''|*[!0-9]*) continue ;; esac
    # IPv6 keys are absent when the kernel was booted with ipv6.disable=1.
    [ -r "/proc/sys/$key" ] || continue
    printf '%s=%s\n' "$key" "$value" >>"$BACKUP_DIR/original-sysctl"
    printf '%s=%s\n' "$key" "$(cat "/proc/sys/$key")" >>"$BACKUP_DIR/sysctl"
  done <{record}
fi"#,
        record = ORIGINAL_SYSCTL_RECORD,
    )
}

/// Persistent sysctl configuration. SirinVPN's own file is already removed
/// when uninstall reads it.
pub(super) const SYSCTL_CONFIGURATION: &str = "/etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf";

pub(super) fn restore_original_sysctl() -> String {
    format!(
        r#"# Docker enables forwarding when it starts, and other configuration may
# require it too. Then leave forwarding as a reboot would, rather than break
# those users; accept_ra stays paired with forwarding, so it is kept as well.
if ! systemctl is-active --quiet docker &&
  ! grep -Eqs '^[[:space:]]*-?net[./](ipv4[./]ip_forward|ipv6[./]conf[./]all[./]forwarding)[[:space:]]*=' {configuration}; then
  while IFS='=' read -r key value; do
    sysctl -q -w "$key=$value"
  done <"$BACKUP_DIR/original-sysctl"
fi"#,
        configuration = SYSCTL_CONFIGURATION,
    )
}

pub(super) const ROLLBACK_SYSCTL: &str = r#"if [ -f "$BACKUP_DIR/sysctl" ]; then
  while IFS='=' read -r key value; do
    [ ! -r "/proc/sys/$key" ] || sysctl -q -w "$key=$value"
  done <"$BACKUP_DIR/sysctl"
fi"#;

pub(super) fn uninstall_script(nonce: &str) -> String {
    format!(
        r#"#!/bin/sh
set -eu
umask 077

for pending in /run/sirinvpn-rollback-*.sh /run/sirinvpn-uninstall-rollback-*.sh /var/lib/sirinvpn-maintenance/sirinvpn-rollback-*.sh /var/lib/sirinvpn-maintenance/sirinvpn-uninstall-rollback-*.sh; do
  [ -f "$pending" ] || continue
  /bin/sh "$pending"
done

{maintenance_begin}

BACKUP_DIR=/var/lib/sirinvpn-maintenance/sirinvpn-uninstall-{nonce}.backup.preparing
MANAGED_PATHS="{managed_paths}"
install -d -m 0700 "$BACKUP_DIR"
: >"$BACKUP_DIR/existing"
for path in $MANAGED_PATHS; do
  [ -e "/$path" ] && printf '%s\n' "$path" >>"$BACKUP_DIR/existing"
done
for unit in sirinvpn-network sirinvpn-firewall sirinvpn-doh unbound sirinvpn-server sirinvpn-security-update.timer sirinvpn-dns-blocklist.path sirinvpn-dns-blocklist.timer; do
  systemctl is-active --quiet "$unit" && : >"$BACKUP_DIR/active.$unit" || true
  systemctl is-enabled --quiet "$unit" && : >"$BACKUP_DIR/enabled.$unit" || true
done
cat /proc/sys/net/ipv4/ip_forward >"$BACKUP_DIR/ip_forward"
# Absent when the kernel was booted with ipv6.disable=1.
if [ -r /proc/sys/net/ipv6/conf/all/forwarding ]; then
  cat /proc/sys/net/ipv6/conf/all/forwarding >"$BACKUP_DIR/ipv6_forwarding"
fi
{snapshot_original_sysctl}
[ -f /etc/sirinvpn/installer-managed-user ] && : >"$BACKUP_DIR/remove-user" || true
[ -f /etc/sirinvpn/installer-managed-update-fetch ] && : >"$BACKUP_DIR/remove-update-fetch-user" || true

ROLLBACK_SCRIPT=/var/lib/sirinvpn-maintenance/sirinvpn-uninstall-rollback-{nonce}.sh
cat >"$ROLLBACK_SCRIPT.preparing" <<'ROLLBACK'
{rollback_begin}
MANAGED_PATHS="{managed_paths}"
if [ -f "$BACKUP_DIR/backup-ready" ]; then
if [ "$BEFORE_START" -eq 0 ]; then
  for unit in sirinvpn-server sirinvpn-doh sirinvpn-firewall sirinvpn-network; do
    if systemctl cat "$unit" >/dev/null 2>&1; then systemctl stop "$unit"; fi
  done
  if [ -x /etc/sirinvpn/firewall.sh ]; then /etc/sirinvpn/firewall.sh down; fi
  if [ -x /etc/sirinvpn/network.sh ]; then /etc/sirinvpn/network.sh down; fi
fi
for path in $MANAGED_PATHS; do
  rm -rf -- "/$path"
done
if [ -s "$BACKUP_DIR/existing" ]; then
  tar -C / -xpf "$BACKUP_DIR/managed.tar"
fi
fi
if [ -s "$BACKUP_DIR/ip_forward" ]; then
  sysctl -q -w "net.ipv4.ip_forward=$(cat "$BACKUP_DIR/ip_forward")"
fi
if [ -s "$BACKUP_DIR/ipv6_forwarding" ]; then
  sysctl -q -w "net.ipv6.conf.all.forwarding=$(cat "$BACKUP_DIR/ipv6_forwarding")"
fi
{rollback_sysctl}
{rollback_finish}
ROLLBACK
{arm_recovery}

systemctl disable --now sirinvpn-security-update.timer >/dev/null 2>&1 || true
systemctl stop sirinvpn-security-update.service >/dev/null 2>&1 || true
systemctl disable --now sirinvpn-dns-blocklist.path sirinvpn-dns-blocklist.timer >/dev/null 2>&1 || true
systemctl stop sirinvpn-dns-blocklist.service >/dev/null 2>&1 || true

for unit in sirinvpn-server sirinvpn-doh sirinvpn-firewall sirinvpn-network; do
  if systemctl cat "$unit.service" >/dev/null 2>&1; then
    systemctl stop "$unit.service"
    systemctl disable "$unit.service" >/dev/null 2>&1 || true
  fi
done
if [ -x /etc/sirinvpn/firewall.sh ]; then
  /etc/sirinvpn/firewall.sh down
fi
if [ -x /etc/sirinvpn/network.sh ]; then
  /etc/sirinvpn/network.sh down
fi
{runtime_table_cleanup}
for path in $MANAGED_PATHS; do
  rm -rf -- "/$path"
done
# The tunnel is gone; return forwarding to the values found before SirinVPN.
{restore_original_sysctl}
rmdir /usr/local/lib/sirinvpn 2>/dev/null || true
rmdir /etc/systemd/system/unbound.service.d 2>/dev/null || true
systemctl daemon-reload
if systemctl cat unbound.service >/dev/null 2>&1; then
  systemctl restart unbound.service
fi
"#,
        nonce = nonce,
        managed_paths = format_args!(
            "{MANAGED_SERVER_PATHS} {} {} var/lib/sirinvpn-server-release",
            super::updates::UPDATE_MANAGED_PATHS,
            super::dns_blocklist::DNS_BLOCKLIST_MANAGED_PATHS
        ),
        maintenance_begin = super::updates::MAINTENANCE_BEGIN,
        rollback_begin = maintenance::rollback_begin(nonce, true),
        rollback_finish = maintenance::rollback_finish(),
        arm_recovery = maintenance::arm(nonce, true),
        runtime_table_cleanup = RUNTIME_TABLE_CLEANUP,
        snapshot_original_sysctl = snapshot_original_sysctl(),
        rollback_sysctl = ROLLBACK_SYSCTL,
        restore_original_sysctl = restore_original_sysctl(),
    )
}

pub(super) fn uninstall_verification_command() -> String {
    format!(
        r#"set -eu
MANAGED_PATHS="{managed_paths}"
for path in $MANAGED_PATHS; do
  if [ -e "/$path" ] || [ -L "/$path" ]; then exit 1; fi
done
for tool in ip nft ss systemctl grep; do
  command -v "$tool" >/dev/null
done
# `set -e` does not fail a shell for a negated command. Make every failed
# absence proof explicit, and do not interpret a failed observer as absence.
ip link show >/dev/null
if ip link show sirinvpn0 >/dev/null 2>&1; then exit 1; fi
nft list tables >/dev/null
for table in sirinvpn_filter sirinvpn_handoff sirinvpn_measurement; do
  if nft list table inet "$table" >/dev/null 2>&1; then exit 1; fi
done
if nft list table ip sirinvpn_nat >/dev/null 2>&1; then exit 1; fi
if nft list table ip6 sirinvpn_nat6 >/dev/null 2>&1; then exit 1; fi
if command -v iptables-save >/dev/null 2>&1; then
  rules=$(iptables-save)
  if printf '%s\n' "$rules" | grep -q -- '--comment sirinvpn-forward-'; then exit 1; fi
fi
if command -v ip6tables-save >/dev/null 2>&1; then
  rules=$(ip6tables-save)
  if printf '%s\n' "$rules" | grep -q -- '--comment sirinvpn-forward6-'; then exit 1; fi
fi
sockets=$(ss -H -lnt 'sport = :8443')
if printf '%s\n' "$sockets" | grep -q 10.77.0.1; then exit 1; fi
for unit in sirinvpn-network sirinvpn-firewall sirinvpn-doh sirinvpn-server sirinvpn-security-update.timer sirinvpn-dns-blocklist.path sirinvpn-dns-blocklist.timer; do
  if systemctl is-active --quiet "$unit"; then exit 1; fi
  if systemctl is-enabled --quiet "$unit"; then exit 1; fi
done
sockets=$(ss -H -lun 'sport = :{doh_proxy_port}')
if printf '%s\n' "$sockets" | grep -q '127.0.0.1:{doh_proxy_port}'; then exit 1; fi
sockets=$(ss -H -lnt 'sport = :{doh_proxy_port}')
if printf '%s\n' "$sockets" | grep -q '127.0.0.1:{doh_proxy_port}'; then exit 1; fi
systemctl is-active --quiet unbound.service
"#,
        managed_paths = format_args!(
            "{MANAGED_SERVER_PATHS} {} {} var/lib/sirinvpn-server-release",
            super::updates::UPDATE_MANAGED_PATHS,
            super::dns_blocklist::DNS_BLOCKLIST_MANAGED_PATHS
        ),
        doh_proxy_port = DOH_PROXY_PORT,
    )
}

pub(super) fn uninstall_commit_command(nonce: &str) -> String {
    maintenance::commit(nonce, true)
}

pub(super) fn uninstall_rollback_now(session: &Session, target: &SshTarget, nonce: &str) {
    run_rollback_now(session, target, &maintenance::rollback_path(nonce, true));
}

pub(super) fn remove_remote_file(session: &Session, path: &str) {
    let path = shell_quote(path);
    let _ = run(
        session,
        &format!("shred -u -- {path} 2>/dev/null || rm -f -- {path}"),
    );
}
