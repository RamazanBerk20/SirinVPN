//! Uninstall.

use super::*;

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
for unit in sirinvpn-network sirinvpn-firewall sirinvpn-doh unbound sirinvpn-server sirinvpn-security-update.timer; do
  systemctl is-active --quiet "$unit" && : >"$BACKUP_DIR/active.$unit" || true
  systemctl is-enabled --quiet "$unit" && : >"$BACKUP_DIR/enabled.$unit" || true
done
cat /proc/sys/net/ipv4/ip_forward >"$BACKUP_DIR/ip_forward"
cat /proc/sys/net/ipv6/conf/all/forwarding >"$BACKUP_DIR/ipv6_forwarding"
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
{rollback_finish}
ROLLBACK
{arm_recovery}

systemctl disable --now sirinvpn-security-update.timer >/dev/null 2>&1 || true
systemctl stop sirinvpn-security-update.service >/dev/null 2>&1 || true

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
for path in $MANAGED_PATHS; do
  rm -rf -- "/$path"
done
rmdir /usr/local/lib/sirinvpn 2>/dev/null || true
rmdir /etc/systemd/system/unbound.service.d 2>/dev/null || true
systemctl daemon-reload
if systemctl cat unbound.service >/dev/null 2>&1; then
  systemctl restart unbound.service
fi
"#,
        nonce = nonce,
        managed_paths = format_args!(
            "{MANAGED_SERVER_PATHS} {} var/lib/sirinvpn-server-release",
            super::updates::UPDATE_MANAGED_PATHS
        ),
        maintenance_begin = super::updates::MAINTENANCE_BEGIN,
        rollback_begin = maintenance::rollback_begin(nonce, true),
        rollback_finish = maintenance::rollback_finish(),
        arm_recovery = maintenance::arm(nonce, true),
    )
}

pub(super) fn uninstall_verification_command() -> String {
    format!(
        r#"set -eu
MANAGED_PATHS="{managed_paths}"
for path in $MANAGED_PATHS; do
  [ ! -e "/$path" ]
done
! ip link show sirinvpn0 >/dev/null 2>&1
! nft list table inet sirinvpn_filter >/dev/null 2>&1
! nft list table ip sirinvpn_nat >/dev/null 2>&1
! nft list table ip6 sirinvpn_nat6 >/dev/null 2>&1
if command -v iptables-save >/dev/null 2>&1; then
  ! iptables-save | grep -q -- '--comment sirinvpn-forward-'
fi
if command -v ip6tables-save >/dev/null 2>&1; then
  ! ip6tables-save | grep -q -- '--comment sirinvpn-forward6-'
fi
! ss -H -lnt 'sport = :8443' | grep -q 10.77.0.1
for unit in sirinvpn-network sirinvpn-firewall sirinvpn-doh sirinvpn-server sirinvpn-security-update.timer; do
  ! systemctl is-active --quiet "$unit"
  ! systemctl is-enabled --quiet "$unit"
done
! ss -H -lun 'sport = :{doh_proxy_port}' | grep -q '127.0.0.1:{doh_proxy_port}'
! ss -H -lnt 'sport = :{doh_proxy_port}' | grep -q '127.0.0.1:{doh_proxy_port}'
systemctl is-active --quiet unbound.service
"#,
        managed_paths = format_args!(
            "{MANAGED_SERVER_PATHS} {} var/lib/sirinvpn-server-release",
            super::updates::UPDATE_MANAGED_PATHS
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
