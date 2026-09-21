//! Persistent rollback guards for the multi-request SSH installer. A committed
//! marker is synced before cleanup; boot recovery runs before the VPN network.

pub(super) const DIRECTORY: &str = "/var/lib/sirinvpn-maintenance";

pub(super) fn rollback_path(nonce: &str, uninstall: bool) -> String {
    let operation = if uninstall { "uninstall-" } else { "" };
    format!("{DIRECTORY}/sirinvpn-{operation}rollback-{nonce}.sh")
}

fn state_variables(nonce: &str, uninstall: bool) -> String {
    let operation = if uninstall { "uninstall" } else { "install" };
    format!(
        r#"BACKUP_DIR={DIRECTORY}/sirinvpn-{operation}-{nonce}.backup
ROLLBACK_SCRIPT={rollback}
ROLLBACK_SERVICE=sirinvpn-{operation}-rollback-{nonce}
LIVE_MARKER=/run/sirinvpn-{operation}-{nonce}.live
DEPENDENCY=/etc/systemd/system/sirinvpn-network.service.d/sirinvpn-maintenance.conf"#,
        rollback = rollback_path(nonce, uninstall)
    )
}

fn cleanup_function() -> &'static str {
    r#"cleanup_transaction() {
  if [ -f "$BACKUP_DIR/committed" ]; then
    if [ -f "$BACKUP_DIR/remove-user" ]; then
      userdel sirinvpn >/dev/null 2>&1 || true
      groupdel sirinvpn >/dev/null 2>&1 || true
    fi
    if [ -f "$BACKUP_DIR/remove-update-fetch-user" ]; then
      userdel sirinvpn-update-fetch >/dev/null 2>&1 || true
      groupdel sirinvpn-update-fetch >/dev/null 2>&1 || true
    fi
  fi
  systemctl stop "$ROLLBACK_SERVICE.timer" >/dev/null 2>&1 || true
  systemctl disable "$ROLLBACK_SERVICE.timer" "$ROLLBACK_SERVICE-boot.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$ROLLBACK_SERVICE.timer" "/etc/systemd/system/$ROLLBACK_SERVICE.service" "/etc/systemd/system/$ROLLBACK_SERVICE-boot.service" "$DEPENDENCY"
  rmdir /etc/systemd/system/sirinvpn-network.service.d 2>/dev/null || true
  rm -rf -- "$BACKUP_DIR" "$BACKUP_DIR.preparing"
  rm -f -- "$ROLLBACK_SCRIPT" "$LIVE_MARKER"
  sync -f /var/lib/sirinvpn-maintenance
  rmdir /var/lib/sirinvpn-maintenance 2>/dev/null || true
  systemctl daemon-reload
  systemctl reset-failed "$ROLLBACK_SERVICE.timer" "$ROLLBACK_SERVICE.service" "$ROLLBACK_SERVICE-boot.service" >/dev/null 2>&1 || true
}"#
}

pub(super) fn rollback_begin(nonce: &str, uninstall: bool) -> String {
    format!(
        r#"#!/bin/sh
set -eu
umask 077
{variables}
# This dependency is satisfied without recovery during the installing boot.
# The marker disappears on reboot, before any VPN interface can be created.
if [ "${{1:-}}" = --before-start ] && [ -f "$LIVE_MARKER" ]; then exit 0; fi
exec 9>/run/sirinvpn-maintenance.lock
flock 9
{cleanup}
if [ ! -d "$BACKUP_DIR" ] || [ -f "$BACKUP_DIR/committed" ]; then
  cleanup_transaction
  exit 0
fi
BEFORE_START=0
[ "${{1:-}}" != --before-start ] || BEFORE_START=1"#,
        variables = state_variables(nonce, uninstall),
        cleanup = cleanup_function()
    )
}

pub(super) fn rollback_finish() -> &'static str {
    r#"sync -f /etc
sync -f /usr/local/lib
sync -f /var/lib
: >"$BACKUP_DIR/restoration-complete"
sync -f "$BACKUP_DIR"
systemctl daemon-reload
for unit in sirinvpn-network sirinvpn-firewall sirinvpn-doh unbound sirinvpn-server sirinvpn-security-update.timer; do
  systemctl disable "$unit" >/dev/null 2>&1 || true
  [ ! -f "$BACKUP_DIR/enabled.$unit" ] || systemctl enable "$unit" >/dev/null
done
for unit in sirinvpn-network sirinvpn-firewall sirinvpn-doh unbound sirinvpn-server sirinvpn-security-update.timer; do
  if [ -f "$BACKUP_DIR/active.$unit" ]; then
    if [ "$BEFORE_START" -eq 1 ]; then
      systemctl --no-block restart "$unit"
    else
      systemctl restart "$unit"
    fi
  elif [ "$BEFORE_START" -eq 1 ]; then
    systemctl --no-block stop "$unit" >/dev/null 2>&1 || true
  else
    systemctl stop "$unit" >/dev/null 2>&1 || true
  fi
done
cleanup_transaction"#
}

pub(super) fn arm(nonce: &str, uninstall: bool) -> String {
    let operation = if uninstall { "uninstall" } else { "install" };
    format!(
        r#"chmod 0700 "$ROLLBACK_SCRIPT.preparing"
sync -f "$ROLLBACK_SCRIPT.preparing"
mv "$ROLLBACK_SCRIPT.preparing" "$ROLLBACK_SCRIPT"
mv "$BACKUP_DIR" {DIRECTORY}/sirinvpn-{operation}-{nonce}.backup
{variables}
: >"$LIVE_MARKER"
cat >/etc/systemd/system/$ROLLBACK_SERVICE.service <<EOF
[Unit]
Description=SirinVPN interrupted maintenance rollback
[Service]
Type=oneshot
ExecStart=/bin/sh $ROLLBACK_SCRIPT
TimeoutStartSec=5min
StandardOutput=null
StandardError=null
EOF
cat >/etc/systemd/system/$ROLLBACK_SERVICE-boot.service <<EOF
[Unit]
Description=SirinVPN maintenance recovery before VPN startup
DefaultDependencies=no
After=local-fs.target
Before=sirinvpn-network.service sirinvpn-firewall.service sirinvpn-doh.service unbound.service sirinvpn-server.service
RequiresMountsFor={DIRECTORY}
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh $ROLLBACK_SCRIPT --before-start
TimeoutStartSec=5min
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/$ROLLBACK_SERVICE.timer <<EOF
[Unit]
Description=SirinVPN maintenance safety timer
[Timer]
OnActiveSec=5min
Unit=$ROLLBACK_SERVICE.service
[Install]
WantedBy=timers.target
EOF
install -d -o root -g root -m 0755 /etc/systemd/system/sirinvpn-network.service.d
cat >"$DEPENDENCY" <<EOF
[Unit]
Requires=$ROLLBACK_SERVICE-boot.service
After=$ROLLBACK_SERVICE-boot.service
EOF
sync -f "$BACKUP_DIR"
sync -f /etc/systemd/system
systemctl daemon-reload
systemctl enable --now "$ROLLBACK_SERVICE-boot.service" "$ROLLBACK_SERVICE.timer" >/dev/null
# Stop authorization writers before the rollback snapshot is captured.
for unit in sirinvpn-server sirinvpn-doh; do
  if systemctl cat "$unit" >/dev/null 2>&1; then systemctl stop "$unit"; fi
done
if [ -s "$BACKUP_DIR/existing" ]; then
  tar -C / -cpf "$BACKUP_DIR/managed.tar" -T "$BACKUP_DIR/existing"
  sync -f "$BACKUP_DIR/managed.tar"
fi
: >"$BACKUP_DIR/backup-ready"
sync -f "$BACKUP_DIR""#,
        variables = state_variables(nonce, uninstall)
    )
}

/// Retain current authorization even if a revocation happened after the old
/// snapshot, while the candidate service was undergoing its health checks.
pub(super) const PRESERVE_AUTHORIZATION: &str = r#"
if [ ! -f "$BACKUP_DIR/preserved-authorization.tar" ] || [ -f "$BACKUP_DIR/restoration-complete" ]; then
  [ -d /etc/sirinvpn/authorization ] && [ -f /etc/sirinvpn/authorization/authorization.json ]
  tar -C /etc/sirinvpn -cpf "$BACKUP_DIR/preserved-authorization.preparing" authorization
  sync -f "$BACKUP_DIR/preserved-authorization.preparing"
  mv "$BACKUP_DIR/preserved-authorization.preparing" "$BACKUP_DIR/preserved-authorization.tar"
  sync -f "$BACKUP_DIR"
fi
rm -f "$BACKUP_DIR/restoration-complete"
sync -f "$BACKUP_DIR"
"#;

pub(super) const RESTORE_AUTHORIZATION: &str = r#"
rm -rf -- /etc/sirinvpn/authorization
tar -C /etc/sirinvpn -xpf "$BACKUP_DIR/preserved-authorization.tar"
[ -f /etc/sirinvpn/authorization-required ]
sync -f /etc/sirinvpn
"#;

pub(super) fn followup(nonce: &str, command: &str) -> String {
    format!(
        r#"set -eu
umask 077
exec 9>/run/sirinvpn-maintenance.lock
flock -n 9 || {{ echo 'SirinVPN maintenance recovery is running' >&2; exit 1; }}
[ -f {DIRECTORY}/sirinvpn-install-{nonce}.backup/backup-ready ]
[ ! -f {DIRECTORY}/sirinvpn-install-{nonce}.backup/committed ]
{command}"#
    )
}

pub(super) fn commit(nonce: &str, uninstall: bool) -> String {
    format!(
        r#"set -eu
umask 077
exec 9>/run/sirinvpn-maintenance.lock
flock -n 9 || {{ echo 'SirinVPN maintenance recovery is running' >&2; exit 1; }}
{variables}
[ -f "$BACKUP_DIR/backup-ready" ]
sync -f /etc
sync -f /usr/local/lib
sync -f /var/lib
: >"$BACKUP_DIR/committed"
sync -f "$BACKUP_DIR"
{cleanup}
cleanup_transaction"#,
        variables = state_variables(nonce, uninstall),
        cleanup = cleanup_function()
    )
}
