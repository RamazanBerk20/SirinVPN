//! Persistent rollback guards for the multi-request SSH installer. A committed
//! marker is synced before cleanup; boot recovery runs before the VPN network.

use sha2::{Digest, Sha256};

pub(super) const DIRECTORY: &str = "/var/lib/sirinvpn-maintenance";

pub(super) fn rollback_path(nonce: &str, uninstall: bool) -> String {
    let operation = if uninstall { "uninstall-" } else { "" };
    format!("{DIRECTORY}/sirinvpn-{operation}rollback-{nonce}.sh")
}

/// Durable result of an install transaction after its backup is cleaned up, so
/// a client whose commit reply was lost can still learn what happened. Uninstall
/// keeps none (it must leave no trace); its result is whether the server remains.
pub(super) fn outcome_path(nonce: &str) -> String {
    format!("{DIRECTORY}/sirinvpn-install-{nonce}.outcome")
}

fn state_variables(nonce: &str, uninstall: bool) -> String {
    let operation = if uninstall { "uninstall" } else { "install" };
    let outcome = if uninstall {
        String::new()
    } else {
        outcome_path(nonce)
    };
    format!(
        r#"BACKUP_DIR={DIRECTORY}/sirinvpn-{operation}-{nonce}.backup
OUTCOME={outcome}
ROLLBACK_SCRIPT={rollback}
ROLLBACK_SERVICE=sirinvpn-{operation}-rollback-{nonce}
LIVE_MARKER=/run/sirinvpn-{operation}-{nonce}.live
DEPENDENCY=/etc/systemd/system/sirinvpn-network.service.d/sirinvpn-maintenance.conf"#,
        rollback = rollback_path(nonce, uninstall)
    )
}

fn cleanup_function() -> &'static str {
    r#"cleanup_transaction() {
  if [ -n "$OUTCOME" ] && [ ! -f "$OUTCOME" ]; then
    if [ -f "$BACKUP_DIR/committed" ]; then
      printf 'committed\n' >"$OUTCOME.preparing"
    else
      printf 'rolled_back\n' >"$OUTCOME.preparing"
    fi
    sync -f "$OUTCOME.preparing"
    mv "$OUTCOME.preparing" "$OUTCOME"
  fi
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
for unit in sirinvpn-network sirinvpn-firewall sirinvpn-doh unbound sirinvpn-server sirinvpn-security-update.timer sirinvpn-dns-blocklist.path sirinvpn-dns-blocklist.timer sirinvpn-alerts.timer; do
  systemctl disable "$unit" >/dev/null 2>&1 || true
  [ ! -f "$BACKUP_DIR/enabled.$unit" ] || systemctl enable "$unit" >/dev/null
done
for unit in sirinvpn-network sirinvpn-firewall sirinvpn-doh unbound sirinvpn-server sirinvpn-security-update.timer sirinvpn-dns-blocklist.path sirinvpn-dns-blocklist.timer sirinvpn-alerts.timer; do
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

/// Short public identifier of the Owner certificate that started a transaction,
/// shown to another device that finds it in progress.
pub(super) fn owner_label(certificate_pem: &str) -> String {
    hex::encode(Sha256::digest(certificate_pem.as_bytes()))[..16].to_owned()
}

/// Runs before a new transaction takes the maintenance lock. A transaction that
/// is still live in this boot with its safety timer running belongs to another
/// client between SSH requests; it must not be rolled back from under it. Only
/// interrupted ones (previous boot, or timer gone) are recovered here.
pub(super) fn recover_pending() -> String {
    format!(
        r#"for pending in /run/sirinvpn-rollback-*.sh /run/sirinvpn-uninstall-rollback-*.sh {DIRECTORY}/sirinvpn-rollback-*.sh {DIRECTORY}/sirinvpn-uninstall-rollback-*.sh; do
  [ -f "$pending" ] || continue
  pending_name=${{pending##*/}}
  pending_name=${{pending_name%.sh}}
  case "$pending_name" in
    sirinvpn-uninstall-rollback-*) pending_operation=uninstall; pending_nonce=${{pending_name#sirinvpn-uninstall-rollback-}} ;;
    *) pending_operation=install; pending_nonce=${{pending_name#sirinvpn-rollback-}} ;;
  esac
  if [ -f "/run/sirinvpn-$pending_operation-$pending_nonce.live" ] &&
    systemctl is-active --quiet "sirinvpn-$pending_operation-rollback-$pending_nonce.timer"; then
    pending_owner=$(cat "{DIRECTORY}/sirinvpn-$pending_operation-$pending_nonce.backup/owner" 2>/dev/null || true)
    printf 'SIRINVPN_TRANSACTION_OWNER=%s
' "$pending_owner"
    printf '%s
' 'SIRINVPN_INSTALL_STEP=busy'
    exit 75
  fi
  /bin/sh "$pending"
done"#
    )
}

/// Read-only probe of one transaction's state on the VPS; see `RemoteTransactionState`.
pub(super) fn state_command(nonce: &str, uninstall: bool) -> String {
    let operation = if uninstall { "uninstall" } else { "install" };
    let finished = if uninstall {
        "if [ -e /usr/local/lib/sirinvpn/sirinvpn-server ]; then echo rolled_back; else echo committed; fi".to_owned()
    } else {
        format!(
            "if [ -f {outcome} ]; then cat {outcome}; else echo unknown; fi",
            outcome = outcome_path(nonce)
        )
    };
    format!(
        r#"BACKUP_DIR={DIRECTORY}/sirinvpn-{operation}-{nonce}.backup
if [ -f "$BACKUP_DIR/committed" ]; then echo committed
elif [ -d "$BACKUP_DIR" ] || [ -d "$BACKUP_DIR.preparing" ]; then
  # A held lock means a script (the install, a commit or a rollback) is still
  # running; otherwise it stopped either after arming (rollback is due) or
  # before arming (nothing was changed).
  if ! (flock -n 9) 9>/run/sirinvpn-maintenance.lock; then echo preparing
  elif [ -d "$BACKUP_DIR" ]; then echo armed
  else echo rolled_back
  fi
else {finished}
fi"#
    )
}

pub(super) fn arm(nonce: &str, uninstall: bool, owner: &str) -> String {
    let operation = if uninstall { "uninstall" } else { "install" };
    format!(
        r#"chmod 0700 "$ROLLBACK_SCRIPT.preparing"
sync -f "$ROLLBACK_SCRIPT.preparing"
mv "$ROLLBACK_SCRIPT.preparing" "$ROLLBACK_SCRIPT"
mv "$BACKUP_DIR" {DIRECTORY}/sirinvpn-{operation}-{nonce}.backup
{variables}
printf '%s\n' '{owner}' >"$BACKUP_DIR/owner"
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
/// Repair accepts the legacy layout, which has no authorization state yet. Its
/// absence is recorded so a retry never captures the restored old snapshot.
pub(super) const PRESERVE_AUTHORIZATION: &str = r#"
if [ -f "$BACKUP_DIR/restoration-complete" ] ||
  { [ ! -f "$BACKUP_DIR/preserved-authorization.tar" ] && [ ! -f "$BACKUP_DIR/preserved-authorization.absent" ]; }; then
  if [ -d /etc/sirinvpn/authorization ] && [ -f /etc/sirinvpn/authorization/authorization.json ]; then
    tar -C /etc/sirinvpn -cpf "$BACKUP_DIR/preserved-authorization.preparing" authorization
    sync -f "$BACKUP_DIR/preserved-authorization.preparing"
    mv "$BACKUP_DIR/preserved-authorization.preparing" "$BACKUP_DIR/preserved-authorization.tar"
    rm -f "$BACKUP_DIR/preserved-authorization.absent"
  else
    : >"$BACKUP_DIR/preserved-authorization.absent"
    rm -f "$BACKUP_DIR/preserved-authorization.tar"
  fi
  sync -f "$BACKUP_DIR"
fi
rm -f "$BACKUP_DIR/restoration-complete"
sync -f "$BACKUP_DIR"
"#;

/// Runs after /etc/sirinvpn was replaced by the snapshot. A legacy snapshot
/// has neither marker, so state a failed migration created is already gone and
/// must not return. Otherwise a missing preserved archive fails closed.
pub(super) const RESTORE_AUTHORIZATION: &str = r#"
if [ -e /etc/sirinvpn/authorization-required ] || [ -d /etc/sirinvpn/authorization ]; then
  rm -rf -- /etc/sirinvpn/authorization
  tar -C /etc/sirinvpn -xpf "$BACKUP_DIR/preserved-authorization.tar"
  [ -f /etc/sirinvpn/authorization/authorization.json ]
fi
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
