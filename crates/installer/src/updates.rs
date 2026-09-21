//! Independent recovery coordinator and opt-in security schedule.
pub(super) const UPDATE_MANAGED_PATHS: &str = "usr/local/lib/sirinvpn/sirinvpn-updater etc/systemd/system/sirinvpn-security-update.service etc/systemd/system/sirinvpn-security-update.timer";

pub(super) const MAINTENANCE_BEGIN: &str = r#"
export LC_ALL=C
if [ -f /var/lib/sirinvpn-server-release/server-transaction.json ]; then
  /usr/local/lib/sirinvpn/sirinvpn-updater release recover >/dev/null
fi
exec 9>/run/sirinvpn-maintenance.lock
flock -n 9 || { echo 'Another SirinVPN installation or update is running' >&2; exit 1; }
[ ! -L /var/lib/sirinvpn-maintenance ]
if [ ! -e /var/lib/sirinvpn-maintenance ]; then
  install -d -o root -g root -m 0700 /var/lib/sirinvpn-maintenance
fi
[ -d /var/lib/sirinvpn-maintenance ]
[ "$(stat -c '%u:%a' /var/lib/sirinvpn-maintenance)" = '0:700' ]
for incomplete in /var/lib/sirinvpn-maintenance/*.backup.preparing; do
  [ ! -d "$incomplete" ] || rm -rf -- "$incomplete"
done
[ ! -L /var/lib/sirinvpn-server-release ]
if [ ! -e /var/lib/sirinvpn-server-release ]; then
  install -d -o root -g root -m 0700 /var/lib/sirinvpn-server-release
fi
[ -d /var/lib/sirinvpn-server-release ]
[ "$(stat -c '%u:%a' /var/lib/sirinvpn-server-release)" = '0:700' ]
[ ! -L /var/lib/sirinvpn-server-release/operations.lock ]
exec 8>/var/lib/sirinvpn-server-release/operations.lock
[ "$(stat -c '%u:%a:%h' /var/lib/sirinvpn-server-release/operations.lock)" = '0:600:1' ]
flock -n 8 || { echo 'A VPS release operation is running' >&2; exit 1; }
"#;

pub(super) const UPDATE_SETUP: &str = r#"
if ! getent passwd sirinvpn-update-fetch >/dev/null 2>&1; then
  : >"$BACKUP_DIR/created-update-fetch-user"
  useradd --system --home /nonexistent --shell /usr/sbin/nologin sirinvpn-update-fetch
  : >/etc/sirinvpn/installer-managed-update-fetch
  chmod 0600 /etc/sirinvpn/installer-managed-update-fetch
fi
install -d -o root -g root -m 0700 /var/lib/sirinvpn-server-release
install -o root -g root -m 0755 /usr/local/lib/sirinvpn/sirinvpn-server /usr/local/lib/sirinvpn/sirinvpn-updater
cat >/etc/systemd/system/sirinvpn-security-update.service <<'UNIT'
[Unit]
Description=SirinVPN optional signed security update
After=network-online.target sirinvpn-server.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/lib/sirinvpn/sirinvpn-updater release automatic
TimeoutStartSec=20min
UMask=0077
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/sirinvpn-server-release /usr/local/lib/sirinvpn
ProtectKernelTunables=yes
ProtectKernelModules=yes
RestrictNamespaces=yes
StandardOutput=null
StandardError=null
UNIT
cat >/etc/systemd/system/sirinvpn-security-update.timer <<'UNIT'
[Unit]
Description=SirinVPN optional daily security check
[Timer]
OnCalendar=daily
RandomizedDelaySec=30min
Persistent=true
Unit=sirinvpn-security-update.service
[Install]
WantedBy=timers.target
UNIT
"#;
