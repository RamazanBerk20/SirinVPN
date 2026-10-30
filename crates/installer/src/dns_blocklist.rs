//! Opt-in DNS blocking: a sandboxed root task that applies the stored policy, started when the
//! authorization state changes and refreshed daily. It downloads as the update-fetch account.
pub(super) const DNS_BLOCKLIST_MANAGED_PATHS: &str = "etc/unbound/unbound.conf.d/sirinvpn-dns-blocklist.conf etc/systemd/system/sirinvpn-dns-blocklist.service etc/systemd/system/sirinvpn-dns-blocklist.path etc/systemd/system/sirinvpn-dns-blocklist.timer var/lib/sirinvpn-dns-blocklist";

/// It must not reload Unbound while an SSH transaction changes its configuration.
pub(super) const DNS_BLOCKLIST_STOP: &str = r#"for unit in sirinvpn-dns-blocklist.path sirinvpn-dns-blocklist.timer sirinvpn-dns-blocklist.service; do
  if systemctl cat "$unit" >/dev/null 2>&1; then systemctl stop "$unit"; fi
done"#;

pub(super) const DNS_BLOCKLIST_SETUP: &str = r#"
install -d -o root -g root -m 0755 /var/lib/sirinvpn-dns-blocklist
cat >/etc/systemd/system/sirinvpn-dns-blocklist.service <<'UNIT'
[Unit]
Description=SirinVPN optional DNS blocklist refresh
After=network-online.target unbound.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/lib/sirinvpn/sirinvpn-server dns-blocklist apply
TimeoutStartSec=30min
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/etc/unbound/unbound.conf.d /var/lib/sirinvpn-dns-blocklist
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
StandardOutput=null
StandardError=null
UNIT
cat >/etc/systemd/system/sirinvpn-dns-blocklist.path <<'UNIT'
[Unit]
Description=SirinVPN DNS blocklist policy watch
[Path]
PathChanged=/etc/sirinvpn/authorization/authorization.json
Unit=sirinvpn-dns-blocklist.service
[Install]
WantedBy=paths.target
UNIT
cat >/etc/systemd/system/sirinvpn-dns-blocklist.timer <<'UNIT'
[Unit]
Description=SirinVPN daily DNS blocklist refresh
[Timer]
OnActiveSec=10min
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
Unit=sirinvpn-dns-blocklist.service
[Install]
WantedBy=timers.target
UNIT
"#;
