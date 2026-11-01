//! Opt-in VPS alerts: an unprivileged task checks the VPS every five minutes and sends only
//! when the Owner has set an alert or heartbeat address. It needs no capability, and of
//! /etc/sirinvpn it sees only the server configuration and authorization, never the keys.
pub(super) const ALERTS_MANAGED_PATHS: &str = "etc/systemd/system/sirinvpn-alerts.service etc/systemd/system/sirinvpn-alerts.timer var/lib/sirinvpn-alerts";

pub(super) const ALERTS_SETUP: &str = r#"
cat >/etc/systemd/system/sirinvpn-alerts.service <<'UNIT'
[Unit]
Description=SirinVPN optional VPS alerts and heartbeat
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=sirinvpn
Group=sirinvpn
ExecStart=/usr/local/lib/sirinvpn/sirinvpn-server alerts check
TimeoutStartSec=2min
StateDirectory=sirinvpn-alerts
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
TemporaryFileSystem=/etc/sirinvpn:ro
BindReadOnlyPaths=/etc/sirinvpn/server.json -/etc/sirinvpn/authorization
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
StandardOutput=null
StandardError=null
UNIT
cat >/etc/systemd/system/sirinvpn-alerts.timer <<'UNIT'
[Unit]
Description=SirinVPN VPS alert check every five minutes
[Timer]
OnActiveSec=5min
OnUnitActiveSec=5min
AccuracySec=30s
Unit=sirinvpn-alerts.service
[Install]
WantedBy=timers.target
UNIT
"#;
