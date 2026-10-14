#!/bin/sh
set -eu

case "${1:-}" in
  configure)
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload
      # An enabled boot kill switch moves from network-pre.target, which is
      # not always started, to sysinit.target.
      if systemctl is-enabled --quiet sirinvpn-killswitch.service 2>/dev/null; then
        systemctl reenable sirinvpn-killswitch.service >/dev/null 2>&1 || true
      fi
      # A running supervisor would keep executing the replaced helper. Its intent,
      # tunnel and guard persist, so a restart does not interrupt the connection.
      systemctl try-restart sirinvpn-reconnect.service >/dev/null 2>&1 || true
      # Apply the probe exclusion without restarting Wi-Fi or Ethernet.
      systemctl reload NetworkManager.service >/dev/null 2>&1 || true
    fi
    ;;
esac
