#!/bin/sh
set -eu

case "${1:-}" in
  configure)
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload
      # Apply the probe exclusion without restarting Wi-Fi or Ethernet.
      systemctl reload NetworkManager.service >/dev/null 2>&1 || true
    fi
    ;;
esac
