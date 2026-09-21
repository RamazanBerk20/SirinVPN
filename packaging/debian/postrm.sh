#!/bin/sh
set -eu

case "${1:-}" in
  remove|purge)
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload
      systemctl reload NetworkManager.service >/dev/null 2>&1 || true
    fi
    ;;
esac

if [ "${1:-}" = purge ]; then
  for rule in /etc/polkit-1/rules.d/49-sirinvpn-user-*.rules; do
    [ -f "$rule" ] || continue
    uid=${rule##*/49-sirinvpn-user-}
    uid=${uid%.rules}
    case "$uid" in ''|*[!0-9]*) continue ;; esac
    rm -f -- "$rule"
  done
fi
