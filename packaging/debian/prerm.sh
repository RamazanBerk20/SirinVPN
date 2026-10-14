#!/bin/sh
set -eu

case "${1:-}" in
  remove|deconfigure)
    # Disconnect while the installed helper and its systemd units still exist.
    # If cleanup fails, dpkg must retain the package so it can be retried.
    # Without saved connection state there is nothing to restore, so removal
    # must not depend on nft or ip inspection succeeding.
    if [ -e /var/lib/sirinvpn/desired-connection.json ] || \
       [ -e /run/sirinvpn/client-state.json ]; then
      if [ -x /usr/lib/sirinvpn/sirinvpn-helper ]; then
        /usr/lib/sirinvpn/sirinvpn-helper disconnect >/dev/null
      else
        echo 'SirinVPN networking cannot be restored because its helper is missing. Reinstall the package and retry removal.' >&2
        exit 1
      fi
    fi
    ;;
esac
