#!/bin/sh
set -eu

: "${SIRINVPN_LINUX_DNS_SERVER_ID:?Set the existing disposable SirinVPN server ID}"
: "${SIRINVPN_LINUX_DNS_HOST_KEY:?Set the independently verified ED25519 SHA256 SSH host fingerprint}"
: "${SIRINVPN_LINUX_DNS_CONFIRM:?Set SIRINVPN_LINUX_DNS_CONFIRM=dns-fault-disposable-vps}"

if [ "$SIRINVPN_LINUX_DNS_CONFIRM" != "dns-fault-disposable-vps" ]; then
  echo "Refusing to interrupt DNS on a VPS without the exact confirmation." >&2
  exit 2
fi

export LC_ALL=C
PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CLI=${SIRINVPN_LINUX_DNS_CLI:-"$PROJECT_ROOT/target/release/sirinvpn"}
LOCAL_HELPER=${SIRINVPN_LINUX_DNS_HELPER:-/usr/lib/sirinvpn/sirinvpn-helper}
REMOTE_HELPER_SOURCE="$PROJECT_ROOT/tests/integration/linux-dns-fault-rollback.py"
SERVER_ID=$SIRINVPN_LINUX_DNS_SERVER_ID
SSH_USER=${SIRINVPN_LINUX_DNS_USER:-root}
SSH_PORT=${SIRINVPN_LINUX_DNS_SSH_PORT:-22}

for command in awk cmp getent grep ip jq nft ping python3 resolvectl sha256sum sort ssh ssh-add ssh-keygen ssh-keyscan stat sudo systemctl timeout wg; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required for the Linux DNS fault gate." >&2
    exit 2
  fi
done
for executable in "$CLI" "$LOCAL_HELPER" "$REMOTE_HELPER_SOURCE"; do
  if [ ! -f "$executable" ]; then
    echo "Required test artifact is missing: $executable" >&2
    exit 2
  fi
done
if ! ssh-add -l >/dev/null 2>&1; then
  echo "No SSH agent identity is loaded." >&2
  exit 2
fi
if ! sudo -n true >/dev/null 2>&1; then
  echo "Prime a short-lived sudo credential with 'sudo -v' before running this gate." >&2
  exit 2
fi
case "$SIRINVPN_LINUX_DNS_HOST_KEY" in
  SHA256:*) ;;
  *)
    echo "The expected SSH host key must use SHA256:... form." >&2
    exit 2
    ;;
esac
case "$SSH_PORT" in
  ''|*[!0-9]*)
    echo "The SSH port must be a decimal integer." >&2
    exit 2
    ;;
esac
if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
  echo "The requested SSH port is outside its safe bound." >&2
  exit 2
fi

TEST_ROOT=$(mktemp -d /tmp/sirinvpn-linux-dns-fault.XXXXXX)
chmod 0700 "$TEST_ROOT"
umask 077
PROFILE="$TEST_ROOT/profile.json"
CONNECT_OUTPUT="$TEST_ROOT/connect.json"
STATUS_OUTPUT="$TEST_ROOT/status.json"
HELPER_STATUS="$TEST_ROOT/helper-status.json"
KNOWN_HOSTS="$TEST_ROOT/known_hosts"
REMOTE_CONFIGURATION="$TEST_ROOT/server.json"
REMOTE_BASELINE="$TEST_ROOT/remote-baseline.sha256"
REMOTE_FINAL="$TEST_ROOT/remote-final.sha256"
REMOTE_TABLES_BASELINE="$TEST_ROOT/remote-tables-baseline.txt"
REMOTE_TABLES_FINAL="$TEST_ROOT/remote-tables-final.txt"
LOCAL_TABLES_BASELINE="$TEST_ROOT/local-tables-baseline.txt"
LOCAL_TABLES_FINAL="$TEST_ROOT/local-tables-final.txt"
NFT_DUMP="$TEST_ROOT/nft.txt"
LOCAL_NFT_DUMP="$TEST_ROOT/local-nft.txt"
DNS_OUTPUT="$TEST_ROOT/dns.txt"
POLICY_BACKUP="$TEST_ROOT/network-policy.original"
POLICY_PRESENT=0
POLICY_HASH=
REMOTE_ARMED=0
REMOTE_ROOT=
REMOTE_HELPER=
NFT_TABLE=
ROLLBACK_BASE=
ROLLBACK_TIMER=
ROLLBACK_SERVICE=
LOCAL_TOUCHED=0
LOCAL_OBSERVER_ACTIVE=0
CLEANUP_RUNNING=0
MAIN_COMPLETE=0
LOCAL_NFT_TABLE="sirinvpn_dns_observer_$$"

USER_HOME_DIRECTORY=$(getent passwd "$(id -u)" | awk -F: 'NR == 1 { print $6 }')
if [ -z "$USER_HOME_DIRECTORY" ]; then
  echo "The current user's home directory could not be resolved." >&2
  exit 2
fi
CONFIGURATION_BASE=${XDG_CONFIG_HOME:-"$USER_HOME_DIRECTORY/.config"}
POLICY_FILE="$CONFIGURATION_BASE/sirinvpn/network-policy.json"
if [ -e "$POLICY_FILE" ]; then
  if [ ! -f "$POLICY_FILE" ] || [ -L "$POLICY_FILE" ] \
    || [ "$(stat -c '%a:%u' "$POLICY_FILE")" != "600:$(id -u)" ]; then
    echo "The existing network-policy file is not a safe mode-0600 user-owned regular file." >&2
    exit 2
  fi
  cp -p -- "$POLICY_FILE" "$POLICY_BACKUP"
  POLICY_PRESENT=1
  POLICY_HASH=$(sha256sum "$POLICY_FILE" | awk '{print $1}')
fi

remote() {
  if [ "$#" -ne 1 ]; then
    echo "The DNS fault gate accepts one bounded remote command at a time." >&2
    return 2
  fi
  ssh \
    -p "$SSH_PORT" \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o GlobalKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$KNOWN_HOSTS" \
    "$SSH_USER@$SERVER_HOST" "export LC_ALL=C; $1"
}

local_root() {
  sudo -n "$@"
}

helper_status() {
  "$LOCAL_HELPER" status
}

remote_hashes() {
  remote "sha256sum \
    /etc/sirinvpn/server.json \
    /etc/sirinvpn/authorization/authorization.json \
    /etc/sirinvpn/wireguard.key \
    /etc/sirinvpn/management.key \
    /etc/sirinvpn/transport.key \
    /etc/sirinvpn/operational.json \
    /usr/local/lib/sirinvpn/sirinvpn-server"
}

set_remote_transaction() {
  TRANSACTION_SUFFIX=$1
  REMOTE_ROOT="/run/sirinvpn-linux-dns-fault-$$-$TRANSACTION_SUFFIX"
  REMOTE_HELPER="$REMOTE_ROOT/rollback.py"
  NFT_TABLE="sirinvpn_dns_fault_$$_$TRANSACTION_SUFFIX"
  ROLLBACK_BASE="sirinvpn-linux-dns-fault-$$-$TRANSACTION_SUFFIX-rollback"
  ROLLBACK_TIMER="$ROLLBACK_BASE.timer"
  ROLLBACK_SERVICE="$ROLLBACK_BASE.service"
}

arm_remote_transaction() {
  set_remote_transaction "$1"
  remote "install -d -m 0700 '$REMOTE_ROOT'"
  remote "install -m 0700 /dev/stdin '$REMOTE_HELPER'" <"$REMOTE_HELPER_SOURCE"
  remote "/usr/bin/python3 '$REMOTE_HELPER' prepare '$REMOTE_ROOT' '$NFT_TABLE'"
  REMOTE_ARMED=1
  remote "systemd-run --quiet --unit='$ROLLBACK_BASE' --on-active=10m --timer-property=AccuracySec=1s --property=Restart=on-failure --property=RestartSec=5s /usr/bin/python3 '$REMOTE_HELPER' rollback '$REMOTE_ROOT' '$NFT_TABLE'"
}

restore_remote_transaction() {
  if ! remote "/usr/bin/python3 '$REMOTE_HELPER' rollback '$REMOTE_ROOT' '$NFT_TABLE'"; then
    remote "set -eu; test ! -e '$REMOTE_ROOT'; ! nft list table inet '$NFT_TABLE' >/dev/null 2>&1; systemctl is-active --quiet unbound.service; systemctl is-active --quiet sirinvpn-server.service" \
      || return 1
  fi
  remote "systemctl stop '$ROLLBACK_TIMER' '$ROLLBACK_SERVICE' >/dev/null 2>&1 || true" \
    || return 1
  remote "systemctl reset-failed '$ROLLBACK_TIMER' '$ROLLBACK_SERVICE' >/dev/null 2>&1 || true" \
    || return 1
  REMOTE_ARMED=0
}

verify_remote_baseline() {
  remote_hashes >"$REMOTE_FINAL" || return 1
  remote "nft list tables | sort" >"$REMOTE_TABLES_FINAL" || return 1
  if ! cmp -s "$REMOTE_BASELINE" "$REMOTE_FINAL"; then
    echo "The VPS identity/configuration hashes did not return to baseline." >&2
    return 1
  fi
  if ! cmp -s "$REMOTE_TABLES_BASELINE" "$REMOTE_TABLES_FINAL"; then
    echo "The VPS nftables table set did not return to baseline." >&2
    return 1
  fi
  remote "set -eu; \
    systemctl is-active --quiet unbound.service; \
    systemctl is-active --quiet sirinvpn-server.service; \
    /usr/local/lib/sirinvpn/sirinvpn-server validate-state; \
    test -z \"\$(find /run -maxdepth 1 -type d -name 'sirinvpn-linux-dns-fault-*' -print -quit)\"; \
    test -z \"\$(systemctl list-units --all --no-legend 'sirinvpn-linux-dns-fault-*-rollback*')\"" \
    || return 1
}

restore_local_policy() {
  if [ "$POLICY_PRESENT" -eq 1 ]; then
    if [ ! -f "$POLICY_BACKUP" ]; then
      echo "The local network-policy backup is unavailable." >&2
      return 1
    fi
    POLICY_TEMP="$POLICY_FILE.linux-dns-fault-$$"
    install -m 0600 "$POLICY_BACKUP" "$POLICY_TEMP" || return 1
    mv -f -- "$POLICY_TEMP" "$POLICY_FILE" || return 1
    if [ "$(sha256sum "$POLICY_FILE" | awk '{print $1}')" != "$POLICY_HASH" ]; then
      echo "The local network-policy hash was not restored." >&2
      return 1
    fi
  else
    case "$POLICY_FILE" in
      */sirinvpn/network-policy.json) rm -f -- "$POLICY_FILE" || return 1 ;;
      *)
        echo "Refusing to remove an unexpected local policy path." >&2
        return 1
        ;;
    esac
  fi
}

assert_vpn_clean() {
  helper_status >"$HELPER_STATUS" || return 1
  jq -e '
    .state == "disconnected"
    and .server_id == null
    and .kill_switch_enabled == false
    and .auto_reconnect_enabled == false
    and .transport_fallback_enabled == false
  ' "$HELPER_STATUS" >/dev/null || return 1
  if ip link show sirinvpn0 >/dev/null 2>&1 \
    || systemctl is-active --quiet sirinvpn-killswitch.service \
    || systemctl is-active --quiet sirinvpn-reconnect.service \
    || systemctl is-active --quiet sirinvpn-transport.service; then
    return 1
  fi
  ! local_root nft list table inet sirinvpn_guard >/dev/null 2>&1 || return 1
  ! local_root nft list table inet sirinvpn_client >/dev/null 2>&1 || return 1
  ! local_root nft list table ip6 sirinvpn_client6 >/dev/null 2>&1 || return 1
}

disconnect_local() {
  "$CLI" disconnect >/dev/null 2>&1 || true
  assert_vpn_clean || return 1
  LOCAL_TOUCHED=0
}

remove_local_observer() {
  if [ "$LOCAL_OBSERVER_ACTIVE" -eq 1 ]; then
    local_root nft delete table inet "$LOCAL_NFT_TABLE" >/dev/null 2>&1 || \
      ! local_root nft list table inet "$LOCAL_NFT_TABLE" >/dev/null 2>&1 || return 1
    LOCAL_OBSERVER_ACTIVE=0
  fi
}

assert_local_baseline() {
  assert_vpn_clean || return 1
  local_root nft list tables | sort >"$LOCAL_TABLES_FINAL" || return 1
  if ! cmp -s "$LOCAL_TABLES_BASELINE" "$LOCAL_TABLES_FINAL"; then
    echo "The local nftables table set did not return to baseline." >&2
    return 1
  fi
}

# Called indirectly by the exit/signal cleanup trap.
# shellcheck disable=SC2317
cleanup() {
  result=$?
  if [ "$CLEANUP_RUNNING" -eq 1 ]; then
    exit "$result"
  fi
  CLEANUP_RUNNING=1
  trap - EXIT HUP INT TERM
  set +e
  cleanup_failed=0

  if [ "$LOCAL_TOUCHED" -eq 1 ] || ! helper_status | jq -e '.state == "disconnected"' >/dev/null 2>&1; then
    if ! disconnect_local; then
      echo "WARNING: local VPN cleanup could not be confirmed." >&2
      cleanup_failed=1
    fi
  fi
  if ! remove_local_observer; then
    echo "WARNING: the local DNS observer could not be removed." >&2
    cleanup_failed=1
  fi
  if [ "$REMOTE_ARMED" -eq 1 ]; then
    if ! restore_remote_transaction; then
      echo "WARNING: VPS DNS rollback could not be confirmed; the 10-minute timer remains the fallback." >&2
      cleanup_failed=1
    fi
  fi
  if [ -s "$REMOTE_BASELINE" ] && [ "$REMOTE_ARMED" -eq 0 ]; then
    if ! verify_remote_baseline; then
      echo "WARNING: final VPS baseline verification failed." >&2
      cleanup_failed=1
    fi
  fi
  if ! restore_local_policy; then
    cleanup_failed=1
  fi
  if [ -s "$LOCAL_TABLES_BASELINE" ] && ! assert_local_baseline; then
    echo "WARNING: final local network cleanup failed." >&2
    cleanup_failed=1
  fi

  case "$TEST_ROOT" in
    /tmp/sirinvpn-linux-dns-fault.*) rm -rf -- "$TEST_ROOT" ;;
    *)
      echo "WARNING: refusing to remove unexpected test directory $TEST_ROOT" >&2
      cleanup_failed=1
      ;;
  esac

  if [ "$cleanup_failed" -ne 0 ]; then
    result=1
  fi
  if [ "$result" -eq 0 ] && [ "$MAIN_COMPLETE" -eq 1 ]; then
    echo "Linux DNS fault gate passed: encrypted-upstream failure stayed private, resolver interruption recovered, and exact cleanup was verified."
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$CLI" --json server list >"$TEST_ROOT/profiles.json"
jq -e --arg id "$SERVER_ID" '.[] | select(.id == $id)' \
  "$TEST_ROOT/profiles.json" >"$PROFILE"
SERVER_HOST=$(jq -er '.endpoint.host' "$PROFILE")
WIREGUARD_PORT=$(jq -er '.endpoint.wireguard_port' "$PROFILE")
CLIENT_ADDRESS=$(jq -er '.client_tunnel_address' "$PROFILE")
SERVER_TUNNEL_ADDRESS=$(jq -er '.server_tunnel_address' "$PROFILE")
IPV6_TUNNEL_ENABLED=$(jq -r '.ipv6_tunnel_enabled // false' "$PROFILE")
case "$SERVER_HOST:$SSH_USER" in
  *[!A-Za-z0-9._:@-]*)
    echo "The stored VPS host or requested SSH username is unsafe for this test harness." >&2
    exit 2
    ;;
esac
case "$WIREGUARD_PORT" in
  ''|*[!0-9]*)
    echo "The stored WireGuard port is not a decimal integer." >&2
    exit 2
    ;;
esac
if [ "$WIREGUARD_PORT" -lt 1 ] || [ "$WIREGUARD_PORT" -gt 65535 ]; then
  echo "The stored WireGuard port is outside its safe bound." >&2
  exit 2
fi

LOCAL_PHYSICAL_INTERFACE=$(ip -4 route show default | awk 'NR == 1 { for (field = 1; field <= NF; field++) if ($field == "dev") { print $(field + 1); exit } }')
case "$LOCAL_PHYSICAL_INTERFACE" in
  ''|*[!A-Za-z0-9_.:-]*)
    echo "The local physical default-route interface could not be identified safely." >&2
    exit 2
    ;;
esac
RESOLVER_UID=$(getent passwd systemd-resolve | awk -F: 'NR == 1 { print $3 }')
if [ -z "$RESOLVER_UID" ]; then
  RESOLVER_UID=$(getent passwd _systemd-resolve | awk -F: 'NR == 1 { print $3 }')
fi
case "$RESOLVER_UID" in
  ''|*[!0-9]*)
    echo "The systemd-resolved service account could not be identified." >&2
    exit 2
    ;;
esac

assert_vpn_clean
local_root nft list tables | sort >"$LOCAL_TABLES_BASELINE"
ssh-keyscan -T 10 -p "$SSH_PORT" -t ed25519 "$SERVER_HOST" \
  >"$KNOWN_HOSTS" 2>/dev/null
ACTUAL_HOST_KEY=$(ssh-keygen -E sha256 -lf "$KNOWN_HOSTS" | awk 'NR == 1 { print $2 }')
if [ "$ACTUAL_HOST_KEY" != "$SIRINVPN_LINUX_DNS_HOST_KEY" ]; then
  echo "The VPS ED25519 host fingerprint does not match the independently verified value." >&2
  exit 2
fi
remote "set -eu; \
  test \"\$(. /etc/os-release; printf '%s' \"\$VERSION_ID\")\" = 13; \
  systemctl is-active --quiet unbound.service; \
  systemctl is-active --quiet sirinvpn-server.service; \
  /usr/local/lib/sirinvpn/sirinvpn-server validate-state; \
  /usr/sbin/unbound-checkconf /etc/unbound/unbound.conf >/dev/null; \
  command -v nft >/dev/null; \
  command -v python3 >/dev/null; \
  command -v systemd-run >/dev/null; \
  test -z \"\$(find /run -maxdepth 1 -type d -name 'sirinvpn-linux-dns-fault-*' -print -quit)\"; \
  ! nft list tables | grep -q sirinvpn_dns_fault_ || exit 1; \
  python3 -c 'import json; d=json.load(open(\"/etc/sirinvpn/authorization/authorization.json\")); assert not d.get(\"invitations\", []); assert not d.get(\"enrollment_receipts\", []); assert not d.get(\"key_rotations\", []); assert not d.get(\"port_forwards\", [])'"
PUBLIC_INTERFACE=$(remote "ip -4 route show default | awk 'NR == 1 { for (field = 1; field <= NF; field++) if (\$field == \"dev\") { print \$(field + 1); exit } }'")
case "$PUBLIC_INTERFACE" in
  ''|*[!A-Za-z0-9_.:-]*)
    echo "The VPS public interface could not be identified safely." >&2
    exit 2
    ;;
esac
remote "cat /etc/sirinvpn/server.json" >"$REMOTE_CONFIGURATION"
if ! jq -e '
  .dns_upstream.mode == "dns_over_tls"
  and (.dns_upstream.endpoints | length >= 1 and length <= 2)
  and all(.dns_upstream.endpoints[];
    (.address | type == "string")
    and (.authentication_name | type == "string" and length >= 1))
' "$REMOTE_CONFIGURATION" >/dev/null; then
  echo "This bounded gate requires an existing one-or-two-endpoint DNS-over-TLS policy." >&2
  exit 2
fi
python3 - "$REMOTE_CONFIGURATION" <<'PY'
import ipaddress
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    document = json.load(source)
for endpoint in document["dns_upstream"]["endpoints"]:
    address = ipaddress.ip_address(endpoint["address"])
    assert str(address) == endpoint["address"]
PY
DOT_ENDPOINTS=$(jq -r '.dns_upstream.endpoints[].address' "$REMOTE_CONFIGURATION")
remote_hashes >"$REMOTE_BASELINE"
remote "nft list tables | sort" >"$REMOTE_TABLES_BASELINE"

assert_authenticated_connection() {
  READY=0
  ATTEMPT=0
  while [ "$ATTEMPT" -lt 20 ]; do
    if "$CLI" --json status >"$STATUS_OUTPUT" 2>/dev/null \
      && jq -e \
        --arg id "$SERVER_ID" \
        --argjson ipv6 "$IPV6_TUNNEL_ENABLED" '
          .local.state == "connected"
          and .local.server_id == $id
          and .local.transport == "direct_udp"
          and .local.kill_switch_enabled == false
          and .local.auto_reconnect_enabled == false
          and .local.transport_fallback_enabled == false
          and .local.routing_mode == "full_tunnel"
          and .local.allow_lan == false
          and .server.connection_state == "connected"
          and .server.transport == "direct_udp"
          and .server.dns_healthy == true
          and (if $ipv6 then .local.ipv6_tunneled == true else .local.ipv6_blocked == true end)
        ' "$STATUS_OUTPUT" >/dev/null; then
      READY=1
      break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
  done
  if [ "$READY" -ne 1 ]; then
    echo "Direct UDP did not return authenticated healthy state." >&2
    return 1
  fi

  ip -4 -o address show dev sirinvpn0 | grep -F " $CLIENT_ADDRESS/" >/dev/null
  ip -4 route show table 51820 | grep -E '^default .*dev sirinvpn0' >/dev/null
  ip -4 rule show priority 10000 | grep -F 'lookup 51820' >/dev/null
  ip -4 rule show priority 10001 | grep -F 'suppress_prefixlength 0' >/dev/null
  resolvectl dns sirinvpn0 | grep -F "$SERVER_TUNNEL_ADDRESS" >/dev/null
  resolvectl domain sirinvpn0 | grep -F '~.' >/dev/null
  local_root wg show sirinvpn0 endpoints | grep -F ":$WIREGUARD_PORT" >/dev/null
  ! systemctl is-active --quiet sirinvpn-transport.service || return 1
}

assert_ip_data_plane() {
  ping -c 1 -W 5 "$SERVER_TUNNEL_ADDRESS" >/dev/null
  python3 - <<'PY'
import socket
with socket.create_connection(("1.1.1.1", 443), timeout=5):
    pass
PY
}

dns_query_succeeds() {
  QUERY_NAME=$1
  if ! timeout 20 resolvectl \
    --cache=no \
    --stale-data=no \
    --synthesize=no \
    --zone=no \
    --legend=no \
    --protocol=dns \
    -4 query "$QUERY_NAME" >"$DNS_OUTPUT" 2>&1; then
    echo "Private DNS did not resolve $QUERY_NAME." >&2
    return 1
  fi
}

dns_query_fails() {
  QUERY_NAME=$1
  if timeout 15 resolvectl \
    --cache=no \
    --stale-data=no \
    --synthesize=no \
    --zone=no \
    --legend=no \
    --protocol=dns \
    -4 query "$QUERY_NAME" >"$DNS_OUTPUT" 2>&1; then
    echo "DNS unexpectedly resolved $QUERY_NAME while its private path was unavailable." >&2
    return 1
  fi
}

decimal_counter() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

remote_counter() {
  COUNTER_COMMENT=$1
  remote "/usr/sbin/nft list table inet '$NFT_TABLE'" >"$NFT_DUMP"
  awk -v comment="$COUNTER_COMMENT" '
    index($0, "comment \"" comment "\"") {
      for (field = 1; field <= NF; field++) {
        if ($field == "packets") {
          total += $(field + 1)
        }
      }
    }
    END { print total + 0 }
  ' "$NFT_DUMP"
}

local_leak_counter() {
  local_root nft list table inet "$LOCAL_NFT_TABLE" >"$LOCAL_NFT_DUMP"
  awk '
    /comment "linux-physical-dns"/ {
      for (field = 1; field <= NF; field++) {
        if ($field == "packets") {
          total += $(field + 1)
        }
      }
    }
    END { print total + 0 }
  ' "$LOCAL_NFT_DUMP"
}

assert_no_physical_dns_delta() {
  BEFORE=$1
  AFTER=$(local_leak_counter)
  if ! decimal_counter "$BEFORE" || ! decimal_counter "$AFTER" \
    || [ "$AFTER" -ne "$BEFORE" ]; then
    echo "systemd-resolved attempted DNS on the physical interface." >&2
    return 1
  fi
}

create_local_observer() {
  LOCAL_OBSERVER_ACTIVE=1
  {
    printf 'add table inet %s\n' "$LOCAL_NFT_TABLE"
    printf 'add chain inet %s output { type filter hook output priority -300; policy accept; }\n' \
      "$LOCAL_NFT_TABLE"
    printf 'add rule inet %s output meta skuid %s oifname "%s" udp dport 53 counter comment "linux-physical-dns"\n' \
      "$LOCAL_NFT_TABLE" "$RESOLVER_UID" "$LOCAL_PHYSICAL_INTERFACE"
    printf 'add rule inet %s output meta skuid %s oifname "%s" tcp dport { 53, 853 } counter comment "linux-physical-dns"\n' \
      "$LOCAL_NFT_TABLE" "$RESOLVER_UID" "$LOCAL_PHYSICAL_INTERFACE"
  } | local_root nft -f -
}

create_dns_fault_table() {
  BLOCK_DOT=$1
  {
    printf 'add table inet %s\n' "$NFT_TABLE"
    printf 'add chain inet %s input { type filter hook input priority -300; policy accept; }\n' \
      "$NFT_TABLE"
    printf 'add chain inet %s output { type filter hook output priority -300; policy accept; }\n' \
      "$NFT_TABLE"
    printf 'add chain inet %s forward { type filter hook forward priority -300; policy accept; }\n' \
      "$NFT_TABLE"
    printf 'add rule inet %s input iifname "sirinvpn0" udp dport 53 counter comment "dns-private-query"\n' \
      "$NFT_TABLE"
    printf 'add rule inet %s input iifname "sirinvpn0" tcp dport 53 counter comment "dns-private-query"\n' \
      "$NFT_TABLE"
    printf 'add rule inet %s output oifname "%s" udp dport 53 counter drop comment "dns-alternate-egress"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE"
    printf 'add rule inet %s output oifname "%s" tcp dport 53 counter drop comment "dns-alternate-egress"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE"
    printf 'add rule inet %s forward iifname "sirinvpn0" oifname "%s" udp dport 53 counter drop comment "dns-alternate-egress"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE"
    printf 'add rule inet %s forward iifname "sirinvpn0" oifname "%s" tcp dport { 53, 853 } counter drop comment "dns-alternate-egress"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE"
    if [ "$BLOCK_DOT" = true ]; then
      for DOT_ENDPOINT in $DOT_ENDPOINTS; do
        if printf '%s\n' "$DOT_ENDPOINT" | grep -q ':'; then
          DOT_FAMILY=ip6
        else
          DOT_FAMILY=ip
        fi
        printf 'add rule inet %s output oifname "%s" %s daddr %s tcp dport 853 counter reject with tcp reset comment "dns-dot-block"\n' \
          "$NFT_TABLE" "$PUBLIC_INTERFACE" "$DOT_FAMILY" "$DOT_ENDPOINT"
      done
    fi
    printf 'add rule inet %s output oifname "%s" tcp dport 853 tcp flags & (syn | ack) == syn counter drop comment "dns-alternate-egress"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE"
  } | remote "/usr/sbin/nft -f -"
}

echo "Control phase: authenticated Direct UDP with private DNS"
LOCAL_TOUCHED=1
"$CLI" --json connect "$SERVER_ID" --transport direct >"$CONNECT_OUTPUT"
assert_authenticated_connection
assert_ip_data_plane
create_local_observer
PHYSICAL_DNS_BEFORE=$(local_leak_counter)
dns_query_succeeds example.com
assert_no_physical_dns_delta "$PHYSICAL_DNS_BEFORE"

echo "Upstream phase: reject every configured DNS-over-TLS endpoint"
arm_remote_transaction upstream
create_dns_fault_table true
remote "systemctl restart unbound.service; systemctl start sirinvpn-server.service; systemctl is-active --quiet unbound.service; systemctl is-active --quiet sirinvpn-server.service"
PRIVATE_QUERY_BEFORE=$(remote_counter dns-private-query)
DOT_BLOCK_BEFORE=$(remote_counter dns-dot-block)
ALTERNATE_BEFORE=$(remote_counter dns-alternate-egress)
PHYSICAL_DNS_BEFORE=$(local_leak_counter)
dns_query_fails example.net
assert_ip_data_plane
assert_authenticated_connection
PRIVATE_QUERY_AFTER=$(remote_counter dns-private-query)
DOT_BLOCK_AFTER=$(remote_counter dns-dot-block)
ALTERNATE_AFTER=$(remote_counter dns-alternate-egress)
for COUNTER in \
  "$PRIVATE_QUERY_BEFORE" "$DOT_BLOCK_BEFORE" "$ALTERNATE_BEFORE" \
  "$PRIVATE_QUERY_AFTER" "$DOT_BLOCK_AFTER" "$ALTERNATE_AFTER"; do
  if ! decimal_counter "$COUNTER"; then
    echo "The DNS fault table exposed an invalid packet counter." >&2
    exit 1
  fi
done
PRIVATE_QUERY_DELTA=$((PRIVATE_QUERY_AFTER - PRIVATE_QUERY_BEFORE))
DOT_BLOCK_DELTA=$((DOT_BLOCK_AFTER - DOT_BLOCK_BEFORE))
ALTERNATE_DELTA=$((ALTERNATE_AFTER - ALTERNATE_BEFORE))
if [ "$PRIVATE_QUERY_DELTA" -lt 1 ] || [ "$DOT_BLOCK_DELTA" -lt 1 ]; then
  echo "The failed query did not exercise both private DNS and encrypted upstream transport." >&2
  exit 1
fi
if [ "$ALTERNATE_DELTA" -ne 0 ]; then
  echo "The DNS stack attempted alternate port-53/853 egress after encrypted upstream failure." >&2
  exit 1
fi
assert_no_physical_dns_delta "$PHYSICAL_DNS_BEFORE"
echo "Encrypted upstream failure: $PRIVATE_QUERY_DELTA private query packet(s), $DOT_BLOCK_DELTA blocked DoT packet(s), no alternate DNS egress"
restore_remote_transaction
verify_remote_baseline
dns_query_succeeds example.org
assert_authenticated_connection

echo "Resolver phase: stop Unbound, retain IP traffic, then recover DNS"
arm_remote_transaction resolver
create_dns_fault_table false
remote "systemctl stop unbound.service; ! systemctl is-active --quiet unbound.service"
ALTERNATE_BEFORE=$(remote_counter dns-alternate-egress)
PRIVATE_QUERY_BEFORE=$(remote_counter dns-private-query)
PHYSICAL_DNS_BEFORE=$(local_leak_counter)
dns_query_fails iana.org
assert_ip_data_plane
assert_no_physical_dns_delta "$PHYSICAL_DNS_BEFORE"
PRIVATE_QUERY_AFTER=$(remote_counter dns-private-query)
ALTERNATE_AFTER=$(remote_counter dns-alternate-egress)
for COUNTER in \
  "$PRIVATE_QUERY_BEFORE" "$ALTERNATE_BEFORE" \
  "$PRIVATE_QUERY_AFTER" "$ALTERNATE_AFTER"; do
  if ! decimal_counter "$COUNTER"; then
    echo "The resolver fault table exposed an invalid packet counter." >&2
    exit 1
  fi
done
PRIVATE_QUERY_DELTA=$((PRIVATE_QUERY_AFTER - PRIVATE_QUERY_BEFORE))
ALTERNATE_DELTA=$((ALTERNATE_AFTER - ALTERNATE_BEFORE))
if [ "$PRIVATE_QUERY_DELTA" -lt 1 ]; then
  echo "The resolver interruption did not observe a private DNS query." >&2
  exit 1
fi
if [ "$ALTERNATE_DELTA" -ne 0 ]; then
  echo "The DNS stack attempted alternate port-53/853 egress while Unbound was stopped." >&2
  exit 1
fi
restore_remote_transaction
verify_remote_baseline
dns_query_succeeds debian.org
assert_authenticated_connection
echo "Resolver interruption: DNS failed privately while stopped and recovered after service restoration"

disconnect_local
remove_local_observer
restore_local_policy
assert_local_baseline
MAIN_COMPLETE=1
exit 0
