#!/bin/sh
set -eu

: "${SIRINVPN_LINUX_FALLBACK_SERVER_ID:?Set the existing disposable SirinVPN server ID}"
: "${SIRINVPN_LINUX_FALLBACK_HOST_KEY:?Set the independently verified ED25519 SHA256 SSH host fingerprint}"
: "${SIRINVPN_LINUX_FALLBACK_CONFIRM:?Set SIRINVPN_LINUX_FALLBACK_CONFIRM=fault-inject-disposable-vps}"

if [ "$SIRINVPN_LINUX_FALLBACK_CONFIRM" != "fault-inject-disposable-vps" ]; then
  echo "Refusing to alter the VPS or local VPN networking." >&2
  exit 2
fi

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CLI=${SIRINVPN_LINUX_FALLBACK_CLI:-"$PROJECT_ROOT/target/release/sirinvpn"}
LOCAL_HELPER=${SIRINVPN_LINUX_FALLBACK_HELPER:-/usr/lib/sirinvpn/sirinvpn-helper}
REMOTE_HELPER_SOURCE="$PROJECT_ROOT/tests/integration/fallback-proxy.py"
SERVER_ID=$SIRINVPN_LINUX_FALLBACK_SERVER_ID
SSH_USER=${SIRINVPN_LINUX_FALLBACK_USER:-root}
SSH_PORT=${SIRINVPN_LINUX_FALLBACK_SSH_PORT:-22}
INTERNAL_TCP_PORT=${SIRINVPN_LINUX_FALLBACK_INTERNAL_TCP_PORT:-4443}

for command in getent ip jq nft ping python3 resolvectl ssh ssh-add ssh-keygen ssh-keyscan sudo systemctl wg; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required for the Linux fallback integration gate." >&2
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
case "$SIRINVPN_LINUX_FALLBACK_HOST_KEY" in
  SHA256:*) ;;
  *)
    echo "The expected SSH host key must use SHA256:... form." >&2
    exit 2
    ;;
esac
case "$SSH_PORT:$INTERNAL_TCP_PORT" in
  *[!0-9:]*)
    echo "SSH and internal TCP ports must be decimal integers." >&2
    exit 2
    ;;
esac
if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ] \
  || [ "$INTERNAL_TCP_PORT" -lt 1024 ] || [ "$INTERNAL_TCP_PORT" -gt 65535 ]; then
  echo "The requested SSH or internal TCP port is outside its safe bound." >&2
  exit 2
fi

TEST_ROOT=$(mktemp -d /tmp/sirinvpn-linux-fallback.XXXXXX)
chmod 0700 "$TEST_ROOT"
umask 077
PROFILE="$TEST_ROOT/profile.json"
CONNECT_OUTPUT="$TEST_ROOT/connect.json"
STATUS_OUTPUT="$TEST_ROOT/status.json"
HELPER_STATUS="$TEST_ROOT/helper-status.json"
NFT_DUMP="$TEST_ROOT/nft.txt"
PROXY_COUNTS="$TEST_ROOT/proxy-counts.txt"
KNOWN_HOSTS="$TEST_ROOT/known_hosts"
REMOTE_BASELINE="$TEST_ROOT/remote-baseline.sha256"
REMOTE_FINAL="$TEST_ROOT/remote-final.sha256"
POLICY_BACKUP="$TEST_ROOT/network-policy.original"
POLICY_PRESENT=0
POLICY_HASH=
REMOTE_ARMED=0
LOCAL_TOUCHED=0
CLEANUP_RUNNING=0
MAIN_COMPLETE=0
FAULT_TIMER=
FAULT_SERVICE=

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
  ssh \
    -p "$SSH_PORT" \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o GlobalKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$KNOWN_HOSTS" \
    "$SSH_USER@$SERVER_HOST" "$@"
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
  REMOTE_ROOT="/run/sirinvpn-linux-fallback-$$-$TRANSACTION_SUFFIX"
  REMOTE_HELPER="$REMOTE_ROOT/fault.py"
  REMOTE_CONFIG=/etc/sirinvpn/server.json
  REMOTE_BACKUP="$REMOTE_ROOT/server.json.original"
  REMOTE_COUNTER="$REMOTE_ROOT/proxy.counts"
  NFT_TABLE="sirinvpn_linux_$$_$TRANSACTION_SUFFIX"
  PROXY_UNIT="sirinvpn-linux-fallback-$$-$TRANSACTION_SUFFIX-proxy.service"
  ROLLBACK_BASE="sirinvpn-linux-fallback-$$-$TRANSACTION_SUFFIX-rollback"
  ROLLBACK_TIMER="$ROLLBACK_BASE.timer"
  ROLLBACK_SERVICE="$ROLLBACK_BASE.service"
  FAULT_TIMER=
  FAULT_SERVICE=
}

arm_remote_transaction() {
  set_remote_transaction "$1"
  remote "install -d -m 0700 '$REMOTE_ROOT'"
  REMOTE_ARMED=1
  remote "install -m 0700 /dev/stdin '$REMOTE_HELPER'" <"$REMOTE_HELPER_SOURCE"
  remote "systemd-run --quiet --unit='$ROLLBACK_BASE' --on-active=15m --timer-property=AccuracySec=1s /usr/bin/python3 '$REMOTE_HELPER' rollback '$REMOTE_CONFIG' '$REMOTE_BACKUP' '$NFT_TABLE' '$PROXY_UNIT' '$REMOTE_ROOT'"
}

restore_remote_transaction() {
  remote "systemctl stop '$ROLLBACK_TIMER' '$ROLLBACK_SERVICE' >/dev/null 2>&1 || true"
  if [ -n "$FAULT_TIMER" ]; then
    remote "systemctl stop '$FAULT_TIMER' '$FAULT_SERVICE' >/dev/null 2>&1 || true"
  fi
  remote "/usr/bin/python3 '$REMOTE_HELPER' rollback '$REMOTE_CONFIG' '$REMOTE_BACKUP' '$NFT_TABLE' '$PROXY_UNIT' '$REMOTE_ROOT'" \
    || remote "test ! -e '$REMOTE_ROOT'"
  remote "systemctl reset-failed '$ROLLBACK_TIMER' '$ROLLBACK_SERVICE' '$PROXY_UNIT' >/dev/null 2>&1 || true"
  if [ -n "$FAULT_TIMER" ]; then
    remote "systemctl reset-failed '$FAULT_TIMER' '$FAULT_SERVICE' >/dev/null 2>&1 || true"
  fi
  REMOTE_ARMED=0
}

verify_remote_baseline() {
  remote_hashes >"$REMOTE_FINAL"
  if ! cmp -s "$REMOTE_BASELINE" "$REMOTE_FINAL"; then
    echo "The VPS identity/configuration hashes did not return to baseline." >&2
    return 1
  fi
  remote "set -eu; \
    systemctl is-active --quiet sirinvpn-server.service; \
    /usr/local/lib/sirinvpn/sirinvpn-server validate-state; \
    ! nft list table inet '$NFT_TABLE' >/dev/null 2>&1 || exit 1; \
    test ! -e '$REMOTE_ROOT'; \
    ss -H -lun 'sport = :$WIREGUARD_PORT' | grep -q .; \
    ss -H -lun 'sport = :$OBFUSCATED_PORT' | grep -q .; \
    ss -H -lnt 'sport = :$TCP_PORT' | grep -q ."
}

restore_local_policy() {
  if [ "$POLICY_PRESENT" -eq 1 ]; then
    if [ ! -f "$POLICY_BACKUP" ]; then
      echo "The local network-policy backup is unavailable." >&2
      return 1
    fi
    POLICY_TEMP="$POLICY_FILE.linux-fallback-$$"
    install -m 0600 "$POLICY_BACKUP" "$POLICY_TEMP"
    mv -f -- "$POLICY_TEMP" "$POLICY_FILE"
    if [ "$(sha256sum "$POLICY_FILE" | awk '{print $1}')" != "$POLICY_HASH" ]; then
      echo "The local network-policy hash was not restored." >&2
      return 1
    fi
  else
    case "$POLICY_FILE" in
      */sirinvpn/network-policy.json) rm -f -- "$POLICY_FILE" ;;
      *)
        echo "Refusing to remove an unexpected local policy path." >&2
        return 1
        ;;
    esac
  fi
}

assert_local_clean() {
  helper_status >"$HELPER_STATUS" || return 1
  jq -e '
    .state == "disconnected"
    and .server_id == null
    and .kill_switch_enabled == false
    and .auto_reconnect_enabled == false
    and .transport_fallback_enabled == false
  ' "$HELPER_STATUS" >/dev/null || return 1
  ! ip link show sirinvpn0 >/dev/null 2>&1 || return 1
  ! systemctl is-active --quiet sirinvpn-killswitch.service || return 1
  ! systemctl is-active --quiet sirinvpn-reconnect.service || return 1
  ! systemctl is-active --quiet sirinvpn-transport.service || return 1
  ! local_root nft list table inet sirinvpn_guard >/dev/null 2>&1 || return 1
  ! local_root nft list table inet sirinvpn_client >/dev/null 2>&1 || return 1
  ! local_root nft list table ip6 sirinvpn_client6 >/dev/null 2>&1 || return 1
}

disconnect_local() {
  "$CLI" disconnect >/dev/null 2>&1 || true
  LOCAL_TOUCHED=0
  assert_local_clean
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
  if [ "$REMOTE_ARMED" -eq 1 ]; then
    if ! restore_remote_transaction; then
      echo "WARNING: automatic VPS rollback could not be confirmed; the 15-minute timer remains the fallback." >&2
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
  if ! assert_local_clean; then
    echo "WARNING: final local network cleanup failed." >&2
    cleanup_failed=1
  fi

  case "$TEST_ROOT" in
    /tmp/sirinvpn-linux-fallback.*) rm -rf -- "$TEST_ROOT" ;;
    *)
      echo "WARNING: refusing to remove unexpected test directory $TEST_ROOT" >&2
      cleanup_failed=1
      ;;
  esac

  if [ "$cleanup_failed" -ne 0 ]; then
    result=1
  fi
  if [ "$result" -eq 0 ] && [ "$MAIN_COMPLETE" -eq 1 ]; then
    echo "Linux live fallback gate passed: Direct -> Obfuscated UDP -> pinned TLS -> raw TCP, persistent guarded recovery, and exact cleanup verified."
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
OBFUSCATED_PORT=$(jq -er '.obfuscated_udp.port' "$PROFILE")
TCP_PORT=$(jq -er '.tcp_fallback.port' "$PROFILE")
TLS_PORT=$(jq -er '.tls_like.port' "$PROFILE")
CLIENT_ADDRESS=$(jq -er '.client_tunnel_address' "$PROFILE")
SERVER_TUNNEL_ADDRESS=$(jq -er '.server_tunnel_address' "$PROFILE")
IPV6_TUNNEL_ENABLED=$(jq -r '.ipv6_tunnel_enabled // false' "$PROFILE")
case "$SERVER_HOST:$SSH_USER" in
  *[!A-Za-z0-9._:@-]*)
    echo "The stored VPS host or requested SSH username is unsafe for this test harness." >&2
    exit 2
    ;;
esac
if [ "$WIREGUARD_PORT" -eq "$OBFUSCATED_PORT" ] \
  || [ "$TCP_PORT" -ne "$TLS_PORT" ] \
  || [ "$TCP_PORT" -eq "$INTERNAL_TCP_PORT" ]; then
  echo "The VPS transport ports are not compatible with this bounded gate." >&2
  exit 2
fi

assert_local_clean
ssh-keyscan -T 10 -p "$SSH_PORT" -t ed25519 "$SERVER_HOST" \
  >"$KNOWN_HOSTS" 2>/dev/null
ACTUAL_HOST_KEY=$(ssh-keygen -E sha256 -lf "$KNOWN_HOSTS" | awk 'NR == 1 { print $2 }')
if [ "$ACTUAL_HOST_KEY" != "$SIRINVPN_LINUX_FALLBACK_HOST_KEY" ]; then
  echo "The VPS ED25519 host fingerprint does not match the independently verified value." >&2
  exit 2
fi
remote "set -eu; \
  test \"\$(. /etc/os-release; printf '%s' \"\$VERSION_ID\")\" = 13; \
  systemctl is-active --quiet sirinvpn-server.service; \
  /usr/local/lib/sirinvpn/sirinvpn-server validate-state; \
  command -v nft >/dev/null; \
  command -v python3 >/dev/null; \
  command -v systemd-run >/dev/null; \
  python3 -c 'import json; d=json.load(open(\"/etc/sirinvpn/authorization/authorization.json\")); assert not d.get(\"invitations\", []); assert not d.get(\"enrollment_receipts\", []); assert not d.get(\"key_rotations\", []); assert not d.get(\"port_forwards\", [])'"
PUBLIC_INTERFACE=$(remote "ip -4 route show default | awk 'NR == 1 { for (field = 1; field <= NF; field++) if (\$field == \"dev\") { print \$(field + 1); exit } }'")
case "$PUBLIC_INTERFACE" in
  ''|*[!A-Za-z0-9_.:-]*)
    echo "The VPS public interface could not be identified safely." >&2
    exit 2
    ;;
esac
if remote "ss -H -lnt 'sport = :$INTERNAL_TCP_PORT' | grep -q ."; then
  echo "The temporary internal TCP port is already in use on the VPS." >&2
  exit 2
fi
remote_hashes >"$REMOTE_BASELINE"

python3 - <<'PY'
import socket
with socket.create_connection(("1.1.1.1", 443), timeout=5):
    pass
PY
getent ahostsv4 example.com >/dev/null

create_fault_table() {
  printf 'add table inet %s\nadd chain inet %s input { type filter hook input priority -300; policy accept; }\nadd chain inet %s forward { type filter hook forward priority -300; policy accept; }\nadd rule inet %s forward iifname "sirinvpn0" oifname "%s" counter comment "linux-tunnel-egress"\n' \
    "$NFT_TABLE" "$NFT_TABLE" "$NFT_TABLE" "$NFT_TABLE" "$PUBLIC_INTERFACE" \
    | remote "/usr/sbin/nft -f -"
}

counter_value() {
  COUNTER_COMMENT=$1
  remote "/usr/sbin/nft list table inet '$NFT_TABLE'" >"$NFT_DUMP"
  awk -v comment="$COUNTER_COMMENT" '
    index($0, "comment \"" comment "\"") {
      for (field = 1; field <= NF; field++) {
        if ($field == "packets") {
          print $(field + 1)
          exit
        }
      }
    }
  ' "$NFT_DUMP"
}

assert_transport_runtime() {
  EXPECTED_TRANSPORT=$1
  case "$EXPECTED_TRANSPORT" in
    direct_udp)
      local_root wg show sirinvpn0 endpoints | grep -F ":$WIREGUARD_PORT" >/dev/null
      ! systemctl is-active --quiet sirinvpn-transport.service || return 1
      ;;
    obfuscated_udp)
      local_root wg show sirinvpn0 endpoints | grep -F '127.0.0.1:51821' >/dev/null
      systemctl is-active --quiet sirinvpn-transport.service
      ss -H -lun 'sport = :51821' | grep -F '127.0.0.1:51821' >/dev/null
      ;;
    tls_like)
      local_root wg show sirinvpn0 endpoints | grep -F '127.0.0.1:51823' >/dev/null
      systemctl is-active --quiet sirinvpn-transport.service
      ss -H -lun 'sport = :51823' | grep -F '127.0.0.1:51823' >/dev/null
      ;;
    tcp_fallback)
      local_root wg show sirinvpn0 endpoints | grep -F '127.0.0.1:51822' >/dev/null
      systemctl is-active --quiet sirinvpn-transport.service
      ss -H -lun 'sport = :51822' | grep -F '127.0.0.1:51822' >/dev/null
      ;;
    *) return 1 ;;
  esac
}

assert_connection() {
  EXPECTED_TRANSPORT=$1
  EXPECTED_PERSISTENT=$2
  CHECK_REMOTE_EGRESS=$3
  READY=0
  ATTEMPT=0
  while [ "$ATTEMPT" -lt 20 ]; do
    if "$CLI" --json status >"$STATUS_OUTPUT" 2>/dev/null \
      && jq -e \
        --arg id "$SERVER_ID" \
        --arg transport "$EXPECTED_TRANSPORT" \
        --argjson persistent "$EXPECTED_PERSISTENT" \
        --argjson ipv6 "$IPV6_TUNNEL_ENABLED" '
          .local.state == "connected"
          and .local.server_id == $id
          and .local.transport == $transport
          and .local.kill_switch_enabled == $persistent
          and .local.auto_reconnect_enabled == $persistent
          and .local.transport_fallback_enabled == $persistent
          and .local.routing_mode == "full_tunnel"
          and .local.allow_lan == false
          and .server.connection_state == "connected"
          and .server.transport == $transport
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
    echo "The $EXPECTED_TRANSPORT phase did not return authenticated healthy state." >&2
    jq '{local, server: (.server | {connection_state, transport, dns_healthy})}' \
      "$STATUS_OUTPUT" >&2 2>/dev/null || true
    return 1
  fi

  ip -4 -o address show dev sirinvpn0 | grep -F " $CLIENT_ADDRESS/" >/dev/null
  ip -4 route show table 51820 | grep -E '^default .*dev sirinvpn0' >/dev/null
  ip -4 rule show priority 10000 | grep -F 'lookup 51820' >/dev/null
  ip -4 rule show priority 10001 | grep -F 'suppress_prefixlength 0' >/dev/null
  resolvectl dns sirinvpn0 | grep -F "$SERVER_TUNNEL_ADDRESS" >/dev/null
  resolvectl domain sirinvpn0 | grep -F '~.' >/dev/null
  ping -c 1 -W 5 "$SERVER_TUNNEL_ADDRESS" >/dev/null
  getent ahostsv4 example.com >/dev/null
  assert_transport_runtime "$EXPECTED_TRANSPORT"
  if [ "$EXPECTED_PERSISTENT" = true ]; then
    systemctl is-active --quiet sirinvpn-killswitch.service
    systemctl is-active --quiet sirinvpn-reconnect.service
    local_root nft list chain inet sirinvpn_guard output \
      | grep -F 'policy drop' >/dev/null
  else
    ! systemctl is-active --quiet sirinvpn-killswitch.service || return 1
    ! systemctl is-active --quiet sirinvpn-reconnect.service || return 1
  fi

  if [ "$CHECK_REMOTE_EGRESS" -eq 1 ]; then
    EGRESS_BEFORE=$(counter_value linux-tunnel-egress)
  fi
  python3 - <<'PY'
import socket
with socket.create_connection(("1.1.1.1", 443), timeout=5):
    pass
PY
  if [ "$CHECK_REMOTE_EGRESS" -eq 1 ]; then
    EGRESS_AFTER=$(counter_value linux-tunnel-egress)
    if [ -z "$EGRESS_BEFORE" ] || [ -z "$EGRESS_AFTER" ] \
      || [ "$EGRESS_AFTER" -le "$EGRESS_BEFORE" ]; then
      echo "The VPS forwarding observer did not see tunnel egress." >&2
      return 1
    fi
  fi
}

run_transient_phase() {
  PHASE_NAME=$1
  EXPECTED_TRANSPORT=$2
  echo "Automatic phase: $PHASE_NAME -> $EXPECTED_TRANSPORT"
  LOCAL_TOUCHED=1
  "$CLI" --json connect "$SERVER_ID" --transport automatic --network-profile normal \
    >"$CONNECT_OUTPUT"
  assert_connection "$EXPECTED_TRANSPORT" false 1
  disconnect_local
}

arm_remote_transaction transient
create_fault_table
run_transient_phase unrestricted direct_udp

printf 'add rule inet %s input iifname "%s" udp dport %s counter drop comment "linux-direct"\n' \
  "$NFT_TABLE" "$PUBLIC_INTERFACE" "$WIREGUARD_PORT" | remote "/usr/sbin/nft -f -"
run_transient_phase direct-blocked obfuscated_udp
DIRECT_PACKETS=$(counter_value linux-direct)
if [ -z "$DIRECT_PACKETS" ] || [ "$DIRECT_PACKETS" -lt 1 ]; then
  echo "The Direct UDP rejection rule did not observe the failed candidate." >&2
  exit 1
fi

printf 'add rule inet %s input iifname "%s" udp dport %s counter drop comment "linux-obfuscated"\n' \
  "$NFT_TABLE" "$PUBLIC_INTERFACE" "$OBFUSCATED_PORT" | remote "/usr/sbin/nft -f -"
run_transient_phase both-udp-paths-blocked tls_like
OBFUSCATED_PACKETS=$(counter_value linux-obfuscated)
if [ -z "$OBFUSCATED_PACKETS" ] || [ "$OBFUSCATED_PACKETS" -lt 1 ]; then
  echo "The Obfuscated UDP rejection rule did not observe the failed candidate." >&2
  exit 1
fi

remote "set -eu; systemctl stop sirinvpn-server.service; /usr/bin/python3 '$REMOTE_HELPER' rewrite-config '$REMOTE_CONFIG' '$REMOTE_BACKUP' '$INTERNAL_TCP_PORT'; systemctl start sirinvpn-server.service"
remote "set -eu; systemctl is-active --quiet sirinvpn-server.service; /usr/local/lib/sirinvpn/sirinvpn-server validate-state; ss -H -lnt 'sport = :$INTERNAL_TCP_PORT' | grep -q ."
remote "systemd-run --quiet --unit='$PROXY_UNIT' --property=Type=simple --property=Restart=no --property=NoNewPrivileges=yes --property=PrivateTmp=yes --property=ProtectHome=yes --property=ProtectSystem=strict --property=ReadWritePaths='$REMOTE_ROOT' /usr/bin/python3 '$REMOTE_HELPER' serve '$TCP_PORT' '$INTERNAL_TCP_PORT' '$REMOTE_COUNTER'"
PROXY_READY=0
ATTEMPT=0
while [ "$ATTEMPT" -lt 15 ]; do
  if remote "systemctl is-active --quiet '$PROXY_UNIT' && ss -H -lnt 'sport = :$TCP_PORT' | grep -q ."; then
    PROXY_READY=1
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  sleep 1
done
if [ "$PROXY_READY" -ne 1 ]; then
  echo "The bounded TLS-rejection proxy did not become ready." >&2
  exit 1
fi

run_transient_phase udp-and-tls-blocked tcp_fallback
remote "cat '$REMOTE_COUNTER'" >"$PROXY_COUNTS"
TLS_REJECTED=$(awk -F= '$1 == "tls_rejected" { print $2 }' "$PROXY_COUNTS")
RAW_FORWARDED=$(awk -F= '$1 == "raw_forwarded" { print $2 }' "$PROXY_COUNTS")
if [ -z "$TLS_REJECTED" ] || [ "$TLS_REJECTED" -lt 1 ] \
  || [ -z "$RAW_FORWARDED" ] || [ "$RAW_FORWARDED" -lt 1 ]; then
  echo "Automatic did not traverse rejected TLS before authenticated raw TCP." >&2
  exit 1
fi
restore_remote_transaction
verify_remote_baseline

arm_remote_transaction persistent
create_fault_table
FAULT_BASE="sirinvpn-linux-fallback-$$-persistent-inject"
FAULT_TIMER="$FAULT_BASE.timer"
FAULT_SERVICE="$FAULT_BASE.service"
remote "systemd-run --quiet --unit='$FAULT_BASE' --on-active=20s --timer-property=AccuracySec=1s /usr/sbin/nft add rule inet '$NFT_TABLE' input iifname '$PUBLIC_INTERFACE' udp dport '$WIREGUARD_PORT' counter drop comment linux-persistent-direct"

echo "Persistent phase: interrupt Direct UDP -> guarded Obfuscated UDP recovery"
LOCAL_TOUCHED=1
"$CLI" --json connect "$SERVER_ID" --persistent --transport automatic --network-profile normal \
  >"$CONNECT_OUTPUT"
assert_connection direct_udp true 0
sleep 22
if ping -c 1 -W 2 "$SERVER_TUNNEL_ADDRESS" >/dev/null 2>&1; then
  echo "The scheduled Direct UDP interruption did not block the established tunnel." >&2
  exit 1
fi
local_root ip link delete dev sirinvpn0
local_root nft list chain inet sirinvpn_guard output | grep -F 'policy drop' >/dev/null
if python3 - 2>/dev/null <<'PY'
import socket
with socket.create_connection(("1.1.1.1", 443), timeout=2):
    pass
PY
then
  echo "Ordinary IPv4 escaped while the persistent tunnel was absent." >&2
  exit 1
fi

RECOVERED=0
ATTEMPT=0
while [ "$ATTEMPT" -lt 75 ]; do
  if ! local_root nft list chain inet sirinvpn_guard output \
    | grep -F 'policy drop' >/dev/null; then
    echo "The persistent guard disappeared during transport recovery." >&2
    exit 1
  fi
  if helper_status >"$HELPER_STATUS" 2>/dev/null \
    && jq -e '
      .state == "connected"
      and .transport == "obfuscated_udp"
      and .kill_switch_enabled == true
      and .auto_reconnect_enabled == true
      and .transport_fallback_enabled == true
    ' "$HELPER_STATUS" >/dev/null; then
    RECOVERED=1
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  sleep 1
done
if [ "$RECOVERED" -ne 1 ]; then
  echo "Persistent Automatic did not recover through Obfuscated UDP." >&2
  exit 1
fi
assert_connection obfuscated_udp true 0
disconnect_local
PERSISTENT_DIRECT_PACKETS=$(counter_value linux-persistent-direct)
if [ -z "$PERSISTENT_DIRECT_PACKETS" ] || [ "$PERSISTENT_DIRECT_PACKETS" -lt 1 ]; then
  echo "The persistent Direct interruption rule observed no packets." >&2
  exit 1
fi
restore_remote_transaction
verify_remote_baseline

restore_local_policy
assert_local_clean
MAIN_COMPLETE=1
exit 0
