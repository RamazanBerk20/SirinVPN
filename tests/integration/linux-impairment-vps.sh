#!/bin/sh
set -eu

: "${SIRINVPN_LINUX_IMPAIRMENT_SERVER_ID:?Set the existing disposable SirinVPN server ID}"
: "${SIRINVPN_LINUX_IMPAIRMENT_HOST_KEY:?Set the independently verified ED25519 SHA256 SSH host fingerprint}"
: "${SIRINVPN_LINUX_IMPAIRMENT_CONFIRM:?Set SIRINVPN_LINUX_IMPAIRMENT_CONFIRM=impair-disposable-vps}"

if [ "$SIRINVPN_LINUX_IMPAIRMENT_CONFIRM" != "impair-disposable-vps" ]; then
  echo "Refusing to shape VPS traffic or alter local VPN networking." >&2
  exit 2
fi

export LC_ALL=C
PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CLI=${SIRINVPN_LINUX_IMPAIRMENT_CLI:-"$PROJECT_ROOT/target/release/sirinvpn"}
LOCAL_HELPER=${SIRINVPN_LINUX_IMPAIRMENT_HELPER:-/usr/lib/sirinvpn/sirinvpn-helper}
REMOTE_HELPER_SOURCE="$PROJECT_ROOT/tests/integration/linux-impairment-netem.py"
SERVER_ID=$SIRINVPN_LINUX_IMPAIRMENT_SERVER_ID
SSH_USER=${SIRINVPN_LINUX_IMPAIRMENT_USER:-root}
SSH_PORT=${SIRINVPN_LINUX_IMPAIRMENT_SSH_PORT:-22}
SAMPLE_COUNT=30
MINIMUM_REPLIES=15
MINIMUM_ADDED_DELAY_MS=60
MINIMUM_SPREAD_MS=10
CARRIER_SAMPLE_COUNT=60
CARRIER_MINIMUM_REPLIES=30
CARRIER_DROP_RESIDUE=19

for command in awk cmp getent grep install ip jq nft ping python3 resolvectl sha256sum ssh ssh-add ssh-keygen ssh-keyscan ss stat sudo systemctl wg; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required for the Linux impairment integration gate." >&2
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
case "$SIRINVPN_LINUX_IMPAIRMENT_HOST_KEY" in
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

TEST_ROOT=$(mktemp -d /tmp/sirinvpn-linux-impairment.XXXXXX)
chmod 0700 "$TEST_ROOT"
umask 077
PROFILE="$TEST_ROOT/profile.json"
CONNECT_OUTPUT="$TEST_ROOT/connect.json"
STATUS_OUTPUT="$TEST_ROOT/status.json"
HELPER_STATUS="$TEST_ROOT/helper-status.json"
KNOWN_HOSTS="$TEST_ROOT/known_hosts"
REMOTE_BASELINE="$TEST_ROOT/remote-baseline.sha256"
REMOTE_FINAL="$TEST_ROOT/remote-final.sha256"
QDISC_BASELINE="$TEST_ROOT/qdisc-baseline.txt"
QDISC_FINAL="$TEST_ROOT/qdisc-final.txt"
MODULE_BASELINE="$TEST_ROOT/module-baseline.txt"
MODULE_FINAL="$TEST_ROOT/module-final.txt"
QDISC_STATS="$TEST_ROOT/qdisc-stats.json"
NFT_DUMP="$TEST_ROOT/nft.txt"
LOCAL_NFT_TABLES="$TEST_ROOT/local-nft-tables.txt"
PING_OUTPUT="$TEST_ROOT/ping.txt"
MTU_OUTPUT="$TEST_ROOT/mtu.txt"
POLICY_BACKUP="$TEST_ROOT/network-policy.original"
POLICY_PRESENT=0
POLICY_HASH=
REMOTE_ARMED=0
LOCAL_TOUCHED=0
CLEANUP_RUNNING=0
MAIN_COMPLETE=0

REMOTE_ROOT="/run/sirinvpn-linux-impairment-$$"
REMOTE_HELPER="$REMOTE_ROOT/netem.py"
NFT_TABLE="sirinvpn_impairment_$$"
ROLLBACK_BASE="sirinvpn-linux-impairment-$$-rollback"
ROLLBACK_TIMER="$ROLLBACK_BASE.timer"
ROLLBACK_SERVICE="$ROLLBACK_BASE.service"

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
    echo "The impairment gate accepts one bounded remote command at a time." >&2
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

remote_module_state() {
  remote "if test -d /sys/module/sch_netem; then echo loaded; else echo absent; fi"
}

remote_stats() {
  remote "/usr/bin/python3 '$REMOTE_HELPER' stats '$REMOTE_ROOT'"
}

arm_remote_transaction() {
  remote "install -d -m 0700 '$REMOTE_ROOT'"
  REMOTE_ARMED=1
  remote "install -m 0700 /dev/stdin '$REMOTE_HELPER'" <"$REMOTE_HELPER_SOURCE"
  remote "/usr/bin/python3 '$REMOTE_HELPER' prepare '$REMOTE_ROOT'"
  remote "systemd-run --quiet --unit='$ROLLBACK_BASE' --on-active=12m --timer-property=AccuracySec=1s /usr/bin/python3 '$REMOTE_HELPER' rollback '$REMOTE_ROOT' '$NFT_TABLE'"
}

restore_remote_transaction() {
  if ! remote "/usr/bin/python3 '$REMOTE_HELPER' rollback '$REMOTE_ROOT' '$NFT_TABLE'"; then
    remote "test ! -e '$REMOTE_ROOT'" || return 1
  fi
  remote "systemctl stop '$ROLLBACK_TIMER' '$ROLLBACK_SERVICE' >/dev/null 2>&1 || true" \
    || return 1
  remote "systemctl reset-failed '$ROLLBACK_TIMER' '$ROLLBACK_SERVICE' >/dev/null 2>&1 || true" \
    || return 1
  REMOTE_ARMED=0
}

verify_remote_baseline() {
  remote_hashes >"$REMOTE_FINAL" || return 1
  remote "/usr/sbin/tc qdisc show dev sirinvpn0" >"$QDISC_FINAL" || return 1
  remote_module_state >"$MODULE_FINAL" || return 1
  if ! cmp -s "$REMOTE_BASELINE" "$REMOTE_FINAL"; then
    echo "The VPS identity/configuration hashes did not return to baseline." >&2
    return 1
  fi
  if ! cmp -s "$QDISC_BASELINE" "$QDISC_FINAL" \
    || ! cmp -s "$MODULE_BASELINE" "$MODULE_FINAL"; then
    echo "The VPS qdisc/module state did not return to baseline." >&2
    return 1
  fi
  remote "set -eu; \
    systemctl is-active --quiet sirinvpn-server.service; \
    /usr/local/lib/sirinvpn/sirinvpn-server validate-state; \
    ! nft list table inet '$NFT_TABLE' >/dev/null 2>&1 || exit 1; \
    test ! -e '$REMOTE_ROOT'; \
    test -z \"\$(systemctl list-units --all --no-legend '$ROLLBACK_BASE*')\"; \
    ! /usr/sbin/tc qdisc show | grep -q '^qdisc netem ' || exit 1; \
    ss -H -lun 'sport = :$WIREGUARD_PORT' | grep -q .; \
    ss -H -lun 'sport = :$OBFUSCATED_PORT' | grep -q .; \
    ss -H -lnt 'sport = :$TCP_PORT' | grep -q ." || return 1
}

restore_local_policy() {
  if [ "$POLICY_PRESENT" -eq 1 ]; then
    if [ ! -f "$POLICY_BACKUP" ]; then
      echo "The local network-policy backup is unavailable." >&2
      return 1
    fi
    POLICY_TEMP="$POLICY_FILE.linux-impairment-$$"
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

assert_local_clean() {
  helper_status >"$HELPER_STATUS" || return 1
  jq -e '
    .state == "disconnected"
    and .server_id == null
    and .kill_switch_enabled == false
    and .auto_reconnect_enabled == false
    and .transport_fallback_enabled == false
  ' "$HELPER_STATUS" >/dev/null || return 1
  local_root nft list tables >"$LOCAL_NFT_TABLES" || return 1
  if ip link show sirinvpn0 >/dev/null 2>&1 \
    || systemctl is-active --quiet sirinvpn-killswitch.service \
    || systemctl is-active --quiet sirinvpn-reconnect.service \
    || systemctl is-active --quiet sirinvpn-transport.service; then
    return 1
  fi
  if grep -Eq '^table inet sirinvpn_(guard|client)$|^table ip6 sirinvpn_client6$' \
    "$LOCAL_NFT_TABLES"; then
    return 1
  fi
}

disconnect_local() {
  "$CLI" disconnect >/dev/null 2>&1 || true
  assert_local_clean || return 1
  LOCAL_TOUCHED=0
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
      echo "WARNING: VPS impairment rollback could not be confirmed; the 12-minute timer remains the fallback." >&2
      cleanup_failed=1
    fi
  fi
  if [ -s "$REMOTE_BASELINE" ] && [ -s "$QDISC_BASELINE" ] \
    && [ "$REMOTE_ARMED" -eq 0 ]; then
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
    /tmp/sirinvpn-linux-impairment.*) rm -rf -- "$TEST_ROOT" ;;
    *)
      echo "WARNING: refusing to remove unexpected test directory $TEST_ROOT" >&2
      cleanup_failed=1
      ;;
  esac

  if [ "$cleanup_failed" -ne 0 ]; then
    result=1
  fi
  if [ "$result" -eq 0 ] && [ "$MAIN_COMPLETE" -eq 1 ]; then
    echo "Linux impairment gate passed: all four transports retained authenticated service under inner delay/loss and bidirectional outer-carrier loss, enforced MTU boundaries, and restored exact state."
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
  || [ "$TCP_PORT" -ne "$TLS_PORT" ]; then
  echo "The VPS transport ports are not compatible with this bounded gate." >&2
  exit 2
fi

assert_local_clean
ssh-keyscan -T 10 -p "$SSH_PORT" -t ed25519 "$SERVER_HOST" \
  >"$KNOWN_HOSTS" 2>/dev/null
ACTUAL_HOST_KEY=$(ssh-keygen -E sha256 -lf "$KNOWN_HOSTS" | awk 'NR == 1 { print $2 }')
if [ "$ACTUAL_HOST_KEY" != "$SIRINVPN_LINUX_IMPAIRMENT_HOST_KEY" ]; then
  echo "The VPS ED25519 host fingerprint does not match the independently verified value." >&2
  exit 2
fi
remote "set -eu; \
  test \"\$(. /etc/os-release; printf '%s' \"\$VERSION_ID\")\" = 13; \
  systemctl is-active --quiet sirinvpn-server.service; \
  /usr/local/lib/sirinvpn/sirinvpn-server validate-state; \
  command -v modprobe >/dev/null; \
  command -v nft >/dev/null; \
  command -v python3 >/dev/null; \
  command -v systemd-run >/dev/null; \
  command -v tc >/dev/null; \
  test -z \"\$(find /run -maxdepth 1 -type d -name 'sirinvpn-linux-impairment-*' -print -quit)\"; \
  ! nft list tables | grep -q sirinvpn_impairment_ || exit 1; \
  ! /usr/sbin/tc qdisc show | grep -q '^qdisc netem ' || exit 1; \
  python3 -c 'import json; d=json.load(open(\"/etc/sirinvpn/authorization/authorization.json\")); assert not d.get(\"invitations\", []); assert not d.get(\"enrollment_receipts\", []); assert not d.get(\"key_rotations\", []); assert not d.get(\"port_forwards\", []); assert len(d.get(\"devices\", [])) == 1'"
PUBLIC_INTERFACE=$(remote "ip -4 route show default | awk 'NR == 1 { for (field = 1; field <= NF; field++) if (\$field == \"dev\") { print \$(field + 1); exit } }'")
case "$PUBLIC_INTERFACE" in
  ''|*[!A-Za-z0-9_.:-]*)
    echo "The VPS public interface could not be identified safely." >&2
    exit 2
    ;;
esac
# Expand SSH_CONNECTION on the remote host, not on this machine.
# shellcheck disable=SC2016
CLIENT_PUBLIC_IPV4=$(remote 'set -- $SSH_CONNECTION; printf "%s\n" "$1"')
if ! python3 -c '
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
assert address.version == 4 and str(address) == sys.argv[1]
' "$CLIENT_PUBLIC_IPV4"; then
  echo "The SSH peer did not expose one canonical public IPv4 address." >&2
  exit 2
fi
remote_hashes >"$REMOTE_BASELINE"
remote "/usr/sbin/tc qdisc show dev sirinvpn0" >"$QDISC_BASELINE"
remote_module_state >"$MODULE_BASELINE"

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

retry_data_plane() {
  READY=0
  ATTEMPT=0
  while [ "$ATTEMPT" -lt 5 ]; do
    if getent ahostsv4 example.com >/dev/null 2>&1 \
      && python3 - <<'PY'
import socket
with socket.create_connection(("1.1.1.1", 443), timeout=5):
    pass
PY
    then
      READY=1
      break
    fi
    ATTEMPT=$((ATTEMPT + 1))
  done
  if [ "$READY" -ne 1 ]; then
    echo "DNS or public TCP did not survive the bounded impairment." >&2
    return 1
  fi
}

assert_connection() {
  EXPECTED_TRANSPORT=$1
  EXPECTED_MTU=$2
  READY=0
  ATTEMPT=0
  while [ "$ATTEMPT" -lt 30 ]; do
    if "$CLI" --json status >"$STATUS_OUTPUT" 2>/dev/null \
      && jq -e \
        --arg id "$SERVER_ID" \
        --arg transport "$EXPECTED_TRANSPORT" \
        --argjson ipv6 "$IPV6_TUNNEL_ENABLED" '
          .local.state == "connected"
          and .local.server_id == $id
          and .local.transport == $transport
          and .local.kill_switch_enabled == false
          and .local.auto_reconnect_enabled == false
          and .local.transport_fallback_enabled == false
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
    return 1
  fi

  ACTUAL_MTU=$(ip -o link show dev sirinvpn0 | awk '{ for (field = 1; field <= NF; field++) if ($field == "mtu") { print $(field + 1); exit } }')
  case "$ACTUAL_MTU" in
    ''|*[!0-9]*)
      echo "The $EXPECTED_TRANSPORT phase did not expose a valid interface MTU." >&2
      return 1
      ;;
  esac
  if [ "$ACTUAL_MTU" -ne "$EXPECTED_MTU" ]; then
    echo "The $EXPECTED_TRANSPORT phase installed MTU $ACTUAL_MTU instead of $EXPECTED_MTU." >&2
    return 1
  fi
  ip -4 -o address show dev sirinvpn0 | grep -F " $CLIENT_ADDRESS/" >/dev/null
  ip -4 route show table 51820 | grep -E '^default .*dev sirinvpn0' >/dev/null
  ip -4 rule show priority 10000 | grep -F 'lookup 51820' >/dev/null
  ip -4 rule show priority 10001 | grep -F 'suppress_prefixlength 0' >/dev/null
  resolvectl dns sirinvpn0 | grep -F "$SERVER_TUNNEL_ADDRESS" >/dev/null
  resolvectl domain sirinvpn0 | grep -F '~.' >/dev/null
  assert_transport_runtime "$EXPECTED_TRANSPORT"
  retry_data_plane
}

measure_ping() {
  COUNT=$1
  MINIMUM=$2
  if ! ping -c "$COUNT" -i 0.2 -W 2 "$SERVER_TUNNEL_ADDRESS" >"$PING_OUTPUT"; then
    echo "The private gateway did not return any impairment samples." >&2
    return 1
  fi
  PING_RECEIVED=$(awk '/packets transmitted/ { print $4; exit }' "$PING_OUTPUT")
  PING_MIN=$(awk -F'= ' '/^rtt / { split($2, values, "/"); print values[1]; exit }' "$PING_OUTPUT")
  PING_AVG=$(awk -F'= ' '/^rtt / { split($2, values, "/"); print values[2]; exit }' "$PING_OUTPUT")
  PING_MAX=$(awk -F'= ' '/^rtt / { split($2, values, "/"); print values[3]; exit }' "$PING_OUTPUT")
  case "$PING_RECEIVED" in
    ''|*[!0-9]*)
      echo "The ping summary could not be parsed." >&2
      return 1
      ;;
  esac
  if ! awk -v minimum="$PING_MIN" -v average="$PING_AVG" -v maximum="$PING_MAX" '
    BEGIN {
      number = "^[0-9]+([.][0-9]+)?$"
      exit !(minimum ~ number && average ~ number && maximum ~ number)
    }
  '; then
    echo "The ping timing summary could not be parsed." >&2
    return 1
  fi
  if [ -z "$PING_RECEIVED" ] || [ "$PING_RECEIVED" -lt "$MINIMUM" ]; then
    echo "Only $PING_RECEIVED of $COUNT private-gateway samples survived." >&2
    return 1
  fi
}

assert_mtu_boundary() {
  MTU=$1
  FIT_PAYLOAD=$((MTU - 28))
  OVERSIZED_PAYLOAD=$((MTU - 27))
  if ! ping -c 8 -i 0.2 -W 2 -M "do" -s "$FIT_PAYLOAD" \
    "$SERVER_TUNNEL_ADDRESS" >"$MTU_OUTPUT"; then
    echo "An IPv4 packet exactly fitting MTU $MTU did not survive." >&2
    return 1
  fi
  if ping -c 1 -W 1 -M "do" -s "$OVERSIZED_PAYLOAD" \
    "$SERVER_TUNNEL_ADDRESS" >"$MTU_OUTPUT" 2>&1; then
    echo "An IPv4 packet larger than MTU $MTU was transmitted." >&2
    return 1
  fi
  if ! grep -Eiq 'message too long|mtu=[0-9]+' "$MTU_OUTPUT"; then
    echo "The oversized IPv4 packet did not fail at the local MTU boundary." >&2
    return 1
  fi
}

echo "Control phase: Direct UDP without impairment"
LOCAL_TOUCHED=1
"$CLI" --json connect "$SERVER_ID" --transport direct >"$CONNECT_OUTPUT"
assert_connection direct_udp 1420
measure_ping 10 8
BASELINE_AVG=$PING_AVG
assert_mtu_boundary 1420
disconnect_local

arm_remote_transaction
printf 'add table inet %s\nadd chain inet %s forward { type filter hook forward priority -300; policy accept; }\nadd rule inet %s forward iifname "sirinvpn0" oifname "%s" counter comment "linux-impairment-egress"\n' \
  "$NFT_TABLE" "$NFT_TABLE" "$NFT_TABLE" "$PUBLIC_INTERFACE" \
  | remote "/usr/sbin/nft -f -"
remote "/usr/bin/python3 '$REMOTE_HELPER' apply '$REMOTE_ROOT'"
remote_stats >"$QDISC_STATS"
PREVIOUS_QDISC_PACKETS=$(jq -er '.packets' "$QDISC_STATS")
PREVIOUS_EGRESS=0

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

run_impaired_phase() {
  LABEL=$1
  CLI_TRANSPORT=$2
  EXPECTED_TRANSPORT=$3
  EXPECTED_MTU=$4
  echo "Impaired phase: $LABEL"
  LOCAL_TOUCHED=1
  "$CLI" --json connect "$SERVER_ID" --transport "$CLI_TRANSPORT" >"$CONNECT_OUTPUT"
  assert_connection "$EXPECTED_TRANSPORT" "$EXPECTED_MTU"
  measure_ping "$SAMPLE_COUNT" "$MINIMUM_REPLIES"
  if ! awk -v average="$PING_AVG" -v baseline="$BASELINE_AVG" \
    -v minimum="$MINIMUM_ADDED_DELAY_MS" \
    'BEGIN { exit !(average >= baseline + minimum) }'; then
    echo "$LABEL added less than $MINIMUM_ADDED_DELAY_MS ms over the control RTT." >&2
    exit 1
  fi
  if ! awk -v minimum="$PING_MIN" -v maximum="$PING_MAX" \
    -v spread="$MINIMUM_SPREAD_MS" \
    'BEGIN { exit !(maximum - minimum >= spread) }'; then
    echo "$LABEL did not expose the configured jitter spread." >&2
    exit 1
  fi
  assert_mtu_boundary "$EXPECTED_MTU"
  PHASE_AVG=$PING_AVG
  PHASE_RECEIVED=$PING_RECEIVED
  disconnect_local

  remote_stats >"$QDISC_STATS"
  CURRENT_QDISC_PACKETS=$(jq -er '.packets' "$QDISC_STATS")
  if [ "$CURRENT_QDISC_PACKETS" -le "$PREVIOUS_QDISC_PACKETS" ]; then
    echo "$LABEL produced no server-to-client netem traffic." >&2
    exit 1
  fi
  PREVIOUS_QDISC_PACKETS=$CURRENT_QDISC_PACKETS
  CURRENT_EGRESS=$(counter_value linux-impairment-egress)
  case "$CURRENT_EGRESS" in
    ''|*[!0-9]*)
      echo "$LABEL produced an invalid VPS forwarding counter." >&2
      exit 1
      ;;
  esac
  if [ "$CURRENT_EGRESS" -le "$PREVIOUS_EGRESS" ]; then
    echo "$LABEL produced no observed VPS-forwarded traffic." >&2
    exit 1
  fi
  PREVIOUS_EGRESS=$CURRENT_EGRESS
  echo "$LABEL: $PHASE_RECEIVED/$SAMPLE_COUNT samples, ${PHASE_AVG} ms average, MTU $EXPECTED_MTU"
}

create_carrier_loss_table() {
  {
    printf 'add table inet %s\n' "$NFT_TABLE"
    printf 'add chain inet %s carrier_input { type filter hook input priority -300; policy accept; }\n' \
      "$NFT_TABLE"
    printf 'add chain inet %s carrier_output { type filter hook output priority -300; policy accept; }\n' \
      "$NFT_TABLE"
    printf 'add rule inet %s carrier_input iifname "%s" ip saddr %s udp dport %s counter comment "carrier-direct-in-seen"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$WIREGUARD_PORT"
    printf 'add rule inet %s carrier_input iifname "%s" ip saddr %s udp dport %s numgen inc mod 20 %s counter drop comment "carrier-direct-in-drop"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$WIREGUARD_PORT" "$CARRIER_DROP_RESIDUE"
    printf 'add rule inet %s carrier_output oifname "%s" ip daddr %s udp sport %s counter comment "carrier-direct-out-seen"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$WIREGUARD_PORT"
    printf 'add rule inet %s carrier_output oifname "%s" ip daddr %s udp sport %s numgen inc mod 20 %s counter drop comment "carrier-direct-out-drop"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$WIREGUARD_PORT" "$CARRIER_DROP_RESIDUE"
    printf 'add rule inet %s carrier_input iifname "%s" ip saddr %s udp dport %s counter comment "carrier-obfuscated-in-seen"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$OBFUSCATED_PORT"
    printf 'add rule inet %s carrier_input iifname "%s" ip saddr %s udp dport %s numgen inc mod 20 %s counter drop comment "carrier-obfuscated-in-drop"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$OBFUSCATED_PORT" "$CARRIER_DROP_RESIDUE"
    printf 'add rule inet %s carrier_output oifname "%s" ip daddr %s udp sport %s counter comment "carrier-obfuscated-out-seen"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$OBFUSCATED_PORT"
    printf 'add rule inet %s carrier_output oifname "%s" ip daddr %s udp sport %s numgen inc mod 20 %s counter drop comment "carrier-obfuscated-out-drop"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$OBFUSCATED_PORT" "$CARRIER_DROP_RESIDUE"
    printf 'add rule inet %s carrier_input iifname "%s" ip saddr %s tcp dport %s counter comment "carrier-tcp-in-seen"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$TCP_PORT"
    printf 'add rule inet %s carrier_input iifname "%s" ip saddr %s tcp dport %s numgen inc mod 20 %s counter drop comment "carrier-tcp-in-drop"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$TCP_PORT" "$CARRIER_DROP_RESIDUE"
    printf 'add rule inet %s carrier_output oifname "%s" ip daddr %s tcp sport %s counter comment "carrier-tcp-out-seen"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$TCP_PORT"
    printf 'add rule inet %s carrier_output oifname "%s" ip daddr %s tcp sport %s numgen inc mod 20 %s counter drop comment "carrier-tcp-out-drop"\n' \
      "$NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$TCP_PORT" "$CARRIER_DROP_RESIDUE"
  } | remote "/usr/sbin/nft -f -"
}

decimal_counter() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

run_carrier_phase() {
  CARRIER_LABEL=$1
  CARRIER_CLI_TRANSPORT=$2
  CARRIER_EXPECTED_TRANSPORT=$3
  CARRIER_EXPECTED_MTU=$4
  CARRIER_PREFIX=$5
  CARRIER_IN_SEEN="carrier-$CARRIER_PREFIX-in-seen"
  CARRIER_IN_DROP="carrier-$CARRIER_PREFIX-in-drop"
  CARRIER_OUT_SEEN="carrier-$CARRIER_PREFIX-out-seen"
  CARRIER_OUT_DROP="carrier-$CARRIER_PREFIX-out-drop"

  CARRIER_BEFORE_IN_SEEN=$(counter_value "$CARRIER_IN_SEEN")
  CARRIER_BEFORE_IN_DROP=$(counter_value "$CARRIER_IN_DROP")
  CARRIER_BEFORE_OUT_SEEN=$(counter_value "$CARRIER_OUT_SEEN")
  CARRIER_BEFORE_OUT_DROP=$(counter_value "$CARRIER_OUT_DROP")
  for CARRIER_VALUE in \
    "$CARRIER_BEFORE_IN_SEEN" "$CARRIER_BEFORE_IN_DROP" \
    "$CARRIER_BEFORE_OUT_SEEN" "$CARRIER_BEFORE_OUT_DROP"; do
    if ! decimal_counter "$CARRIER_VALUE"; then
      echo "$CARRIER_LABEL did not expose valid baseline carrier counters." >&2
      exit 1
    fi
  done

  echo "Carrier-loss phase: $CARRIER_LABEL"
  LOCAL_TOUCHED=1
  "$CLI" --json connect "$SERVER_ID" --transport "$CARRIER_CLI_TRANSPORT" \
    >"$CONNECT_OUTPUT"
  assert_connection "$CARRIER_EXPECTED_TRANSPORT" "$CARRIER_EXPECTED_MTU"
  measure_ping "$CARRIER_SAMPLE_COUNT" "$CARRIER_MINIMUM_REPLIES"
  assert_mtu_boundary "$CARRIER_EXPECTED_MTU"
  assert_connection "$CARRIER_EXPECTED_TRANSPORT" "$CARRIER_EXPECTED_MTU"
  CARRIER_PHASE_RECEIVED=$PING_RECEIVED
  CARRIER_PHASE_AVG=$PING_AVG
  disconnect_local

  CARRIER_AFTER_IN_SEEN=$(counter_value "$CARRIER_IN_SEEN")
  CARRIER_AFTER_IN_DROP=$(counter_value "$CARRIER_IN_DROP")
  CARRIER_AFTER_OUT_SEEN=$(counter_value "$CARRIER_OUT_SEEN")
  CARRIER_AFTER_OUT_DROP=$(counter_value "$CARRIER_OUT_DROP")
  for CARRIER_VALUE in \
    "$CARRIER_AFTER_IN_SEEN" "$CARRIER_AFTER_IN_DROP" \
    "$CARRIER_AFTER_OUT_SEEN" "$CARRIER_AFTER_OUT_DROP"; do
    if ! decimal_counter "$CARRIER_VALUE"; then
      echo "$CARRIER_LABEL did not expose valid final carrier counters." >&2
      exit 1
    fi
  done

  CARRIER_IN_SEEN_DELTA=$((CARRIER_AFTER_IN_SEEN - CARRIER_BEFORE_IN_SEEN))
  CARRIER_IN_DROP_DELTA=$((CARRIER_AFTER_IN_DROP - CARRIER_BEFORE_IN_DROP))
  CARRIER_OUT_SEEN_DELTA=$((CARRIER_AFTER_OUT_SEEN - CARRIER_BEFORE_OUT_SEEN))
  CARRIER_OUT_DROP_DELTA=$((CARRIER_AFTER_OUT_DROP - CARRIER_BEFORE_OUT_DROP))
  if [ "$CARRIER_IN_SEEN_DELTA" -lt 20 ] \
    || [ "$CARRIER_OUT_SEEN_DELTA" -lt 20 ] \
    || [ "$CARRIER_IN_DROP_DELTA" -lt 1 ] \
    || [ "$CARRIER_OUT_DROP_DELTA" -lt 1 ] \
    || [ "$CARRIER_IN_DROP_DELTA" -ge "$CARRIER_IN_SEEN_DELTA" ] \
    || [ "$CARRIER_OUT_DROP_DELTA" -ge "$CARRIER_OUT_SEEN_DELTA" ]; then
    echo "$CARRIER_LABEL did not exercise bounded carrier loss in both directions." >&2
    exit 1
  fi
  echo "$CARRIER_LABEL: $CARRIER_PHASE_RECEIVED/$CARRIER_SAMPLE_COUNT samples, ${CARRIER_PHASE_AVG} ms average, VPS ingress $CARRIER_IN_DROP_DELTA/$CARRIER_IN_SEEN_DELTA dropped, VPS egress $CARRIER_OUT_DROP_DELTA/$CARRIER_OUT_SEEN_DELTA dropped"
}

run_impaired_phase "Direct UDP" direct direct_udp 1420
run_impaired_phase "Obfuscated UDP" obfuscated obfuscated_udp 1320
run_impaired_phase "Pinned TLS" tls tls_like 1280
run_impaired_phase "Raw TCP" tcp tcp_fallback 1280

remote_stats >"$QDISC_STATS"
TOTAL_DROPPED=$(jq -er '.dropped' "$QDISC_STATS")
if [ "$TOTAL_DROPPED" -lt 1 ]; then
  echo "The configured 10% loss produced no observed drop." >&2
  exit 1
fi

restore_remote_transaction
verify_remote_baseline

echo "Carrier-loss transaction: deterministic 5% loss in both directions"
arm_remote_transaction
create_carrier_loss_table
run_carrier_phase "Direct UDP" direct direct_udp 1420 direct
run_carrier_phase "Obfuscated UDP" obfuscated obfuscated_udp 1320 obfuscated
run_carrier_phase "Pinned TLS" tls tls_like 1280 tcp
run_carrier_phase "Raw TCP" tcp tcp_fallback 1280 tcp
restore_remote_transaction
verify_remote_baseline

if [ "$POLICY_PRESENT" -eq 1 ]; then
  if [ "$(sha256sum "$POLICY_FILE" | awk '{print $1}')" != "$POLICY_HASH" ]; then
    echo "Manual transport testing unexpectedly changed the network-policy cache." >&2
    exit 1
  fi
elif [ -e "$POLICY_FILE" ]; then
  echo "Manual transport testing unexpectedly created a network-policy cache." >&2
  exit 1
fi

restore_local_policy
assert_local_clean
MAIN_COMPLETE=1
exit 0
