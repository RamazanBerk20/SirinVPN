#!/bin/sh
set -eu

if [ "${SIRINVPN_LINUX_OUTBOUND_SCOPED:-0}" != 1 ]; then
  if ! command -v systemd-run >/dev/null 2>&1; then
    echo "systemd-run is required for the outbound-audit process boundary." >&2
    exit 2
  fi
  SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
  SCRIPT_PATH="$SCRIPT_DIRECTORY/${0##*/}"
  exec systemd-run \
    --user \
    --scope \
    --quiet \
    --collect \
    --unit="sirinvpn-outbound-audit-scope-$$" \
    /usr/bin/env SIRINVPN_LINUX_OUTBOUND_SCOPED=1 "$SCRIPT_PATH" "$@"
fi

: "${SIRINVPN_LINUX_OUTBOUND_SERVER_ID:?Set the existing disposable SirinVPN server ID}"
: "${SIRINVPN_LINUX_OUTBOUND_HOST_KEY:?Set the independently verified ED25519 SHA256 SSH host fingerprint}"
: "${SIRINVPN_LINUX_OUTBOUND_CONFIRM:?Set SIRINVPN_LINUX_OUTBOUND_CONFIRM=audit-disposable-vps}"

if [ "$SIRINVPN_LINUX_OUTBOUND_CONFIRM" != "audit-disposable-vps" ]; then
  echo "Refusing to install audit observers without the exact disposable-VPS confirmation." >&2
  exit 2
fi

export LC_ALL=C
PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CLI=${SIRINVPN_LINUX_OUTBOUND_CLI:-"$PROJECT_ROOT/target/release/sirinvpn"}
LOCAL_HELPER=${SIRINVPN_LINUX_OUTBOUND_HELPER:-/usr/lib/sirinvpn/sirinvpn-helper}
REMOTE_HELPER_SOURCE="$PROJECT_ROOT/tests/integration/linux-outbound-audit-rollback.py"
SERVER_ID=$SIRINVPN_LINUX_OUTBOUND_SERVER_ID
SSH_USER=${SIRINVPN_LINUX_OUTBOUND_USER:-root}
SSH_PORT=${SIRINVPN_LINUX_OUTBOUND_SSH_PORT:-22}
MANAGEMENT_PORT=8443

for command in awk cmp getent grep install ip jq nft ping python3 resolvectl sha256sum ssh ssh-add ssh-keygen ssh-keyscan ss stat sudo systemctl systemd-run timeout wg; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required for the Linux outbound-network audit gate." >&2
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
case "$SIRINVPN_LINUX_OUTBOUND_HOST_KEY" in
  SHA256:*) ;;
  *)
    echo "The expected SSH host key must use SHA256:... form." >&2
    exit 2
    ;;
esac

valid_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

if ! valid_port "$SSH_PORT"; then
  echo "The requested SSH port is outside its safe bound." >&2
  exit 2
fi

AUDIT_CGROUP=$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)
case "$AUDIT_CGROUP" in
  /user.slice/user-*.slice/user@*.service/app.slice/sirinvpn-outbound-audit-scope-*.scope) ;;
  *)
    echo "The audit worker is not inside its dedicated systemd scope." >&2
    exit 2
    ;;
esac
AUDIT_CGROUP_LEVEL=$(printf '%s\n' "$AUDIT_CGROUP" | awk -F/ '{ print NF - 1 }')
case "$AUDIT_CGROUP_LEVEL" in
  ''|*[!0-9]*)
    echo "The audit worker cgroup depth could not be determined." >&2
    exit 2
    ;;
esac
AUDIT_CGROUP_PATH=${AUDIT_CGROUP#/}

TEST_ROOT=$(mktemp -d /tmp/sirinvpn-linux-outbound-audit.XXXXXX)
chmod 0700 "$TEST_ROOT"
umask 077
PROFILE="$TEST_ROOT/profile.json"
PROFILES="$TEST_ROOT/profiles.json"
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
LOCAL_BEFORE="$TEST_ROOT/local-before.nft"
LOCAL_AFTER="$TEST_ROOT/local-after.nft"
DNS_LOCAL_BEFORE="$TEST_ROOT/dns-local-before.nft"
DNS_LOCAL_AFTER="$TEST_ROOT/dns-local-after.nft"
REMOTE_BEFORE="$TEST_ROOT/remote-before.nft"
REMOTE_AFTER="$TEST_ROOT/remote-after.nft"
DNS_OUTPUT="$TEST_ROOT/dns.txt"
POLICY_BACKUP="$TEST_ROOT/network-policy.original"
POLICY_PRESENT=0
POLICY_HASH=
REMOTE_ARMED=0
LOCAL_OBSERVER_ACTIVE=0
LOCAL_TOUCHED=0
CLEANUP_RUNNING=0
MAIN_COMPLETE=0

LOCAL_NFT_TABLE="sirinvpn_outbound_audit_$$"
REMOTE_NFT_TABLE="sirinvpn_outbound_audit_$$"
REMOTE_ROOT="/run/sirinvpn-linux-outbound-audit-$$"
REMOTE_HELPER="$REMOTE_ROOT/rollback.py"
ROLLBACK_BASE="sirinvpn-linux-outbound-audit-$$-rollback"
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
    echo "The outbound-audit gate accepts one bounded remote command at a time." >&2
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
    local_root nft delete table inet "$LOCAL_NFT_TABLE" >/dev/null 2>&1 \
      || ! local_root nft list table inet "$LOCAL_NFT_TABLE" >/dev/null 2>&1 \
      || return 1
    LOCAL_OBSERVER_ACTIVE=0
  fi
}

arm_remote_transaction() {
  REMOTE_ARMED=1
  remote "install -d -m 0700 '$REMOTE_ROOT'"
  remote "install -m 0700 /dev/stdin '$REMOTE_HELPER'" <"$REMOTE_HELPER_SOURCE"
  remote "/usr/bin/python3 '$REMOTE_HELPER' prepare '$REMOTE_ROOT' '$REMOTE_NFT_TABLE'"
  remote "systemd-run --quiet --unit='$ROLLBACK_BASE' --on-active=12m --timer-property=AccuracySec=1s --property=Restart=on-failure --property=RestartSec=5s /usr/bin/python3 '$REMOTE_HELPER' rollback '$REMOTE_ROOT' '$REMOTE_NFT_TABLE'"
}

restore_remote_transaction() {
  if ! remote "/usr/bin/python3 '$REMOTE_HELPER' rollback '$REMOTE_ROOT' '$REMOTE_NFT_TABLE'"; then
    remote "set -eu; \
      if test -d '$REMOTE_ROOT' && ! test -e '$REMOTE_ROOT/state.json'; then \
        ! nft list table inet '$REMOTE_NFT_TABLE' >/dev/null 2>&1 || exit 1; \
        test -z \"\$(find '$REMOTE_ROOT' -mindepth 1 -maxdepth 1 ! -name rollback.py -print -quit)\"; \
        rm -f '$REMOTE_HELPER'; \
        rmdir '$REMOTE_ROOT'; \
      fi; \
      test ! -e '$REMOTE_ROOT'; \
      ! nft list table inet '$REMOTE_NFT_TABLE' >/dev/null 2>&1" \
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
    test -z \"\$(find /run -maxdepth 1 -type d -name 'sirinvpn-linux-outbound-audit-*' -print -quit)\"; \
    test -z \"\$(systemctl list-units --all --no-legend 'sirinvpn-linux-outbound-audit-*-rollback*')\"" \
    || return 1
}

restore_local_policy() {
  if [ "$POLICY_PRESENT" -eq 1 ]; then
    if [ ! -f "$POLICY_BACKUP" ]; then
      echo "The local network-policy backup is unavailable." >&2
      return 1
    fi
    POLICY_TEMP="$POLICY_FILE.linux-outbound-audit-$$"
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

  if [ "$LOCAL_TOUCHED" -eq 1 ] \
    || ! helper_status | jq -e '.state == "disconnected"' >/dev/null 2>&1; then
    if ! disconnect_local; then
      echo "WARNING: local VPN cleanup could not be confirmed." >&2
      cleanup_failed=1
    fi
  fi
  if ! remove_local_observer; then
    echo "WARNING: the local outbound observer could not be removed." >&2
    cleanup_failed=1
  fi
  if [ "$REMOTE_ARMED" -eq 1 ]; then
    if ! restore_remote_transaction; then
      echo "WARNING: VPS audit cleanup could not be confirmed; the 12-minute timer remains the fallback." >&2
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
    /tmp/sirinvpn-linux-outbound-audit.*) rm -rf -- "$TEST_ROOT" ;;
    *)
      echo "WARNING: refusing to remove unexpected test directory $TEST_ROOT" >&2
      cleanup_failed=1
      ;;
  esac

  if [ "$cleanup_failed" -ne 0 ]; then
    result=1
  fi
  if [ "$result" -eq 0 ] && [ "$MAIN_COMPLETE" -eq 1 ]; then
    echo "Linux outbound-network audit gate passed: all four transports, private management, and encrypted DNS used only documented ownership paths, no unexpected SirinVPN-originated TCP/UDP egress was observed, and exact cleanup was verified."
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$CLI" --json server list >"$PROFILES"
jq -e --arg id "$SERVER_ID" '.[] | select(.id == $id)' "$PROFILES" >"$PROFILE"
if ! jq -e '.role == "owner"' "$PROFILE" >/dev/null; then
  echo "The outbound audit must run from the enrolled Owner profile." >&2
  exit 2
fi
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
for PORT in "$WIREGUARD_PORT" "$OBFUSCATED_PORT" "$TCP_PORT" "$TLS_PORT"; do
  if ! valid_port "$PORT"; then
    echo "A stored transport port is outside its safe bound." >&2
    exit 2
  fi
done
if [ "$WIREGUARD_PORT" -eq "$OBFUSCATED_PORT" ] \
  || [ "$TCP_PORT" -ne "$TLS_PORT" ]; then
  echo "The VPS transport ports are not compatible with this bounded gate." >&2
  exit 2
fi
if ! python3 - "$SERVER_HOST" "$CLIENT_ADDRESS" "$SERVER_TUNNEL_ADDRESS" <<'PY'
import ipaddress
import sys

for value in sys.argv[1:]:
    address = ipaddress.ip_address(value)
    assert address.version == 4 and str(address) == value
PY
then
  echo "The outbound audit requires canonical IPv4 public and tunnel addresses." >&2
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
if [ "$ACTUAL_HOST_KEY" != "$SIRINVPN_LINUX_OUTBOUND_HOST_KEY" ]; then
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
  test -z \"\$(find /run -maxdepth 1 -type d -name 'sirinvpn-linux-outbound-audit-*' -print -quit)\"; \
  ! nft list tables | grep -q sirinvpn_outbound_audit_ || exit 1; \
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
SERVER_CGROUP=$(remote "systemctl show -p ControlGroup --value sirinvpn-server.service")
UNBOUND_CGROUP=$(remote "systemctl show -p ControlGroup --value unbound.service")
if [ "$SERVER_CGROUP" != "/system.slice/sirinvpn-server.service" ] \
  || [ "$UNBOUND_CGROUP" != "/system.slice/unbound.service" ]; then
  echo "A VPS service cgroup ownership boundary could not be resolved." >&2
  exit 2
fi
SERVER_CGROUP_PATH=${SERVER_CGROUP#/}
UNBOUND_CGROUP_PATH=${UNBOUND_CGROUP#/}
SERVER_CGROUP_LEVEL=$(printf '%s\n' "$SERVER_CGROUP" | awk -F/ '{ print NF - 1 }')
UNBOUND_CGROUP_LEVEL=$(printf '%s\n' "$UNBOUND_CGROUP" | awk -F/ '{ print NF - 1 }')

remote "cat /etc/sirinvpn/server.json" >"$REMOTE_CONFIGURATION"
if ! jq -e '
  .dns_upstream.mode == "dns_over_tls"
  and (.dns_upstream.endpoints | length >= 1 and length <= 2)
  and all(.dns_upstream.endpoints[];
    (.address | type == "string")
    and (.authentication_name | type == "string" and length >= 1))
' "$REMOTE_CONFIGURATION" >/dev/null; then
  echo "This bounded audit requires an existing one-or-two-endpoint DNS-over-TLS policy." >&2
  exit 2
fi
if ! python3 - "$REMOTE_CONFIGURATION" <<'PY'
import ipaddress
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    document = json.load(source)
for endpoint in document["dns_upstream"]["endpoints"]:
    address = ipaddress.ip_address(endpoint["address"])
    assert str(address) == endpoint["address"]
PY
then
  echo "The configured DNS-over-TLS endpoints are not canonical IP addresses." >&2
  exit 2
fi
DOT_ENDPOINTS=$(jq -r '.dns_upstream.endpoints[].address' "$REMOTE_CONFIGURATION")

remote_hashes >"$REMOTE_BASELINE"
remote "nft list tables | sort" >"$REMOTE_TABLES_BASELINE"
arm_remote_transaction
remote "systemctl restart unbound.service; systemctl is-active --quiet unbound.service; systemctl is-active --quiet sirinvpn-server.service"

create_local_observer() {
  LOCAL_OBSERVER_ACTIVE=1
  {
    printf 'add table inet %s\n' "$LOCAL_NFT_TABLE"
    printf 'add chain inet %s output { type filter hook output priority -300; policy accept; }\n' "$LOCAL_NFT_TABLE"
    printf 'add rule inet %s output oifname "%s" meta mark 0xca6c ip daddr %s udp dport %s counter return comment "client-direct-carrier"\n' \
      "$LOCAL_NFT_TABLE" "$LOCAL_PHYSICAL_INTERFACE" "$SERVER_HOST" "$WIREGUARD_PORT"
    printf 'add rule inet %s output oifname "%s" meta mark 0xca6c ip daddr %s udp dport %s counter return comment "client-obfuscated-carrier"\n' \
      "$LOCAL_NFT_TABLE" "$LOCAL_PHYSICAL_INTERFACE" "$SERVER_HOST" "$OBFUSCATED_PORT"
    printf 'add rule inet %s output oifname "%s" meta mark 0xca6c ip daddr %s tcp dport %s counter return comment "client-tcp-carrier"\n' \
      "$LOCAL_NFT_TABLE" "$LOCAL_PHYSICAL_INTERFACE" "$SERVER_HOST" "$TCP_PORT"
    printf 'add rule inet %s output oifname "%s" meta mark 0xca6c counter comment "client-unexpected-marked"\n' \
      "$LOCAL_NFT_TABLE" "$LOCAL_PHYSICAL_INTERFACE"
    printf 'add rule inet %s output oifname "lo" meta mark 0xca6c ip daddr 127.0.0.1 udp dport { 51821, 51822, 51823 } counter return comment "client-relay-loopback"\n' \
      "$LOCAL_NFT_TABLE"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" ip daddr %s tcp dport %s counter return comment "audit-harness-ssh"\n' \
      "$LOCAL_NFT_TABLE" "$AUDIT_CGROUP_LEVEL" "$AUDIT_CGROUP_PATH" "$SERVER_HOST" "$SSH_PORT"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "sirinvpn0" ip daddr %s tcp dport %s counter return comment "client-management"\n' \
      "$LOCAL_NFT_TABLE" "$AUDIT_CGROUP_LEVEL" "$AUDIT_CGROUP_PATH" "$SERVER_TUNNEL_ADDRESS" "$MANAGEMENT_PORT"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" meta l4proto { tcp, udp } counter comment "client-unexpected-worker"\n' \
      "$LOCAL_NFT_TABLE" "$AUDIT_CGROUP_LEVEL" "$AUDIT_CGROUP_PATH"
    printf 'add rule inet %s output meta skuid %s oifname "sirinvpn0" ip daddr %s udp dport 53 counter return comment "client-private-dns"\n' \
      "$LOCAL_NFT_TABLE" "$RESOLVER_UID" "$SERVER_TUNNEL_ADDRESS"
    printf 'add rule inet %s output meta skuid %s oifname "sirinvpn0" ip daddr %s tcp dport 53 counter return comment "client-private-dns"\n' \
      "$LOCAL_NFT_TABLE" "$RESOLVER_UID" "$SERVER_TUNNEL_ADDRESS"
    printf 'add rule inet %s output meta skuid %s oifname "%s" udp dport 53 counter comment "client-unexpected-physical-dns"\n' \
      "$LOCAL_NFT_TABLE" "$RESOLVER_UID" "$LOCAL_PHYSICAL_INTERFACE"
    printf 'add rule inet %s output meta skuid %s oifname "%s" tcp dport { 53, 853 } counter comment "client-unexpected-physical-dns"\n' \
      "$LOCAL_NFT_TABLE" "$RESOLVER_UID" "$LOCAL_PHYSICAL_INTERFACE"
  } | local_root nft -f -
}

create_remote_observer() {
  {
    printf 'add table inet %s\n' "$REMOTE_NFT_TABLE"
    printf 'add chain inet %s input { type filter hook input priority -300; policy accept; }\n' "$REMOTE_NFT_TABLE"
    printf 'add chain inet %s output { type filter hook output priority -300; policy accept; }\n' "$REMOTE_NFT_TABLE"
    printf 'add rule inet %s input iifname "sirinvpn0" ip saddr %s ip daddr %s udp dport 53 counter comment "server-private-dns-query"\n' \
      "$REMOTE_NFT_TABLE" "$CLIENT_ADDRESS" "$SERVER_TUNNEL_ADDRESS"
    printf 'add rule inet %s input iifname "sirinvpn0" ip saddr %s ip daddr %s tcp dport 53 counter comment "server-private-dns-query"\n' \
      "$REMOTE_NFT_TABLE" "$CLIENT_ADDRESS" "$SERVER_TUNNEL_ADDRESS"
    printf 'add rule inet %s output oifname "%s" ip daddr %s udp sport %s counter return comment "server-direct-carrier"\n' \
      "$REMOTE_NFT_TABLE" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$WIREGUARD_PORT"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "%s" ip daddr %s udp sport %s counter return comment "server-obfuscated-carrier"\n' \
      "$REMOTE_NFT_TABLE" "$SERVER_CGROUP_LEVEL" "$SERVER_CGROUP_PATH" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$OBFUSCATED_PORT"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "%s" ip daddr %s tcp sport %s counter return comment "server-tcp-carrier"\n' \
      "$REMOTE_NFT_TABLE" "$SERVER_CGROUP_LEVEL" "$SERVER_CGROUP_PATH" "$PUBLIC_INTERFACE" "$CLIENT_PUBLIC_IPV4" "$TCP_PORT"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "sirinvpn0" ip daddr %s tcp sport %s counter return comment "server-management"\n' \
      "$REMOTE_NFT_TABLE" "$SERVER_CGROUP_LEVEL" "$SERVER_CGROUP_PATH" "$CLIENT_ADDRESS" "$MANAGEMENT_PORT"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "lo" ip daddr 127.0.0.1 udp dport %s counter return comment "server-relay-backend"\n' \
      "$REMOTE_NFT_TABLE" "$SERVER_CGROUP_LEVEL" "$SERVER_CGROUP_PATH" "$WIREGUARD_PORT"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "lo" ip saddr 127.0.0.1 udp sport %s counter return comment "server-relay-backend"\n' \
      "$REMOTE_NFT_TABLE" "$SERVER_CGROUP_LEVEL" "$SERVER_CGROUP_PATH" "$WIREGUARD_PORT"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "sirinvpn0" ip daddr %s udp sport 53 counter return comment "server-private-dns-response"\n' \
      "$REMOTE_NFT_TABLE" "$UNBOUND_CGROUP_LEVEL" "$UNBOUND_CGROUP_PATH" "$CLIENT_ADDRESS"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "sirinvpn0" ip daddr %s tcp sport 53 counter return comment "server-private-dns-response"\n' \
      "$REMOTE_NFT_TABLE" "$UNBOUND_CGROUP_LEVEL" "$UNBOUND_CGROUP_PATH" "$CLIENT_ADDRESS"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 udp sport 53 counter return comment "server-local-dns-response"\n' \
      "$REMOTE_NFT_TABLE" "$UNBOUND_CGROUP_LEVEL" "$UNBOUND_CGROUP_PATH"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 53 counter return comment "server-local-dns-response"\n' \
      "$REMOTE_NFT_TABLE" "$UNBOUND_CGROUP_LEVEL" "$UNBOUND_CGROUP_PATH"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 udp dport 53 counter return comment "server-local-dns-query"\n' \
      "$REMOTE_NFT_TABLE" "$UNBOUND_CGROUP_LEVEL" "$UNBOUND_CGROUP_PATH"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport 53 counter return comment "server-local-dns-query"\n' \
      "$REMOTE_NFT_TABLE" "$UNBOUND_CGROUP_LEVEL" "$UNBOUND_CGROUP_PATH"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" oifname "lo" meta l4proto { tcp, udp } counter return comment "server-local-resolver-ipc"\n' \
      "$REMOTE_NFT_TABLE" "$UNBOUND_CGROUP_LEVEL" "$UNBOUND_CGROUP_PATH"
    for DOT_ENDPOINT in $DOT_ENDPOINTS; do
      if printf '%s\n' "$DOT_ENDPOINT" | grep -q ':'; then
        DOT_FAMILY=ip6
      else
        DOT_FAMILY=ip
      fi
      printf 'add rule inet %s output socket cgroupv2 level %s "%s" %s daddr %s tcp dport 853 counter return comment "server-dot-upstream"\n' \
        "$REMOTE_NFT_TABLE" "$UNBOUND_CGROUP_LEVEL" "$UNBOUND_CGROUP_PATH" "$DOT_FAMILY" "$DOT_ENDPOINT"
    done
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" ct direction reply meta l4proto { tcp, udp } counter return comment "server-inbound-reply"\n' \
      "$REMOTE_NFT_TABLE" "$SERVER_CGROUP_LEVEL" "$SERVER_CGROUP_PATH"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" meta l4proto { tcp, udp } counter comment "server-unexpected-sirinvpn"\n' \
      "$REMOTE_NFT_TABLE" "$SERVER_CGROUP_LEVEL" "$SERVER_CGROUP_PATH"
    printf 'add rule inet %s output socket cgroupv2 level %s "%s" meta l4proto { tcp, udp } counter comment "server-unexpected-unbound"\n' \
      "$REMOTE_NFT_TABLE" "$UNBOUND_CGROUP_LEVEL" "$UNBOUND_CGROUP_PATH"
    printf 'add rule inet %s output oifname "%s" udp sport %s counter comment "server-unexpected-wireguard"\n' \
      "$REMOTE_NFT_TABLE" "$PUBLIC_INTERFACE" "$WIREGUARD_PORT"
  } | remote "/usr/sbin/nft -f -"
}

counter_from() {
  COUNTER_FILE=$1
  COUNTER_COMMENT=$2
  awk -v comment="$COUNTER_COMMENT" '
    index($0, "comment \"" comment "\"") {
      for (field = 1; field <= NF; field++) {
        if ($field == "packets") {
          total += $(field + 1)
        }
      }
    }
    END { print total + 0 }
  ' "$COUNTER_FILE"
}

decimal_counter() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

capture_local_counters() {
  local_root nft list table inet "$LOCAL_NFT_TABLE" >"$1"
}

capture_remote_counters() {
  remote "/usr/sbin/nft list table inet '$REMOTE_NFT_TABLE'" >"$1"
}

assert_no_unexpected_traffic() {
  capture_remote_counters "$REMOTE_AFTER"
  capture_local_counters "$LOCAL_AFTER"
  for SPECIFICATION in \
    "$LOCAL_AFTER:client-unexpected-marked" \
    "$LOCAL_AFTER:client-unexpected-worker" \
    "$REMOTE_AFTER:server-unexpected-sirinvpn" \
    "$REMOTE_AFTER:server-unexpected-unbound" \
    "$REMOTE_AFTER:server-unexpected-wireguard"; do
    COUNTER_FILE=${SPECIFICATION%%:*}
    COUNTER_COMMENT=${SPECIFICATION#*:}
    COUNTER_VALUE=$(counter_from "$COUNTER_FILE" "$COUNTER_COMMENT")
    if ! decimal_counter "$COUNTER_VALUE" || [ "$COUNTER_VALUE" -ne 0 ]; then
      echo "Unexpected SirinVPN-owned egress was observed at the $COUNTER_COMMENT boundary." >&2
      return 1
    fi
  done
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
    echo "The $EXPECTED_TRANSPORT audit phase did not return authenticated healthy state." >&2
    return 1
  fi
  ip -4 -o address show dev sirinvpn0 | grep -F " $CLIENT_ADDRESS/" >/dev/null
  ip -4 route show table 51820 | grep -E '^default .*dev sirinvpn0' >/dev/null
  ip -4 rule show priority 10000 | grep -F 'lookup 51820' >/dev/null
  ip -4 rule show priority 10001 | grep -F 'suppress_prefixlength 0' >/dev/null
  resolvectl dns sirinvpn0 | grep -F "$SERVER_TUNNEL_ADDRESS" >/dev/null
  resolvectl domain sirinvpn0 | grep -F '~.' >/dev/null
  assert_transport_runtime "$EXPECTED_TRANSPORT"
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
    echo "Private DNS did not resolve the phase's public test name." >&2
    return 1
  fi
}

positive_delta() {
  DELTA_BEFORE=$1
  DELTA_AFTER=$2
  DELTA_LABEL=$3
  if ! decimal_counter "$DELTA_BEFORE" || ! decimal_counter "$DELTA_AFTER" \
    || [ "$DELTA_AFTER" -le "$DELTA_BEFORE" ]; then
    echo "The $DELTA_LABEL ownership path produced no observed packets." >&2
    return 1
  fi
}

run_phase() {
  PHASE_LABEL=$1
  PHASE_CLI_TRANSPORT=$2
  PHASE_EXPECTED_TRANSPORT=$3
  PHASE_CLIENT_CARRIER=$4
  PHASE_SERVER_CARRIER=$5
  PHASE_DNS_NAME=$6
  PHASE_RELAY_REQUIRED=$7

  echo "Outbound audit phase: $PHASE_LABEL"
  capture_local_counters "$LOCAL_BEFORE"
  capture_remote_counters "$REMOTE_BEFORE"
  CLIENT_CARRIER_BEFORE=$(counter_from "$LOCAL_BEFORE" "$PHASE_CLIENT_CARRIER")
  CLIENT_MANAGEMENT_BEFORE=$(counter_from "$LOCAL_BEFORE" client-management)
  CLIENT_DNS_BEFORE=$(counter_from "$LOCAL_BEFORE" client-private-dns)
  CLIENT_RELAY_BEFORE=$(counter_from "$LOCAL_BEFORE" client-relay-loopback)
  SERVER_CARRIER_BEFORE=$(counter_from "$REMOTE_BEFORE" "$PHASE_SERVER_CARRIER")
  SERVER_MANAGEMENT_BEFORE=$(counter_from "$REMOTE_BEFORE" server-management)
  SERVER_DNS_QUERY_BEFORE=$(counter_from "$REMOTE_BEFORE" server-private-dns-query)
  SERVER_DNS_RESPONSE_BEFORE=$(counter_from "$REMOTE_BEFORE" server-private-dns-response)
  SERVER_RELAY_BEFORE=$(counter_from "$REMOTE_BEFORE" server-relay-backend)

  LOCAL_TOUCHED=1
  "$CLI" --json connect "$SERVER_ID" --transport "$PHASE_CLI_TRANSPORT" \
    >"$CONNECT_OUTPUT"
  assert_connection "$PHASE_EXPECTED_TRANSPORT"
  ping -c 3 -W 5 "$SERVER_TUNNEL_ADDRESS" >/dev/null
  capture_local_counters "$DNS_LOCAL_BEFORE"
  CLIENT_PHYSICAL_DNS_BEFORE=$(counter_from "$DNS_LOCAL_BEFORE" client-unexpected-physical-dns)
  dns_query_succeeds "$PHASE_DNS_NAME"
  capture_local_counters "$DNS_LOCAL_AFTER"
  CLIENT_PHYSICAL_DNS_AFTER=$(counter_from "$DNS_LOCAL_AFTER" client-unexpected-physical-dns)
  if ! decimal_counter "$CLIENT_PHYSICAL_DNS_BEFORE" \
    || ! decimal_counter "$CLIENT_PHYSICAL_DNS_AFTER" \
    || [ "$CLIENT_PHYSICAL_DNS_AFTER" -ne "$CLIENT_PHYSICAL_DNS_BEFORE" ]; then
    echo "The system resolver used physical DNS during the protected $PHASE_LABEL query." >&2
    return 1
  fi
  assert_connection "$PHASE_EXPECTED_TRANSPORT"

  capture_remote_counters "$REMOTE_AFTER"
  capture_local_counters "$LOCAL_AFTER"
  CLIENT_CARRIER_AFTER=$(counter_from "$LOCAL_AFTER" "$PHASE_CLIENT_CARRIER")
  CLIENT_MANAGEMENT_AFTER=$(counter_from "$LOCAL_AFTER" client-management)
  CLIENT_DNS_AFTER=$(counter_from "$LOCAL_AFTER" client-private-dns)
  CLIENT_RELAY_AFTER=$(counter_from "$LOCAL_AFTER" client-relay-loopback)
  SERVER_CARRIER_AFTER=$(counter_from "$REMOTE_AFTER" "$PHASE_SERVER_CARRIER")
  SERVER_MANAGEMENT_AFTER=$(counter_from "$REMOTE_AFTER" server-management)
  SERVER_DNS_QUERY_AFTER=$(counter_from "$REMOTE_AFTER" server-private-dns-query)
  SERVER_DNS_RESPONSE_AFTER=$(counter_from "$REMOTE_AFTER" server-private-dns-response)
  SERVER_RELAY_AFTER=$(counter_from "$REMOTE_AFTER" server-relay-backend)

  positive_delta "$CLIENT_CARRIER_BEFORE" "$CLIENT_CARRIER_AFTER" "$PHASE_LABEL client carrier"
  positive_delta "$CLIENT_MANAGEMENT_BEFORE" "$CLIENT_MANAGEMENT_AFTER" "$PHASE_LABEL private management request"
  positive_delta "$CLIENT_DNS_BEFORE" "$CLIENT_DNS_AFTER" "$PHASE_LABEL private DNS request"
  positive_delta "$SERVER_CARRIER_BEFORE" "$SERVER_CARRIER_AFTER" "$PHASE_LABEL server carrier response"
  positive_delta "$SERVER_MANAGEMENT_BEFORE" "$SERVER_MANAGEMENT_AFTER" "$PHASE_LABEL private management response"
  positive_delta "$SERVER_DNS_QUERY_BEFORE" "$SERVER_DNS_QUERY_AFTER" "$PHASE_LABEL VPS-private DNS ingress"
  positive_delta "$SERVER_DNS_RESPONSE_BEFORE" "$SERVER_DNS_RESPONSE_AFTER" "$PHASE_LABEL VPS-private DNS response"
  if [ "$PHASE_RELAY_REQUIRED" = true ]; then
    positive_delta "$CLIENT_RELAY_BEFORE" "$CLIENT_RELAY_AFTER" "$PHASE_LABEL client loopback relay"
    positive_delta "$SERVER_RELAY_BEFORE" "$SERVER_RELAY_AFTER" "$PHASE_LABEL loopback relay"
  fi
  assert_no_unexpected_traffic

  CLIENT_CARRIER_DELTA=$((CLIENT_CARRIER_AFTER - CLIENT_CARRIER_BEFORE))
  SERVER_CARRIER_DELTA=$((SERVER_CARRIER_AFTER - SERVER_CARRIER_BEFORE))
  MANAGEMENT_DELTA=$((CLIENT_MANAGEMENT_AFTER - CLIENT_MANAGEMENT_BEFORE))
  DNS_DELTA=$((CLIENT_DNS_AFTER - CLIENT_DNS_BEFORE))
  echo "$PHASE_LABEL: $CLIENT_CARRIER_DELTA client carrier packet(s), $SERVER_CARRIER_DELTA server carrier packet(s), $MANAGEMENT_DELTA private management packet(s), $DNS_DELTA private DNS packet(s)"
  disconnect_local
}

create_remote_observer
create_local_observer
capture_remote_counters "$REMOTE_BEFORE"
DOT_BEFORE=$(counter_from "$REMOTE_BEFORE" server-dot-upstream)

run_phase "Direct UDP" direct direct_udp client-direct-carrier server-direct-carrier example.com false
run_phase "Obfuscated UDP" obfuscated obfuscated_udp client-obfuscated-carrier server-obfuscated-carrier example.net true
run_phase "Pinned TLS" tls tls_like client-tcp-carrier server-tcp-carrier example.org true
run_phase "Raw TCP" tcp tcp_fallback client-tcp-carrier server-tcp-carrier iana.org true

capture_remote_counters "$REMOTE_AFTER"
DOT_AFTER=$(counter_from "$REMOTE_AFTER" server-dot-upstream)
positive_delta "$DOT_BEFORE" "$DOT_AFTER" "configured encrypted DNS upstream"
assert_no_unexpected_traffic
disconnect_local
assert_no_unexpected_traffic

if [ "$POLICY_PRESENT" -eq 1 ]; then
  if [ "$(sha256sum "$POLICY_FILE" | awk '{print $1}')" != "$POLICY_HASH" ]; then
    echo "Manual transport auditing unexpectedly changed the network-policy cache." >&2
    exit 1
  fi
elif [ -e "$POLICY_FILE" ]; then
  echo "Manual transport auditing unexpectedly created a network-policy cache." >&2
  exit 1
fi

remove_local_observer
restore_remote_transaction
verify_remote_baseline
restore_local_policy
assert_local_baseline
MAIN_COMPLETE=1
exit 0
