#!/bin/sh
set -eu

: "${SIRINVPN_TEST_HOST:?Set the disposable Debian 13 VPS hostname or IPv4 address}"
: "${SIRINVPN_TEST_HOST_KEY:?Set the independently verified SHA256 SSH host fingerprint}"

SIRINVPN_TEST_USER=${SIRINVPN_TEST_USER:-root}
SIRINVPN_TEST_PORT=${SIRINVPN_TEST_PORT:-22}
SIRINVPN_TEST_NAME=${SIRINVPN_TEST_NAME:-SirinVPN-P1A-Test}
SIRINVPN_TEST_CONFIRM=${SIRINVPN_TEST_CONFIRM:-}

if [ "$SIRINVPN_TEST_CONFIRM" != "provision-disposable-vps" ]; then
  echo "Refusing to modify the VPS. Set SIRINVPN_TEST_CONFIRM=provision-disposable-vps." >&2
  exit 2
fi

if ! ssh-add -l >/dev/null 2>&1; then
  echo "No SSH agent identity is loaded." >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the integration assertions." >&2
  exit 2
fi

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CLI="$PROJECT_ROOT/target/release/sirinvpn"
SERVER=${SIRINVPN_TEST_SERVER_BINARY:-$PROJECT_ROOT/target/release/sirinvpn-server}
PROFILE_OUTPUT=$(mktemp)
REPAIR_OUTPUT=$(mktemp)
ROTATION_OUTPUT=$(mktemp)
MEMBERS_BEFORE_ROTATION=$(mktemp)
MEMBERS_AFTER_ROTATION=$(mktemp)
FAILED_OUTPUT=$(mktemp)
CONNECTED=0

cleanup() {
  if [ "$CONNECTED" -eq 1 ]; then
    "$CLI" disconnect >/dev/null 2>&1 || true
  fi
  rm -f "$PROFILE_OUTPUT" "$REPAIR_OUTPUT" "$ROTATION_OUTPUT" \
    "$MEMBERS_BEFORE_ROTATION" "$MEMBERS_AFTER_ROTATION" "$FAILED_OUTPUT"
}
trap cleanup EXIT HUP INT TERM

cd "$PROJECT_ROOT"
cargo build --release -p sirinvpn-cli -p sirinvpn-linux-helper
if [ -z "${SIRINVPN_TEST_SERVER_BINARY:-}" ]; then
  cargo build --release -p sirinvpn-server
fi

"$CLI" --json server add \
  --name "$SIRINVPN_TEST_NAME" \
  --host "$SIRINVPN_TEST_HOST" \
  --username "$SIRINVPN_TEST_USER" \
  --ssh-port "$SIRINVPN_TEST_PORT" \
  --ssh-agent \
  --host-key "$SIRINVPN_TEST_HOST_KEY" \
  --server-binary "$SERVER" \
  --passwordless-sudo >"$PROFILE_OUTPUT"

SERVER_ID=$(jq -er '.id' "$PROFILE_OUTPUT")
IPV6_TUNNEL_ENABLED=$(jq -r '.ipv6_tunnel_enabled // false' "$PROFILE_OUTPUT")
jq -e '.obfuscated_udp.port == 443 and (.obfuscated_udp.server_public_key | length) == 44' \
  "$PROFILE_OUTPUT" >/dev/null
jq -e '.tcp_fallback.port == 443 and (.tcp_fallback.server_public_key | length) == 44' \
  "$PROFILE_OUTPUT" >/dev/null
"$CLI" connect "$SERVER_ID" --persistent
CONNECTED=1

LOCAL_READY=0
ATTEMPT=0
while [ "$ATTEMPT" -lt 15 ]; do
  if "$CLI" --json status | jq -e \
    --arg id "$SERVER_ID" \
    --argjson ipv6 "$IPV6_TUNNEL_ENABLED" \
    '.local.state == "connected"
      and .local.server_id == $id
      and .local.transport == "direct_udp"
      and .local.kill_switch_enabled == true
      and .local.auto_reconnect_enabled == true
      and .server.dns_healthy == true
      and (if $ipv6 then .local.ipv6_tunneled == true else .local.ipv6_blocked == true end)' >/dev/null 2>&1; then
    LOCAL_READY=1
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  sleep 1
done
if [ "$LOCAL_READY" -ne 1 ]; then
  echo "Persistent protection did not become healthy." >&2
  exit 1
fi
systemctl is-active --quiet sirinvpn-killswitch.service
systemctl is-active --quiet sirinvpn-reconnect.service
getent ahostsv4 example.com >/dev/null
if [ "$IPV6_TUNNEL_ENABLED" = "true" ]; then
  ip -6 route show table 51820 | grep -q 'dev sirinvpn0'
  ip -6 rule show priority 10000 | grep -q 'lookup 51820'
  ip -6 rule show priority 10001 | grep -q 'suppress_prefixlength 0'
  getent ahostsv6 example.com >/dev/null
fi

wait_for_diagnostics() {
  DIAGNOSE_READY=0
  ATTEMPT=0
  while [ "$ATTEMPT" -lt 15 ]; do
    if "$CLI" --json diagnose "$SERVER_ID" | jq -e \
      '[.checks[].level] | all(. == "pass")' >/dev/null 2>&1; then
      DIAGNOSE_READY=1
      break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
  done
  if [ "$DIAGNOSE_READY" -ne 1 ]; then
    echo "The server did not become healthy." >&2
    return 1
  fi
}

wait_for_diagnostics

METRICS_READY=0
ATTEMPT=0
while [ "$ATTEMPT" -lt 10 ]; do
  if "$CLI" --json status | jq -e \
    '.server.cpu_usage_basis_points >= 0
      and .server.cpu_usage_basis_points <= 10000
      and .server.memory_total_bytes > 0
      and .server.memory_used_bytes >= 0
      and .server.memory_used_bytes <= .server.memory_total_bytes
      and .server.rx_bytes_per_second >= 0
      and .server.tx_bytes_per_second >= 0' >/dev/null 2>&1; then
    METRICS_READY=1
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  sleep 1
done
if [ "$METRICS_READY" -ne 1 ]; then
  echo "Ephemeral live server metrics did not become available." >&2
  exit 1
fi

if "$CLI" server add \
  --name "$SIRINVPN_TEST_NAME-conflicting-owner" \
  --host "$SIRINVPN_TEST_HOST" \
  --username "$SIRINVPN_TEST_USER" \
  --ssh-port "$SIRINVPN_TEST_PORT" \
  --ssh-agent \
  --host-key "$SIRINVPN_TEST_HOST_KEY" \
  --server-binary "$SERVER" \
  --passwordless-sudo >"$FAILED_OUTPUT" 2>&1; then
  echo "A conflicting owner reinstall unexpectedly succeeded." >&2
  exit 1
fi

wait_for_diagnostics
"$CLI" disconnect
CONNECTED=0
! systemctl is-active --quiet sirinvpn-killswitch.service || exit 1
! systemctl is-active --quiet sirinvpn-reconnect.service || exit 1

"$CLI" --json server repair "$SERVER_ID" \
  --username "$SIRINVPN_TEST_USER" \
  --ssh-port "$SIRINVPN_TEST_PORT" \
  --ssh-agent \
  --host-key "$SIRINVPN_TEST_HOST_KEY" \
  --server-binary "$SERVER" \
  --passwordless-sudo \
  --confirm-repair >"$REPAIR_OUTPUT"

EXPECTED_ARTIFACT_HASH=$(sha256sum "$SERVER" | awk '{print $1}')
jq -e \
  --arg id "$SERVER_ID" \
  --arg digest "$EXPECTED_ARTIFACT_HASH" \
  '.repaired == true and .server_id == $id and .artifact_sha256 == $digest' \
  "$REPAIR_OUTPUT" >/dev/null

"$CLI" connect "$SERVER_ID" --persistent --transport obfuscated
CONNECTED=1
wait_for_diagnostics
OBFUSCATED_READY=0
ATTEMPT=0
while [ "$ATTEMPT" -lt 15 ]; do
  if "$CLI" --json status | jq -e \
    --arg id "$SERVER_ID" \
    '.local.state == "connected"
      and .local.server_id == $id
      and .local.transport == "obfuscated_udp"
      and .local.kill_switch_enabled == true
      and .local.auto_reconnect_enabled == true
      and .server.transport == "obfuscated_udp"
      and .server.dns_healthy == true' >/dev/null 2>&1; then
    OBFUSCATED_READY=1
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  sleep 1
done
if [ "$OBFUSCATED_READY" -ne 1 ]; then
  echo "Obfuscated UDP did not become healthy." >&2
  exit 1
fi
systemctl is-active --quiet sirinvpn-transport.service
wg show sirinvpn0 endpoints | grep -q '127.0.0.1:51821'
ss -H -lun 'sport = :51821' | grep -q '127.0.0.1:51821'
"$CLI" --json server members "$SERVER_ID" >"$MEMBERS_BEFORE_ROTATION"
OWNER_DEVICE_ID=$(jq -er '.members[] | select(.role == "owner") | .devices[0].id' "$MEMBERS_BEFORE_ROTATION")
OWNER_DEVICE_NAME=$(jq -er --arg id "$OWNER_DEVICE_ID" '.members[].devices[] | select(.id == $id) | .name' "$MEMBERS_BEFORE_ROTATION")
OWNER_DEVICE_ADDRESS=$(jq -er --arg id "$OWNER_DEVICE_ID" '.members[].devices[] | select(.id == $id) | .client_tunnel_address' "$MEMBERS_BEFORE_ROTATION")
OWNER_OLD_FINGERPRINT=$(jq -er --arg id "$OWNER_DEVICE_ID" '.members[].devices[] | select(.id == $id) | .identity_fingerprint' "$MEMBERS_BEFORE_ROTATION")
if "$CLI" server rotate-keys "$SERVER_ID" >/dev/null 2>&1; then
  echo "Device key rotation did not require explicit confirmation." >&2
  exit 1
fi
"$CLI" --json server rotate-keys "$SERVER_ID" \
  --confirm-key-rotation >"$ROTATION_OUTPUT"
OWNER_NEW_FINGERPRINT=$(jq -er \
  --arg id "$SERVER_ID" \
  'select(.server_id == $id and .resumed == false) | .identity_fingerprint' \
  "$ROTATION_OUTPUT")
if [ "$OWNER_NEW_FINGERPRINT" = "$OWNER_OLD_FINGERPRINT" ]; then
  echo "Device key rotation retained the old management identity." >&2
  exit 1
fi
wait_for_diagnostics
"$CLI" --json server members "$SERVER_ID" >"$MEMBERS_AFTER_ROTATION"
jq -e \
  --arg id "$OWNER_DEVICE_ID" \
  --arg name "$OWNER_DEVICE_NAME" \
  --arg address "$OWNER_DEVICE_ADDRESS" \
  --arg fingerprint "$OWNER_NEW_FINGERPRINT" \
  '[.members[].devices[]] | any(.id == $id and .name == $name and .client_tunnel_address == $address and .identity_fingerprint == $fingerprint)' \
  "$MEMBERS_AFTER_ROTATION" >/dev/null
"$CLI" --json status | jq -e \
  --arg id "$SERVER_ID" \
  --arg device "$OWNER_DEVICE_ID" \
  --arg fingerprint "$OWNER_NEW_FINGERPRINT" \
  '.local.state == "connected"
    and .local.server_id == $id
    and .local.transport == "obfuscated_udp"
    and .local.kill_switch_enabled == true
    and .local.auto_reconnect_enabled == true
    and .server.caller_device_id == $device
    and .server.caller_identity_fingerprint == $fingerprint' >/dev/null
"$CLI" disconnect
CONNECTED=0

"$CLI" connect "$SERVER_ID" --persistent --transport tcp
CONNECTED=1
wait_for_diagnostics
TCP_READY=0
ATTEMPT=0
while [ "$ATTEMPT" -lt 15 ]; do
  if "$CLI" --json status | jq -e \
    --arg id "$SERVER_ID" \
    '.local.state == "connected"
      and .local.server_id == $id
      and .local.transport == "tcp_fallback"
      and .local.kill_switch_enabled == true
      and .local.auto_reconnect_enabled == true
      and .server.transport == "tcp_fallback"
      and .server.dns_healthy == true' >/dev/null 2>&1; then
    TCP_READY=1
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  sleep 1
done
if [ "$TCP_READY" -ne 1 ]; then
  echo "TCP fallback did not become healthy." >&2
  exit 1
fi
systemctl is-active --quiet sirinvpn-transport.service
wg show sirinvpn0 endpoints | grep -q '127.0.0.1:51822'
ss -H -lun 'sport = :51822' | grep -q '127.0.0.1:51822'
ss -H -nt 'dport = :443' | grep -q ESTAB
getent ahostsv4 example.com >/dev/null
"$CLI" disconnect
CONNECTED=0

"$CLI" connect "$SERVER_ID" --transport direct
CONNECTED=1
wait_for_diagnostics
"$CLI" --json status | jq -e \
  --arg id "$SERVER_ID" \
  '.local.state == "connected"
    and .local.server_id == $id
    and .local.transport == "direct_udp"
    and .local.kill_switch_enabled == false
    and .local.auto_reconnect_enabled == false' >/dev/null
"$CLI" disconnect
CONNECTED=0

echo "Debian 13 VPS provisioning, Automatic/Direct/Obfuscated UDP/TCP fallback, persistent protection, IPv6 capability, DNS, diagnostics, repair, key rotation, and rollback checks passed."
