#!/bin/sh
set -eu

: "${SIRINVPN_P1B2_SERVER_ID:?Set the existing disposable SirinVPN server ID}"
: "${SIRINVPN_P1B2_CONFIRM:?Set SIRINVPN_P1B2_CONFIRM=test-disposable-vps}"

if [ "$SIRINVPN_P1B2_CONFIRM" != "test-disposable-vps" ]; then
  echo "Refusing to change authorization on the VPS." >&2
  exit 2
fi

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CLI=${SIRINVPN_P1B2_CLI:-"$PROJECT_ROOT/target/release/sirinvpn"}
SERVER_ID=$SIRINVPN_P1B2_SERVER_ID
TEST_ROOT=$(mktemp -d)
chmod 0700 "$TEST_ROOT"
umask 077

ADMIN_ROOT="$TEST_ROOT/admin"
MEMBER_ROOT="$TEST_ROOT/member"
MEMBER_TWO_ROOT="$TEST_ROOT/member-two"
OWNER_TWO_ROOT="$TEST_ROOT/owner-two"
mkdir -m 0700 "$ADMIN_ROOT" "$MEMBER_ROOT" "$MEMBER_TWO_ROOT" "$OWNER_TWO_ROOT"

TAG="P1B2-Live-$$"
ADMIN_NAME="$TAG-Admin"
MEMBER_NAME="$TAG-Member"
ADMIN_DEVICE="$TAG-Admin-Laptop"
MEMBER_DEVICE="$TAG-Member-Laptop"
MEMBER_DEVICE_RENAMED="$TAG-Member-Renamed"
MEMBER_TWO_DEVICE="$TAG-Member-Tablet"
OWNER_TWO_DEVICE="$TAG-Owner-Second"
PORT_FORWARD_BASE=$((40000 + ($$ % 20000)))
MEMBER_PUBLIC_PORT=$PORT_FORWARD_BASE
LIFECYCLE_PUBLIC_PORT=$((PORT_FORWARD_BASE + 1))
OWNER_PUBLIC_PORT=$((PORT_FORWARD_BASE + 2))
CLEANED=0
OWNER_DEVICE_ID=""
MEMBER_DEVICE_ID=""

profile_cli() {
  profile_root=$1
  shift
  XDG_CONFIG_HOME="$profile_root" "$CLI" "$@"
}

disconnect_quietly() {
  "$CLI" disconnect >/dev/null 2>&1 || true
}

connect_owner() {
  disconnect_quietly
  "$CLI" connect "$SERVER_ID" >/dev/null
}

join_from_file() {
  profile_root=$1
  invitation_file=$2
  output_file=$3
  python3 - "$invitation_file" <<'PY' |
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["code"])
PY
    profile_cli "$profile_root" --json server join --code-stdin >"$output_file"
}

json_field() {
  document=$1
  field_path=$2
  python3 - "$document" "$field_path" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
for field in sys.argv[2].split("."):
    value = value[field]
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("null")
else:
    print(value)
PY
}

member_value() {
  snapshot=$1
  member_name=$2
  field=$3
  python3 - "$snapshot" "$member_name" "$field" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    snapshot = json.load(source)
member = next(item for item in snapshot["members"] if item["name"] == sys.argv[2])
value = member[sys.argv[3]]
print(value)
PY
}

device_value() {
  snapshot=$1
  device_name=$2
  field=$3
  python3 - "$snapshot" "$device_name" "$field" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    snapshot = json.load(source)
device = next(
    device
    for member in snapshot["members"]
    for device in member["devices"]
    if device["name"] == sys.argv[2]
)
field = sys.argv[3]
value = device.get(field, False) if field == "peer_communication_enabled" else device[field]
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

assert_port_forward() {
  snapshot=$1
  protocol=$2
  public_port=$3
  device_id=$4
  device_port=$5
  expected=$6
  python3 - "$snapshot" "$protocol" "$public_port" "$device_id" "$device_port" "$expected" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    snapshot = json.load(source)
found = any(
    item["protocol"] == sys.argv[2]
    and item["public_port"] == int(sys.argv[3])
    and item["device_id"] == sys.argv[4]
    and item["device_port"] == int(sys.argv[5])
    for item in snapshot.get("port_forwards", [])
)
assert found == (sys.argv[6] == "true")
PY
}

assert_live_access() {
  profile_root=$1
  expected_role=$2
  expected_administrator=$3
  output_file="$TEST_ROOT/status.json"
  if [ "$profile_root" = default ]; then
    "$CLI" --json status >"$output_file"
  else
    profile_cli "$profile_root" --json status >"$output_file"
  fi
  python3 - "$output_file" "$expected_role" "$expected_administrator" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    status = json.load(source)
server = status["server"]
assert status["local"]["state"] == "connected"
assert server["caller_role"] == sys.argv[2]
assert bool(server.get("caller_administrator", False)) == (sys.argv[3] == "true")
PY
}

cleanup_server_state() {
  disconnect_quietly
  if [ -n "$OWNER_DEVICE_ID" ] && [ -n "$MEMBER_DEVICE_ID" ]; then
    if profile_cli "$MEMBER_ROOT" connect "$SERVER_ID" >/dev/null 2>&1; then
      profile_cli "$MEMBER_ROOT" server transfer-ownership "$SERVER_ID" "$OWNER_DEVICE_ID" \
        --confirm-transfer >/dev/null 2>&1 || true
    fi
    disconnect_quietly
  fi
  if ! "$CLI" connect "$SERVER_ID" >/dev/null 2>&1; then
    return 1
  fi
  for public_port in "$MEMBER_PUBLIC_PORT" "$LIFECYCLE_PUBLIC_PORT" "$OWNER_PUBLIC_PORT"; do
    "$CLI" server remove-port-forward "$SERVER_ID" --protocol tcp \
      --public-port "$public_port" >/dev/null 2>&1 || true
    "$CLI" server remove-port-forward "$SERVER_ID" --protocol udp \
      --public-port "$public_port" >/dev/null 2>&1 || true
  done
  snapshot="$TEST_ROOT/cleanup-members.json"
  if ! "$CLI" --json server members "$SERVER_ID" >"$snapshot" 2>/dev/null; then
    return 1
  fi

  python3 - "$snapshot" "$TAG" <<'PY' >"$TEST_ROOT/cleanup-invitations"
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    snapshot = json.load(source)
for invitation in snapshot["active_invitations"]:
    if invitation["member_name"].startswith(sys.argv[2]) or invitation["device_name"].startswith(sys.argv[2]):
        print(invitation["id"])
PY
  while IFS= read -r invitation_id; do
    [ -z "$invitation_id" ] || "$CLI" server cancel-invitation "$SERVER_ID" "$invitation_id" >/dev/null 2>&1 || true
  done <"$TEST_ROOT/cleanup-invitations"

  "$CLI" --json server members "$SERVER_ID" >"$snapshot"
  python3 - "$snapshot" "$TAG" <<'PY' >"$TEST_ROOT/cleanup-devices"
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    snapshot = json.load(source)
for member in snapshot["members"]:
    for device in member["devices"]:
        if device["name"].startswith(sys.argv[2]):
            print(device["id"])
PY
  while IFS= read -r device_id; do
    [ -z "$device_id" ] || "$CLI" server revoke-device "$SERVER_ID" "$device_id" >/dev/null 2>&1 || true
  done <"$TEST_ROOT/cleanup-devices"
}

cleanup_local_state() {
  disconnect_quietly
  for profile_root in "$ADMIN_ROOT" "$MEMBER_ROOT" "$MEMBER_TWO_ROOT" "$OWNER_TWO_ROOT"; do
    profile_cli "$profile_root" server remove "$SERVER_ID" >/dev/null 2>&1 || true
  done
}

cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ "$CLEANED" -ne 1 ]; then
    cleanup_server_state || true
    cleanup_local_state || true
  fi
  disconnect_quietly
  case "$TEST_ROOT" in
    /tmp/*) rm -rf -- "$TEST_ROOT" ;;
  esac
  exit "$result"
}
trap cleanup EXIT HUP INT TERM

connect_owner
"$CLI" --json server members "$SERVER_ID" >"$TEST_ROOT/initial-members.json"
OWNER_MEMBER_ID=$(member_value "$TEST_ROOT/initial-members.json" Owner id)
OWNER_DEVICE_ID=$(device_value "$TEST_ROOT/initial-members.json" "Owner device" id)

"$CLI" --json server invite "$SERVER_ID" \
  --member-name "$ADMIN_NAME" \
  --admin \
  --device-name "$ADMIN_DEVICE" \
  --expires-in 600 >"$TEST_ROOT/admin-invitation.json"
disconnect_quietly
join_from_file "$ADMIN_ROOT" "$TEST_ROOT/admin-invitation.json" "$TEST_ROOT/admin-profile.json"
ADMIN_MEMBER_ID=$(json_field "$TEST_ROOT/admin-profile.json" member_id)
ADMIN_DEVICE_ID=$(json_field "$TEST_ROOT/admin-profile.json" device_id)
assert_live_access "$ADMIN_ROOT" member true
profile_cli "$ADMIN_ROOT" --json server members "$SERVER_ID" >"$TEST_ROOT/admin-members.json"

if profile_cli "$ADMIN_ROOT" server invite "$SERVER_ID" \
  --member-name "$TAG-Forbidden-Admin" --admin --device-name "$TAG-Forbidden" \
  --expires-in 600 >/dev/null 2>&1; then
  echo "An Admin created another Admin." >&2
  exit 1
fi
if profile_cli "$ADMIN_ROOT" server invite "$SERVER_ID" \
  --member-id "$OWNER_MEMBER_ID" --device-name "$TAG-Forbidden-Owner" \
  --expires-in 600 >/dev/null 2>&1; then
  echo "An Admin created an Owner device invitation." >&2
  exit 1
fi
if profile_cli "$ADMIN_ROOT" server rename-device "$SERVER_ID" "$ADMIN_DEVICE_ID" \
  --name "$TAG-Forbidden-Rename" >/dev/null 2>&1; then
  echo "An Admin renamed an Admin device." >&2
  exit 1
fi

profile_cli "$ADMIN_ROOT" --json server invite "$SERVER_ID" \
  --member-name "$MEMBER_NAME" \
  --device-name "$MEMBER_DEVICE" \
  --expires-in 600 >"$TEST_ROOT/member-invitation.json"
disconnect_quietly
join_from_file "$MEMBER_ROOT" "$TEST_ROOT/member-invitation.json" "$TEST_ROOT/member-profile.json"
MEMBER_ID=$(json_field "$TEST_ROOT/member-profile.json" member_id)
MEMBER_DEVICE_ID=$(json_field "$TEST_ROOT/member-profile.json" device_id)
assert_live_access "$MEMBER_ROOT" member false
if profile_cli "$MEMBER_ROOT" server members "$SERVER_ID" >/dev/null 2>&1; then
  echo "An ordinary Member read management state." >&2
  exit 1
fi
if profile_cli "$MEMBER_ROOT" server set-peer-communication "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --mode peers >/dev/null 2>&1; then
  echo "An ordinary Member changed peer communication." >&2
  exit 1
fi
if profile_cli "$MEMBER_ROOT" server add-port-forward "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --protocol tcp --public-port "$MEMBER_PUBLIC_PORT" --device-port 8080 \
  --confirm-public-exposure >/dev/null 2>&1; then
  echo "An ordinary Member opened a public port." >&2
  exit 1
fi

disconnect_quietly
profile_cli "$ADMIN_ROOT" connect "$SERVER_ID" >/dev/null
profile_cli "$ADMIN_ROOT" --json server members "$SERVER_ID" >"$TEST_ROOT/peer-defaults.json"
[ "$(device_value "$TEST_ROOT/peer-defaults.json" "$ADMIN_DEVICE" peer_communication_enabled)" = "false" ]
[ "$(device_value "$TEST_ROOT/peer-defaults.json" "$MEMBER_DEVICE" peer_communication_enabled)" = "false" ]
if profile_cli "$ADMIN_ROOT" server set-peer-communication "$SERVER_ID" "$ADMIN_DEVICE_ID" \
  --mode peers >/dev/null 2>&1; then
  echo "An Admin changed peer communication for an Admin device." >&2
  exit 1
fi
if profile_cli "$ADMIN_ROOT" server set-peer-communication "$SERVER_ID" "$OWNER_DEVICE_ID" \
  --mode peers >/dev/null 2>&1; then
  echo "An Admin changed peer communication for an Owner device." >&2
  exit 1
fi
if profile_cli "$ADMIN_ROOT" server add-port-forward "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --protocol tcp --public-port "$MEMBER_PUBLIC_PORT" --device-port 8080 >/dev/null 2>&1; then
  echo "A public port was opened without explicit confirmation." >&2
  exit 1
fi
if profile_cli "$ADMIN_ROOT" server add-port-forward "$SERVER_ID" "$ADMIN_DEVICE_ID" \
  --protocol tcp --public-port "$MEMBER_PUBLIC_PORT" --device-port 8080 \
  --confirm-public-exposure >/dev/null 2>&1; then
  echo "An Admin forwarded a public port to an Admin device." >&2
  exit 1
fi
if profile_cli "$ADMIN_ROOT" server add-port-forward "$SERVER_ID" "$OWNER_DEVICE_ID" \
  --protocol tcp --public-port "$MEMBER_PUBLIC_PORT" --device-port 8080 \
  --confirm-public-exposure >/dev/null 2>&1; then
  echo "An Admin forwarded a public port to an Owner device." >&2
  exit 1
fi
if profile_cli "$ADMIN_ROOT" server add-port-forward "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --protocol tcp --public-port 8443 --device-port 8080 \
  --confirm-public-exposure >/dev/null 2>&1; then
  echo "The private management port was forwarded." >&2
  exit 1
fi
profile_cli "$ADMIN_ROOT" --json server add-port-forward "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --protocol tcp --public-port "$MEMBER_PUBLIC_PORT" --device-port 8080 \
  --confirm-public-exposure >"$TEST_ROOT/member-forward-created.json"
assert_port_forward "$TEST_ROOT/member-forward-created.json" tcp "$MEMBER_PUBLIC_PORT" \
  "$MEMBER_DEVICE_ID" 8080 true
if profile_cli "$ADMIN_ROOT" server add-port-forward "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --protocol tcp --public-port "$MEMBER_PUBLIC_PORT" --device-port 8081 \
  --confirm-public-exposure >/dev/null 2>&1; then
  echo "A duplicate public protocol and port was forwarded." >&2
  exit 1
fi
profile_cli "$ADMIN_ROOT" --json server remove-port-forward "$SERVER_ID" \
  --protocol tcp --public-port "$MEMBER_PUBLIC_PORT" >"$TEST_ROOT/member-forward-removed.json"
assert_port_forward "$TEST_ROOT/member-forward-removed.json" tcp "$MEMBER_PUBLIC_PORT" \
  "$MEMBER_DEVICE_ID" 8080 false
profile_cli "$ADMIN_ROOT" --json server set-peer-communication "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --mode peers >"$TEST_ROOT/member-peer-enabled.json"
[ "$(device_value "$TEST_ROOT/member-peer-enabled.json" "$MEMBER_DEVICE" peer_communication_enabled)" = "true" ]
profile_cli "$ADMIN_ROOT" --json server set-peer-communication "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --mode internet-only >"$TEST_ROOT/member-peer-isolated.json"
[ "$(device_value "$TEST_ROOT/member-peer-isolated.json" "$MEMBER_DEVICE" peer_communication_enabled)" = "false" ]
profile_cli "$ADMIN_ROOT" server rename-device "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --name "$MEMBER_DEVICE_RENAMED" >/dev/null

profile_cli "$ADMIN_ROOT" --json server invite "$SERVER_ID" \
  --member-name "$TAG-Unused" --device-name "$TAG-Unused-Device" \
  --expires-in 600 >"$TEST_ROOT/unused-invitation.json"
UNUSED_INVITATION_ID=$(json_field "$TEST_ROOT/unused-invitation.json" invitation_id)
profile_cli "$ADMIN_ROOT" server cancel-invitation "$SERVER_ID" "$UNUSED_INVITATION_ID" >/dev/null

if profile_cli "$ADMIN_ROOT" server invite "$SERVER_ID" \
  --member-id "$ADMIN_MEMBER_ID" --device-name "$TAG-Forbidden-Admin-Device" \
  --expires-in 600 >/dev/null 2>&1; then
  echo "An Admin created a device invitation for an Admin." >&2
  exit 1
fi

profile_cli "$ADMIN_ROOT" --json server invite "$SERVER_ID" \
  --member-id "$MEMBER_ID" --device-name "$MEMBER_TWO_DEVICE" \
  --expires-in 600 >"$TEST_ROOT/member-two-invitation.json"
disconnect_quietly
join_from_file "$MEMBER_TWO_ROOT" "$TEST_ROOT/member-two-invitation.json" "$TEST_ROOT/member-two-profile.json"
[ "$(json_field "$TEST_ROOT/member-two-profile.json" member_id)" = "$MEMBER_ID" ]
[ "$(json_field "$TEST_ROOT/member-two-profile.json" role)" = "member" ]
MEMBER_TWO_DEVICE_ID=$(json_field "$TEST_ROOT/member-two-profile.json" device_id)

disconnect_quietly
profile_cli "$ADMIN_ROOT" connect "$SERVER_ID" >/dev/null
profile_cli "$ADMIN_ROOT" server add-port-forward "$SERVER_ID" "$MEMBER_TWO_DEVICE_ID" \
  --protocol udp --public-port "$LIFECYCLE_PUBLIC_PORT" --device-port 5353 \
  --confirm-public-exposure >/dev/null
profile_cli "$ADMIN_ROOT" --json server revoke-device "$SERVER_ID" "$MEMBER_TWO_DEVICE_ID" \
  >"$TEST_ROOT/member-two-revoked.json"
assert_port_forward "$TEST_ROOT/member-two-revoked.json" udp "$LIFECYCLE_PUBLIC_PORT" \
  "$MEMBER_TWO_DEVICE_ID" 5353 false

connect_owner
"$CLI" --json server add-port-forward "$SERVER_ID" "$OWNER_DEVICE_ID" \
  --protocol tcp --public-port "$OWNER_PUBLIC_PORT" --device-port 9090 \
  --confirm-public-exposure >"$TEST_ROOT/owner-forward-created.json"
assert_port_forward "$TEST_ROOT/owner-forward-created.json" tcp "$OWNER_PUBLIC_PORT" \
  "$OWNER_DEVICE_ID" 9090 true
"$CLI" --json server remove-port-forward "$SERVER_ID" --protocol tcp \
  --public-port "$OWNER_PUBLIC_PORT" >"$TEST_ROOT/owner-forward-removed.json"
assert_port_forward "$TEST_ROOT/owner-forward-removed.json" tcp "$OWNER_PUBLIC_PORT" \
  "$OWNER_DEVICE_ID" 9090 false
"$CLI" --json server set-peer-communication "$SERVER_ID" "$OWNER_DEVICE_ID" \
  --mode peers >"$TEST_ROOT/owner-peer-enabled.json"
[ "$(device_value "$TEST_ROOT/owner-peer-enabled.json" "Owner device" peer_communication_enabled)" = "true" ]
"$CLI" --json server set-peer-communication "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --mode peers >"$TEST_ROOT/both-peers-enabled.json"
[ "$(device_value "$TEST_ROOT/both-peers-enabled.json" "$MEMBER_DEVICE_RENAMED" peer_communication_enabled)" = "true" ]
"$CLI" server set-peer-communication "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --mode internet-only >/dev/null
"$CLI" server set-peer-communication "$SERVER_ID" "$OWNER_DEVICE_ID" \
  --mode internet-only >/dev/null
if "$CLI" server set-member-access "$SERVER_ID" "$MEMBER_ID" --level admin >/dev/null 2>&1; then
  echo "Member access changed while an enrollment retry receipt was active." >&2
  exit 1
fi
if "$CLI" server transfer-ownership "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --confirm-transfer >/dev/null 2>&1; then
  echo "Ownership changed while an enrollment retry receipt was active." >&2
  exit 1
fi
access_attempt=0
while ! "$CLI" server set-member-access "$SERVER_ID" "$MEMBER_ID" --level admin >/dev/null 2>&1; do
  access_attempt=$((access_attempt + 1))
  if [ "$access_attempt" -ge 8 ]; then
    echo "The enrollment retry receipt was not pruned in time." >&2
    exit 1
  fi
  sleep 10
done
disconnect_quietly
profile_cli "$MEMBER_ROOT" connect "$SERVER_ID" >/dev/null
assert_live_access "$MEMBER_ROOT" member true
profile_cli "$MEMBER_ROOT" --json server members "$SERVER_ID" >"$TEST_ROOT/promoted-members.json"
profile_cli "$MEMBER_ROOT" --json server invite "$SERVER_ID" \
  --member-name "$TAG-Promoted-Invite" --device-name "$TAG-Promoted-Device" \
  --expires-in 600 >"$TEST_ROOT/promoted-invitation.json"
PROMOTED_INVITATION_ID=$(json_field "$TEST_ROOT/promoted-invitation.json" invitation_id)
profile_cli "$MEMBER_ROOT" server cancel-invitation "$SERVER_ID" "$PROMOTED_INVITATION_ID" >/dev/null

connect_owner
"$CLI" server set-member-access "$SERVER_ID" "$MEMBER_ID" --level member >/dev/null
disconnect_quietly
profile_cli "$MEMBER_ROOT" connect "$SERVER_ID" >/dev/null
assert_live_access "$MEMBER_ROOT" member false
if profile_cli "$MEMBER_ROOT" server members "$SERVER_ID" >/dev/null 2>&1; then
  echo "A demoted Admin retained management access." >&2
  exit 1
fi
profile_cli "$MEMBER_ROOT" --json status >"$TEST_ROOT/member-before-rotation.json"
MEMBER_OLD_FINGERPRINT=$(json_field "$TEST_ROOT/member-before-rotation.json" server.caller_identity_fingerprint)
if profile_cli "$MEMBER_ROOT" server rotate-keys "$SERVER_ID" >/dev/null 2>&1; then
  echo "Member key rotation did not require explicit confirmation." >&2
  exit 1
fi
profile_cli "$MEMBER_ROOT" --json server rotate-keys "$SERVER_ID" \
  --confirm-key-rotation >"$TEST_ROOT/member-rotation.json"
[ "$(json_field "$TEST_ROOT/member-rotation.json" server_id)" = "$SERVER_ID" ]
[ "$(json_field "$TEST_ROOT/member-rotation.json" device_id)" = "$MEMBER_DEVICE_ID" ]
MEMBER_NEW_FINGERPRINT=$(json_field "$TEST_ROOT/member-rotation.json" identity_fingerprint)
[ "$MEMBER_NEW_FINGERPRINT" != "$MEMBER_OLD_FINGERPRINT" ]
assert_live_access "$MEMBER_ROOT" member false
profile_cli "$MEMBER_ROOT" --json status >"$TEST_ROOT/member-after-rotation.json"
[ "$(json_field "$TEST_ROOT/member-after-rotation.json" server.caller_identity_fingerprint)" = "$MEMBER_NEW_FINGERPRINT" ]

connect_owner
if "$CLI" server transfer-ownership "$SERVER_ID" "$MEMBER_DEVICE_ID" >/dev/null 2>&1; then
  echo "Ownership transfer did not require explicit confirmation." >&2
  exit 1
fi
"$CLI" server transfer-ownership "$SERVER_ID" "$MEMBER_DEVICE_ID" \
  --confirm-transfer >/dev/null
assert_live_access default member true
if "$CLI" server transfer-ownership "$SERVER_ID" "$OWNER_DEVICE_ID" \
  --confirm-transfer >/dev/null 2>&1; then
  echo "The previous Owner transferred ownership after becoming an Admin." >&2
  exit 1
fi
disconnect_quietly
profile_cli "$MEMBER_ROOT" connect "$SERVER_ID" >/dev/null
assert_live_access "$MEMBER_ROOT" owner false
profile_cli "$MEMBER_ROOT" server transfer-ownership "$SERVER_ID" "$OWNER_DEVICE_ID" \
  --confirm-transfer >/dev/null
assert_live_access "$MEMBER_ROOT" member true
connect_owner
assert_live_access default owner false
"$CLI" server set-member-access "$SERVER_ID" "$MEMBER_ID" --level member >/dev/null

connect_owner
"$CLI" --json server invite "$SERVER_ID" \
  --member-id "$OWNER_MEMBER_ID" --device-name "$OWNER_TWO_DEVICE" \
  --expires-in 600 >"$TEST_ROOT/owner-two-invitation.json"
disconnect_quietly
join_from_file "$OWNER_TWO_ROOT" "$TEST_ROOT/owner-two-invitation.json" "$TEST_ROOT/owner-two-profile.json"
[ "$(json_field "$TEST_ROOT/owner-two-profile.json" member_id)" = "$OWNER_MEMBER_ID" ]
[ "$(json_field "$TEST_ROOT/owner-two-profile.json" role)" = "owner" ]
OWNER_TWO_DEVICE_ID=$(json_field "$TEST_ROOT/owner-two-profile.json" device_id)
assert_live_access "$OWNER_TWO_ROOT" owner false

connect_owner
"$CLI" server revoke-device "$SERVER_ID" "$OWNER_TWO_DEVICE_ID" >/dev/null
if "$CLI" server revoke-device "$SERVER_ID" "$OWNER_DEVICE_ID" >/dev/null 2>&1; then
  echo "The final Owner device was revoked." >&2
  exit 1
fi
"$CLI" server revoke-device "$SERVER_ID" "$MEMBER_DEVICE_ID" >/dev/null
"$CLI" server revoke-device "$SERVER_ID" "$ADMIN_DEVICE_ID" >/dev/null
"$CLI" --json server members "$SERVER_ID" >"$TEST_ROOT/final-members.json"
python3 - "$TEST_ROOT/final-members.json" "$OWNER_DEVICE_ID" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    snapshot = json.load(source)
assert snapshot["active_invitations"] == []
assert len(snapshot["members"]) == 1
owner = snapshot["members"][0]
assert owner["role"] == "owner"
assert len(owner["devices"]) == 1
assert owner["devices"][0]["id"] == sys.argv[2]
PY

cleanup_local_state
CLEANED=1
connect_owner
"$CLI" --json diagnose "$SERVER_ID" >"$TEST_ROOT/final-diagnostics.json"
python3 - "$TEST_ROOT/final-diagnostics.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    report = json.load(source)
assert all(check["level"] == "pass" for check in report["checks"])
PY
disconnect_quietly

echo "P1 live Admin, multi-device, port-forward, ownership transfer, revocation, and cleanup checks passed."
