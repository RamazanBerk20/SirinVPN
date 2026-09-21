#!/bin/sh
set -eu

: "${SIRINVPN_DEBIAN13_IMAGE:?Set an absolute path to a Debian 13 generic cloud qcow2 image}"

case "$SIRINVPN_DEBIAN13_IMAGE" in
  /*) ;;
  *)
    echo "SIRINVPN_DEBIAN13_IMAGE must be an absolute path." >&2
    exit 2
    ;;
esac

if [ ! -f "$SIRINVPN_DEBIAN13_IMAGE" ]; then
  echo "The Debian 13 cloud image does not exist." >&2
  exit 2
fi

for tool in qemu-system-x86_64 qemu-img ssh ssh-keygen ssh-agent ssh-add; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required for the VM gate." >&2
    exit 2
  fi
done

if ! command -v cloud-localds >/dev/null 2>&1 && ! command -v xorriso >/dev/null 2>&1; then
  echo "cloud-localds or xorriso is required to create the cloud-init seed." >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "jq or python3 is required to validate the CLI response." >&2
  exit 2
fi

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
VM_WORK_ROOT=${SIRINVPN_VM_WORK_ROOT:-$PROJECT_ROOT/.cache}
case "$VM_WORK_ROOT" in
  /*) ;;
  *)
    echo "SIRINVPN_VM_WORK_ROOT must be an absolute path." >&2
    exit 2
    ;;
esac
mkdir -p "$VM_WORK_ROOT"
WORK_DIRECTORY=$(mktemp -d "$VM_WORK_ROOT/sirinvpn-vm.XXXXXX")
SSH_PORT=${SIRINVPN_VM_SSH_PORT:-22222}
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  QEMU_ACCEL=kvm
  QEMU_CPU=host
else
  QEMU_ACCEL=tcg
  QEMU_CPU=max
fi
CLI=${SIRINVPN_TEST_CLI_BINARY:-$PROJECT_ROOT/target/release/sirinvpn}
SERVER=${SIRINVPN_TEST_SERVER_BINARY:-$PROJECT_ROOT/target/release/sirinvpn-server}
PROFILE_OUTPUT="$WORK_DIRECTORY/profile.json"
REPAIR_OUTPUT="$WORK_DIRECTORY/repair.json"
FAILED_OUTPUT="$WORK_DIRECTORY/conflicting-install.txt"
PROFILE_ID=
XDG_CONFIG_HOME="$WORK_DIRECTORY/xdg"
export XDG_CONFIG_HOME

cleanup() {
  if [ -n "${PROFILE_ID:-}" ] && [ -x "$CLI" ]; then
    "$CLI" server remove "$PROFILE_ID" >/dev/null 2>&1 || true
  fi
  if [ -f "$WORK_DIRECTORY/qemu.pid" ]; then
    VM_PID=$(cat "$WORK_DIRECTORY/qemu.pid")
    kill "$VM_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "${SSH_AGENT_PID:-}" ]; then
    ssh-agent -k >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK_DIRECTORY"
}
trap cleanup EXIT HUP INT TERM

ssh-keygen -q -t ed25519 -N '' -f "$WORK_DIRECTORY/id_ed25519"
PUBLIC_KEY=$(cat "$WORK_DIRECTORY/id_ed25519.pub")

cat >"$WORK_DIRECTORY/user-data" <<EOF
#cloud-config
users:
  - name: sirin
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $PUBLIC_KEY
ssh_pwauth: false
package_update: false
EOF

cat >"$WORK_DIRECTORY/meta-data" <<'EOF'
instance-id: sirinvpn-debian13-test
local-hostname: sirinvpn-test
EOF

qemu-img create -q -f qcow2 -F qcow2 \
  -b "$SIRINVPN_DEBIAN13_IMAGE" "$WORK_DIRECTORY/disk.qcow2"
if command -v cloud-localds >/dev/null 2>&1; then
  cloud-localds "$WORK_DIRECTORY/seed.img" \
    "$WORK_DIRECTORY/user-data" "$WORK_DIRECTORY/meta-data"
else
  xorriso -as mkisofs \
    -output "$WORK_DIRECTORY/seed.img" \
    -volid cidata \
    -joliet \
    -rock \
    -graft-points \
    "user-data=$WORK_DIRECTORY/user-data" \
    "meta-data=$WORK_DIRECTORY/meta-data" >/dev/null 2>&1
fi

qemu-system-x86_64 \
  -machine "accel=$QEMU_ACCEL" \
  -cpu "$QEMU_CPU" \
  -m 2048 \
  -smp 2 \
  -drive "file=$WORK_DIRECTORY/disk.qcow2,if=virtio,format=qcow2" \
  -drive "file=$WORK_DIRECTORY/seed.img,if=virtio,format=raw,readonly=on" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
  -device virtio-net-pci,netdev=net0 \
  -display none \
  -serial "file:$WORK_DIRECTORY/serial.log" \
  -daemonize \
  -pidfile "$WORK_DIRECTORY/qemu.pid"

READY=0
ATTEMPT=0
while [ "$ATTEMPT" -lt 90 ]; do
  if ssh \
    -i "$WORK_DIRECTORY/id_ed25519" \
    -p "$SSH_PORT" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    sirin@127.0.0.1 true >/dev/null 2>&1; then
    READY=1
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  sleep 2
done

if [ "$READY" -ne 1 ]; then
  echo "The Debian 13 VM did not become ready." >&2
  exit 1
fi

eval "$(ssh-agent -s)" >/dev/null
ssh-add "$WORK_DIRECTORY/id_ed25519" >/dev/null

vm_ssh() {
  ssh \
    -i "$WORK_DIRECTORY/id_ed25519" \
    -p "$SSH_PORT" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    sirin@127.0.0.1 "$@"
}

cd "$PROJECT_ROOT"
cargo build --release -p sirinvpn-cli -p sirinvpn-linux-helper
if [ -z "${SIRINVPN_TEST_SERVER_BINARY:-}" ]; then
  cargo build --release -p sirinvpn-server
fi
HOST_KEY=$("$CLI" host-key 127.0.0.1 --port "$SSH_PORT")

if ! "$CLI" --json server add \
  --name SirinVPN-VM \
  --host 127.0.0.1 \
  --username sirin \
  --ssh-port "$SSH_PORT" \
  --ssh-agent \
  --host-key "$HOST_KEY" \
  --server-binary "$SERVER" \
  --passwordless-sudo >"$PROFILE_OUTPUT"; then
  echo "Provisioning failed; collecting the disposable VM service state." >&2
  if kill -0 "$(cat "$WORK_DIRECTORY/qemu.pid")" >/dev/null 2>&1; then
    echo "QEMU process is still running." >&2
  else
    echo "QEMU process exited unexpectedly." >&2
  fi
  vm_ssh sudo systemctl --failed --no-pager --plain >&2 || true
  vm_ssh sudo journalctl -b --no-pager -p warning -n 120 >&2 || true
  tail -n 160 "$WORK_DIRECTORY/serial.log" >&2 || true
  exit 1
fi

if command -v jq >/dev/null 2>&1; then
  jq -e '.role == "owner" and .endpoint.host == "127.0.0.1" and (.ipv6_tunnel_enabled // false) == false and .obfuscated_udp.port == 443 and (.obfuscated_udp.server_public_key | length) == 44 and .tcp_fallback.port == 443 and (.tcp_fallback.server_public_key | length) == 44' "$PROFILE_OUTPUT" >/dev/null
  PROFILE_ID=$(jq -r '.id' "$PROFILE_OUTPUT")
else
  python3 -c 'import json, sys; profile = json.load(open(sys.argv[1], encoding="utf-8")); assert profile["role"] == "owner" and profile["endpoint"]["host"] == "127.0.0.1" and not profile.get("ipv6_tunnel_enabled", False) and profile["obfuscated_udp"]["port"] == 443 and len(profile["obfuscated_udp"]["server_public_key"]) == 44 and profile["tcp_fallback"]["port"] == 443 and len(profile["tcp_fallback"]["server_public_key"]) == 44' "$PROFILE_OUTPUT"
  PROFILE_ID=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["id"])' "$PROFILE_OUTPUT")
fi

vm_ssh sudo systemctl is-active --quiet sirinvpn-network sirinvpn-firewall unbound sirinvpn-server
BEFORE_HASH=$(vm_ssh sudo sha256sum /etc/sirinvpn/server.json | awk '{print $1}')
BEFORE_IDENTITY=$(vm_ssh sudo sha256sum \
  /etc/sirinvpn/server.json \
  /etc/sirinvpn/wireguard.key \
  /etc/sirinvpn/transport.key \
  /etc/sirinvpn/management.crt \
  /etc/sirinvpn/management.key \
  /etc/sirinvpn/authorization-required \
  /etc/sirinvpn/authorization/authorization.json)

vm_ssh sudo rm -f /etc/systemd/system/sirinvpn-firewall.service
vm_ssh sudo systemctl daemon-reload

"$CLI" --json server repair "$PROFILE_ID" \
  --username sirin \
  --ssh-port "$SSH_PORT" \
  --ssh-agent \
  --host-key "$HOST_KEY" \
  --server-binary "$SERVER" \
  --passwordless-sudo \
  --confirm-repair >"$REPAIR_OUTPUT"

EXPECTED_ARTIFACT_HASH=$(sha256sum "$SERVER" | awk '{print $1}')
if command -v jq >/dev/null 2>&1; then
  jq -e \
    --arg id "$PROFILE_ID" \
    --arg digest "$EXPECTED_ARTIFACT_HASH" \
    '.repaired == true and .server_id == $id and .artifact_sha256 == $digest' \
    "$REPAIR_OUTPUT" >/dev/null
else
  python3 -c 'import json, sys; value = json.load(open(sys.argv[1], encoding="utf-8")); assert value == {"repaired": True, "server_id": sys.argv[2], "artifact_sha256": sys.argv[3]}' "$REPAIR_OUTPUT" "$PROFILE_ID" "$EXPECTED_ARTIFACT_HASH"
fi

AFTER_IDENTITY=$(vm_ssh sudo sha256sum \
  /etc/sirinvpn/server.json \
  /etc/sirinvpn/wireguard.key \
  /etc/sirinvpn/transport.key \
  /etc/sirinvpn/management.crt \
  /etc/sirinvpn/management.key \
  /etc/sirinvpn/authorization-required \
  /etc/sirinvpn/authorization/authorization.json)
if [ "$BEFORE_IDENTITY" != "$AFTER_IDENTITY" ]; then
  echo "Repair changed persistent SirinVPN identity or authorization." >&2
  exit 1
fi
vm_ssh sudo test -f /etc/systemd/system/sirinvpn-firewall.service
vm_ssh sudo systemctl is-active --quiet sirinvpn-network sirinvpn-firewall unbound sirinvpn-server
vm_ssh sudo ss -H -lun 'sport = :443' | grep -q ':443'
vm_ssh sudo ss -H -lnt 'sport = :443' | grep -q ':443'
vm_ssh sudo nft list chain inet sirinvpn_filter input | grep -q 'udp dport 443 accept'
vm_ssh sudo nft list chain inet sirinvpn_filter input | grep -q 'tcp dport 443 accept'
INSTALLED_ARTIFACT_HASH=$(vm_ssh sudo sha256sum /usr/local/lib/sirinvpn/sirinvpn-server | awk '{print $1}')
if [ "$EXPECTED_ARTIFACT_HASH" != "$INSTALLED_ARTIFACT_HASH" ]; then
  echo "Repair did not install the verified candidate artifact." >&2
  exit 1
fi

if "$CLI" server add \
  --name SirinVPN-VM-conflicting-owner \
  --host 127.0.0.1 \
  --username sirin \
  --ssh-port "$SSH_PORT" \
  --ssh-agent \
  --host-key "$HOST_KEY" \
  --server-binary "$SERVER" \
  --passwordless-sudo >"$FAILED_OUTPUT" 2>&1; then
  echo "A conflicting VM reinstall unexpectedly succeeded." >&2
  exit 1
fi

AFTER_HASH=$(vm_ssh sudo sha256sum /etc/sirinvpn/server.json | awk '{print $1}')
if [ "$BEFORE_HASH" != "$AFTER_HASH" ]; then
  echo "Rollback did not restore the prior server configuration." >&2
  exit 1
fi

vm_ssh sudo systemctl is-active --quiet sirinvpn-network sirinvpn-firewall unbound sirinvpn-server
vm_ssh sudo nft list table inet sirinvpn_filter >/dev/null
vm_ssh sudo nft list table ip sirinvpn_nat >/dev/null
if vm_ssh sudo nft list table ip6 sirinvpn_nat6 >/dev/null 2>&1; then
  echo "IPv6 NAT was enabled in the IPv4-only VM fixture." >&2
  exit 1
fi

echo "Disposable Debian 13 VM installation, authenticated UDP/TCP listeners, IPv4-only fallback, identity-preserving repair, and rollback checks passed."
