#!/bin/sh
set -eu

: "${SIRINVPN_DEBIAN13_IMAGE:?Set an absolute path to a Debian 13 generic cloud qcow2 image}"
: "${SIRINVPN_RELEASE_VM_PACKAGE_A:?Set an absolute path to the full release-A Debian package}"
: "${SIRINVPN_RELEASE_VM_PACKAGE_B:?Set an absolute path to the full release-B Debian package}"
: "${SIRINVPN_RELEASE_VM_VERSION_A:?Set the canonical SemVer for release A}"
: "${SIRINVPN_RELEASE_VM_VERSION_B:?Set the newer canonical SemVer for release B}"

for path in \
  "$SIRINVPN_DEBIAN13_IMAGE" \
  "$SIRINVPN_RELEASE_VM_PACKAGE_A" \
  "$SIRINVPN_RELEASE_VM_PACKAGE_B"; do
  case "$path" in
    /*) ;;
    *)
      echo "Every VM image and package path must be absolute." >&2
      exit 2
      ;;
  esac
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    echo "$path must be a regular, non-symlink file." >&2
    exit 2
  fi
done

PROJECT_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/../.." && pwd)
SIGNING_TOOL=${SIRINVPN_RELEASE_SIGNING_BINARY:-$PROJECT_ROOT/target/release/sirinvpn-release}
COMPATIBILITY=$PROJECT_ROOT/release/state-compatibility.json
TARGET=x86_64-unknown-linux-gnu
SSH_PORT=${SIRINVPN_RELEASE_VM_SSH_PORT:-22223}
VM_WORK_ROOT=${SIRINVPN_VM_WORK_ROOT:-$PROJECT_ROOT/.cache}

case "$SSH_PORT" in
  '' | *[!0-9]*)
    echo "SIRINVPN_RELEASE_VM_SSH_PORT must be a decimal TCP port." >&2
    exit 2
    ;;
esac
if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
  echo "SIRINVPN_RELEASE_VM_SSH_PORT must be between 1 and 65535." >&2
  exit 2
fi

case "$VM_WORK_ROOT" in
  /*) ;;
  *)
    echo "SIRINVPN_VM_WORK_ROOT must be an absolute path." >&2
    exit 2
    ;;
esac

if [ -n "${SIRINVPN_RELEASE_FAULT_BINARY:-}" ]; then
  FAULT_TOOL=$SIRINVPN_RELEASE_FAULT_BINARY
else
  FAULT_TOOL=$PROJECT_ROOT/target/release-fault/release/sirinvpn-release
  "$PROJECT_ROOT/scripts/build-release-fault-tool-container.sh" >/dev/null
fi

for path in "$SIGNING_TOOL" "$FAULT_TOOL"; do
  case "$path" in
    /*) ;;
    *)
      echo "$path must be an absolute release-tool path." >&2
      exit 2
      ;;
  esac
  if [ ! -f "$path" ] || [ -L "$path" ] || [ ! -x "$path" ]; then
    echo "$path must be an executable, non-symlink release tool." >&2
    exit 2
  fi
done

for tool in qemu-system-x86_64 qemu-img ssh scp ssh-keygen xorriso jq sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required for the Debian release-update VM gate." >&2
    exit 2
  fi
done

mkdir -p "$VM_WORK_ROOT"
WORK_DIRECTORY=$(mktemp -d "$VM_WORK_ROOT/sirinvpn-release-vm.XXXXXX")
case "$WORK_DIRECTORY" in
  "$VM_WORK_ROOT"/sirinvpn-release-vm.*) ;;
  *)
    echo "The VM work directory is outside the configured work root." >&2
    exit 2
    ;;
esac

VM_RUNNING=0

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$status" -ne 0 ] && [ -f "$WORK_DIRECTORY/serial.log" ]; then
    echo "Last disposable-VM serial output:" >&2
    tail -n 160 "$WORK_DIRECTORY/serial.log" >&2 || true
  fi
  if [ "$VM_RUNNING" -eq 1 ] && [ -f "$WORK_DIRECTORY/qemu.pid" ]; then
    vm_pid=$(cat "$WORK_DIRECTORY/qemu.pid")
    kill "$vm_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK_DIRECTORY"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  QEMU_ACCEL=kvm
  QEMU_CPU=host
else
  QEMU_ACCEL=tcg
  QEMU_CPU=max
fi

SSH_KEY=$WORK_DIRECTORY/id_ed25519
ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY"
PUBLIC_SSH_KEY=$(cat "$SSH_KEY.pub")

cat >"$WORK_DIRECTORY/user-data" <<EOF
#cloud-config
users:
  - name: sirin
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $PUBLIC_SSH_KEY
ssh_pwauth: false
package_update: false
EOF

cat >"$WORK_DIRECTORY/meta-data" <<'EOF'
instance-id: sirinvpn-debian13-release-update
local-hostname: sirinvpn-release-test
EOF

xorriso -as mkisofs \
  -output "$WORK_DIRECTORY/seed.img" \
  -volid cidata \
  -joliet \
  -rock \
  -graft-points \
  "user-data=$WORK_DIRECTORY/user-data" \
  "meta-data=$WORK_DIRECTORY/meta-data" >/dev/null 2>&1

qemu-img create -q -f qcow2 -F qcow2 \
  -b "$SIRINVPN_DEBIAN13_IMAGE" "$WORK_DIRECTORY/disk.qcow2"
qemu-img resize -q "$WORK_DIRECTORY/disk.qcow2" 12G

vm_ssh() {
  ssh \
    -i "$SSH_KEY" \
    -p "$SSH_PORT" \
    -o BatchMode=yes \
    -o ConnectTimeout=4 \
    -o LogLevel=ERROR \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    sirin@127.0.0.1 "$@"
}

vm_scp() {
  scp \
    -i "$SSH_KEY" \
    -P "$SSH_PORT" \
    -o BatchMode=yes \
    -o ConnectTimeout=4 \
    -o LogLevel=ERROR \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$@"
}

wait_for_vm_exit() {
  vm_pid=$1
  attempts=0
  while kill -0 "$vm_pid" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 30 ]; then
      echo "QEMU did not stop within 30 seconds." >&2
      return 1
    fi
    sleep 1
  done
}

start_vm() {
  restrict_network=$1
  rm -f "$WORK_DIRECTORY/qemu.pid"
  qemu-system-x86_64 \
    -machine "accel=$QEMU_ACCEL" \
    -cpu "$QEMU_CPU" \
    -m 3072 \
    -smp 2 \
    -drive "file=$WORK_DIRECTORY/disk.qcow2,if=virtio,format=qcow2,cache=writeback" \
    -drive "file=$WORK_DIRECTORY/seed.img,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=net0,restrict=$restrict_network,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -serial "file:$WORK_DIRECTORY/serial.log" \
    -daemonize \
    -pidfile "$WORK_DIRECTORY/qemu.pid"
  VM_RUNNING=1

  ready=0
  attempts=0
  while [ "$attempts" -lt 120 ]; do
    if vm_ssh true >/dev/null 2>&1; then
      ready=1
      break
    fi
    attempts=$((attempts + 1))
    sleep 2
  done
  if [ "$ready" -ne 1 ]; then
    echo "The Debian 13 release-update VM did not become ready." >&2
    return 1
  fi
}

graceful_power_off() {
  vm_pid=$(cat "$WORK_DIRECTORY/qemu.pid")
  vm_ssh sudo systemctl poweroff >/dev/null 2>&1 || true
  wait_for_vm_exit "$vm_pid"
  VM_RUNNING=0
}

hard_power_off() {
  vm_pid=$(cat "$WORK_DIRECTORY/qemu.pid")
  kill -KILL "$vm_pid"
  wait_for_vm_exit "$vm_pid"
  VM_RUNNING=0
}

RELEASE_A=$WORK_DIRECTORY/release-a
RELEASE_B=$WORK_DIRECTORY/release-b
GUEST_INPUT=$WORK_DIRECTORY/guest-input
mkdir -m 0700 "$RELEASE_A" "$RELEASE_B" "$GUEST_INPUT"

PACKAGE_A_NAME=SirinVPN_release_A_amd64.deb
PACKAGE_B_NAME=SirinVPN_release_B_amd64.deb
cp "$SIRINVPN_RELEASE_VM_PACKAGE_A" "$RELEASE_A/$PACKAGE_A_NAME"
cp "$SIRINVPN_RELEASE_VM_PACKAGE_B" "$RELEASE_B/$PACKAGE_B_NAME"

PRIVATE_KEY=$WORK_DIRECTORY/release-private.pem
PUBLIC_KEY=$WORK_DIRECTORY/release-public.pem
"$SIGNING_TOOL" keygen --private-key "$PRIVATE_KEY" --public-key "$PUBLIC_KEY" >/dev/null

"$SIGNING_TOOL" create \
  --version "$SIRINVPN_RELEASE_VM_VERSION_A" \
  --sequence 1 \
  --artifact "linux_deb,$TARGET,$RELEASE_A/$PACKAGE_A_NAME" \
  --compatibility "$COMPATIBILITY" \
  --private-key "$PRIVATE_KEY" \
  --manifest "$RELEASE_A/sirinvpn-release.json" \
  --signature "$RELEASE_A/sirinvpn-release.sig.json" >/dev/null

"$SIGNING_TOOL" create \
  --version "$SIRINVPN_RELEASE_VM_VERSION_B" \
  --sequence 2 \
  --artifact "linux_deb,$TARGET,$RELEASE_B/$PACKAGE_B_NAME" \
  --compatibility "$COMPATIBILITY" \
  --private-key "$PRIVATE_KEY" \
  --manifest "$RELEASE_B/sirinvpn-release.json" \
  --signature "$RELEASE_B/sirinvpn-release.sig.json" >/dev/null

"$SIGNING_TOOL" verify \
  --manifest "$RELEASE_A/sirinvpn-release.json" \
  --signature "$RELEASE_A/sirinvpn-release.sig.json" \
  --trusted-public-key "$PUBLIC_KEY" \
  --artifact-directory "$RELEASE_A" >/dev/null
"$SIGNING_TOOL" verify \
  --manifest "$RELEASE_B/sirinvpn-release.json" \
  --signature "$RELEASE_B/sirinvpn-release.sig.json" \
  --trusted-public-key "$PUBLIC_KEY" \
  --artifact-directory "$RELEASE_B" >/dev/null
"$SIGNING_TOOL" plan \
  --current-manifest "$RELEASE_A/sirinvpn-release.json" \
  --current-signature "$RELEASE_A/sirinvpn-release.sig.json" \
  --candidate-manifest "$RELEASE_B/sirinvpn-release.json" \
  --candidate-signature "$RELEASE_B/sirinvpn-release.sig.json" \
  --trusted-public-key "$PUBLIC_KEY" \
  --candidate-artifact-directory "$RELEASE_B" >/dev/null

cp -R "$RELEASE_A" "$GUEST_INPUT/release-a"
cp -R "$RELEASE_B" "$GUEST_INPUT/release-b"
cp "$PUBLIC_KEY" "$GUEST_INPUT/release-public.pem"
cp "$FAULT_TOOL" "$GUEST_INPUT/sirinvpn-release-fault"
chmod 0755 "$GUEST_INPUT/sirinvpn-release-fault"

PACKAGE_A_SHA256=$(sha256sum "$SIRINVPN_RELEASE_VM_PACKAGE_A")
PACKAGE_A_SHA256=${PACKAGE_A_SHA256%% *}
PACKAGE_B_SHA256=$(sha256sum "$SIRINVPN_RELEASE_VM_PACKAGE_B")
PACKAGE_B_SHA256=${PACKAGE_B_SHA256%% *}

REMOTE_ROOT=/home/sirin/sirinvpn-release-gate
REMOTE_TOOL=/usr/lib/sirinvpn/sirinvpn-release
REMOTE_FAULT_TOOL=$REMOTE_ROOT/sirinvpn-release-fault
REMOTE_PUBLIC_KEY=$REMOTE_ROOT/release-public.pem
REMOTE_A=$REMOTE_ROOT/release-a
REMOTE_B=$REMOTE_ROOT/release-b

state_arguments() {
  release_directory=$1
  printf '%s ' \
    --manifest "$release_directory/sirinvpn-release.json" \
    --signature "$release_directory/sirinvpn-release.sig.json" \
    --trusted-public-key "$REMOTE_PUBLIC_KEY" \
    --artifact-directory "$release_directory" \
    --artifact-target "$TARGET"
  printf '\n'
}

assert_receipt() {
  expected_version=$1
  expected_active_sequence=$2
  expected_high_sequence=$3
  summary=$(vm_ssh "sudo $REMOTE_TOOL --json state inspect")
  printf '%s\n' "$summary" | jq -e \
    --arg version "$expected_version" \
    --argjson active "$expected_active_sequence" \
    --argjson high "$expected_high_sequence" \
    '.active_release_version == $version
      and .active_release_sequence == $active
      and .highest_accepted_release_sequence == $high
      and .active_artifact.kind == "linux_deb"
      and .active_artifact.target == "x86_64-unknown-linux-gnu"' >/dev/null
}

assert_installed_package() {
  expected_version=$1
  status=$(vm_ssh "dpkg-query --show --showformat='\${db:Status-Abbrev}\t\${Version}\n' sirin-vpn")
  expected_status=$(printf 'ii \t%s' "$expected_version")
  if [ "$status" != "$expected_status" ]; then
    echo "Expected configured SirinVPN package $expected_version; found: $status" >&2
    return 1
  fi
  verification=$(vm_ssh "sudo dpkg --verify sirin-vpn")
  if [ -n "$verification" ]; then
    echo "The full SirinVPN package failed dpkg verification:" >&2
    echo "$verification" >&2
    return 1
  fi
  reported=$(vm_ssh "sudo $REMOTE_TOOL --version")
  if [ "$reported" != "sirinvpn-release $expected_version" ]; then
    echo "The installed release coordinator reports the wrong version: $reported" >&2
    return 1
  fi
}

assert_cache() {
  expected=$(printf '%s\n' "$@" | sed 's/$/.deb/' | sort)
  actual=$(vm_ssh "sudo find /var/lib/sirinvpn-release/packages -mindepth 1 -maxdepth 1 -printf '%f\n' | sort")
  if [ "$actual" != "$expected" ]; then
    echo "Unexpected authenticated package cache." >&2
    echo "Expected:" >&2
    echo "$expected" >&2
    echo "Actual:" >&2
    echo "$actual" >&2
    return 1
  fi
}

assert_journal_present() {
  vm_ssh "sudo test -f /var/lib/sirinvpn-release/debian-update.json"
  mode=$(vm_ssh "sudo stat -c '%U:%G %a' /var/lib/sirinvpn-release/debian-update.json")
  if [ "$mode" != "root:root 600" ]; then
    echo "The interruption journal has unsafe ownership or permissions: $mode" >&2
    return 1
  fi
  entries=$(vm_ssh "sudo find /var/lib/sirinvpn-release -mindepth 1 -maxdepth 1 -printf '%f\n' | sort")
  expected=$(printf '%s\n' debian-update.json packages receipt.json receipt.lock | sort)
  if [ "$entries" != "$expected" ]; then
    echo "The interrupted transaction retained unexpected release-state entries." >&2
    return 1
  fi
}

assert_journal_absent() {
  if vm_ssh "sudo test -e /var/lib/sirinvpn-release/debian-update.json"; then
    echo "A resolved release transaction retained its journal." >&2
    return 1
  fi
  entries=$(vm_ssh "sudo find /var/lib/sirinvpn-release -mindepth 1 -maxdepth 1 -printf '%f\n' | sort")
  expected=$(printf '%s\n' packages receipt.json receipt.lock | sort)
  if [ "$entries" != "$expected" ]; then
    echo "A resolved transaction retained unexpected release-state entries." >&2
    return 1
  fi
}

assert_guest_internet_blocked() {
  vm_ssh "command -v timeout >/dev/null"
  if vm_ssh "timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'" >/dev/null 2>&1; then
    echo "The update VM unexpectedly retained guest internet access." >&2
    return 1
  fi
}

assert_package_has_no_fault_hook() {
  remote_package=$1
  extraction=$2
  vm_ssh "command -v grep >/dev/null"
  vm_ssh "sudo mkdir -m 0700 $extraction"
  vm_ssh "sudo dpkg-deb --extract $remote_package $extraction"
  vm_ssh "sudo test -f $extraction/usr/lib/sirinvpn/sirinvpn-release"
  if vm_ssh "sudo grep -a -q SIRINVPN_RELEASE_TEST_CRASH_POINT $extraction/usr/lib/sirinvpn/sirinvpn-release"; then
    echo "$remote_package contains the test-only release crash hook." >&2
    return 1
  fi
}

recover_and_assert() {
  expected_action=$1
  expected_version=$2
  expected_active_sequence=$3
  expected_high_sequence=$4
  recovery=$(vm_ssh "sudo $REMOTE_TOOL --json state recover-debian")
  printf '%s\n' "$recovery" | jq -e \
    --arg action "$expected_action" \
    --arg version "$expected_version" \
    --argjson active "$expected_active_sequence" \
    --argjson high "$expected_high_sequence" \
    '.action == $action
      and .state.active_release_version == $version
      and .state.active_release_sequence == $active
      and .state.highest_accepted_release_sequence == $high' >/dev/null
}

run_faulted_update() {
  crash_point=$1
  expected_exit=$2
  output=$WORK_DIRECTORY/fault-$crash_point.txt
  if vm_ssh \
    "sudo env SIRINVPN_RELEASE_TEST_CRASH_CONFIRM=crash-disposable-debian13-vm SIRINVPN_RELEASE_TEST_CRASH_POINT=$crash_point $REMOTE_FAULT_TOOL --json state install-debian $(state_arguments "$REMOTE_B")" \
    >"$output" 2>&1; then
    echo "The instrumented coordinator did not terminate at $crash_point." >&2
    return 1
  else
    status=$?
  fi
  if [ "$status" -ne "$expected_exit" ]; then
    echo "The $crash_point coordinator exited $status instead of $expected_exit." >&2
    cat "$output" >&2
    return 1
  fi
  if ! grep -q "terminating at the disposable-VM release test point: $crash_point" "$output"; then
    echo "The instrumented coordinator did not confirm $crash_point." >&2
    cat "$output" >&2
    return 1
  fi
}

assert_guest_platform() {
  vm_ssh \
    "set -eu; . /etc/os-release; test \"\$ID\" = debian; test \"\$VERSION_ID\" = 13; test \"\$(dpkg --print-architecture)\" = amd64"
}

dpkg_log_digest() {
  vm_ssh "sudo sha256sum /var/log/dpkg.log" | awk '{print $1}'
}

echo "Preparing a fresh Debian 13 VM and installing full release A..."
start_vm off
vm_ssh "sudo cloud-init status --wait" >/dev/null
assert_guest_platform
vm_scp -r "$GUEST_INPUT" "sirin@127.0.0.1:$REMOTE_ROOT" >/dev/null
vm_ssh "sudo chown -R root:root $REMOTE_ROOT && sudo chmod 0700 $REMOTE_ROOT && sudo chmod 0755 $REMOTE_FAULT_TOOL"
assert_package_has_no_fault_hook "$REMOTE_A/$PACKAGE_A_NAME" /var/tmp/sirinvpn-package-a
assert_package_has_no_fault_hook "$REMOTE_B/$PACKAGE_B_NAME" /var/tmp/sirinvpn-package-b
vm_ssh "sudo apt-get -o Acquire::Retries=3 update" >/dev/null
vm_ssh "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y $REMOTE_A/$PACKAGE_A_NAME" >/dev/null
vm_ssh "sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer" >/dev/null
vm_ssh "sudo systemctl mask apt-daily.service apt-daily-upgrade.service" >/dev/null
vm_ssh \
  "sudo $REMOTE_TOOL --json state commit-installation $(state_arguments "$REMOTE_A") --artifact-kind linux_deb" \
  >/dev/null
assert_installed_package "$SIRINVPN_RELEASE_VM_VERSION_A"
assert_receipt "$SIRINVPN_RELEASE_VM_VERSION_A" 1 1
assert_cache "$PACKAGE_A_SHA256"
assert_journal_absent

echo "Restarting with guest internet disabled for the update/recovery phases..."
graceful_power_off
start_vm on
assert_guest_internet_blocked

echo "Crash phase: candidate healthy, immediately before receipt commit..."
run_faulted_update before_receipt_commit 86
hard_power_off

start_vm on
assert_installed_package "$SIRINVPN_RELEASE_VM_VERSION_B"
assert_receipt "$SIRINVPN_RELEASE_VM_VERSION_A" 1 1
assert_cache "$PACKAGE_A_SHA256" "$PACKAGE_B_SHA256"
assert_journal_present
recover_and_assert restored_previous_release "$SIRINVPN_RELEASE_VM_VERSION_A" 1 1
assert_installed_package "$SIRINVPN_RELEASE_VM_VERSION_A"
assert_receipt "$SIRINVPN_RELEASE_VM_VERSION_A" 1 1
assert_cache "$PACKAGE_A_SHA256"
assert_journal_absent
recover_and_assert nothing_pending "$SIRINVPN_RELEASE_VM_VERSION_A" 1 1

echo "Crash phase: receipt committed, immediately before journal cleanup..."
run_faulted_update after_receipt_commit 87
hard_power_off

start_vm on
assert_installed_package "$SIRINVPN_RELEASE_VM_VERSION_B"
assert_receipt "$SIRINVPN_RELEASE_VM_VERSION_B" 2 2
assert_cache "$PACKAGE_A_SHA256" "$PACKAGE_B_SHA256"
assert_journal_present
DPKG_LOG_BEFORE_FINALIZE=$(dpkg_log_digest)
recover_and_assert finalized_candidate_release "$SIRINVPN_RELEASE_VM_VERSION_B" 2 2
DPKG_LOG_AFTER_FINALIZE=$(dpkg_log_digest)
if [ "$DPKG_LOG_AFTER_FINALIZE" != "$DPKG_LOG_BEFORE_FINALIZE" ]; then
  echo "Post-commit recovery unexpectedly reinstalled a package." >&2
  exit 1
fi
assert_installed_package "$SIRINVPN_RELEASE_VM_VERSION_B"
assert_receipt "$SIRINVPN_RELEASE_VM_VERSION_B" 2 2
assert_cache "$PACKAGE_B_SHA256"
assert_journal_absent
recover_and_assert nothing_pending "$SIRINVPN_RELEASE_VM_VERSION_B" 2 2

echo "Debian 13 full-package release gate passed: pre-commit crash restored A after hard reboot, post-commit crash finalized B after hard reboot, and exact state cleanup was verified offline."
