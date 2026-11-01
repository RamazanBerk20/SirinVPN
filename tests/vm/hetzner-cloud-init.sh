#!/bin/sh
# Boots a Debian 13 cloud image with the cloud-init user data that Hetzner
# creation sends, then checks the pre-seeded host key and the root login key.
set -eu

: "${SIRINVPN_DEBIAN13_IMAGE:?Set an absolute path to a Debian 13 generic cloud qcow2 image}"
case "$SIRINVPN_DEBIAN13_IMAGE" in
  /*) ;;
  *) echo "SIRINVPN_DEBIAN13_IMAGE must be an absolute path." >&2; exit 2 ;;
esac
for tool in qemu-system-x86_64 qemu-img xorriso ssh ssh-keyscan ssh-keygen cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required for this check." >&2
    exit 2
  fi
done

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
VM_WORK_ROOT=${SIRINVPN_VM_WORK_ROOT:-$PROJECT_ROOT/.cache}
mkdir -p "$VM_WORK_ROOT"
WORK_DIRECTORY=$(mktemp -d "$VM_WORK_ROOT/sirinvpn-hetzner-cloud-init.XXXXXX")
SSH_PORT=${SIRINVPN_VM_SSH_PORT:-22223}
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  QEMU_ACCEL=kvm QEMU_CPU=host
else
  QEMU_ACCEL=tcg QEMU_CPU=max
fi

cleanup() {
  if [ -f "$WORK_DIRECTORY/qemu.pid" ]; then
    kill "$(cat "$WORK_DIRECTORY/qemu.pid")" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK_DIRECTORY"
}
trap cleanup EXIT HUP INT TERM

(cd "$PROJECT_ROOT" && cargo build --quiet -p sirinvpn-installer --example hetzner_cloud_init)
SEED_TOOL="$PROJECT_ROOT/target/debug/examples/hetzner_cloud_init"
PIN=$("$SEED_TOOL" prepare "$WORK_DIRECTORY")
printf 'instance-id: sirinvpn-hetzner-cloud-init\nlocal-hostname: sirinvpn-test\n' >"$WORK_DIRECTORY/meta-data"
xorriso -as mkisofs -output "$WORK_DIRECTORY/seed.img" -volid cidata -joliet -rock -graft-points \
  "user-data=$WORK_DIRECTORY/user-data" "meta-data=$WORK_DIRECTORY/meta-data" >/dev/null 2>&1
qemu-img create -q -f qcow2 -F qcow2 -b "$SIRINVPN_DEBIAN13_IMAGE" "$WORK_DIRECTORY/disk.qcow2"
# No guest Internet: cloud-init's SSH modules need none, and the host keeps a clean result.
qemu-system-x86_64 \
  -machine "accel=$QEMU_ACCEL" -cpu "$QEMU_CPU" -m 1024 -smp 2 \
  -drive "file=$WORK_DIRECTORY/disk.qcow2,if=virtio,format=qcow2" \
  -drive "file=$WORK_DIRECTORY/seed.img,if=virtio,format=raw,readonly=on" \
  -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
  -device virtio-net-pci,netdev=net0 \
  -display none -serial "file:$WORK_DIRECTORY/serial.log" \
  -daemonize -pidfile "$WORK_DIRECTORY/qemu.pid"

"$SEED_TOOL" verify "$WORK_DIRECTORY" "$SSH_PORT"

# A just-booted guest can drop a scan while cloud-init finishes; retry briefly.
for _ in 1 2 3 4 5; do
  ssh-keyscan -T 10 -p "$SSH_PORT" 127.0.0.1 2>>"$WORK_DIRECTORY/keyscan.log" | sed '/^#/d' >"$WORK_DIRECTORY/keyscan"
  [ -s "$WORK_DIRECTORY/keyscan" ] && break
  sleep 3
done
if [ ! -s "$WORK_DIRECTORY/keyscan" ]; then
  echo "ssh-keyscan saw no host key:" >&2
  cat "$WORK_DIRECTORY/keyscan.log" >&2
  exit 1
fi
OFFERED=$(awk '{print $2}' "$WORK_DIRECTORY/keyscan" | sort -u | tr '\n' ' ')
if [ "$OFFERED" != "ssh-ed25519 " ]; then
  echo "sshd offers host key types other than the pre-seeded one: $OFFERED" >&2
  exit 1
fi
SCANNED=$(ssh-keygen -l -E sha256 -f "$WORK_DIRECTORY/keyscan" | awk '{print $2}')
if [ "$SCANNED" != "$PIN" ]; then
  echo "ssh-keyscan saw $SCANNED, expected $PIN" >&2
  exit 1
fi
if ssh -p "$SSH_PORT" -o BatchMode=yes -o PreferredAuthentications=password \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 true \
  2>"$WORK_DIRECTORY/password.log"; then
  echo "password login unexpectedly succeeded" >&2
  exit 1
fi
if ! grep -q 'Permission denied (publickey)' "$WORK_DIRECTORY/password.log"; then
  echo "sshd still offers a method other than public keys:" >&2
  cat "$WORK_DIRECTORY/password.log" >&2
  exit 1
fi
# OpenSSH with only the scanned key trusted: sshd must use the drop-in's single HostKey.
ssh -p "$SSH_PORT" -i "$WORK_DIRECTORY/ssh-keys/$(cat "$WORK_DIRECTORY/name")" -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WORK_DIRECTORY/keyscan" \
  root@127.0.0.1 'sshd -T' >"$WORK_DIRECTORY/sshd-config"
HOST_KEYS=$(grep -i '^hostkey ' "$WORK_DIRECTORY/sshd-config" | awk '{print $2}' | tr '\n' ' ')
if [ "$HOST_KEYS" != "/etc/ssh/ssh_host_ed25519_key " ]; then
  echo "sshd uses host keys: $HOST_KEYS" >&2
  exit 1
fi
if ! grep -qx 'passwordauthentication no' "$WORK_DIRECTORY/sshd-config"; then
  echo "sshd still allows password authentication" >&2
  exit 1
fi
echo "Hetzner cloud-init check passed: only $PIN is offered, root logs in with the generated key, passwords are off."
