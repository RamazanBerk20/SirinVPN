#!/bin/sh
# Real networking occurs only inside the existing disposable QEMU harness.
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"
base=${1:?Pass a verified disposable Debian 13 base image}
output=${2:?Pass a new evidence/fixture output directory}
[ ! -e "$output" ] || { echo "Use a new fixture output directory" >&2; exit 1; }
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "KVM unavailable; kernel acceptance is blocked" >&2
  exit 1
fi
mkdir -p "$output/input"
docker build --memory 8g --memory-swap 8g --cpu-period 100000 --cpu-quota 400000 -f packaging/Dockerfile.linux -t sirinvpn-remediation-builder .
docker build --memory 8g --memory-swap 8g --cpu-period 100000 --cpu-quota 400000 -f tests/vm/Dockerfile.kernel -t sirinvpn-kernel-runtime:acceptance .
docker save -o "$output/input/runtime.tar" sirinvpn-kernel-runtime:acceptance
docker run --rm --cpus 4 --memory 8g --memory-swap 8g --pids-limit 512 \
  --user "$(id -u):$(id -g)" \
  --volume "$project_root:/workspace" --workdir /workspace \
  --env CARGO_HOME=/workspace/.cache/kernel-cargo --env CARGO_BUILD_JOBS=4 \
  --env CARGO_TARGET_DIR=/workspace/target/kernel-acceptance \
  sirinvpn-remediation-builder sh -ec '
    cargo build --locked -p sirinvpn-linux-helper -p sirinvpn-server --bins
    mkdir -p apps/desktop/src-tauri/binaries
    cp target/kernel-acceptance/debug/sirinvpn-helper apps/desktop/src-tauri/binaries/sirinvpn-helper
    cp target/kernel-acceptance/debug/sirinvpn-server apps/desktop/src-tauri/binaries/sirinvpn-server
    cargo test --locked -p sirinvpn-server -p sirinvpn-linux-helper -p sirinvpn-installer --lib --no-run --message-format=json
  ' > "$output/input/artifacts.json"
sh tests/vm/run-kernel-acceptance.sh --base "$base" --image "$output/input/runtime.tar" \
  --artifacts "$output/input/artifacts.json" --output "$output/run"
