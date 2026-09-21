#!/bin/sh
# The test cannot route to the host or VPS. It creates only disposable container interfaces.
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
if ! docker image inspect sirinvpn-linux-builder >/dev/null 2>&1; then
  docker build -f "$project_root/packaging/Dockerfile.linux" \
    -t sirinvpn-linux-builder "$project_root"
fi
docker build -f "$project_root/tests/network/Dockerfile.policy" \
  -t sirinvpn-policy-test "$project_root"
mkdir -p "$project_root/.cache/policy-container-target"
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --volume "$project_root:/workspace" --workdir /workspace \
  --volume "$HOME/.cargo:/cargo" --env CARGO_HOME=/cargo \
  --env CARGO_TARGET_DIR=/workspace/.cache/policy-container-target \
  sirinvpn-policy-test cargo +1.97.1 test --offline --locked \
  -p sirinvpn-linux-helper --lib --no-run --message-format=json \
  > "$project_root/.cache/policy-container-target/artifacts.json"
# Only the test process receives network-admin permissions, in its own empty network namespace.
docker run --rm --network none --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
  --volume "$project_root:/workspace:ro" --workdir /workspace \
  --env SIRINVPN_POLICY_ISOLATED=1 \
  --env "SIRINVPN_KERNEL_FILTER=${1:-kernel_guard_packet_matrix_and_atomic_replacement}" \
  sirinvpn-policy-test python3 -c '
import json, os
with open("/workspace/.cache/policy-container-target/artifacts.json") as artifacts:
    binaries = [row["executable"] for line in artifacts if (row := json.loads(line)).get("executable")
                and row.get("profile", {}).get("test")]
assert len(binaries) == 1, binaries
os.execv(binaries[0], [binaries[0], "--ignored", os.environ["SIRINVPN_KERNEL_FILTER"], "--nocapture"])
'
