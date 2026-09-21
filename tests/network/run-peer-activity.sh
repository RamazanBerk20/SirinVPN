#!/bin/sh
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
docker build -f "$project_root/tests/network/Dockerfile.policy" -t sirinvpn-policy-test "$project_root"
mkdir -p "$project_root/.cache/policy-container-target"
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --volume "$project_root:/workspace" --workdir /workspace \
  --volume "$HOME/.cargo:/cargo" --env CARGO_HOME=/cargo \
  --env CARGO_TARGET_DIR=/workspace/.cache/policy-container-target \
  sirinvpn-policy-test cargo +1.97.1 test --offline --locked \
  -p sirinvpn-server --lib --no-run --message-format=json \
  > "$project_root/.cache/policy-container-target/peer-artifacts.json"
docker run --rm --network none --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
  --volume "$project_root:/workspace:ro" --workdir /workspace \
  --env SIRINVPN_POLICY_ISOLATED=1 sirinvpn-policy-test python3 -c '
import json, os
with open("/workspace/.cache/policy-container-target/peer-artifacts.json") as artifacts:
    binaries = [row["executable"] for line in artifacts if (row := json.loads(line)).get("executable")
                and row.get("profile", {}).get("test")]
assert len(binaries) == 1
os.execv(binaries[0], [binaries[0], "--ignored", "kernel_peer_activity_uses_actual_handshakes", "--nocapture"])
'
