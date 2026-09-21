#!/bin/sh
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
docker image inspect sirinvpn-policy-test >/dev/null
mkdir -p "$project_root/.cache/policy-container-target"
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --volume "$project_root:/workspace" --workdir /workspace \
  --volume "$HOME/.cargo:/cargo" --env CARGO_HOME=/cargo \
  --env CARGO_TARGET_DIR=/workspace/.cache/policy-container-target \
  sirinvpn-policy-test cargo +1.97.1 build --offline --locked -p sirinvpn-server
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --volume "$project_root:/workspace" --workdir /workspace \
  --volume "$HOME/.cargo:/cargo" --env CARGO_HOME=/cargo \
  --env CARGO_TARGET_DIR=/workspace/.cache/policy-container-target \
  sirinvpn-policy-test cargo +1.97.1 test --offline --locked \
  -p sirinvpn-linux-helper --lib --no-run --message-format=json \
  > "$project_root/.cache/policy-container-target/automatic-artifacts.json"
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
  --volume "$project_root:/workspace:ro" --workdir /workspace \
  --env SIRINVPN_POLICY_ISOLATED=1 --env SIRINVPN_SOAK_SECONDS="${SIRINVPN_SOAK_SECONDS:-60}" \
  --env SIRINVPN_FAULT_ONE_WAY="${SIRINVPN_FAULT_ONE_WAY:-0}" \
  --env SIRINVPN_TEST_SERVER=/workspace/.cache/policy-container-target/debug/sirinvpn-server \
  sirinvpn-policy-test python3 -c '
import json, os, subprocess
subprocess.run(["mount", "-o", "remount,rw", "/proc/sys"], check=True)
with open("/workspace/.cache/policy-container-target/automatic-artifacts.json") as f:
    paths = [r["executable"] for line in f if (r := json.loads(line)).get("executable") and r.get("profile", {}).get("test")]
assert len(paths) == 1
os.execv(paths[0], [paths[0], "--ignored", "kernel_automatic_transport_continuity_and_soak", "--nocapture"])
'
