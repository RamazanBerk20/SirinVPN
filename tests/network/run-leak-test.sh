#!/bin/sh
set -eu
# The speed test runs over the same link: see run-speed-test.sh.
test=${1:-kernel_leak_addresses_reach_the_vps_only_through_the_tunnel}
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
if ! docker image inspect sirinvpn-policy-test >/dev/null 2>&1; then
  docker build -f "$project_root/tests/network/Dockerfile.policy" -t sirinvpn-policy-test "$project_root"
fi
mkdir -p "$project_root/.cache/policy-container-target"
docker run --rm --network none --memory=6g --memory-swap=6g --cpus=4 --pids-limit=512 \
  --user "$(id -u):$(id -g)" \
  --volume "$project_root:/workspace" --workdir /workspace \
  --volume "$HOME/.cargo:/cargo" --env CARGO_HOME=/cargo --env CARGO_BUILD_JOBS=4 \
  --env CARGO_TARGET_DIR=/workspace/.cache/policy-container-target \
  sirinvpn-policy-test cargo +1.97.1 test --offline --locked \
  -p sirinvpn-server --lib --no-run --message-format=json \
  > "$project_root/.cache/policy-container-target/leak-test-server-artifacts.json"
docker run --rm --network none --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  --volume "$project_root:/workspace:ro" --workdir /workspace \
  --env SIRINVPN_POLICY_ISOLATED=1 --env SIRINVPN_KERNEL_TEST="$test" \
  sirinvpn-policy-test python3 -c '
import json, os
with open("/workspace/.cache/policy-container-target/leak-test-server-artifacts.json") as artifacts:
    binaries = [row["executable"] for line in artifacts if (row := json.loads(line)).get("executable")
                and row.get("profile", {}).get("test")]
assert len(binaries) == 1
os.execv(binaries[0], [binaries[0], "--ignored", os.environ["SIRINVPN_KERNEL_TEST"], "--nocapture"])
'
