#!/bin/sh
# Root file-ownership checks in an ordinary container. No systemd, host devices,
# network capabilities or privileged container mode are used.
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
docker image inspect sirinvpn-policy-test >/dev/null
mkdir -p "$project_root/.cache/policy-container-target" "$project_root/.cache/check-logs"
docker run --rm --network none --memory=4g --memory-swap=4g --cpus=1.5 --pids-limit=256 \
  --user "$(id -u):$(id -g)" --volume "$project_root:/workspace" --workdir /workspace \
  --volume "$HOME/.cargo:/cargo" --env CARGO_HOME=/cargo \
  --env CARGO_TARGET_DIR=/workspace/.cache/policy-container-target \
  --env CARGO_BUILD_JOBS=2 --env RUST_TEST_THREADS=2 \
  sirinvpn-policy-test cargo +1.97.1 test --offline --locked -p sirinvpn-installer \
  --lib --no-run --message-format=json \
  > "$project_root/.cache/check-logs/installer-release-guard-artifacts.json"
docker run --rm --network none --memory=1g --memory-swap=1g --cpus=1 --pids-limit=128 \
  --volume "$project_root:/workspace:ro" --workdir /workspace \
  --env SIRINVPN_POLICY_ISOLATED=1 --env RUST_TEST_THREADS=1 \
  sirinvpn-policy-test python3 -c '
import json, os
with open("/workspace/.cache/check-logs/installer-release-guard-artifacts.json") as artifacts:
    binaries = [row["executable"] for line in artifacts if (row := json.loads(line)).get("executable")
                and row.get("profile", {}).get("test") and row["target"]["name"] == "sirinvpn_installer"]
assert len(binaries) == 1
os.execv(binaries[0], [binaries[0], "--ignored", "isolated_root_staging_rejects_policy_races_and_artifact_swaps_before_execution", "--nocapture"])
'
