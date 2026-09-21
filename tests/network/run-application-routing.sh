#!/bin/sh
# No live VPN, host network, devices, systemd, or privileged container is used.
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
docker image inspect sirinvpn-policy-test >/dev/null
mkdir -p "$project_root/.cache/policy-container-target" "$project_root/.cache/check-logs"
docker run --rm --network none --memory=4g --memory-swap=4g --cpus=1.5 --pids-limit=256 \
  --user "$(id -u):$(id -g)" --volume "$project_root:/workspace" --workdir /workspace \
  --volume "$HOME/.cargo:/cargo" --env CARGO_HOME=/cargo \
  --env CARGO_TARGET_DIR=/workspace/.cache/policy-container-target \
  --env CARGO_BUILD_JOBS=2 --env RUST_TEST_THREADS=2 \
  sirinvpn-policy-test cargo +1.97.1 test --offline --locked -p sirinvpn-linux-helper \
  --lib --no-run --message-format=json > "$project_root/.cache/check-logs/application-artifacts.json"
docker run --rm --network none --memory=4g --memory-swap=4g --cpus=1.5 --pids-limit=256 \
  --user "$(id -u):$(id -g)" --volume "$project_root:/workspace" --workdir /workspace \
  --volume "$HOME/.cargo:/cargo" --env CARGO_HOME=/cargo \
  --env CARGO_TARGET_DIR=/workspace/.cache/policy-container-target --env CARGO_BUILD_JOBS=2 \
  sirinvpn-policy-test cargo +1.97.1 build --offline --locked -p sirinvpn-linux-helper --bin sirinvpn-helper
# SYS_ADMIN permits mount/network namespace creation; SYS_PTRACE permits the
# parent's UID/namespace inspection after the child permanently drops root.
docker run --rm --network none --memory=1g --memory-swap=1g --cpus=1 --pids-limit=128 \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
  --security-opt apparmor=unconfined \
  --volume "$project_root:/workspace:ro" --workdir /workspace \
  --env SIRINVPN_POLICY_ISOLATED=1 --env RUST_TEST_THREADS=1 \
  sirinvpn-policy-test python3 -c '
import json, os, pathlib, shutil
destination = pathlib.Path("/usr/lib/sirinvpn/sirinvpn-helper")
destination.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile("/workspace/.cache/policy-container-target/debug/sirinvpn-helper", destination)
destination.chmod(0o755)
with open("/workspace/.cache/check-logs/application-artifacts.json") as artifacts:
    binaries = [row["executable"] for line in artifacts if (row := json.loads(line)).get("executable")
                and row.get("profile", {}).get("test")]
assert len(binaries) == 1
os.execv(binaries[0], [binaries[0], "--ignored", "kernel_application_packet_dns_privilege_and_disconnect_matrix", "--nocapture"])
'
