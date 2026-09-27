#!/bin/sh
# No host D-Bus, keyring, home directory, credentials or networking enter the fixture.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
docker build --memory 4g --memory-swap 4g --cpu-period 100000 --cpu-quota 150000 \
  -f packaging/Dockerfile.linux -t sirinvpn-linux-builder .
docker build --memory 4g --memory-swap 4g --cpu-period 100000 --cpu-quota 150000 \
  -t sirinvpn-keyring-fixture - <<'DOCKERFILE'
FROM sirinvpn-linux-builder
RUN apt-get update && apt-get install -y --no-install-recommends dbus gnome-keyring && rm -rf /var/lib/apt/lists/*
DOCKERFILE
docker run --rm --cpus 1.5 --memory 4g --memory-swap 4g --pids-limit 256 \
  --user "$(id -u):$(id -g)" --volume "$root:/workspace" --workdir /workspace \
  --env CARGO_HOME=/workspace/.cache/keyring-cargo --env CARGO_BUILD_JOBS=2 \
  --env CARGO_TARGET_DIR=/workspace/.cache/policy-container-target \
  sirinvpn-keyring-fixture cargo test --locked -p sirinvpn-core --lib --no-run --message-format=json \
  > .cache/keyring-artifacts.json
binary=$(python3 - <<'PY'
import json
from pathlib import Path
for line in Path('.cache/keyring-artifacts.json').read_text().splitlines():
    value = json.loads(line)
    if value.get('executable') and value.get('target', {}).get('name') == 'sirinvpn_core':
        print(value['executable'])
        break
else:
    raise SystemExit('Core test executable missing')
PY
)
docker run --rm --network none --cpus 1.5 --memory 512m --memory-swap 512m --pids-limit 128 \
  --volume "$root/.cache/policy-container-target:/workspace/.cache/policy-container-target:ro" \
  --tmpfs /root:rw,mode=0700 --tmpfs /run:rw,mode=0755 \
  sirinvpn-keyring-fixture sh -ec '
    touch /run/sirinvpn-keyring-fixture
    mkdir -m 0700 /run/session
    export XDG_RUNTIME_DIR=/run/session
    dbus-run-session -- sh -ec '\''
      printf "%s" synthetic-fixture-password | gnome-keyring-daemon --unlock --components=secrets >/dev/null
      "$1" --exact secrets::linux::tests::real_secret_service_interop_migration_duplicates_and_lock --ignored --nocapture
    '\'' sh "$1"
  ' sh "$binary"
