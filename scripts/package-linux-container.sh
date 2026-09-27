#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
HOST_UID=$(id -u)
HOST_GID=$(id -g)
BUILD_IMAGE=${SIRINVPN_LINUX_BUILD_IMAGE:-sirinvpn-linux-builder}

restore_generated_ownership() {
  build_status=$?
  trap - 0

  docker run --rm \
    --network none --cpus 0.5 --memory 256m --memory-swap 256m --pids-limit 64 \
    --volume "$PROJECT_ROOT:/workspace" \
    --workdir /workspace \
    "$BUILD_IMAGE" \
    sh -c '
      owner=$1
      shift
      for path do
        [ ! -e "$path" ] || chown -R "$owner" "$path"
      done
    ' sh "$HOST_UID:$HOST_GID" \
      /workspace/target \
      /workspace/apps/desktop/dist \
      /workspace/apps/desktop/src-tauri/binaries \
    || true

  exit "$build_status"
}

if [ "${SIRINVPN_REUSE_BUILD_IMAGE:-0}" != 1 ]; then
  docker build --memory 4g --memory-swap 4g --cpu-period 100000 --cpu-quota 150000 \
    -f "$PROJECT_ROOT/packaging/Dockerfile.linux" -t "$BUILD_IMAGE" "$PROJECT_ROOT"
fi
set --
# Mount only the public dependency registry, never the user's Cargo credentials.
if [ -n "${SIRINVPN_CARGO_REGISTRY:-}" ]; then
  set -- "$@" --volume "$SIRINVPN_CARGO_REGISTRY:/var/cache/sirinvpn/cargo/registry:ro" \
    --env CARGO_NET_OFFLINE=true
fi
if [ -n "${SIRINVPN_TAURI_CACHE:-}" ]; then
  set -- "$@" --volume "$SIRINVPN_TAURI_CACHE:/root/.cache/tauri"
fi
trap restore_generated_ownership 0
docker run --rm \
  --cpus 1.5 --memory 4g --memory-swap 4g --pids-limit 256 \
  --volume "$PROJECT_ROOT:/workspace" \
  --workdir /workspace \
  --env NO_STRIP=1 \
  --env "RUSTUP_TOOLCHAIN=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$PROJECT_ROOT/rust-toolchain.toml")" \
  --env CARGO_BUILD_JOBS=2 --env RUST_TEST_THREADS=2 \
  --env "SIRINVPN_DEPENDENCIES_READY=${SIRINVPN_DEPENDENCIES_READY:-0}" \
  "$@" \
  "$BUILD_IMAGE" \
  ./scripts/package-linux.sh
