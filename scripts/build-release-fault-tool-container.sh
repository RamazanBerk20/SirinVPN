#!/bin/sh
set -eu

PROJECT_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${SIRINVPN_LINUX_BUILDER_IMAGE:-sirinvpn-linux-builder:latest}
OUTPUT_ROOT=$PROJECT_ROOT/target/release-fault
HOST_UID=$(id -u)
HOST_GID=$(id -g)

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to build the Debian-compatible fault coordinator." >&2
  exit 2
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Build $IMAGE with packaging/Dockerfile.linux before running this command." >&2
  exit 2
fi

restore_ownership() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -e "$OUTPUT_ROOT" ]; then
    docker run --rm \
      --volume "$PROJECT_ROOT:/workspace" \
      "$IMAGE" \
      chown -R "$HOST_UID:$HOST_GID" /workspace/target/release-fault \
      >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap restore_ownership EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

docker run --rm \
  --network host \
  --volume "$PROJECT_ROOT:/workspace" \
  --workdir /workspace \
  --env CARGO_TARGET_DIR=/workspace/target/release-fault \
  "$IMAGE" \
  cargo build --locked --release -p sirinvpn-release \
    --features test-release-fault-injection

test -x "$OUTPUT_ROOT/release/sirinvpn-release"
echo "$OUTPUT_ROOT/release/sirinvpn-release"
