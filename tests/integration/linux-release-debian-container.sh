#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)

if [ "${SIRINVPN_RELEASE_CONTAINER_INNER:-0}" != "1" ]; then
  IMAGE=${SIRINVPN_RELEASE_CONTAINER_IMAGE:-sirinvpn-linux-builder:latest}
  RELEASE_TOOL=${SIRINVPN_RELEASE_CONTAINER_BINARY:-"$PROJECT_ROOT/target/release/sirinvpn-release"}
  for command in docker uname; do
    if ! command -v "$command" >/dev/null 2>&1; then
      echo "$command is required for the offline Debian release gate." >&2
      exit 2
    fi
  done
  if [ "$(uname -m)" != "x86_64" ]; then
    echo "The current offline Debian release gate requires an x86_64 container host." >&2
    exit 2
  fi
  if [ ! -x "$RELEASE_TOOL" ]; then
    echo "Build the release-mode sirinvpn-release binary before running this gate." >&2
    exit 2
  fi
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Build $IMAGE with packaging/Dockerfile.linux before running this gate." >&2
    exit 2
  fi
  docker run --rm \
    --network none \
    --env SIRINVPN_RELEASE_CONTAINER_INNER=1 \
    --volume "$PROJECT_ROOT:/workspace:ro" \
    --volume "$RELEASE_TOOL:/opt/sirinvpn-release:ro" \
    "$IMAGE" \
    /workspace/tests/integration/linux-release-debian-container.sh
  exit $?
fi

export LC_ALL=C.UTF-8
umask 077

for command in dpkg dpkg-deb dpkg-query install sha256sum; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required inside the offline Debian release gate." >&2
    exit 2
  fi
done

RELEASE_TOOL=/opt/sirinvpn-release
COMPATIBILITY=/workspace/release/state-compatibility.json
TARGET=x86_64-unknown-linux-gnu
TEST_ROOT=$(mktemp -d /tmp/sirinvpn-release-debian.XXXXXX)
KEY_DIRECTORY="$TEST_ROOT/key"
PUBLIC_KEY="$KEY_DIRECTORY/public.pem"
PRIVATE_KEY="$KEY_DIRECTORY/private.pem"

mkdir -m 0700 "$KEY_DIRECTORY"

make_package() {
  version=$1
  sequence=$2
  helper_state=$3
  release_directory="$TEST_ROOT/release-$sequence"
  package_root="$TEST_ROOT/package-$sequence"
  package="$release_directory/SirinVPN_${version}_amd64.deb"

  mkdir -p \
    "$release_directory" \
    "$package_root/DEBIAN" \
    "$package_root/usr/bin" \
    "$package_root/usr/lib/sirinvpn"
  chmod 0755 \
    "$package_root" \
    "$package_root/DEBIAN" \
    "$package_root/usr" \
    "$package_root/usr/bin" \
    "$package_root/usr/lib" \
    "$package_root/usr/lib/sirinvpn"

  cat >"$package_root/DEBIAN/control" <<EOF
Package: sirin-vpn
Version: $version
Architecture: amd64
Maintainer: SirinVPN test gate
Priority: optional
Description: Offline SirinVPN transactional updater fixture
EOF

  for path in \
    "$package_root/usr/bin/sirinvpn" \
    "$package_root/usr/bin/sirinvpn-desktop" \
    "$package_root/usr/lib/sirinvpn/sirinvpn-server"; do
    cat >"$path" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod 0755 "$path"
  done

  cat >"$package_root/usr/lib/sirinvpn/sirinvpn-release" <<EOF
#!/bin/sh
if [ "\${1:-}" = "--version" ]; then
  printf '%s\n' 'sirinvpn-release $version'
  exit 0
fi
exit 1
EOF
  chmod 0755 "$package_root/usr/lib/sirinvpn/sirinvpn-release"

  cat >"$package_root/usr/lib/sirinvpn/sirinvpn-helper" <<EOF
#!/bin/sh
if [ "\${1:-}" = "status" ]; then
  printf '%s\n' '{"state":"$helper_state","interface_name":"sirinvpn0","server_id":null,"rx_bytes":0,"tx_bytes":0,"ipv6_blocked":false,"ipv6_tunneled":false,"transport":null,"kill_switch_enabled":false,"auto_reconnect_enabled":false,"transport_fallback_enabled":false,"routing_mode":"full_tunnel","allow_lan":false}'
  exit 0
fi
exit 1
EOF
  chmod 0755 "$package_root/usr/lib/sirinvpn/sirinvpn-helper"

  dpkg-deb --build --root-owner-group "$package_root" "$package" >/dev/null
}

sign_release() {
  version=$1
  sequence=$2
  release_directory="$TEST_ROOT/release-$sequence"
  package="$release_directory/SirinVPN_${version}_amd64.deb"
  "$RELEASE_TOOL" create \
    --version "$version" \
    --sequence "$sequence" \
    --artifact "linux_deb,$TARGET,$package" \
    --compatibility "$COMPATIBILITY" \
    --private-key "$PRIVATE_KEY" \
    --manifest "$release_directory/sirinvpn-release.json" \
    --signature "$release_directory/sirinvpn-release.sig.json" >/dev/null
}

state_candidate() {
  command_name=$1
  sequence=$2
  shift 2
  release_directory="$TEST_ROOT/release-$sequence"
  "$RELEASE_TOOL" state "$command_name" \
    --manifest "$release_directory/sirinvpn-release.json" \
    --signature "$release_directory/sirinvpn-release.sig.json" \
    --trusted-public-key "$PUBLIC_KEY" \
    --artifact-directory "$release_directory" \
    --artifact-target "$TARGET" \
    "$@"
}

assert_installed_version() {
  expected=$1
  # dpkg-query, not the shell, expands this format.
  # shellcheck disable=SC2016
  actual=$(dpkg-query --show --showformat='${Version}' sirin-vpn)
  if [ "$actual" != "$expected" ]; then
    echo "Expected installed package $expected, found $actual." >&2
    exit 1
  fi
}

assert_single_cache() {
  set -- /var/lib/sirinvpn-release/packages/*.deb
  if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "The release state did not retain exactly one Debian package." >&2
    exit 1
  fi
  cached_name=${1##*/}
  cached_digest=${cached_name%.deb}
  actual_digest=$(sha256sum "$1")
  actual_digest=${actual_digest%% *}
  if [ "$actual_digest" != "$cached_digest" ]; then
    echo "The retained Debian package does not match its content address." >&2
    exit 1
  fi
  if [ -e /var/lib/sirinvpn-release/debian-update.json ]; then
    echo "A completed transaction retained its interruption journal." >&2
    exit 1
  fi
}

assert_receipt() {
  active_version=$1
  active_sequence=$2
  high_sequence=$3
  summary=$("$RELEASE_TOOL" state inspect)
  case "$summary" in
    *"release $active_version (sequence $active_sequence,"*"highest accepted"*"(sequence $high_sequence)"*) ;;
    *)
      echo "Installed-release receipt did not contain the expected active/high state." >&2
      echo "$summary" >&2
      exit 1
      ;;
  esac
}

"$RELEASE_TOOL" keygen \
  --private-key "$PRIVATE_KEY" \
  --public-key "$PUBLIC_KEY" >/dev/null

make_package 1.0.0 1 disconnected
make_package 1.1.0 2 disconnected
make_package 1.2.0 3 connected
sign_release 1.0.0 1
sign_release 1.1.0 2
sign_release 1.2.0 3

dpkg --install "$TEST_ROOT/release-1/SirinVPN_1.0.0_amd64.deb" >/dev/null
state_candidate commit-installation 1 --artifact-kind linux_deb >/dev/null
assert_installed_version 1.0.0
assert_receipt 1.0.0 1 1
assert_single_cache

state_candidate install-debian 2 >/dev/null
assert_installed_version 1.1.0
assert_receipt 1.1.0 2 2
assert_single_cache

state_candidate install-debian 1 --allow-rollback >/dev/null
assert_installed_version 1.0.0
assert_receipt 1.0.0 1 2
assert_single_cache

state_candidate install-debian 2 >/dev/null
assert_installed_version 1.1.0
assert_receipt 1.1.0 2 2
assert_single_cache

if state_candidate install-debian 3 >/dev/null 2>&1; then
  echo "The unhealthy candidate unexpectedly committed." >&2
  exit 1
fi
assert_installed_version 1.1.0
assert_receipt 1.1.0 2 2
assert_single_cache

recovery=$("$RELEASE_TOOL" state recover-debian)
case "$recovery" in
  "No interrupted Debian update required recovery."*) ;;
  *)
    echo "A clean transaction unexpectedly required recovery." >&2
    exit 1
    ;;
esac

echo "Offline Debian release gate passed: real dpkg upgrade, rollback, high-watermark restore, health-failure restoration, and exact cleanup verified."
