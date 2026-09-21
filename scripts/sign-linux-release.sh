#!/bin/sh
set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 5 ]; then
  echo "usage: $0 PRIVATE_KEY RELEASE_SEQUENCE OUTPUT_DIRECTORY [stable|preview] [security]" >&2
  exit 2
fi

PROJECT_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
PRIVATE_KEY=$1
RELEASE_SEQUENCE=$2
OUTPUT_DIRECTORY=$3
RELEASE_CHANNEL=${4:-stable}
RELEASE_CLASS=${5:-normal}
COMPATIBILITY="$PROJECT_ROOT/release/state-compatibility.json"
TRUST_POLICY=${SIRINVPN_RELEASE_TRUST_POLICY:-}
TRUST_SIGNATURE=${SIRINVPN_RELEASE_TRUST_SIGNATURE:-}

case "$RELEASE_SEQUENCE" in
  ''|*[!0-9]*|0) echo "release sequence must be a positive integer" >&2; exit 2 ;;
esac
case "$RELEASE_CHANNEL" in
  stable|preview) ;;
  *) echo "release channel must be stable or preview" >&2; exit 2 ;;
esac
case "$RELEASE_CLASS" in
  normal|security) ;;
  *) echo "release class must be security when provided" >&2; exit 2 ;;
esac
[ -f "$PRIVATE_KEY" ] || { echo "release private key is unavailable" >&2; exit 1; }
[ -f "$COMPATIBILITY" ] || { echo "release compatibility contract is unavailable" >&2; exit 1; }
if [ -n "$TRUST_POLICY" ] || [ -n "$TRUST_SIGNATURE" ]; then
  if [ -z "$TRUST_POLICY" ] || [ -z "$TRUST_SIGNATURE" ]; then
    echo "both SIRINVPN_RELEASE_TRUST_POLICY and SIRINVPN_RELEASE_TRUST_SIGNATURE are required" >&2
    exit 2
  fi
fi

RELEASE_VERSION=$(awk '
  /^\[workspace.package\]$/ { workspace_package = 1; next }
  /^\[/ { workspace_package = 0 }
  workspace_package && /^version = "/ {
    value = $0
    sub(/^version = "/, "", value)
    sub(/"$/, "", value)
    print value
    exit
  }
' "$PROJECT_ROOT/Cargo.toml")
[ -n "$RELEASE_VERSION" ] || { echo "workspace release version is unavailable" >&2; exit 1; }

RUST_TARGET=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$RUST_TARGET" ] || { echo "Rust host target is unavailable" >&2; exit 1; }

find_one() {
  found=
  for candidate in "$1"/*"$2"; do
    [ -f "$candidate" ] || continue
    if [ -n "$found" ]; then
      echo "expected exactly one $2 artifact below $1" >&2
      return 1
    fi
    found=$candidate
  done
  [ -n "$found" ] || { echo "no $2 artifact found below $1" >&2; return 1; }
  printf '%s\n' "$found"
}

APPIMAGE=$(find_one "$PROJECT_ROOT/target/release/bundle/appimage" '.AppImage')
DEB=$(find_one "$PROJECT_ROOT/target/release/bundle/deb" '.deb')

OUTPUT_PARENT=$(dirname -- "$OUTPUT_DIRECTORY")
[ -d "$OUTPUT_PARENT" ] || { echo "release output parent does not exist" >&2; exit 1; }
if [ -e "$OUTPUT_DIRECTORY" ] || [ -L "$OUTPUT_DIRECTORY" ]; then
  echo "refusing to replace existing release output" >&2
  exit 1
fi

STAGING=$(mktemp -d "$OUTPUT_PARENT/.sirinvpn-release.XXXXXX")
cleanup_release_staging() {
  rm -rf -- "$STAGING"
}
trap cleanup_release_staging 0 HUP INT TERM

APPIMAGE_NAME=$(basename -- "$APPIMAGE")
DEB_NAME=$(basename -- "$DEB")
install -m 0644 "$APPIMAGE" "$STAGING/$APPIMAGE_NAME"
install -m 0644 "$DEB" "$STAGING/$DEB_NAME"
if [ -n "$TRUST_POLICY" ]; then
  install -m 0644 "$TRUST_POLICY" "$STAGING/sirinvpn-release-trust.json"
  install -m 0644 "$TRUST_SIGNATURE" "$STAGING/sirinvpn-release-trust.sig.json"
fi

if [ "$RELEASE_CLASS" = security ]; then
  set -- --security-update
else
  set --
fi

cargo run --manifest-path "$PROJECT_ROOT/Cargo.toml" --locked --quiet \
  -p sirinvpn-release -- create \
  --version "$RELEASE_VERSION" \
  --sequence "$RELEASE_SEQUENCE" \
  --channel "$RELEASE_CHANNEL" \
  "$@" \
  --compatibility "$COMPATIBILITY" \
  --private-key "$PRIVATE_KEY" \
  --artifact "linux_appimage,$RUST_TARGET,$STAGING/$APPIMAGE_NAME" \
  --artifact "linux_deb,$RUST_TARGET,$STAGING/$DEB_NAME" \
  --manifest "$STAGING/sirinvpn-release.json" \
  --signature "$STAGING/sirinvpn-release.sig.json"

if [ -n "$TRUST_POLICY" ]; then
  cargo run --manifest-path "$PROJECT_ROOT/Cargo.toml" --locked --quiet \
    -p sirinvpn-release -- verify-trusted \
    --manifest "$STAGING/sirinvpn-release.json" \
    --signature "$STAGING/sirinvpn-release.sig.json" \
    --trust-policy "$STAGING/sirinvpn-release-trust.json" \
    --trust-signature "$STAGING/sirinvpn-release-trust.sig.json" \
    --artifact-directory "$STAGING" >/dev/null
fi

chmod 0755 "$STAGING"
mv -T -n -- "$STAGING" "$OUTPUT_DIRECTORY"
if [ -d "$STAGING" ]; then
  echo "release output appeared before the staged bundle could be committed" >&2
  exit 1
fi
trap - 0 HUP INT TERM
echo "Signed Linux release written to $OUTPUT_DIRECTORY"
