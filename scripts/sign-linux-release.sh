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
RELEASE_NOTES=${SIRINVPN_RELEASE_NOTES:-}
# The owner-signed universal Android APK (both ABIs), when this release ships one.
ANDROID_APK=${SIRINVPN_ANDROID_APK:-}

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
[ -z "$RELEASE_NOTES" ] || [ -f "$RELEASE_NOTES" ] || { echo "release notes summary is unavailable" >&2; exit 1; }
[ -z "$ANDROID_APK" ] || [ -f "$ANDROID_APK" ] || { echo "the Android APK is unavailable" >&2; exit 1; }
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
# The VPS server payloads the packages carry: signed here so the same release
# serves "Install signed VPS baseline" and the VPS updater.
for SERVER_ARCH in x86_64 aarch64; do
  [ -f "$PROJECT_ROOT/target/server-payloads/$SERVER_ARCH-unknown-linux-gnu/release/sirinvpn-server" ] || {
    echo "the $SERVER_ARCH VPS server payload is unavailable; build packaging/Dockerfile.server-payloads first" >&2
    exit 1
  }
done

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
trap cleanup_release_staging 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

APPIMAGE_NAME=$(basename -- "$APPIMAGE")
DEB_NAME=$(basename -- "$DEB")
install -m 0644 "$APPIMAGE" "$STAGING/$APPIMAGE_NAME"
install -m 0644 "$DEB" "$STAGING/$DEB_NAME"
for SERVER_ARCH in x86_64 aarch64; do
  install -m 0644 "$PROJECT_ROOT/target/server-payloads/$SERVER_ARCH-unknown-linux-gnu/release/sirinvpn-server" \
    "$STAGING/sirinvpn-server-$SERVER_ARCH"
done
# One universal APK serves both Android targets; a manifest names each file once, so the
# x86_64 slot gets an identical copy under its own name.
APK_ARM64="SirinVPN_${RELEASE_VERSION}_android.apk"
APK_X86_64="SirinVPN_${RELEASE_VERSION}_android_x86_64.apk"
if [ -n "$ANDROID_APK" ]; then
  # Signed, aligned, non-debuggable, this version, and bundling these server payloads.
  python3 "$PROJECT_ROOT/scripts/check-android-package.py" --expect-version "$RELEASE_VERSION" "$ANDROID_APK" >/dev/null || {
    echo "the Android APK is not a signed release build of $RELEASE_VERSION" >&2
    exit 1
  }
  install -m 0644 "$ANDROID_APK" "$STAGING/$APK_ARM64"
  install -m 0644 "$ANDROID_APK" "$STAGING/$APK_X86_64"
fi
if [ -n "$TRUST_POLICY" ]; then
  install -m 0644 "$TRUST_POLICY" "$STAGING/sirinvpn-release-trust.json"
  install -m 0644 "$TRUST_SIGNATURE" "$STAGING/sirinvpn-release-trust.sig.json"
fi

if [ "$RELEASE_CLASS" = security ]; then
  set -- --security-update
else
  set --
fi
if [ -n "$ANDROID_APK" ]; then
  set -- "$@" \
    --artifact "android_apk,aarch64-linux-android,$STAGING/$APK_ARM64" \
    --artifact "android_apk,x86_64-linux-android,$STAGING/$APK_X86_64"
else
  echo "note: SIRINVPN_ANDROID_APK is unset; this release has no Android APK" >&2
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
  --artifact "server_elf,x86_64-unknown-linux-gnu,$STAGING/sirinvpn-server-x86_64" \
  --artifact "server_elf,aarch64-unknown-linux-gnu,$STAGING/sirinvpn-server-aarch64" \
  --manifest "$STAGING/sirinvpn-release.json" \
  --signature "$STAGING/sirinvpn-release.sig.json"

if [ -n "$RELEASE_NOTES" ]; then
  cargo run --manifest-path "$PROJECT_ROOT/Cargo.toml" --locked --quiet \
    -p sirinvpn-release -- notes \
    --manifest "$STAGING/sirinvpn-release.json" \
    --signature "$STAGING/sirinvpn-release.sig.json" \
    --summary "$RELEASE_NOTES" \
    --private-key "$PRIVATE_KEY" \
    --output "$STAGING/sirinvpn-release-notes.json" >/dev/null
fi

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
