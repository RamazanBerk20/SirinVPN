#!/bin/sh
set -eu

PROJECT_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
DESKTOP_DIR="$PROJECT_ROOT/apps/desktop"
BIN_DIR="$DESKTOP_DIR/src-tauri/binaries"
NO_STRIP=${NO_STRIP:-1}
CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
RUST_TEST_THREADS=${RUST_TEST_THREADS:-2}
export NO_STRIP CARGO_BUILD_JOBS RUST_TEST_THREADS

SIRINVPN_PACKAGE_TMP=$(mktemp -d)
cleanup_package_tmp() {
  rm -rf -- "$SIRINVPN_PACKAGE_TMP"
}
trap cleanup_package_tmp 0 HUP INT TERM

prepare_appimage_pkgconf_compat() {
  if command -v pkgconf >/dev/null 2>&1; then
    SIRINVPN_REAL_PKGCONF=$(command -v pkgconf)
  elif command -v pkg-config >/dev/null 2>&1; then
    SIRINVPN_REAL_PKGCONF=$(command -v pkg-config)
  else
    return 0
  fi

  SIRINVPN_GDK_PIXBUF_BINARY_DIR=$(
    "$SIRINVPN_REAL_PKGCONF" --variable=gdk_pixbuf_binarydir gdk-pixbuf-2.0 2>/dev/null || true
  )
  if [ -z "$SIRINVPN_GDK_PIXBUF_BINARY_DIR" ] || [ -d "$SIRINVPN_GDK_PIXBUF_BINARY_DIR" ]; then
    return 0
  fi

  SIRINVPN_COMPAT_BIN="$SIRINVPN_PACKAGE_TMP/bin"
  SIRINVPN_GDK_PIXBUF_COMPAT_ROOT="$SIRINVPN_PACKAGE_TMP/gdk-pixbuf-2.0/2.10.0"
  mkdir -p "$SIRINVPN_COMPAT_BIN" "$SIRINVPN_GDK_PIXBUF_COMPAT_ROOT/loaders"
  ln -s "$PROJECT_ROOT/scripts/pkgconf-appimage-compat.sh" "$SIRINVPN_COMPAT_BIN/pkgconf"
  export SIRINVPN_REAL_PKGCONF SIRINVPN_GDK_PIXBUF_COMPAT_ROOT
  PATH="$SIRINVPN_COMPAT_BIN:$PATH"
  export PATH
  echo "Using built-in GdkPixbuf loader compatibility for AppImage packaging."
}

repair_appimage_runtime() {
  SIRINVPN_APPIMAGE_BUNDLE_DIR="$PROJECT_ROOT/target/release/bundle/appimage"
  SIRINVPN_APPDIR="$SIRINVPN_APPIMAGE_BUNDLE_DIR/SirinVPN.AppDir"
  SIRINVPN_APPDIR_SERVER="$SIRINVPN_APPDIR/usr/lib/sirinvpn/sirinvpn-server"
  SIRINVPN_APPIMAGE=
  for SIRINVPN_CANDIDATE in "$SIRINVPN_APPIMAGE_BUNDLE_DIR"/*.AppImage; do
    [ -f "$SIRINVPN_CANDIDATE" ] || continue
    case "$SIRINVPN_CANDIDATE" in
      *.repaired.AppImage) continue ;;
    esac
    if [ -n "$SIRINVPN_APPIMAGE" ]; then
      echo "Expected exactly one AppImage in $SIRINVPN_APPIMAGE_BUNDLE_DIR" >&2
      return 1
    fi
    SIRINVPN_APPIMAGE=$SIRINVPN_CANDIDATE
  done
  if [ ! -d "$SIRINVPN_APPDIR/usr/lib" ] || [ -z "$SIRINVPN_APPIMAGE" ]; then
    echo "Tauri did not produce the expected AppImage bundle" >&2
    return 1
  fi
  if [ ! -f "$SIRINVPN_APPDIR_SERVER" ] || [ ! -f "$BIN_DIR/sirinvpn-server" ]; then
    echo "Tauri did not stage the SirinVPN server payload" >&2
    return 1
  fi

  SIRINVPN_REPACK_REQUIRED=0
  # linuxdeploy adds an AppImage-local RUNPATH to every staged executable.
  # These two components are installed outside the AppImage. Preserve their
  # canonical bytes, including the helper used for exact installed-build checks.
  for SIRINVPN_SYSTEM_COMPONENT in sirinvpn-server sirinvpn-helper; do
    SIRINVPN_APPDIR_COMPONENT="$SIRINVPN_APPDIR/usr/lib/sirinvpn/$SIRINVPN_SYSTEM_COMPONENT"
    if [ ! -f "$SIRINVPN_APPDIR_COMPONENT" ] || [ ! -f "$BIN_DIR/$SIRINVPN_SYSTEM_COMPONENT" ]; then
      echo "Tauri did not stage $SIRINVPN_SYSTEM_COMPONENT" >&2
      return 1
    fi
    if ! cmp -s "$BIN_DIR/$SIRINVPN_SYSTEM_COMPONENT" "$SIRINVPN_APPDIR_COMPONENT"; then
      install -m 0755 "$BIN_DIR/$SIRINVPN_SYSTEM_COMPONENT" "$SIRINVPN_APPDIR_COMPONENT"
      SIRINVPN_REPACK_REQUIRED=1
    fi
  done

  SIRINVPN_WAYLAND_LIBRARY_COUNT=0
  for SIRINVPN_LIBRARY in "$SIRINVPN_APPDIR/usr/lib"/libwayland-*.so*; do
    if [ -e "$SIRINVPN_LIBRARY" ] || [ -L "$SIRINVPN_LIBRARY" ]; then
      rm -f -- "$SIRINVPN_LIBRARY"
      SIRINVPN_WAYLAND_LIBRARY_COUNT=$((SIRINVPN_WAYLAND_LIBRARY_COUNT + 1))
    fi
  done
  if [ "$SIRINVPN_WAYLAND_LIBRARY_COUNT" -gt 0 ]; then
    SIRINVPN_REPACK_REQUIRED=1
  fi
  if [ "$SIRINVPN_REPACK_REQUIRED" -eq 0 ]; then
    return 0
  fi

  # Tauri's GTK bundler currently includes Bookworm's libwayland, which is
  # incompatible with newer host Mesa releases. Repack with the host ABI libs.
  SIRINVPN_TAURI_CACHE=${XDG_CACHE_HOME:-"$HOME/.cache"}/tauri
  SIRINVPN_APPIMAGE_PLUGIN=
  for SIRINVPN_CANDIDATE in \
    "$SIRINVPN_TAURI_CACHE/linuxdeploy-plugin-appimage.AppImage" \
    "$SIRINVPN_TAURI_CACHE/linuxdeploy-plugin-appimage-$(uname -m).AppImage"; do
    if [ -x "$SIRINVPN_CANDIDATE" ]; then
      SIRINVPN_APPIMAGE_PLUGIN=$SIRINVPN_CANDIDATE
      break
    fi
  done
  if [ -z "$SIRINVPN_APPIMAGE_PLUGIN" ]; then
    echo "Tauri's AppImage output plugin was not found" >&2
    return 1
  fi

  SIRINVPN_REPAIRED_APPIMAGE="${SIRINVPN_APPIMAGE%.AppImage}.repaired.AppImage"
  rm -f -- "$SIRINVPN_REPAIRED_APPIMAGE"
  if ! APPIMAGE_EXTRACT_AND_RUN=1 \
      ARCH=$(uname -m) \
      LDAI_OUTPUT="$SIRINVPN_REPAIRED_APPIMAGE" \
      "$SIRINVPN_APPIMAGE_PLUGIN" --appdir "$SIRINVPN_APPDIR"; then
    rm -f -- "$SIRINVPN_REPAIRED_APPIMAGE"
    return 1
  fi
  mv -f -- "$SIRINVPN_REPAIRED_APPIMAGE" "$SIRINVPN_APPIMAGE"
}

cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" --locked --release \
  -p sirinvpn-server \
  -p sirinvpn-linux-helper \
  -p sirinvpn-cli \
  -p sirinvpn-release \
  -p sirinvpn-release-fetch

mkdir -p "$BIN_DIR"
install -m 0755 "$PROJECT_ROOT/target/release/sirinvpn-server" "$BIN_DIR/sirinvpn-server"
install -m 0755 "$PROJECT_ROOT/target/release/sirinvpn-helper" "$BIN_DIR/sirinvpn-helper"
install -m 0755 "$PROJECT_ROOT/target/release/sirinvpn" "$BIN_DIR/sirinvpn"
install -m 0755 "$PROJECT_ROOT/target/release/sirinvpn-release" "$BIN_DIR/sirinvpn-release"
install -m 0755 "$PROJECT_ROOT/target/release/sirinvpn-release-fetch" "$BIN_DIR/sirinvpn-release-fetch"

cd "$DESKTOP_DIR"
if [ "${SIRINVPN_DEPENDENCIES_READY:-0}" != 1 ]; then
  pnpm install --frozen-lockfile
fi
pnpm test
pnpm build
prepare_appimage_pkgconf_compat
pnpm tauri build
repair_appimage_runtime
