#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
NDK_HOME=${NDK_HOME:-$ANDROID_HOME/ndk/30.0.16248370}
GO_BIN=${GO_BIN:-$ROOT/.cache/android-tools/go/bin/go}
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
case "${1:-x86_64}" in
  x86_64) TARGET=x86_64-linux-android; ABI=x86_64; GOARCH=amd64 ;;
  aarch64) TARGET=aarch64-linux-android; ABI=arm64-v8a; GOARCH=arm64 ;;
  *) echo 'Choose x86_64 or aarch64' >&2; exit 2 ;;
esac
export GOARCH GOOS=android CGO_ENABLED=1
export CC="$TOOLCHAIN/${TARGET}29-clang"
export AR="$TOOLCHAIN/llvm-ar"
export RANLIB="$TOOLCHAIN/llvm-ranlib"
export RANLIB_aarch64_linux_android="$RANLIB" RANLIB_x86_64_linux_android="$RANLIB"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android29-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/x86_64-linux-android29-clang"
export RUSTFLAGS='-C link-arg=-Wl,-z,max-page-size=16384'
export CGO_LDFLAGS='-Wl,-z,max-page-size=16384'
OUT="$ROOT/apps/desktop/src-tauri/gen/android/app/src/main/jniLibs/$ABI"
mkdir -p "$OUT"
cd "$ROOT/apps/desktop/android/wireguard"
"$GO_BIN" build -trimpath -buildmode=c-shared -ldflags='-s -w' -o "$OUT/libsirin_wireguard.so" .
rm -f "$OUT/libsirin_wireguard.h"
cd "$ROOT"
case "${2:-debug}" in
  debug) cargo build --locked -p sirinvpn-android-runtime --target "$TARGET" ; PROFILE=debug ;;
  release) cargo build --locked --release -p sirinvpn-android-runtime --target "$TARGET" ; PROFILE=release ;;
  *) echo 'Choose debug or release' >&2; exit 2 ;;
esac
cp "$ROOT/target/$TARGET/$PROFILE/libsirinvpn_android_runtime.so" "$OUT/"
"$TOOLCHAIN/llvm-strip" --strip-unneeded "$OUT/libsirinvpn_android_runtime.so"
