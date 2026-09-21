#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
export JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk}
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
export NDK_HOME=${NDK_HOME:-$ANDROID_HOME/ndk/30.0.16248370}
export RANLIB="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib"
export RANLIB_aarch64_linux_android="$RANLIB" RANLIB_x86_64_linux_android="$RANLIB"
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
cd "$ROOT"
if [ ! -f apps/desktop/src-tauri/gen/android/app/build.gradle.kts ]; then
  pnpm --dir apps/desktop tauri android init --ci --skip-targets-install
fi
python3 scripts/prepare-android.py
case "${1:-aarch64}" in
  aarch64) TARGETS=aarch64; SIRIN_ANDROID_ABIS=arm64-v8a ;;
  x86_64) TARGETS=x86_64; SIRIN_ANDROID_ABIS=x86_64 ;;
  all) TARGETS='aarch64 x86_64'; SIRIN_ANDROID_ABIS=arm64-v8a,x86_64 ;;
  *) echo 'Choose aarch64, x86_64 or all' >&2; exit 2 ;;
esac
export SIRIN_ANDROID_ABIS
PROFILE=${2:-debug}
case "$PROFILE" in debug) MODE=--debug ;; release) MODE= ;; *) echo 'Choose debug or release' >&2; exit 2 ;; esac
for target in $TARGETS; do sh scripts/build-android-native.sh "$target" "$PROFILE"; done
# The expansion is a closed list of architecture names and an optional fixed flag.
pnpm --dir apps/desktop tauri android build --ci $MODE --target $TARGETS --apk --config src-tauri/tauri.android.conf.json
