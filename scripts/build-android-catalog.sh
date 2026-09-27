#!/bin/sh
# Fictional presentation harness in a separate test APK; never production assets.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk}"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
pnpm --dir apps/desktop exec vite build --config ../../tests/android/catalog.config.ts
python3 - <<'PY'
from pathlib import Path
import shutil
out=Path('target/android-catalog')
(out/'index.html').write_text('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="catalog.css"></head><body><div id="root"></div><script src="catalog.js"></script></body></html>')
dest=Path('apps/desktop/src-tauri/gen/android/app/src/androidTest/assets/catalog')
shutil.copytree(out,dest,dirs_exist_ok=True)
PY
python3 scripts/prepare-android.py
cd apps/desktop/src-tauri/gen/android
./gradlew :app:assembleUniversalDebugAndroidTest -x rustBuildUniversalDebug --max-workers=2
