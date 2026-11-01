#!/bin/sh
# Serve the catalog for another checkout's UI with this harness: serve_ui.sh <checkout-or-snapshot> <port>.
# The snapshot needs apps/desktop/{index.html,src,node_modules}; this copies tests/ui/catalog and tests/android in.
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
TARGET=$(CDPATH='' cd -- "$1" && pwd)
mkdir -p "$TARGET/tests/ui" "$TARGET/tests/android"
cp -r "$HERE/tests/ui/catalog" "$TARGET/tests/ui/"
cp "$HERE/tests/android/catalog.ts" "$HERE/tests/android/catalog.config.ts" "$TARGET/tests/android/"
cd "$TARGET/apps/desktop"
exec "$HERE/apps/desktop/node_modules/.bin/vite" --config ../../tests/ui/catalog/vite.config.ts --port "$2"
