#!/bin/sh
set -eu

CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
RUST_TEST_THREADS=${RUST_TEST_THREADS:-2}
export CARGO_BUILD_JOBS RUST_TEST_THREADS

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DESKTOP_DIR="$PROJECT_ROOT/apps/desktop"

cd "$PROJECT_ROOT"
python3 "$PROJECT_ROOT/scripts/check-maintainability.py"
python3 -m unittest discover -s "$PROJECT_ROOT/tests/unit"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

cd "$DESKTOP_DIR"
pnpm test
pnpm build

cd "$PROJECT_ROOT"
"$PROJECT_ROOT/scripts/check-privacy.sh"

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "$PROJECT_ROOT"/scripts/*.sh
  shellcheck "$PROJECT_ROOT"/tests/integration/*.sh
  shellcheck "$PROJECT_ROOT"/tests/vm/*.sh
else
  echo "ShellCheck is not installed; optional shell lint was skipped."
fi

if command -v xmllint >/dev/null 2>&1; then
  xmllint --noout "$PROJECT_ROOT/packaging/polkit/org.sirinvpn.network.policy"
else
  echo "xmllint is not installed; optional policy XML validation was skipped."
fi

echo "All local SirinVPN gates passed."
