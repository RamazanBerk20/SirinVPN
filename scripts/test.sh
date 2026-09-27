#!/bin/sh
set -eu

CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
RUST_TEST_THREADS=${RUST_TEST_THREADS:-2}
export CARGO_BUILD_JOBS RUST_TEST_THREADS

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DESKTOP_DIR="$PROJECT_ROOT/apps/desktop"

cd "$PROJECT_ROOT"
for tool in python3 cargo node pnpm rg shellcheck xmllint; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Required validation tool missing: $tool" >&2; exit 1; }
done
expected_pnpm=$(node -p "require('./apps/desktop/package.json').packageManager.split('@')[1]")
[ "$(pnpm --version)" = "$expected_pnpm" ] || { echo "Use repository-pinned pnpm $expected_pnpm" >&2; exit 1; }
python3 "$PROJECT_ROOT/scripts/check-maintainability.py"
python3 "$PROJECT_ROOT/scripts/check-remediation-contracts.py"
python3 "$PROJECT_ROOT/scripts/check-vendored.py"
python3 -m unittest discover -s "$PROJECT_ROOT/tests/unit"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

cd "$DESKTOP_DIR"
pnpm test
pnpm build

cd "$PROJECT_ROOT"
"$PROJECT_ROOT/scripts/check-privacy.sh"

shellcheck "$PROJECT_ROOT"/scripts/*.sh
shellcheck "$PROJECT_ROOT"/tests/integration/*.sh
shellcheck "$PROJECT_ROOT"/tests/vm/*.sh
xmllint --noout "$PROJECT_ROOT/packaging/polkit/org.sirinvpn.network.policy"

echo "All local SirinVPN gates passed."
