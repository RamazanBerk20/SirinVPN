#!/bin/sh
set -eu

: "${SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY:?Set an absolute path to the pre-production root private key}"
: "${SIRINVPN_RELEASE_TRUST_CONFIRM:?Set SIRINVPN_RELEASE_TRUST_CONFIRM=exercise-preproduction-release-root}"

if [ "$SIRINVPN_RELEASE_TRUST_CONFIRM" != exercise-preproduction-release-root ]; then
  echo "Refusing to use the release root without the exact test confirmation." >&2
  exit 2
fi
case "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" in
  /*) ;;
  *) echo "The release root private-key path must be absolute." >&2; exit 2 ;;
esac
if [ ! -f "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" ] || [ -L "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" ]; then
  echo "The release root private key must be a regular, non-symlink file." >&2
  exit 2
fi

PROJECT_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/../.." && pwd)
WORK_ROOT=$PROJECT_ROOT/.cache
mkdir -p "$WORK_ROOT"
WORK_DIRECTORY=$(mktemp -d "$WORK_ROOT/sirinvpn-release-trust.XXXXXX")
case "$WORK_DIRECTORY" in
  "$WORK_ROOT"/sirinvpn-release-trust.*) ;;
  *) echo "The trust-test directory escaped its work root." >&2; exit 2 ;;
esac

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  case "$WORK_DIRECTORY" in
    "$WORK_ROOT"/sirinvpn-release-trust.*) rm -rf -- "$WORK_DIRECTORY" ;;
  esac
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in cargo jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required for the release trust gate." >&2
    exit 2
  fi
done

cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" --locked -p sirinvpn-release >/dev/null
RELEASE_TOOL=$PROJECT_ROOT/target/debug/sirinvpn-release
COMPATIBILITY=$PROJECT_ROOT/release/state-compatibility.json

"$RELEASE_TOOL" keygen \
  --private-key "$WORK_DIRECTORY/release-a-private.pem" \
  --public-key "$WORK_DIRECTORY/release-a-public.pem" >/dev/null
"$RELEASE_TOOL" keygen \
  --private-key "$WORK_DIRECTORY/release-b-private.pem" \
  --public-key "$WORK_DIRECTORY/release-b-public.pem" >/dev/null

"$RELEASE_TOOL" trust create \
  --sequence 1 \
  --release-key "$WORK_DIRECTORY/release-a-public.pem" \
  --root-private-key "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" \
  --policy "$WORK_DIRECTORY/trust-1.json" \
  --signature "$WORK_DIRECTORY/trust-1.sig.json" >/dev/null
"$RELEASE_TOOL" trust verify \
  --policy "$WORK_DIRECTORY/trust-1.json" \
  --signature "$WORK_DIRECTORY/trust-1.sig.json" >/dev/null

printf 'release A\n' >"$WORK_DIRECTORY/sirinvpn-server-a"
"$RELEASE_TOOL" create \
  --version 0.1.0 \
  --sequence 1 \
  --channel stable \
  --artifact "server_elf,x86_64-unknown-linux-gnu,$WORK_DIRECTORY/sirinvpn-server-a" \
  --compatibility "$COMPATIBILITY" \
  --private-key "$WORK_DIRECTORY/release-a-private.pem" \
  --manifest "$WORK_DIRECTORY/release-a.json" \
  --signature "$WORK_DIRECTORY/release-a.sig.json" >/dev/null
"$RELEASE_TOOL" verify-trusted \
  --manifest "$WORK_DIRECTORY/release-a.json" \
  --signature "$WORK_DIRECTORY/release-a.sig.json" \
  --trust-policy "$WORK_DIRECTORY/trust-1.json" \
  --trust-signature "$WORK_DIRECTORY/trust-1.sig.json" \
  --artifact-directory "$WORK_DIRECTORY" >/dev/null

"$RELEASE_TOOL" trust create \
  --sequence 2 \
  --release-key "$WORK_DIRECTORY/release-a-public.pem" \
  --release-key "$WORK_DIRECTORY/release-b-public.pem" \
  --root-private-key "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" \
  --policy "$WORK_DIRECTORY/trust-2.json" \
  --signature "$WORK_DIRECTORY/trust-2.sig.json" >/dev/null

printf 'release B\n' >"$WORK_DIRECTORY/sirinvpn-server-b"
"$RELEASE_TOOL" create \
  --version 0.2.0 \
  --sequence 2 \
  --channel stable \
  --artifact "server_elf,x86_64-unknown-linux-gnu,$WORK_DIRECTORY/sirinvpn-server-b" \
  --compatibility "$COMPATIBILITY" \
  --private-key "$WORK_DIRECTORY/release-b-private.pem" \
  --manifest "$WORK_DIRECTORY/release-b.json" \
  --signature "$WORK_DIRECTORY/release-b.sig.json" >/dev/null
"$RELEASE_TOOL" verify-trusted \
  --manifest "$WORK_DIRECTORY/release-b.json" \
  --signature "$WORK_DIRECTORY/release-b.sig.json" \
  --trust-policy "$WORK_DIRECTORY/trust-2.json" \
  --trust-signature "$WORK_DIRECTORY/trust-2.sig.json" \
  --artifact-directory "$WORK_DIRECTORY" >/dev/null

RELEASE_A_KEY_ID=$(
  "$RELEASE_TOOL" --json verify-trusted \
    --manifest "$WORK_DIRECTORY/release-a.json" \
    --signature "$WORK_DIRECTORY/release-a.sig.json" \
    --trust-policy "$WORK_DIRECTORY/trust-2.json" \
    --trust-signature "$WORK_DIRECTORY/trust-2.sig.json" \
    --artifact-directory "$WORK_DIRECTORY" |
    jq -er '.release.key_id_sha256'
)
"$RELEASE_TOOL" trust create \
  --sequence 3 \
  --release-key "$WORK_DIRECTORY/release-b-public.pem" \
  --revoke-key-id "$RELEASE_A_KEY_ID" \
  --root-private-key "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" \
  --policy "$WORK_DIRECTORY/trust-3.json" \
  --signature "$WORK_DIRECTORY/trust-3.sig.json" >/dev/null
"$RELEASE_TOOL" verify-trusted \
  --manifest "$WORK_DIRECTORY/release-b.json" \
  --signature "$WORK_DIRECTORY/release-b.sig.json" \
  --trust-policy "$WORK_DIRECTORY/trust-3.json" \
  --trust-signature "$WORK_DIRECTORY/trust-3.sig.json" \
  --artifact-directory "$WORK_DIRECTORY" >/dev/null

if "$RELEASE_TOOL" verify-trusted \
  --manifest "$WORK_DIRECTORY/release-a.json" \
  --signature "$WORK_DIRECTORY/release-a.sig.json" \
  --trust-policy "$WORK_DIRECTORY/trust-3.json" \
  --trust-signature "$WORK_DIRECTORY/trust-3.sig.json" \
  --artifact-directory "$WORK_DIRECTORY" \
  >"$WORK_DIRECTORY/revoked.out" 2>"$WORK_DIRECTORY/revoked.err"; then
  echo "A release signed by the revoked key was unexpectedly accepted." >&2
  exit 1
fi
if ! grep -q "release signing key is revoked" "$WORK_DIRECTORY/revoked.err"; then
  echo "The revoked release failed for an unexpected reason." >&2
  exit 1
fi

echo "Release trust gate passed: bundled root, overlap rotation, successor release, and permanent old-key revocation verified offline."
