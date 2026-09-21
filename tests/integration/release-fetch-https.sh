#!/bin/sh
set -eu

: "${SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY:?Set the absolute pre-production root private-key path}"
: "${SIRINVPN_RELEASE_FETCH_CONFIRM:?Set SIRINVPN_RELEASE_FETCH_CONFIRM=exercise-preproduction-release-fetch}"

if [ "$SIRINVPN_RELEASE_FETCH_CONFIRM" != exercise-preproduction-release-fetch ]; then
  echo "Refusing to use the pre-production root without exact confirmation." >&2
  exit 2
fi
case "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" in
  /*) ;;
  *) echo "The root private-key path must be absolute." >&2; exit 2 ;;
esac
if [ ! -f "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" ] \
  || [ -L "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" ]; then
  echo "The root private key must be a regular, non-symlink file." >&2
  exit 2
fi
if [ "$(stat -c %a "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY")" != 600 ]; then
  echo "The root private key must have mode 0600." >&2
  exit 2
fi

for tool in cargo cmp find jq openssl python3 stat; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required for the release-fetch HTTPS gate." >&2
    exit 2
  fi
done

PROJECT_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/../.." && pwd)
WORK_ROOT=${SIRINVPN_RELEASE_FETCH_TEST_ROOT:-${TMPDIR:-/tmp}}
mkdir -p "$WORK_ROOT"
WORK_DIRECTORY=$(mktemp -d "$WORK_ROOT/sirinvpn-release-fetch.XXXXXX")
case "$WORK_DIRECTORY" in
  "$WORK_ROOT"/sirinvpn-release-fetch.*) ;;
  *) echo "The test directory escaped its configured root." >&2; exit 2 ;;
esac
SERVER_PID=
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  case "$WORK_DIRECTORY" in
    "$WORK_ROOT"/sirinvpn-release-fetch.*) rm -rf -- "$WORK_DIRECTORY" ;;
  esac
  exit "$status"
}
trap cleanup EXIT HUP INT TERM
umask 077

cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" --locked \
  -p sirinvpn-release -p sirinvpn-release-fetch >/dev/null
RELEASE_TOOL=$PROJECT_ROOT/target/debug/sirinvpn-release
FETCH_TOOL=$PROJECT_ROOT/target/debug/sirinvpn-release-fetch
SOURCE_ROOT=$WORK_DIRECTORY/source
SOURCE=$SOURCE_ROOT/stable
OUTPUT=$WORK_DIRECTORY/fetched
TAMPERED_OUTPUT=$WORK_DIRECTORY/tampered
mkdir -p "$SOURCE"

LEAF_PRIVATE=$WORK_DIRECTORY/leaf-private.pem
LEAF_PUBLIC=$WORK_DIRECTORY/leaf-public.pem
"$RELEASE_TOOL" keygen \
  --private-key "$LEAF_PRIVATE" \
  --public-key "$LEAF_PUBLIC" >/dev/null

ARTIFACT=$SOURCE/SirinVPN_fetch_test_amd64.deb
printf '%s\n' 'authenticated release fetch fixture' >"$ARTIFACT"
"$RELEASE_TOOL" create \
  --version 0.2.0 \
  --sequence 2 \
  --channel stable \
  --security-update \
  --artifact "linux_deb,x86_64-unknown-linux-gnu,$ARTIFACT" \
  --compatibility "$PROJECT_ROOT/release/state-compatibility.json" \
  --private-key "$LEAF_PRIVATE" \
  --manifest "$SOURCE/sirinvpn-release.json" \
  --signature "$SOURCE/sirinvpn-release.sig.json" >/dev/null
"$RELEASE_TOOL" trust create \
  --sequence 1 \
  --release-key "$LEAF_PUBLIC" \
  --root-private-key "$SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY" \
  --policy "$SOURCE/sirinvpn-release-trust.json" \
  --signature "$SOURCE/sirinvpn-release-trust.sig.json" >/dev/null

TLS_CA_KEY=$WORK_DIRECTORY/https-ca-key.pem
TLS_CA_CERTIFICATE=$WORK_DIRECTORY/https-ca-certificate.pem
TLS_KEY=$WORK_DIRECTORY/https-key.pem
TLS_REQUEST=$WORK_DIRECTORY/https-request.pem
TLS_CERTIFICATE=$WORK_DIRECTORY/https-certificate.pem
TLS_EXTENSIONS=$WORK_DIRECTORY/https-extensions.conf
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj /CN=SirinVPN-release-fetch-test-CA \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign \
  -keyout "$TLS_CA_KEY" \
  -out "$TLS_CA_CERTIFICATE" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -subj /CN=127.0.0.1 \
  -keyout "$TLS_KEY" \
  -out "$TLS_REQUEST" >/dev/null 2>&1
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=IP:127.0.0.1' >"$TLS_EXTENSIONS"
openssl x509 -req -in "$TLS_REQUEST" \
  -CA "$TLS_CA_CERTIFICATE" \
  -CAkey "$TLS_CA_KEY" \
  -CAcreateserial \
  -days 1 -sha256 \
  -extfile "$TLS_EXTENSIONS" \
  -out "$TLS_CERTIFICATE" >/dev/null 2>&1
PORT_FILE=$WORK_DIRECTORY/https-port
python3 "$PROJECT_ROOT/tests/integration/release_https_server.py" \
  "$SOURCE_ROOT" "$TLS_CERTIFICATE" "$TLS_KEY" "$PORT_FILE" &
SERVER_PID=$!
attempts=0
while [ ! -s "$PORT_FILE" ]; do
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 100 ]; then
    echo "The local HTTPS fixture did not start." >&2
    exit 1
  fi
  sleep 0.05
done
PORT=$(cat "$PORT_FILE")
SOURCE_URL=https://127.0.0.1:$PORT/stable/

SSL_CERT_FILE=$TLS_CA_CERTIFICATE "$FETCH_TOOL" --json \
  --source "$SOURCE_URL" \
  --channel stable \
  --artifact-kind linux_deb \
  --artifact-target x86_64-unknown-linux-gnu \
  --output "$OUTPUT" >"$WORK_DIRECTORY/result.json"
jq -e \
  '.release_version == "0.2.0"
    and .release_sequence == 2
    and .channel == "stable"
    and .security_update == true
    and .trust_policy_sequence == 1
    and .artifact.kind == "linux_deb"
    and .artifact.target == "x86_64-unknown-linux-gnu"' \
  "$WORK_DIRECTORY/result.json" >/dev/null
cmp "$ARTIFACT" "$OUTPUT/artifact/SirinVPN_fetch_test_amd64.deb"
[ "$(stat -c %a "$OUTPUT")" = 700 ]
[ "$(stat -c %a "$OUTPUT/sirinvpn-release.json")" = 600 ]
[ "$(stat -c %a "$OUTPUT/artifact/SirinVPN_fetch_test_amd64.deb")" = 600 ]
"$RELEASE_TOOL" verify-trusted \
  --manifest "$OUTPUT/sirinvpn-release.json" \
  --signature "$OUTPUT/sirinvpn-release.sig.json" \
  --trust-policy "$OUTPUT/sirinvpn-release-trust.json" \
  --trust-signature "$OUTPUT/sirinvpn-release-trust.sig.json" \
  --artifact-directory "$OUTPUT/artifact" >/dev/null

if SSL_CERT_FILE=$TLS_CA_CERTIFICATE "$FETCH_TOOL" \
  --source "$SOURCE_URL" \
  --artifact-kind linux_deb \
  --artifact-target x86_64-unknown-linux-gnu \
  --output "$OUTPUT" >"$WORK_DIRECTORY/collision.txt" 2>&1; then
  echo "The fetcher replaced an existing output directory." >&2
  exit 1
fi
if ! grep -q 'destination already exists' "$WORK_DIRECTORY/collision.txt"; then
  echo "The fetcher did not report its no-clobber refusal." >&2
  exit 1
fi

printf '%s\n' 'tampered release fetch fixture bytes' >"$ARTIFACT"
if SSL_CERT_FILE=$TLS_CA_CERTIFICATE "$FETCH_TOOL" \
  --source "$SOURCE_URL" \
  --artifact-kind linux_deb \
  --artifact-target x86_64-unknown-linux-gnu \
  --output "$TAMPERED_OUTPUT" >"$WORK_DIRECTORY/tamper.txt" 2>&1; then
  echo "The fetcher accepted a changed artifact." >&2
  exit 1
fi
[ ! -e "$TAMPERED_OUTPUT" ]
if find "$WORK_DIRECTORY" -mindepth 1 -maxdepth 1 \
  -name '.sirinvpn-release-fetch.*' | grep -q .; then
  echo "The fetcher retained an incomplete staging directory." >&2
  exit 1
fi

echo "Release-fetch HTTPS gate passed: bundled-root verification, bounded download, private atomic publication, no-clobber, tamper rejection, and exact cleanup verified."
