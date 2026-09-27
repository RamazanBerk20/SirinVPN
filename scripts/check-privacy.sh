#!/bin/sh
set -eu

PROJECT_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
DESKTOP_DIR="$PROJECT_ROOT/apps/desktop"

FORBIDDEN_DEPENDENCIES='(^|[^[:alnum:]])sentry([^[:alnum:]]|$)|crashlytics|posthog|@segment|segment-analytics|mixpanel|amplitude|appcenter|firebase-analytics|google-analytics|matomo|plausible|datadog|newrelic|bugsnag|(^|[^[:alnum:]])rollbar([^[:alnum:]]|$)'
LOGGING_PATTERN='tracing::|\blog::|env_logger|tracing_subscriber'

if printf '%s\n' 'CreateUnicastIpAddressEntry(&row)' | rg -q -i "$FORBIDDEN_DEPENDENCIES" \
  || ! printf '%s\n' 'sentry = "0.44"' '@sentry/react' 'sentry_tracing' | rg -q -i "$FORBIDDEN_DEPENDENCIES"; then
  echo "privacy check failed: dependency scanner regression" >&2
  exit 1
fi

if printf '%s\n' 'scrollbar-gutter: stable;' | rg -q -i "$FORBIDDEN_DEPENDENCIES" \
  || ! printf '%s\n' '"rollbar": "3.0.0"' | rg -q -i "$FORBIDDEN_DEPENDENCIES"; then
  echo "privacy check failed: CSS scrollbar or Rollbar dependency scanner regression" >&2
  exit 1
fi

if printf '%s\n' '.plugin(tauri_plugin_dialog::init())' | rg -q "$LOGGING_PATTERN" \
  || ! printf '%s\n' 'log::info!("event")' | rg -q "$LOGGING_PATTERN"; then
  echo "privacy check failed: production logging scanner regression" >&2
  exit 1
fi

if rg -n -i "$FORBIDDEN_DEPENDENCIES" \
  "$PROJECT_ROOT/Cargo.toml" \
  "$PROJECT_ROOT/crates" \
  "$DESKTOP_DIR/package.json" \
  "$DESKTOP_DIR/src" \
  "$DESKTOP_DIR/src-tauri/Cargo.toml" \
  "$DESKTOP_DIR/src-tauri/src"; then
  echo "privacy check failed: telemetry or remote-reporting code is present" >&2
  exit 1
fi

if (
  cd "$DESKTOP_DIR"
  pnpm list --prod --json
) | rg -q -i "$FORBIDDEN_DEPENDENCIES"; then
  echo "privacy check failed: production frontend dependency tree contains a reporting SDK" >&2
  exit 1
fi

if rg -n '\b(fetch|WebSocket|EventSource|XMLHttpRequest)\b' "$DESKTOP_DIR/src"; then
  echo "privacy check failed: the desktop frontend contains a direct web transport" >&2
  exit 1
fi

if rg -n "$LOGGING_PATTERN" \
  "$PROJECT_ROOT/crates/server" \
  "$PROJECT_ROOT/crates/windows-service" \
  "$PROJECT_ROOT/apps/desktop/src-tauri/src"; then
  echo "privacy check failed: production service logging code is present" >&2
  exit 1
fi

if rg -n '(connection_history|dns_history|browsing_history|last_connected|last_disconnected|traffic_history|audit_log)' \
  "$PROJECT_ROOT/crates" \
  "$PROJECT_ROOT/apps/desktop/src-tauri/src"; then
  echo "privacy check failed: a historical activity field is present" >&2
  exit 1
fi

# These exact source forms are an inline SVG namespace and a loopback TLS test.
# A second URI scheme in the SVG must still fail the scan.
NON_NETWORK_URLS='src/styles/forms[.]css:[0-9]+:  background-image: url\("data:image/svg\+xml,%3Csvg xmlns=\x27http://www[.]w3[.]org/2000/svg\x27[^:]*"\);$|core/src/management/tests[.]rs:[0-9]+:    client[.]base_url = format!\("https://\{\}", listener[.]local_addr\(\)[.]unwrap\(\)\);$'
if printf '%s\n' \
  'src/styles/forms.css:1:  background-image: url("https://assets.example/icon.svg");' \
  "src/styles/forms.css:1:  background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3Ehttps://assets.example/%3C/svg%3E\");" \
  'core/src/management/tests.rs:1:    client.base_url = "https://service.example".into();' \
  'server/src/runtime.rs:1:    client.base_url = format!("https://{}", listener.local_addr().unwrap());' \
  | rg -q "$NON_NETWORK_URLS"; then
  echo "privacy check failed: non-network URL exception accepted a remote URL" >&2
  exit 1
fi

URL_MATCHES=$(rg -n -g '!THIRD-PARTY-NOTICES' 'https?://' \
  "$PROJECT_ROOT/crates" \
  "$DESKTOP_DIR/src" \
  "$DESKTOP_DIR/src-tauri/src" || true)
# These URL-validation fixtures use a reserved .example domain. Production
# release destinations still come only from explicit user input.
UNEXPECTED_URLS=$(printf '%s\n' "$URL_MATCHES" | rg -v "$NON_NETWORK_URLS" | rg -v 'windows-service/src/wireguard.rs:[0-9]+://! ABI source: https://git[.]zx2c4[.]com/wireguard-nt/tree/api/wireguard[.]h$' | rg -v '(features/settings/VpsUpdateDialog.test.tsx|installer/src/release_update/tests.rs|server/src/release_update/policy/tests.rs):[0-9]+:.*https?://(user:pass@)?releases[.]example/' | rg -v 'src/format.ts:[0-9]+:      const address = new URL\(`http://\[\$\{host\}\]`\).hostname;$' | rg -v \
  'management.rs:.*https://\{\}:8443|installer/src/lib.rs:.*https://\{SERVER_TUNNEL_ADDRESS\}|freedesktop.org/standards/PolicyKit|src/assets/mountains.svg:1:<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 520 660" fill="none">$|core/src/management/tests.rs:[0-9]+:.*format!\("https://\{address\}"\)|core/src/management/status_stream/tests.rs:[0-9]+:.*format!\("https://\{\}", listener.local_addr\(\).unwrap\(\)\)' || true)
if [ -n "$UNEXPECTED_URLS" ]; then
  printf '%s\n' "$UNEXPECTED_URLS" >&2
  echo "privacy check failed: unexpected production URL literal" >&2
  exit 1
fi

if rg -n 'updater|process:allow|shell:allow|http:allow' \
  "$DESKTOP_DIR/src-tauri/capabilities" \
  "$DESKTOP_DIR/src-tauri/tauri.conf.json"; then
  echo "privacy check failed: an unnecessary Tauri capability is enabled" >&2
  exit 1
fi

# Publisher provenance is data used by the separate packaging script. Its source
# URLs are never read by the offline release coordinator.
if rg -n -g '!publisher-notice-sources.json' 'reqwest|hyper|TcpStream|UdpSocket|std::net|tokio::net|https?://' \
  "$PROJECT_ROOT/crates/release" \
  "$PROJECT_ROOT/release"; then
  echo "privacy check failed: the offline release path contains networking code" >&2
  exit 1
fi

# An enrolled management certificate is the complete trust store for this client.
MANAGEMENT_CLIENT="$PROJECT_ROOT/crates/core/src/management.rs"
for invariant in \
  '.tls_built_in_root_certs(false)' \
  '.redirect(reqwest::redirect::Policy::none())' \
  '.referer(false)' \
  '.retry(reqwest::retry::never())'; do
  if ! rg -F -q "$invariant" "$MANAGEMENT_CLIENT"; then
    echo "privacy check failed: private management lost its strict trust boundary" >&2
    exit 1
  fi
done

RELEASE_FETCHER="$PROJECT_ROOT/crates/release-fetch/src/lib.rs"
for invariant in \
  '.https_only(true)' \
  '.redirect(reqwest::redirect::Policy::none())' \
  '.retry(reqwest::retry::never())' \
  '.referer(false)' \
  '.no_proxy()' \
  '.header(ACCEPT_ENCODING, "identity")'; do
  if ! rg -F -q "$invariant" "$RELEASE_FETCHER"; then
    echo "privacy check failed: the explicit release fetcher lost a network privacy invariant" >&2
    exit 1
  fi
done
if rg -n "$LOGGING_PATTERN" "$PROJECT_ROOT/crates/release-fetch"; then
  echo "privacy check failed: the release fetcher contains production logging code" >&2
  exit 1
fi

DESKTOP_RELEASE_UPDATE="$DESKTOP_DIR/src-tauri/src/release_update.rs"
for invariant in \
  'Command::new(fetcher)' \
  'const PKEXEC_BINARY: &str = "/usr/bin/pkexec"' \
  'const RELEASE_COORDINATOR_BINARY: &str = "/usr/lib/sirinvpn/sirinvpn-release"' \
  'input.confirmed' \
  'pending: Option<PendingReleaseUpdate>'; do
  if ! rg -F -q "$invariant" "$DESKTOP_RELEASE_UPDATE"; then
    echo "privacy check failed: the manual desktop release boundary lost an invariant" >&2
    exit 1
  fi
done
if rg -n 'reqwest|hyper|TcpStream|UdpSocket|std::net|tokio::net' "$DESKTOP_RELEASE_UPDATE"; then
  echo "privacy check failed: desktop release coordination contains in-process networking" >&2
  exit 1
fi

if rg -n '\b(device_id|server_id|installation_id|user_id|request_id|network_id)\b' \
  "$PROJECT_ROOT/crates/release" \
  "$PROJECT_ROOT/crates/release-fetch" \
  "$PROJECT_ROOT/release"; then
  echo "privacy check failed: release metadata contains an installation-correlating field" >&2
  exit 1
fi

echo "Privacy invariants passed."
