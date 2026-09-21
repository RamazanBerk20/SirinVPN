# Current-condition diagnostics — 7 September 2026

Run diagnostics is available on desktop and Android while disconnected. The CLI
uses `sirinvpn diagnose SERVER_ID`. The native layer reads current state on demand;
no report is written, automatically uploaded or added to a history store.

## Local checks and remote reachability

The report distinguishes an unavailable native service, a disconnected or
recovering tunnel, another selected server, a user-paused reconnect, current
traffic protection, concrete transport, routing scope, IPv6 handling, available
quality samples and MTU state. Configured routing is described as configuration,
not an independent packet-level proof. Missing readings remain unknown.

Remote checks run only when current native state matches the selected connected
server. Desktop/CLI private DNS and management sockets bind to that device's
private tunnel address. Android DNS additionally binds to the exact Android VPN
Network whose link address matches the active native configuration. The DNS probe
asks only for the DNS root's NS record at the private VPS address, has a
three-second deadline, and validates the transaction ID and question. It reports
SERVFAIL, refusal, timeout and malformed responses separately.

Android also reports its current underlying network capability: offline,
captive portal, validated or unvalidated. This reads Android's current observation;
SirinVPN does not send an external connectivity probe for it. Current VPN permission
and invalid retained connection plans receive actionable checks.

Saved identity parsing is separate from current VPS authorization. Diagnostic
management requests use pinned TLS 1.3/mTLS and no system proxy or redirects.
Typed TLS errors establish a TLS handshake failure; typed timeouts establish a
request timeout. Other connection failures do not pretend to identify an invalid
certificate or blocked UDP. Authorization rejection directs the owner to device
revocation, suspension, expiration and UTC access schedules. Pins are never
replaced or bypassed by diagnostics.

The desktop/native request has a sixteen-second response deadline and one active
worker. An already-waiting native read may finish afterward, but keeps the worker
slot and cannot start new probe work after cancellation is observed. Late results
are discarded. Android identity maintenance serializes against the request.

## VPS observations

Only a currently authorized device can request or receive the server report.
Authorization is checked again after collection. One request collects at a time.
Commands have one-second deadlines and bounded output; raw stdout/stderr does not
enter the report. No command changes routes, firewall state or services.

The server inspects:

- Its configured interface, current WireGuard public identity/listening port and
  IPv4 forwarding; optional IPv6 forwarding/private addressing.
- External default and owned tunnel-subnet routes in the main routing table.
- Owned nftables input/forward hooks and tunnel-isolation structure; owned IPv4
  and optional IPv6 source masquerade rules for the current tunnel subnet.
- Listening sockets for configured VPN transports, private management and DNS;
  no peer endpoint, process list or unrelated listener is exported.
- System service activation, interface MTU minimum and current CPU/memory/disk
  capacity. CPU uses a short in-memory sample, not a retained trend.
- Actual private-resolver, configured encrypted upstream and split-zone DNS replies.

A table/listener being present does not prove all firewall semantics or provider
reachability. The report states those limits. Missing tools/permissions produce
an unavailable reading, not a healthy result. It does not capture packets, inspect
browsing destinations or guess a private key from a command dump.

## Sanitization and lifetime

The management client reconstructs remote checks from known codes and a fixed
message vocabulary. It discards remote free-form labels, unknown/duplicate codes
and arbitrary error text. Known DNS causes and bounded numeric resource/latency
values survive; zone labels use indexes. Rejected incoming strings are cleared
where practical. The raw response buffer is already bounded and zeroized.

The UI reports pass/review/attention counts. Closing the desktop dialog, changing
server, leaving Android Diagnostics or pressing Clear results releases the report.
Generation checks prevent a late response from repopulating a closed/replaced
view. Copy sanitized report is explicit and copies only displayed check fields;
the operating system clipboard then retains that user-requested copy.

## Focused verification

- Five core checks cover sanitization, numeric bounds, current-server/recovery
  gating, MTU suggestions, typed TLS causes and a real loopback DNS exchange.
- Five server/DNS checks cover route selection, exact NAT source/hook matching,
  listener parsing, unavailable/high resource readings and DNS response validation.
- A real loopback TLS fixture verifies rejection/classification of an impostor certificate and no redirect following. Nested I/O error causes retain their typed TLS evidence.
- Nineteen UI tests pass for desktop workspace, Android administration and
  explicit copying; they include report disposal and disconnected operation.
- Seven native Android JVM tests pass; instrumentation sources compile.
- Desktop/CLI/server compile, Android Rust cross-compilation and Windows test-target
  cross-compilation pass. These are not platform networking acceptance tests.

Implementation uses the [nftables JSON contract](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html)
and [Linux current network tables](https://www.man7.org/linux/man-pages/man5/proc_pid_net.5.html).
Full packet-level, device and final-package acceptance remains in the next phase.
