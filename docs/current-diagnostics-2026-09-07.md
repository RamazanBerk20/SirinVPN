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

## VPS operating-system updates (1 November 2026)

VPS diagnostics add two checks that never fail the report, because neither affects the
tunnel itself:

- `os_security_updates` passes when `unattended-upgrades` is installed,
  `APT::Periodic::Unattended-Upgrade` is non-zero (read with `apt-config`) and
  `apt-daily-upgrade.timer` is enabled. Otherwise it warns.
- `os_reboot_required` warns when `/run/reboot-required` exists, or when a
  `/boot/vmlinuz-*` file's inode change time is after the boot time in `/proc/stat`. It
  uses the change time because dpkg keeps a package's build time as the file's mtime.

The server reads these locally on request and keeps nothing. The client replaces the
VPS text with fixed messages and turns any failure level into a warning. Debian 13 and
Ubuntu 24.04 cloud images ship with unattended-upgrades on. The installer installs and
enables it only on a VPS where it is missing. It leaves an existing setup, including a
deliberately disabled one, unchanged, and it never restarts the VPS.

## Leak test (31 October 2026)

While connected, desktop, CLI and Android diagnostics add `leak_ipv4`, `leak_ipv6` and
`leak_dns` checks with a pass, fail or `not_applicable` level. The test uses only
the user's VPS: a pinned mTLS request to a documentation address that the VPS
redirects only from the tunnel, and a system lookup of a one-off name in a zone
only the VPS resolver answers. The VPS echoes the request's source address and
keeps nothing. A VPS report cannot add these codes or the `not_applicable` level;
the sanitizer drops both. Android appends the checks to its VPS report.
See [architecture](architecture.md#leak-test) for the exact mechanism and limits.

Evidence: unit and handler tests; a real `serve_management` reached over TLS by
the `sirinvpn.local` name; `tests/network/run-leak-test.sh` over a real WireGuard
link from a full-tunnel namespace (IPv4 and IPv6 redirected, tunnel sources
reported); and Unbound 1.26.2 (Debian 13) and 1.19.2 (Ubuntu 24.04) answering
random leak-test names with `10.77.0.1` through `getaddrinfo` with DNSSEC on.
The two-VM lab step was added but not completed: on 31 October the VPS could not
download the blocklist and the client guest's package mirror ran at about
72 KB/s, so neither run reached it. Android: unit tests map the active tunnel's
routing and IPv6 state; the leak test has not yet run on an emulator against the
isolated VPS.

## Speed test (1 November 2026)

The Owner or an Admin can run `sirinvpn speed-test <server>`, or the speed test
under the desktop and Android diagnostics results. It measures download, upload and
latency (idle, during download, during upload) through the tunnel to the user's
own VPS over one connection, and says it is not internet speed. Members don't see
it, and the VPS refuses them. The result is shown once and kept nowhere; the VPS
logs nothing. See [architecture](architecture.md#speed-test) for the limits.

Evidence: limiter, handler and cap tests (paused time); the real `serve_management`
carrying a 2 MiB chunked upload past the router's 64 KiB body limit and a streamed
download over pinned TLS; client rate, median, body and message tests; and
`tests/network/run-speed-test.sh`. There the real client in a full-tunnel
namespace runs over kernel WireGuard shaped to 100 Mbit/s each way, so both
directions take the full eight seconds. It measured 96.2 Mbit/s down and up, with
latency 0.95 ms idle, 11.0 ms during download and 10.7 ms during upload, and an
immediate second run was refused by the cooldown. The first two-VM lab run found
that the client's 8-second read timeout, which reqwest also applies to the wait for
response headers, ended every full-length upload; the shaped kernel test fails the
same way without the fix. With the fix, the full two-VM lab passed (31 steps, Debian
13 client and VPS, package at 82e494a). In its new step the packaged CLI measured
1.63 Gbit/s down and 1.04 Gbit/s up, with latency 0.2 ms idle, 6.4 ms during
download and 6.1 ms during upload. The repeat was refused, the physical network saw
no DNS or IPv6, and the VPS journal didn't mention the test. The desktop component has UI tests; Android shares that UI and the
runtime command passes Android-target clippy but has not run on an emulator.

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
