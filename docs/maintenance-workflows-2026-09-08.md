# Maintenance workflows — 8 September 2026

This pass keeps Home's layout, palette, font families and main-page sizing. It
brings repair, VPS updates and diagnostics into the same component system, then
clarifies the scope of automation, application routing, MTU and owner recovery.

## Repair and shared dialogs

Repair completion now uses a short result heading above left-aligned details.
Completed checks, preserved settings and unverified external network conditions
are separate. Ports wrap horizontally in normal document flow. Docker and other
firewall-table observations appear under network details; their presence alone
does not produce a warning. Provider firewall access is explicitly unverified.

The result describes completed work in the past tense. Private DNS verification
and the number of configured private records have separate rows. Preservation
wording follows the requested repair options. The server identity fingerprint
comes from the pinned management public key, with Copy and Show full controls.
The installed software's SHA-256 is a different field under software details.
Return to Home is the final action.

Dialogs share a persistent title and close control, a scrolling body and an
optional persistent action footer. Diagnostic names and form controls use the
main interface's readable typography roles. Long-content dialogs initially focus
the title, retain modal focus trapping and restore focus on close. During an
uninterruptible maintenance operation, the close control stays visible but is
disabled, Escape and outside dismissal are blocked, and the footer explains why.

## VPS updates

First-time setup now leads through choosing a release source, verifying the
release and explicitly finishing setup. A matching authenticated installation can
be registered without reinstalling it; a required software installation has its
own review and explicit action. Routine updates show installed and available
versions, channel, verification, compatibility and restart notes. Source changes,
rollback and download/privacy details remain available as secondary controls.

The source is reused from the VPS policy or this VPS's last successfully verified
source preference. The local preference stores a download location, never a new
trusted signing key. Source changes invalidate the current review. Native trusted
root verification, signed baseline and candidate binding, compatibility checks,
rollback protections and interrupted-transaction recovery remain mandatory.

Checking never installs a release or enables automatic updates. The schedule has
explicit disabled, saved, unsaved and failure states. Saving reads back the VPS
policy before claiming success. Disabling an existing schedule remains possible
when release verification fails. After installation, the application checks the
active version and installed-byte verification before reporting completion.

## Diagnostics and current observations

Needs attention, Review and unavailable results appear before collapsed passed
checks. Fixed evidence labels distinguish Configuration inspected, Service
reported, Observed test result and Not checked. Unrecognized report codes receive
a conservative label. Reading an armed service state does not claim a complete
traffic-leak test. Reports remain in memory until the dialog closes; only an
explicit action copies sanitized text to the clipboard.

Home details now show latency only from a valid received private-tunnel ICMP
sample belonging to the active transport. Management-request duration is not used
as tunnel latency. Existing tests cover stale server metrics and native
measurement bounds. MTU details show current, recommended and pending values only
when the native service supplies them. Copy explains that automatic detection can
adjust an eligible protected, idle tunnel, while changing the saved MTU preference
applies on the next connection.

## Feature boundaries

- Wi-Fi trust describes a user exception, not a network security assessment. The
  friendly name is optional, and unavailable recognition has an adjacent reason.
  The page refreshes current automation status, displays a manual-disconnect
  pause and blocks trusting a different network until it is reviewed. Its chosen
  automation server is independent of sidebar navigation. Monitoring continues
  while the app is hidden to the tray and stops on Quit app. Only current
  preferences and explicitly saved exceptions are retained.
- Startup connection has compact saved, active and unavailable states. The
  existing Connect & activate startup action remains available.
- Linux application routing explicitly covers applications launched through
  SirinVPN; already-running processes keep their existing network context. Home,
  DNS and protection copy state that scope. Windows retains its distinct native
  executable-routing explanation.
- Owner recovery explains that the material is kept offline and the VPS performs
  validation online. Add server offers Recovery key on a fresh client before an
  ordinary authorized connection exists.
- Legacy default owner-device names receive a recognizable local display name
  with their saved name still available. The forwarding target select uses the
  app font. Native tray status rows use normal menu contrast and open Home without
  a connection action.

## Evidence and packages

The [workflow handoff](../target/deliverables/2026-09-08/workflow-fixes/README.md)
records the exact package and source hashes, checks, screenshots and limitations.

| Verification | Result | Execution |
| --- | --- | --- |
| Frontend tests | 182 passed in 38 files | Rerun inside the Linux package build |
| Native Rust tests | 329 passed | Core, desktop, installer, helper, release and server |
| Deferred kernel tests | 15 tests, 16 cases passed | Real Debian guest kernel, isolated containers |
| Packaged Linux acceptance | 26 checks passed | Fresh client and VPS guests, including actual GUI closure |
| Native tray | 10 checks passed | Real GTK/DBus menu with an isolated synthetic helper |
| Browser workflows | Three viewport sizes, 42 screenshots, no page errors | Synthetic native replies |
| Package inspection | All five application packages passed | Extracted binaries, resources, architectures and hashes |
| Code checks | Passed | TypeScript/Vite, host and Windows cross-target Clippy, formatting, privacy and whitespace |

Browser workflow checks use synthetic native replies at 1220×780, 1024×680 and
390×844. They cover repair layout, busy dismissal, setup and routine updating,
schedule failure, persistent headings, keyboard focus, diagnostics ordering,
latency, Wi-Fi network changes and fresh-client recovery. The native Linux tray
uses the real GTK/DBus menu with an isolated deterministic helper.

Native tests cover updater verification and interruption boundaries, repair
rollback, policy transitions and recovery authorization. The disposable kernel
suite exercises real packet, DNS, IPv6, application-routing, MTU and owner-recovery
behavior. The packaged Linux acceptance lab adds real GUI closure and all four
kill-switch/reconnect interruption combinations to its existing transport,
DNS-failure, reboot and cleanup checks. Results distinguish these execution
levels rather than treating a green status label as security evidence.

The interruption fault blocks the guest VPS ports and removes the client guest's
tunnel interface. DNS and IPv6 escape probes run for the kill-switch-enabled
cases. Helper restart is checked with the kill switch and reconnect enabled.
The earlier first attempt exposed a probe-fixture assumption: an active kernel
rule can reject UDP `sendto` itself with `EPERM`. The fixture now records specific
route/policy denials while still requiring zero escaped physical packets;
unexpected socket errors still fail. The unchanged Debian package passed the
complete rerun. No product networking code changed for this correction.

Native tray checks cover Reconnect without Disconnect, the active-server target,
confirmed switching, paused recovery, failed Disconnect and quit staying open,
acknowledged disconnection before exit, unknown helper status and ordinary Quit
without a VPN mutation. The source inventory has no files above 1,000 lines.

Builds run sequentially with at most 4 GiB memory, 150% CPU, two Cargo jobs and no
additional swap. The user's live VPS and VPN are not modified by these tests.
The prior successful live repair remains documented separately.

Windows and Android packages still require native platform acceptance. The
Windows engineering driver requires normal Microsoft signing before executable
routing can enable; Android APKs use development signing. These packages and
checksums are an engineering handoff, not a publisher-signed update feed.
