# SirinVPN Android rebuild prompt

Deferred at the owner's request on 13 September 2026, until the desktop version
is finished. The attempted replacement was deleted. This brief is historical
reference for a future explicitly requested project; it is not active work or a
claim that these features or performance targets have been delivered.

---

You are rebuilding SirinVPN for Android from scratch in this repository:

`/home/ramazan/Belgeler/AI/Code/SirinVPN`

The previous Android app was removed on 13 September 2026 and uninstalled from
my Samsung phone. The desktop app works well. Preserve its behavior, appearance,
profiles, keys, build process and compatibility with existing servers.

I want a fast, dependable Android VPN client. The old app frequently took seconds
to show local state, froze controls behind unrelated work, showed inconsistent
connection states, and sometimes restarted after an explicit disconnect. Features
were added faster than their interaction and lifecycle could be verified. The new
implementation must earn additional scope through working, measured releases.

## 1. Establish the boundaries first

Read the repository instructions, README, PRIVACY.md, SECURITY.md,
docs/architecture.md and docs/android-reset-2026-09-13.md. Inspect the current
server and protocol implementation before choosing libraries or proposing API
changes. Historical Android reports describe a retired implementation; their
passing tests are not evidence for this new app.

Build a standalone native Android application under `apps/android`, using Kotlin,
Jetpack Compose and Android's VPN APIs. Give it its own Gradle wrapper, dependency
locks or verification metadata, build variants and Android tests. Do not recreate
the Tauri/WebView Android client inside `apps/desktop`, restore the removed
plugins, or copy their connection controllers into a new directory.

Reuse verified protocol, cryptography and carrier implementations where that
reduces risk. Prefer a maintained WireGuard backend over implementing WireGuard.
If shared Rust is needed, expose a small typed native boundary with explicit
ownership, cancellation and errors. Document its call graph and dependency
footprint. Keep SSH provisioning and other optional libraries off the startup
path. Do not rewrite the server protocol or invent new cryptography to simplify
the Android implementation.

Verify current stable Android, Kotlin, Compose, Gradle, WireGuard and native
dependency compatibility using primary documentation. Pin selected versions and
explain the minimum supported Android version. My primary acceptance device is a
Samsung SM-S936B running Android 16; discover the currently attached device rather
than assuming a serial number. Do not use private/hidden OS APIs.

Before coding, produce a short architecture decision, module map, state-transition
table and testable milestone plan. Then implement milestone 1. Routine reversible
engineering work does not need repeated approval.

## 2. Make connection ownership unambiguous

The VPN service and a single connection coordinator own the live session. Compose
screens, notifications and Quick Settings only observe state and submit commands.
An Activity, screen, ViewModel, navigation change or UI collector must never own
the lifetime of the tunnel. Use one-way observable state consistent with the
[Compose architecture guidance](https://developer.android.com/develop/ui/compose/architecture).

Use explicit states such as Idle, Preparing, Connecting, Connected, Recovering,
Stopping and Failed, with permission/system-protection conditions represented
separately. Include session identity and a monotonically changing operation
generation. Distinguish desired intent, actual local interface state and verified
VPN reachability. An old result must never overwrite a newer command or session.

Connect, Cancel and Disconnect must be idempotent. Cancellation must interrupt
connection preparation, DNS, transport handshakes and retries. Slow I/O must not
hold a global lock that blocks status reads or stopping. Use structured
concurrency, bounded waits and explicit ownership of sockets/file descriptors.
The UI should acknowledge a command immediately and then display its real phase.
Do not label the VPN connected merely because the interface was created.

For an app-controlled session, explicit Disconnect must durably disarm recovery
before teardown, cancel outstanding work, close the owned tunnel/carriers and
remove the active notification. A late success callback, network change, tile
refresh, process restart or reopening the app must not reconnect it. Retain the
saved profile and last-selected server independently from automatic restart intent.

Use a separate service process only if there is a demonstrated requirement and a
tested IPC design. Do not recreate several competing controllers, queues and
recovery loops. Keep the initial implementation easy to reason about.

## 3. Follow Android lifecycle and protection semantics

Swiping the app away from Recents must leave an established, intended VPN running.
Support screen-off operation, Activity recreation, network loss, Wi-Fi/cellular
handover and bounded recovery without opening the UI. Handle permission revocation
and service restarts explicitly. Distinguish Recents dismissal, process death and
the user's Force stop action; do not promise to bypass Android's Force stop rules.

Implement consent, socket protection, foreground service handling and cleanup
using the official [VpnService API](https://developer.android.com/reference/android/net/VpnService).
Protect carrier sockets from routing into their own tunnel. Do not bind all
application traffic to the underlay: private management traffic belongs on the
authenticated VPN path. Audit both address families and DNS behavior.

Android's Always-on VPN and “Block connections without VPN” are system settings.
Show their actual supported/current state and provide access to Settings. Never
present a saved checkbox as proof that traffic is blocked. Treat system-managed
Always-on as a separate operating mode: the Android VPN guide directs apps to
disable app-owned disconnect controls in that mode. Offer the appropriate system
settings action rather than displaying a successful disconnect that Android
immediately reverses. Explain this clearly in the design and test it on the phone.
See the [official Always-on behavior](https://developer.android.com/develop/connectivity/vpn#always-on).

Do not require Always-on/lockdown merely to keep an ordinary foreground VPN alive
after closing the UI. If the user requests strict blocking, verify the system
prerequisites and explain that disabling the tunnel can leave system traffic
blocked. Never silently weaken a requested protection policy.

Persist only the minimum encrypted session intent needed for supported recovery.
Define behavior before and after device unlock. Avoid periodic restart alarms,
polling loops or battery-exemption requests without measured necessity.

## 4. Make local state and navigation fast

Render the real initial UI from local state. A person with saved profiles should
not briefly see “Add your VPN” while initialization is still running. Use a small
loading state only for genuinely unresolved data; navigation must remain usable.
Do not generate temporary identities, perform cryptographic round-trip self-tests,
scan applications, open management connections or run diagnostics on every launch.

Publish a coherent immutable local status snapshot. Reading it must not trigger
DNS, remote HTTP, expensive storage decryption or the connection mutation queue.
High-frequency counters should update their own small UI area. Stop unnecessary
UI collection when screens are not visible without stopping the VPN itself.

Use pooled authenticated management clients and independent cancellable reads.
Show a bounded, profile/device-scoped Devices cache immediately, then refresh it.
Keep local VPN status independent of a slow or unavailable VPS management request.
Cancel stale screen requests on navigation or server/session change. Prevent old
responses from crossing identity or role boundaries. Revalidate authorization for
privileged mutations; a stale Devices cache is not permission to act.

Show actionable failures and retry controls. “Unknown” must not become a permanent
disabled screen. Keep Cancel/Stop available when appropriate even when unrelated
metadata cannot load. Never fabricate counters or connection health.

## 5. Product behavior and native controls

Use the existing desktop visual identity as a reference, adapted to native mobile
navigation. Keep Home, Servers, Devices and Settings straightforward, with readable
text, proper insets, accessible touch targets and clear spacing. Test larger text,
keyboard visibility and TalkBack. Avoid long technical paragraphs in ordinary
flows; details belong in disclosures when they help a decision.

Use the approved logo exactly as the source:
`apps/desktop/src/assets/sirin-mark.png`.
Create Android adaptive, legacy and monochrome assets with comfortable safe-area
padding. Check the actual Samsung launcher crop; the mark must not touch the mask.
Do not alter the desktop master asset or invent another logo.

Each device has one canonical shared device name, entered once and shown
consistently to every viewer. A local “This device” badge is fine; replacing its
name with “My computer” or displaying a second “Saved device name” is not. Keep
Owner/Admin/Member roles clear. Do not expose a member's device name as an “Access
group.” Preserve the server's internal membership model without duplicating it in
the naming flow.

Provide one native ongoing VPN notification while the service is active, with
accurate state, server label, download/upload rates when available, and the
appropriate Disconnect/Settings action. Avoid duplicate colored logos and repeated
rate rows. Use Android's notification templates and sensible lock-screen privacy.
A normal Disconnect action should target the service directly and leave the shade
open where the OS permits; it must not launch a disposable Activity or kill the
entire app process. See [notification construction](https://developer.android.com/develop/ui/compose/notifications/create-notification).

Add a Quick Settings tile after the basic lifecycle passes. It must use the same
command path and refresh after every transition, including disconnects from the
app, notification, system and tile itself. An ordinary toggle should not launch
the full app; missing profile/consent may open the necessary UI. Follow the
[official TileService lifecycle and add-tile flow](https://developer.android.com/develop/ui/views/quicksettings-tiles).
Do not confuse a Quick Settings tile, notification and home-screen AppWidget in
the UI or documentation. A separate launcher widget can be a later milestone.

“Add tile” and “Enable VPN notifications” must reflect real setup state. Refresh
permission/channel state on returning from Settings. Use supported tile lifecycle
callbacks; do not claim an OS query exists if it does not. When setup is confirmed,
show that and disable the redundant setup action; restore it when the system
reports removal/revocation. Handle unknown state explicitly.

Remove the old separate in-app notification toggle/test-alert feature on Android.
Byte counters and packet counters are different capabilities: show only what the
chosen backend really measures, with a short explanation for unsupported fields.
“Public reachability not checked” means a check was not performed, not a detected
firewall fault. A successful transport proves only its tested path.

## 6. Preserve security and interoperability

Match the current signed invitation, enrollment, device identity, endpoint and
pinned management contracts in `crates/protocol`, `crates/core` and
`crates/server`. Generate device keys locally. Verify certificate/key bindings and
server pins, reject malformed/expired inputs, bound message sizes and preserve
retry safety. Do not introduce trust-all TLS, automatic pin replacement or public
management API bypasses.

Keep private material in app-private encrypted storage with a non-exportable
Keystore wrapping key. Make migrations atomic and versioned; explicitly handle
key invalidation and corrupt records. Exclude secrets from automatic backups,
logs, analytics, screenshots used as test evidence and crash attachments. Export
only through an explicit encrypted backup flow. Do not retain traffic, DNS,
connection or discovered-network histories. Preserve the project's no-account,
no-telemetry design.

Uninstall erased this phone's old profiles and private device keys. Plan for fresh
enrollment with a separate test device identity. Do not revoke or overwrite the
working desktop identity, reinstall the production VPS, or change live server
policy just to make a test pass. Ask for missing fixture access only when needed.

## 7. Deliver in gated milestones

**Milestone 1 — prove the core.** Implement local profile persistence, a compatible
invitation enrollment path, Direct UDP, explicit Connect/Cancel/Disconnect, truthful
status, a basic required service notification, permission flows and Recents-safe
ownership. Cover denial, offline startup, failed handshake, cancellation and
relaunch after stop. Produce and test an actual release APK before expanding scope.

**Milestone 2 — daily use.** Add the tile, polished notification, system-protection
awareness, cached Devices, accurate counters and measured network/process recovery.
Repeat the lifecycle and responsiveness tests after each addition. Keep all entry
points consistent. Do not add optional automation to repair an ownership defect.

**Later scope — deliberate parity.** Inventory desktop capabilities and state which
ones the Android product actually needs: additional authenticated transports and
fallback, routing/LAN policy, QR scanning, administration, DNS/forwarding,
backup/recovery, key rotation, endpoint migration, SSH provisioning/maintenance and
signed updates. Design small vertical milestones for them after the core is
accepted. Do not display controls for unimplemented capabilities or silently label
a Direct-UDP-only app as complete feature parity.

**Wi-Fi trust and automatic connection are excluded until I provide a separate
prompt.** Ordinary network handover for an already intended connection is required;
it is not authorization to reintroduce trusted-Wi-Fi rules, location permissions,
network-triggered auto-connect or hidden Wi-Fi recovery plans.

## 8. Measure release performance and failure behavior

These are proposed acceptance budgets on the reference phone, not existing results:

| Interaction | Target at the 95th percentile |
| --- | --- |
| Visible feedback after a tap | 100 ms |
| Local service status reaches a visible observer | 250 ms |
| Cold launch to usable saved-profile Home | 2 seconds |
| Warm return to usable Home | 500 ms |
| Cached Devices shown | 100 ms |
| Fresh Devices on a healthy established VPN, VPS RTT under 50 ms | 2 seconds |
| Cancel/Disconnect completes local teardown | 2 seconds |
| Direct UDP reaches verified connectivity on a healthy network | 3 seconds |

Separate local processing, OS scheduling/consent and remote network time in the
results. Permission dialogs are separate flows. Do not hide timeouts, discard slow
runs or loosen budgets without reporting the evidence and reason. Usable means
the correct screen and enabled intended controls, not merely the first frame.
Measure initial and full display separately using the
[startup measurement guidance](https://developer.android.com/topic/performance/vitals/launch-time).

Use a non-debuggable, optimized release variant with known signing identity for
phone acceptance; use an appropriate profileable benchmark variant for tracing.
Record build hash, dependency versions, device/OS, network, sample count, median,
p95 and failures. Use at least 20 measured repetitions for startup and basic
operations. Follow [Macrobenchmark guidance](https://developer.android.com/topic/performance/benchmarking/macrobenchmark-overview)
and inspect Perfetto traces for missed budgets. Add baseline profiles if measurement
justifies them. Do not call a debug-signed local build a production-signed release.

Required regressions include rapidly alternating commands; cancel during DNS and
handshake; a late successful connect after stop; switching servers mid-request;
disconnect from every control; reopening after stop; Recents dismissal; service
restart; screen off; Wi-Fi/cellular transitions; connectivity loss; permission
revocation; denied notifications; and Always-on/lockdown combinations. Test that
unreachable Devices/diagnostics never block local controls. Check idle wakeups,
battery use and unbounded growth during a prolonged background connection.

Keep pure coordinator transitions unit-testable, then verify Android ownership,
routing, notification and tile behavior with instrumentation and the physical
phone. Distinguish a simulated test, an emulator test and a real network test.
Retain exact sanitized results. A passing build is not lifecycle acceptance.

## 9. What to deliver

Deliver the milestone's source, reproducible build commands, test results,
performance report, exact release APK path/hash/signing description and a short
phone test guide. Install the release on my explicitly available test phone after
checking device availability and obtaining any genuinely missing setup data.
Preserve its new profiles on subsequent updates; do not uninstall to bypass a
signing mismatch without asking.

Run the repository's relevant desktop/server regression gates after shared-code
changes. Report limitations precisely, including tests not run. Fix foundational
state and lifecycle failures before adding features. Finish milestone 1 and stop
for acceptance; do not automatically expand into later milestones or Wi-Fi work.
