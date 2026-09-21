# Operational UX revision — 5 September 2026

This revision implements the supplied interface audit while retaining the existing
Linux and Android feature boundaries. It keeps the SirinVPN identity and centered
connection control, and replaces promotional Home content with operational status,
this device's traffic, and a quieter VPS overview.

## Confirmed issues and corrections

| Finding | Correction |
| --- | --- |
| A failed local status read substituted false protection flags | Status becomes explicitly unknown. Stale values cannot enable Connect, label protection Off, or enable an app update. Refresh remains available. |
| Configured protection looked like verified enforcement | Runtime configuration, next-connection choices, and firewall enforcement are labeled separately. Linux read-only status cannot independently verify nftables enforcement; kill-switch and IPv6-blocking details say so. |
| Management failures obscured data-plane connectivity | A failed management request clears server measurements while preserving independently obtained local tunnel status and device counters. |
| VPS packet counts occupied the device-traffic role | Linux reports local interface packets, byte rates, and current tunnel duration. VPS totals remain server-wide. Android supplies byte rates/totals and native monotonic tunnel duration; unavailable packet counts are identified. |
| Authorized count depended on server interface availability | Authorization count now remains the authorization count even if the interface is down. A separate optional recent-handshake count uses authorized keys only. |
| Repeated slogans, status cards, and framing consumed the viewport | Home uses a compact server header, an explicit Connect/Disconnect action, scoped device traffic, resources, and expandable technical details. Sidebar decoration and the duplicate update shortcut are removed. |
| Device actions required expanding technical details | Compact rows show activity text, member/role, address, and a keyboard-operable action menu. Expansion contains technical details and short/copyable/revealable fingerprints. |
| Settings scopes were mixed | General; Connection; Network; Keys & recovery; VPS maintenance. Tabs retain context while scrolling and scroll horizontally within their own region on narrow screens. |
| Port forwarding was hidden under Devices → Advanced | Network contains the existing forwarding workflow, an explicit public-exposure notice, responsive fields, and a mapping preview before confirmation. |
| Collection cards had an ambiguous action | Open selects the server and shows Home without connecting. Separate actions rename locally, favorite, and open maintenance. Endpoints are named and copyable. |
| Enlarged text clipped native fields and sidebar content | The shell uses a text-relative width, form heights grow with text, and metric grids reflow before values clip. |
| First-run Android Settings retained the large onboarding header | Operational pages now use the compact header even before enrollment. Unknown platform protection uses a neutral question icon. |
| Notification initialization issued a blocked permission query | The capability policy now permits that read-only query. Direct plugin notification delivery remains blocked; app-owned preference and privacy controls still govern delivery. |

General preferences retain startup, minimized launch, tray, private notifications,
and reduced-motion behavior. Save errors and success appear beside the changed
control. Closing/quitting the GUI continues to leave the VPN running; the native
tray's quit action already states this. Invitation expiration, member roles,
last-owner restrictions, key rotation, and confirmation/rollback workflows are
preserved. No live VPS was modified.

The [feature map](overhaul-feature-map.md) records the current entry points.
Source comparison retains all 53 direct UI API references from the committed
baseline, with five additions and none removed. Runtime tests separately exercise
the role guards, enrollment, backup, recovery, and connection workflows.

## Measurement and compatibility boundaries

- Device counters belong to the current tunnel interface. Reconnect recreates the
  counter scope. Rates use one previous in-memory observation, and discard samples
  across counter resets, session changes, failures, and long pauses. Counter epochs
  identify only the current runtime; no traffic history is written.
- VPS uptime is host uptime. Storage is the root filesystem. VPS traffic combines
  all devices on the server VPN interface. Management response measures an
  authenticated status request and is not advertised as tunnel latency.
- Recently active means a WireGuard handshake within three minutes. It is not a
  promise of current connectivity. Unknown activity remains unknown. Unavailable
  status requests and absent optional measurements are not presented as zero or
  Healthy.
- The local helper must be updated for the new Linux counters. Existing VPSs need
  **Settings → VPS maintenance → Update VPS software** to provide new optional
  server measurements. The guarded workflow requires disconnecting and verified
  SSH access. Older servers remain usable with missing measurements unavailable.
- Connection and routing choices are next-connection drafts retained while that
  server is open. App-wide preferences, local server names/favorites, and native
  persistent protection retain their existing disk-backed lifetimes. The UI does
  not claim that every connection draft survives an app restart.
- Android still lacks general membership administration, selected-route policy,
  server maintenance beyond enrollment/uninstall, and packet-count reporting.
  Those pre-existing capability boundaries are explicit in Settings; no unsupported
  functional switches were added.

## Verification and delivery

Final results, artifact hashes, and measured source counts are recorded in
[the evidence manifest](audit/2026-09-05/operational-ux.json).
The verification covers state reconciliation, roles/actions, local collection
persistence, reset-safe rates, existing enrollment/recovery tests, native rendering,
keyboard focus, mobile layouts, 200% text enlargement, and automated accessibility.

The final repository gate passed **279 Rust tests**, **63 frontend tests**, two
Python tests, warning-free Clippy, Rust formatting, the production frontend build,
privacy checks, and policy XML validation. The optional ShellCheck pass was skipped
because ShellCheck is not installed. The source inventory covers **312 first-party
files**, with **zero over 1,000 lines**. This file-size gate complements the module
extraction; it does not by itself establish that every module is well designed.

The browser pass covers **11 platform/viewport scenarios** and **14 additional
fault, collection, long-content, and enlarged-text checks**, with **zero automated
accessibility findings**. Three native WebKitGTK layout checks and the notification
capability boundary check pass. Screenshots
include [Home](../.cache/operational-ux/screenshots/desktop-connected-1220-home.png),
[Devices](../.cache/operational-ux/screenshots/desktop-connected-1220-devices.png),
[Network settings](../.cache/operational-ux/screenshots/desktop-connected-1220-settings-network.png),
and [unknown local status](../.cache/operational-ux/screenshots/operational-local-unknown.png).

The Pixel 10 emulator passed **six native instrumentation tests** (five VPN and
one secure-storage test). The final x86_64 debug APK was installed and cold-launched;
its real Keystore/identity checks, native status contract, compact Settings header,
unknown-protection display, and system Back navigation passed. Three native
preference checks verified unsupported-setting rejection, actual notification
delivery, and persistence across a full app restart. Original preferences and
notification permission were restored. APK inspection verified backup exclusions
and both current x86_64/aarch64 VPS payloads; the app itself is an x86_64 emulator
build, not a production phone release.

Browser and WebKitGTK review screenshots use synthetic VPS responses. The Android
native smoke test uses the installed APK, actual Keystore, and actual native bridge.
These checks do not establish live traffic, firewall enforcement, or full production
Android qualification. The accessibility checks follow the W3C guidance for
[contrast](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum),
[text enlargement](https://www.w3.org/WAI/WCAG21/Understanding/resize-text),
[focus](https://www.w3.org/WAI/WCAG22/Understanding/focus-visible.html), and
[status messages](https://www.w3.org/WAI/WCAG22/Understanding/status-messages.html).
Automated findings and the tested layouts are evidence, not a blanket conformance claim.

This revision introduces no additional dependencies beyond the earlier same-day
settings update. That [dependency audit](audit/2026-09-05/results.json) reported zero
Rust vulnerability entries and zero affected packages among 79 resolved Maven
packages, plus **17 upstream Rust warnings**, including GTK3 maintenance warnings
and a GLib unsoundness advisory. Those warnings remain unresolved; this UI work
does not imply a clean security bill for the dependency stack. The frontend also
retains a build warning about its main JavaScript chunk exceeding 500 kB.

- [Linux AppImage](../target/release/bundle/appimage/SirinVPN_0.1.0_amd64.AppImage)
- [Debian package](../target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb)
- [Android emulator APK](../apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk)
- [Review screenshots](../.cache/operational-ux/screenshots)

## Completion and next step

The original project overhaul acceptance remains **23/24 = 95.8%**, with the full
live-network fault matrix still partial. This is a percentage of the documented
[acceptance checklist](overhaul-checklist.md), not a percentage guarantee that the
product is complete or secure. This interface revision does not claim credit for
untested network qualification.

Next, qualify protection and reconnection on disposable client/server systems:
management loss while traffic continues, real nftables enforcement, DNS failures,
carrier/MTU changes, IPv6, reboot, and interrupted recovery. Then build/sign an ARM64
Android release and test a physical phone. Independent effective-firewall status
and Android management parity remain substantive product work beyond this UI revision.
