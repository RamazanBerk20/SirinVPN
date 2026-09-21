# Native tray connection controls

Implemented the first tray milestone using the existing native Tauri menu. Connection actions execute in Rust while the window is hidden. The current layout, title bar, border, fonts, notifications, and background VPN lifetime are preserved.

## Available controls

| Control | Behavior |
| --- | --- |
| Status and kill switch | Disabled information rows show the local connection and acknowledged protection. Unavailable observations remain unknown. |
| Connect / Disconnect | Connect uses the selected server's saved preferences. Disconnect names the active session and explains release of the traffic block, cancellation of retries, and suspension of startup connection. |
| Cancel / Stop reconnecting | Pauses attempts and retains the current traffic policy. Resume and an explicit Disconnect remain available. The saved startup preference is unchanged. |
| Reconnect | Restarts from the helper's acknowledged configuration, preserving the independent guard. It never invokes Disconnect. |
| Switch server | Offers at most six entries, prioritizing the active server, selection, and favorites, plus Manage servers. A checkmark means connected. |
| Settings / Connection settings | Opens the corresponding page directly, including app settings when no server is configured. |
| Diagnostics | Opens the existing diagnostic result workflow. Results remain local and ephemeral; this action does not repair the VPS. |
| Quit app | Describes whether a connection, recovery, paused policy, or traffic block remains. Unknown or changed exit consequences require review. Quitting sends no network mutation. |
| Disconnect and quit | Confirms consequences, requests a checked disconnect, verifies its response and a fresh status, then exits. A failed operation keeps the app open and presents the error. |

The icon has connected, muted disconnected, progress, blocked, and attention variants. Text conveys the state as well. Native menus carry essential actions; neither Linux tooltip support nor raw tray mouse gestures are required. See the [Tauri native tray documentation](https://v2.tauri.app/learn/system-tray/).

## Session and security behavior

Helper protocol **13** adds checked disconnect, pause, reconnect, and server handoff operations. Runtime status advertises their availability and distinguishes established-session recovery from initial connection attempts. Older helpers expose an update route. A legacy session on the current helper can still disconnect; safe reconnect and handoff require a fresh independently configured session.

During server switching, **the active session's kill switch, automatic reconnect, startup, and routing choices carry across**. The target's saved transport preference selects its supported transport plan. Target-server protection and routing preferences stay saved for a fresh connection, and the confirmation explains this distinction. The helper rejects a handoff that tries to change protection or routing. Selecting a different page or server has no network effect.

The handoff resolves its endpoint before teardown using the existing routing policy. It never opens an unprotected DNS allowance for resolution. If an unavailable tunnel prevents hostname resolution, the operation fails and the existing policy remains; numeric endpoints do not require that lookup.

Reconnect uses the root-owned acknowledged request and resolved endpoint. Switching/reconnecting retain the existing nftables base-chain hook and atomically update only owned rules before tearing down the tunnel. Failure paths retain protection and manual recovery state. A completed handoff replaces current intent with the destination server, preserving the session's startup decision. Stale disconnect requests for another server are rejected under the helper's operation lock.

GUI connection controls and tray operations share a native operation gate. A pending key rotation prevents tray reconnection or switching. Native page requests are queued and acknowledged after delivery, so opening Settings or Diagnostics does not depend on a visible, already subscribed WebView.

## Verification

| Verification | Result |
| --- | --- |
| Rust workspace | 306 tests passed; final changed desktop/helper suites also pass. |
| Frontend | 79 tests passed; production frontend compiles. |
| Native GTK/Wayland tray | Nine scenarios passed through actual DBus menu events and GTK dialogs, using a deterministic helper fixture. |
| Real Linux networking | 500 IPv4/IPv6/DNS packet checks passed in a disposable container. |
| Continuous packet probing | 1,057,443 probes across 30 atomic rule replacements; zero observed escapes. |
| Independent policy matrix | All four kill-switch/reconnect combinations exercised pause, manual restart, handoff, stale-target rejection, and deliberate release. |
| Source checks | Workspace Clippy with warnings denied, Rust formatting, whitespace, privacy invariants, and maintainability checks pass. No first-party source file exceeds 1,000 lines. |

The native tests use a private session bus, temporary profiles/preferences, and a read-only bubblewrap mount namespace. The installed helper is shadowed with a test fixture inside that namespace; authorization and network calls cannot reach the real helper. Tests confirm hidden-window connection, targeting the active server despite another GUI selection, preservation of policy despite differing target preferences, retention of the traffic block when stopping retries, diagnostic navigation, failed/successful disconnect-and-quit, unknown status, and plain quit without network mutation. Four icon variants were captured from the native tray's exported icon files.

The packet tests use `--network none` containers. They run production nftables rules, real WireGuard interface/routing changes, and public/DNS/IPv6 packet probes. The added session test doubles only systemd and systemd-resolved, which are absent inside the container. It does not prove real systemd boot ordering, resolver integration, successful remote WireGuard handshakes, or every relay transport failure case. Screenshot/menu fixtures are not evidence of firewall enforcement.

Reproducible tests: [native tray](../tests/ui/desktop_tray_smoke.py), [helper state transitions](../crates/linux-helper/src/tests/policy_tests/session_control.rs), [kernel session operations](../crates/linux-helper/src/tests/session_kernel.rs), and [packet runner](../tests/network/run-policy-kernel.sh). Captured evidence and package hashes are indexed in [the audit manifest](audit/2026-09-05/tray-controls.json).

## Delivery and next steps

The Linux `.deb` and AppImage include helper protocol 13. The installed host helper and active VPN were left untouched. After intentionally disconnecting, install/use the rebuilt package and reconnect to activate the new helper through the existing authorization flow. The VPS does not need an update for these tray controls.

The requested first tray milestone is implemented. Saved-preference checkboxes and optional clipboard/update shortcuts remain a later tray extension; Connection settings opens the existing per-server preference controls now.

The original overhaul acceptance checklist remains **23/24 = 95.8%**, as defined in the [preceding reliability audit](state-reliability-2026-09-05.md). This is checklist completion, not a percentage of every possible feature or a security certification. The next release gate remains a disposable VM run covering actual boot/service ordering, resolver behavior, abrupt failure, and all supported transport recovery paths. Android packaging/runtime was not retested for this desktop tray change.
