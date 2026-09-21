# Settings and layout follow-up — 2026-09-05

The later [interface refinements](interface-refinements-2026-09-05.md) supersede
the package artifacts linked in this earlier settings handoff.

The requested layout and app-preference changes are implemented on top of
`5668e67`. Settings now has General, Connection, Devices, and Advanced categories.
The server cards use compact horizontal rows, connection controls fill their
panel, and headers, action buttons, and metric values share consistent alignment.
Transport descriptions wrap instead of being truncated.

Page changes, expanded panels, dialogs, and buttons have short transitions.
Animations can be disabled in General; the system's reduced-motion preference
also takes precedence. Navigation preserves connection choices and ongoing forms.

| Preference | Default | Behavior |
| --- | --- | --- |
| Start on system startup | Off | Linux registers the current app for desktop login using the XDG autostart directory. |
| Launch minimized | Off | Linux starts in the taskbar, or hidden when Close to tray is also enabled. |
| Close to tray | Off | Closing the Linux window keeps the app running; the tray or app launcher can reopen it. |
| Connection notifications | Off | Native connection alerts and a test-notification button, subject to OS permission. Linux monitoring continues in the tray. Android alerts follow status changes while the app runs. |
| Interface animations | On | Short transitions, with support for reduced motion. |

App settings are accessible before adding a server. Existing device backup and
key-rotation actions are under Devices; server recovery, endpoint changes,
repair, diagnostics, removal, and expandable system health are under Advanced.
Android exposes its connection/protection controls, identity management, and
native security checks through the same categories.

Preferences are stored atomically in a private native configuration file,
separately from server profiles and keys. Startup registration follows the
[freedesktop autostart specification](https://specifications.freedesktop.org/autostart/latest/).
Executable paths are quoted for spaces, Unicode, and percent characters; a failed
preference write restores the previous startup setting. Corrupt or unsupported
preference files produce an error instead of being silently overwritten.

Native testing also exposed an Android notification-plugin request that never
resolved when permission was already granted. The app now checks permission
before requesting it. Notification text contains no server names, addresses,
or key material. Closing or quitting the desktop app leaves its VPN running;
automatic GUI startup does not initiate a connection.

## Verification

- **274 Rust tests** passed across the workspace; the final desktop crate's
  **14 tests** and Clippy with warnings denied passed after the native corrections.
- **52 frontend tests** passed, including permission denial, failed saves,
  settings availability, reduced motion, and the existing Android/release flows.
- **Eight browser scenarios** covered desktop/Android, different viewport sizes,
  connected/disconnected states, and onboarding. All four settings categories,
  keyboard navigation, persistence, connection choices, and dialog focus were
  checked. Automated accessibility findings: **0**; horizontal overflow: **0**.
- **Real Linux native checks** passed for defaults, private persistence, startup
  registration, filesystem-failure rollback, desktop notification delivery,
  close-to-tray, restoring a single instance, both minimized-launch modes, and
  launching the actual desktop entry with a spaced Unicode/percent filename.
- **Real Pixel emulator checks** passed for the native bridge, Keystore/identity
  checks, hardware Back, isolated identity preparation/removal, rejecting desktop
  preferences, notification delivery, and preferences surviving a process restart.
- Privacy invariants, source-size checks, and existing shell regression tests
  passed. No maintained source file exceeds 1,000 lines.
- The Rust advisory scan found **0 known vulnerabilities**. The earlier **17
  upstream warnings** remain: 16 unmaintained packages and one unsoundness warning.
- The resolved Android dependency scan checked **79 Maven packages** and found
  **0 packages with advisories**.

Browser screenshots use synthetic server responses. Native checks used isolated
local settings and the emulator; they did not exercise a live VPN connection.
Two temporary screenshot attachments were unavailable, so those alignment fixes
were guided by the descriptions and inspection of the running UI.

## Deliverables and remaining work

- [Linux AppImage](../target/release/bundle/appimage/SirinVPN_0.1.0_amd64.AppImage)
- [Linux Debian package](../target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb)
- [Android x86_64 debug emulator APK](../apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk)
- [Screenshots](../.cache/settings/screenshots/)
- [Verification results and package checksums](audit/2026-09-05/results.json)

This follow-up's requested functionality is implemented. The latest project-wide
completion measure remains **23/24 original acceptance items, or 95.8%**, as
defined in the [project audit](audit-2026-09-04.md). The next step is to complete
the live network/privacy fault matrix, then qualify signed production releases,
including an ARM64 Android build on a physical phone.
