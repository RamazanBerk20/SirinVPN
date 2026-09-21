# Interface refinements — 5 September 2026

**Superseded by the [operational UX revision](operational-ux-2026-09-05.md).**
The build paths below now contain the newer artifacts; use the newer report for
current navigation, measurements, checksums, and verification.

This follow-up implements the compact device layout, additional metrics, and
alignment corrections requested after the settings update. It preserves the
existing startup, tray, notification, membership, and invitation behavior.

## Changes

- Home contains the connection control and current metrics. Transport, routing,
  network profile, and persistent-protection controls live only in Settings →
  Connection. Selections survive navigation back to Home.
- Metric, device, form, and sidebar icons are centered inside their boxes. The
  first-launch header uses one wrapping action row, keeping App settings and
  Check for app updates aligned through provisioning and window resizing.
- Devices use the full content width. Each compact row shows an activity dot,
  device icon, name, tunnel address, and expansion arrow. Member identity, role,
  fingerprint, peer permissions, renaming, revocation, additional-device invites,
  and ownership controls are in the expanded row. Existing Owner/Admin limits,
  last-owner-device protection, and pending-invitation restrictions remain.
- Member/device/invitation totals are inline. Active invitations expand below the
  device list. Public port forwarding expands under Advanced, with the open-port
  count visible when rules exist.
- The metrics panel adds root-filesystem storage, received/sent packet counts,
  aggregate VPS byte totals, service health, and protection state. CPU, memory,
  and storage have utilization gauges. Device byte totals, VPN address, IPv6,
  routing, and fallback state are in Connection details.
- The provisioning progress indicator now has an accessible progressbar role.

## Data and compatibility

Device activity is a current snapshot: green means this client is connected or
its latest WireGuard handshake is within three minutes; amber means no recent
handshake and can include idle or offline devices. Gray means the information is
unavailable. Device icons use recognizable device names; ambiguous names use a
generic icon. The API does not currently store an operating-system field.

The membership API reads only the public-key/handshake subset of WireGuard's
runtime output and returns a boolean. Timestamps are discarded and never added
to authorization files, backups, or logs. The wire format is documented in the
[WireGuard manual](https://man7.org/linux/man-pages/man8/wg.8.html). Packet counts
come from the current VPN interface; storage is the root filesystem's current
usage. These counters do not create a traffic history.

Existing VPS installations need **Settings → Advanced → Repair VPS** with the
new app build to expose the additional server counters and device activity.
Older servers remain compatible and missing values display as unavailable.
No live VPS was modified by this interface follow-up.

## Verification

- Rust workspace: **277 tests passed**; workspace Clippy passed with warnings denied.
- Frontend: **55 tests passed**; production build passed.
- Browser: **11 viewport/platform scenarios**, including the provisioning state,
  keyboard expansion, all settings categories, and narrow device layouts;
  **zero automated WCAG findings** and no horizontal overflow.
- Linux WebKitGTK: centered icons, compact metrics, device expansion, collapsed
  secondary controls, and the 958px onboarding header passed in the native app.
- The rebuilt Android emulator APK passed native bridge, Keystore, identity,
  layout, and system Back checks.
- Privacy invariants and the 1,000-line source-file limit passed.

Browser and native-renderer screenshots use synthetic server responses, not a
live tunnel. Native operating-system preferences were verified in the earlier
[settings report](settings-follow-up-2026-09-05.md). The remaining original audit
qualification is unchanged: live-network fault testing and production ARM64
Android testing remain outside this interface work.

Current screenshots are in [the review folder](../.cache/layout-follow-up/screenshots).
Package hashes and final verification results are recorded in
[the machine-readable result](audit/2026-09-05/layout-follow-up.json).

## Builds

- [Linux AppImage](../target/release/bundle/appimage/SirinVPN_0.1.0_amd64.AppImage)
- [Debian package](../target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb)
- [Android emulator APK](../apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk),
  x86_64 debug build; not the ARM64 production phone package.
