# Android security and platform boundaries

The UI process contains presentation and native form/picker controls. The `:vpn`
process initializes its own Rust runtime and WireGuard engine, independent of
the Activity and WebView. Binder calls require the application's UID. Native
protected entry/viewing can carry secrets across that same-UID Binder boundary;
the WebView receives opaque, expiring handles. Protocol keys necessarily enter
native memory. They are not claimed to be non-exportable hardware keys.

## Storage and inputs

- Credentials and resumable sensitive operation checkpoints use Android
  Keystore AES-256-GCM, random IVs, reference-bound AAD and atomic files in
  `noBackupFilesDir`. A missing original key does not cause replacement of
  existing unreadable credentials. Keystore hardware backing depends on the
  device; the emulator is not hardware-security evidence.
- Protected input handles expire after ten minutes and have a sixteen-entry
  ceiling. Native password/QR windows use `FLAG_SECURE`; explicit clipboard
  copy is marked sensitive and cleared after a minute if it is still the same
  value. No secret form value is put in WebView localStorage or an Intent.
- Current profile metadata, connection intent/preferences and unfinished
  transaction state persist. Counters, packet samples, connection/activity
  history and DNS queries do not. Recovery journals are operational state,
  not an audit log. Persisted connection intent is never rendered as proof of
  a live tunnel.
- Both automatic backup and device transfer are excluded. Explicit encrypted
  exports use user-selected SAF content URIs; imports have an 8 MiB ceiling.
  Sharing requires a recent export authorized by the native controller, uses
  a read-only URI grant and launches Android's chooser. An external/cloud
  document provider is used only after the user's selection.
- Native QR scanning uses the local ZXing decoder. Incoming codes still need
  normal preview, verification, authorization and confirmation. There is no
  automatic enrollment deep link.

## Network and lifecycle

Transport sockets are opened without a WireGuard endpoint, protected with
`VpnService.protect`, bound to the selected underlying network, and only then
committed. Relay sockets use the same protection boundary. The app itself
remains routed; excluding its whole UID is not a transport shortcut.

The controller owns endpoint changes. Upstream WireGuard's mobile roaming
disable hook prevents delayed authenticated packets from undoing a carrier
handoff. Isolated quality probes use the existing short-lived server lease,
two comparisons and bounded probes. Positive handoff and injected rollback
retained the actual TUN and passed traffic. A lease conflict can leave quality
optimization unavailable for the current connection; it does not fabricate
measurements or prevent the active tunnel from carrying traffic.

Android's Always-on and “Block connections without VPN” settings are the
system policy authority. App-only disconnect is rejected while Always-on
owns an established VPN. Permission-protected system starts are honored even
on Android 10, where `isAlwaysOn()` is false before the first TUN exists.
System-requested reconnection also survives an underlying-network change
during boot. Ordinary recovery uses bounded retries; an explicit Stop cancels
pending work and pauses automation.

Home, Back, UI process loss and task removal do not stop an active service.
Actual VPN-process loss, reboot and package replacement interrupt traffic;
permitted reconstruction creates a new session. Force stop, OS Stop and
consent revocation are not treated as invitations to resurrect the VPN.
The reboot test used an unlocked emulator with no PIN; locked boot and OEM
battery policies remain separate verification requirements.

Full routing includes IPv6 containment for an IPv4-only profile; configured
split routes and app exclusions are represented explicitly. An observed
containment route is not an external IPv6 leak test. Per-app exclusions remain
subject to system lockdown. Unknown/redacted Wi-Fi identities are never
classified as trusted. Fine location is used for Wi-Fi identity; background
recognition needs the corresponding Android permission/settings.

## Components, permissions and dependencies

The exported launcher accepts no enrollment/destructive command. The exported
VPN and tile services require Android's signature-level bind permissions.
Controller, maintenance, action and package-result components are not exported.
The VPN uses the documented authorized-VPN `systemExempted` foreground-service
eligibility; finite maintenance uses `dataSync`. There is no wake lock, overlay,
device administrator, broad filesystem permission or permanent hidden WebView.

Camera, notification and location requests have explicit user flows. Package
enumeration is used for VPN app selection; package installation permission is
used only for direct APK updates. Android-specific Tauri capabilities exclude
the desktop dialog/notification/tray layer. No telemetry, analytics, crash-upload
or hard-coded remote service was added to Android's production sources.

`dependencies.json` records 393 external Rust packages in the relevant closure
(including build dependencies), 33 production JavaScript packages, 81 resolved
Android coordinates including BOM constraints, and four Android Go modules.
These are dependency inventories, not a binary-level SBOM or vulnerability
certification. Core Android additions are upstream WireGuard Go (MIT), ZXing
Android Embedded/core (Apache-2.0), AndroidX and the existing Tauri stack.
Available upstream license texts and attribution metadata are collected beside
the development APK in `target/android-distribution/licenses`.

The privacy script passes after recognizing the exact inline SVG namespace and
loopback TLS test URL forms. Its regression check still rejects remote URLs in
those locations, including an additional URI in the inline SVG. Android Kotlin/Go
sources, merged components and dependency inventory were inspected separately;
this is not exhaustive outbound packet capture across every workflow.

## Distribution constraints

APK release metadata/artifact verification reuses the shared signed release
implementation. Native package checks additionally require the expected package,
a newer version and a compatible installed signing certificate/lineage. Android
10 needs both signing-certificate and legacy-signature archive flags to collect
the certificate; acceptance testing covers this behavior. The user approves
installation in Android's UI. Closing an in-app review does not silently cancel
a pending OS approval; an explicit cancellation is available.

No silent APK downgrade/AppImage rollback is offered on Android. The APK delivered
here is a development build signed with the existing debug identity. Production
signing, store distribution and physical ARM64/OEM testing are not claimed.
