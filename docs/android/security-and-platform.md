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
where `isAlwaysOn()` is false before the first TUN exists.
System-requested reconnection also survives an underlying-network change
during boot. Ordinary recovery uses bounded retries; an explicit Stop cancels
pending work and pauses automation.

Reconnect changes update both saved preferences and the live retry state before
the app confirms the save. Turning reconnect off cancels pending attempts.
An established VPN stays connected until Disconnect. Pending retries and network
reads cannot restore settings or connection intent superseded by a newer command.
Wi-Fi auto-connect follows the desktop rule; see [below](#wi-fi-auto-connect).

Home, Back, UI process loss and task removal do not stop an active service.
Actual VPN-process loss, reboot and package replacement interrupt traffic;
permitted reconstruction creates a new session. Force stop, OS Stop and
consent revocation are not treated as invitations to resurrect the VPN.
The reboot test used an unlocked emulator with no PIN; locked boot and OEM
battery policies remain separate verification requirements.

Full routing includes IPv6 containment for an IPv4-only profile; configured
split routes and app exclusions are represented explicitly. An observed
containment route is not an external IPv6 leak test. Per-app exclusions remain
subject to system lockdown.
Notification and animation preferences have one owner in the VPN process, with
a one-time migration from the older UI preferences. Connection failure alerts
honor the notification switch; Android still controls the foreground VPN notice.

## Wi-Fi auto-connect

The rule is the desktop's (`src-tauri/src/wifi_automation.rs`, `WifiRule.kt`):
on Wi-Fi that isn't trusted it connects to the chosen server once per network
entry. An entry is one Android `Network` in one boot, so rejoining, even the same
network, is a new entry; a policy, server or trust change is one too. A session
already running owns the entry, so a later Disconnect is never undone on that
network. Trusted Wi-Fi, mobile data and Ethernet never connect, and nothing ever
disconnects. The rule also runs when the VPN process starts, as desktop's does at
launch. The trusted list and the server live in the shared network policy store
(`network.json`), the same code as the desktop's.

Trust is keyed on the network name plus its security class (open, password or
enterprise), the parts of Android's own saved-network key an app can read. The
desktop keys on the OS saved profile; Android has no stable profile ID for apps
(the old `networkId` is renumbered at every boot). Only a salted hash is saved,
never the name.

Android shows the Wi-Fi name only with precise location, with Location on, and
from a closed app only with location "Allow all the time". When the name is
hidden, the network is unidentified and therefore untrusted: auto-connect fails
safe and connects. Settings → General then says what is missing and offers one
button: **Allow location**, **Allow all the time** (Android grants it on its
own settings page), or **Turn on Location**. Battery use set to Restricted also
gets a notice, since Android then refuses background starts. SirinVPN never
requests coordinates; it reads the name through a network callback with
`FLAG_INCLUDE_LOCATION_INFO`.

What sees the next network while the app is closed:

| State | Watcher | Notification |
| --- | --- | --- |
| VPN on | the VPN process's own network callback | the VPN's |
| Off Wi-Fi (mobile data, none), VPN off | a `PendingIntent` network callback for Wi-Fi | none |
| On Wi-Fi, VPN off (trusted, or paused after Disconnect) | `WifiWatchService` | a silent "Wi-Fi auto-connect" notice with **Hide notice** |

Android sends a `PendingIntent` network callback once, at once if a matching
network already exists, and releases it 5 s after delivery (AOSP
`ConnectivityService`), so it can't watch for a different Wi-Fi while one is
connected; no public request can exclude the current network. That is the only
case with a running service. An app can't hide that notice: Android raises a
foreground service's off or minimum channel to visible until the user turns it
off (seen on the API 36 emulator). So the notice has one action, **Hide notice**,
which opens that channel's switch. Once it's off, Android 13+ keeps the service
running and lists it only under Quick Settings' active apps; Android 12 may
show the system's own "running in the background" notice instead.
Boot and package replacement re-arm the watch without opening the app. A force
stop cancels it until the app is opened again, as Android intends. Background
starts of the VPN and of the watcher use the authorized-VPN exemption
(`OP_ACTIVATE_VPN`), so VPN consent must already be granted: turning
auto-connect on asks for it. With Android's own Always-on VPN the VPN is always
up and the rule only reports it. An OEM that freezes background apps (Samsung's
sleeping apps) can still block the wake-up; set battery use to Unrestricted
there. Android TV doesn't show the feature: a TV doesn't change Wi-Fi, and many
have no location provider, so the name would stay hidden.

## Components, permissions and dependencies

The exported launcher accepts no enrollment/destructive command. The exported
VPN and tile services require Android's signature-level bind permissions.
The [automation receiver](automation.md) is exported only behind
`org.sirinvpn.permission.CONTROL_VPN`, a `dangerous` permission the user grants
to an automation app; it can connect, disconnect and choose the Quick Settings
server, and returns nothing. `scripts/check-remediation-contracts.py` rejects
any other exported component without a permission.
Controller, maintenance, action, widget and package-result components are not exported.
The home-screen widget is drawn by the VPN process and uses the tile's and
notification's control paths. It shows the state and the server's name, never
its address, and declares only the home-screen category, so Android never
offers it on the lock screen.
The VPN uses the documented authorized-VPN `systemExempted` foreground-service
eligibility; finite maintenance uses `dataSync`. There is no wake lock, overlay,
device administrator, broad filesystem permission or permanent hidden WebView.

Camera and notification requests have explicit user flows. Package
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
