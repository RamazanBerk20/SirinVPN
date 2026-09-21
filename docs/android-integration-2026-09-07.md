> Historical report: this Android implementation was removed on 13 September 2026. See [reset record](android-reset-2026-09-13.md); these results do not validate a replacement.

# Android implementation and evidence — 7 September 2026

The Android client now implements enrollment by pinned SSH or invitation/QR,
Keystore-backed identities, all four persistent VPN transports, network roaming,
CIDR and application routing, IPv6 where configured, and authenticated VPS
administration. Implementation checks are distinct from device/network acceptance.

## Connection and administration

The foreground VPN controller owns a bounded reconnect plan, protected carrier
sockets and cancellation epochs. Direct UDP, obfuscated UDP, framed TCP and pinned
TLS/HTTPS transport plans remain native; private keys never enter the WebView.
A foreground keeper and Android Always-on restart restore explicitly retained
plans. Android system Always-on with Block connections without VPN is the source
of traffic lockdown; a foreground service alone does not provide that guarantee.

The phone can manage members, invitations, device revocation, port forwarding,
recovery policy, key rotation, endpoint updates, server backup/restore,
repair/removal and signed VPS updates. Operations load the enrolled identity
through secure storage and recheck authorization. Conflicting maintenance,
identity changes and profile deletion require active/recovering VPN plans,
persistent protection and Wi-Fi automation to be stopped as appropriate.

## Opt-in Wi-Fi automation

Automation is off by default. Enabling it saves a separate encrypted native
connection plan for one enrolled profile. It uses the saved transport and routing
preferences; toggling it off and on adopts changed preferences. It starts on
untrusted Wi-Fi when no other VPN or persistent connection owns the network.
Failure recovery uses the existing bounded retry schedule. Moving to trusted
Wi-Fi or mobile data does not disconnect an existing protected session.

Disconnect pauses automation on the current network handle in memory. Disabling
automation removes its retained plan; use Disconnect to stop a current session.
A boot/package-replaced receiver restores only an explicitly armed, valid plan
after unlock and with existing VPN permission. Force-stopping the app suspends
Android background work until it is reopened.

Optional trusted-network recognition requests coarse and precise location only
when the user presses its permission button. Android 12+ requires precise
location, location services and a fresh callback that includes location-sensitive
Wi-Fi information. This is a platform restriction on reading SSID/BSSID; the app
does not request background location, read GPS, or scan nearby networks. Older
Android versions and redacted observations remain untrusted. Background reads
can be redacted even after foreground permission; those observations are treated
as untrusted rather than inheriting stale trust.

Only explicitly trusted labels and salted, domain-separated fingerprints are
retained. SSID, BSSID, visited-network lists, connection timestamps and quality
history are not stored. A fresh opaque network token prevents trusting a network
that changed while its UI was open. Open, WEP, OWE and unknown-security networks
cannot be trusted by this policy. Invalid retained state requires an explicit
reset and is not silently replaced.

## Current quality and MTU

Native ICMP probes bind to the exact VPN network and tunnel source address and
reach only the private VPS tunnel address. Eight bounded probes measure delivery,
latency and jitter. Results remain in memory and expire after 90 seconds or a
network/transport change. ICMP filtering produces an unavailable reading; it
never alone establishes that the VPN is broken.

Automatic transport comparison requires automatic transport selection, verified
Android Always-on lockdown and a current idle interval. It compares at most four
candidates per ten-minute cycle, prefers delivery, applies latency/jitter
hysteresis and rolls a worse trial back to the best working transport. Ordinary
recovery resets the comparison. No measurement history survives process restart.

Automatic MTU discovery uses nonfragmenting IPv4 datagrams and two successful
probes per candidate within a six-second bound. It respects the IPv6 minimum.
Changing MTU also requires verified lockdown and idle state; a failed change
restores the prior working configuration. Manual MTU remains a user choice.
Link-property changes on an existing network handle trigger fresh recovery and
measurements, as do Wi-Fi/mobile roaming events.

## Focused evidence

- Native Kotlin unit tests and instrumentation sources compile; seven JVM policy/diagnostic
  tests pass. Instrumentation compilation is not device execution.
- Android VPN Rust model/routing/QR/automation tests: 18 passed.
- Release compatibility tests: 46 passed, including the encrypted Wi-Fi trust and
  native connection-plan schema declarations.
- Windows-independent policy tests: 10 passed after the shared quality changes.
- Android UI: 32 tests passed across Wi-Fi controls, administration, enrollment
  and QR; TypeScript compilation passed before the final diagnostics additions.
- The later diagnostics checkpoint passed 19 focused UI tests, TypeScript compilation, Android native/Rust cross-checks, and bounded DNS/TLS fixtures; see [diagnostics evidence](current-diagnostics-2026-09-07.md).
- Privacy and source-size gates passed at the network-feature checkpoint.

The final x86_64 emulator and ARM64 phone APKs have been rebuilt and inspected,
including the current native transport library and both VPS payloads. Their
debug signatures verify; see the [delivery record](implementation-delivery-2026-09-07.md)
for files, checksums and the development-build boundary.
Real Android Always-on/lockdown restart, boot recovery, permission/redaction
behavior, carrier socket protection, roaming, MTU, restrictive networks and device
UI acceptance still require the subsequent testing phase. No host VPN, live VPS
or privileged network fixture was used for these implementation checks.

## Platform references

- [Android WifiInfo and redaction](https://developer.android.com/reference/android/net/wifi/WifiInfo)
- [NetworkCallback location-sensitive information](https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback#FLAG_INCLUDE_LOCATION_INFO)
- [Android foreground services and background starts](https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start)
- [Android VPN service and Always-on](https://developer.android.com/develop/connectivity/vpn)
