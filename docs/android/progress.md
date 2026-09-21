# Android implementation and verification — 21 September 2026

The native Android port and development APK are implemented. Full desktop parity
is **not verified**. The matrix separates implemented branches from tested outcomes;
these figures are not a claim of 646 working end-to-end tests.

Links below into `target/` identify local artifacts from the recorded test runs.
They are not included in this source repository or published as release assets.
See the [build guide](build-and-test.md) to reproduce the APK and evidence.

## Deliverables

- [Development APK](../../target/android-distribution/SirinVPN-Android-0.1.0-dev.apk),
  [checksum](../../target/android-distribution/SHA256SUMS), and
  [dependency notices](../../target/android-distribution/SirinVPN-Android-notices.zip).
- [646 scenario mappings](scenarios.json), [feature families](features.md), and
  [mobile gallery](../../target/android-evidence/mobile-redesign/index.html), plus
  [phone polish screenshots](../../target/android-evidence/phone-polish/index.html).
- [Architecture/security](security-and-platform.md), [build/test commands](build-and-test.md),
  and [test summary](../../target/android-evidence/summary.json).

The APK supports Android 10/API 29 through target API 36 and contains ARM64 and
x86_64 libraries. Acceptance tests used isolated x86_64 API 29 and 36 emulators
with WebView 133. An earlier build was installed and launched on the connected
ARM64 phone; that does not establish physical-device acceptance coverage.
The QR fix and mobile redesign were tested on the emulator while the user used
the phone. After the user requested installation, the updated APK was installed
over the existing app on the SM_S936B, its installed checksum was verified and
the app launched successfully. Physical QR retesting remains pending.
[Installation record](../../target/android-evidence/mobile-redesign/phone-install.json).
This is a **debug-signed, debuggable development build**, not a production release.
Existing desktop changes and the existing signing identity were retained.

## Phone feedback: icon, spacing and permissions

The monochrome system icon now follows the brand's curved ribbon and keyhole.
Notification buttons share a vertical action group with a 12 px gap. Wi-Fi
settings now distinguish missing precise-location permission from Location
being off and place the relevant Android action beside the trust controls.
Granting access identifies the network; marking it trusted remains a separate,
explicit action bound to the reviewed network token.

The phone had Location enabled but had not granted location permission to
SirinVPN. Android hides Wi-Fi identifiers without that access; the app uses
them for local trust matching and does not request GPS coordinates.
[Android Wi-Fi identity rules](https://developer.android.com/reference/android/net/wifi/WifiInfo).

Android now requests notifications once on the first connection/join or Wi-Fi
automation enable action, continuing if declined. Test notification requests
permission when needed and reports denial. The notification switch reflects
actual Android access, and the settings shortcut opens Android settings.

Validation: **21 settings tests passed**, along with the universal APK build,
signature/ABI/16 KB package checks, and native emulator permission flows.
Those flows exercise notification prompt/denial/retry, test-notification grant,
Wi-Fi identification after grant, explicit trust, stale-token rejection and
Location-off rejection. They use no real endpoint. **12 presentation captures**
cover 320/390 px widths and 200% system text. Lint: **0 errors, 88 warnings,
1 hint**. Earlier full-suite and QR evidence below predates this polish;
the current checks are scoped to these changes.

[Settings tests](../../target/android-evidence/phone-polish/settings-tests.log),
[native permission results](../../target/android-evidence/phone-polish/permissions.json),
[layout results](../../target/android-evidence/phone-polish/layout.json),
[package check](../../target/android-evidence/phone-polish/package.json).

The checked update was reinstalled on the SM_S936B at the user's request;
the installed APK checksum matches the distribution. No phone location or
notification permissions were changed by the agent.
[Installation](../../target/android-evidence/phone-polish/phone-install.json).

## Notification Disconnect keeps the panel open

Notification controls now request authentication only while the device is locked.
Android's unconditional authentication path also closes the notification shade
on an already-unlocked device; the action was taking that path on every tap.
[Android SystemUI implementation](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/packages/SystemUI/src/com/android/systemui/statusbar/phone/StatusBarRemoteInputCallback.java).
Disconnect and Stop attempts still use the existing broadcast receiver and
generation checks. The receiver checks the lock again when an action arrives,
including an action created before the device locked. Retry uses the same
action builder, and lock changes invalidate the notification update throttle.

The emulator check passed real SystemUI taps for Disconnect and Stop attempts:
the foreground service notification disappears, the shade stays open, and a
separate shell notification remains. A temporary emulator PIN also verified
the locked-action flag and rejection of an action created before locking.
This uses an idle foreground service and contacts no endpoint. The Kotlin shell
was rebuilt with the previously checked native libraries and embedded frontend
unchanged. APK signature/ABI/16 KB checks passed; lint remains **0 errors,
88 warnings, 1 hint**.
[Results](../../target/android-evidence/notification-shade/results.json),
[native test](../../target/android-evidence/notification-shade/instrumentation.log),
[package check](../../target/android-evidence/notification-shade/package.json).
The update was installed on the SM_S936B and its installed checksum verified;
phone permissions were not reset.
[Installation](../../target/android-evidence/notification-shade/phone-install.json).

## Launcher notification badge

The phone's VPN channel had badges enabled, so its ongoing notification showed
a persistent launcher count. All app channels now disable badges. Existing
installs migrate to new channel IDs because Android ignores badge changes on
an existing channel. Active notifications keep their IDs and actions during
migration; importance, sound and vibration settings carry across.
[Android badge guidance](https://developer.android.com/develop/ui/views/notifications/badges).

The emulator regression passed migration of an already-posted notification,
preservation of its content action, removal of the unused legacy channel, and
badge suppression on the VPN, maintenance and update channels.
[Native test](../../target/android-evidence/notification-badge/instrumentation.log).
The universal APK build, signature/ABI/16 KB checks passed, and lint remains
**0 errors, 88 warnings, 1 hint**. The six native libraries, including the
embedded frontend, are unchanged.
[Package check](../../target/android-evidence/notification-badge/package.json).
The real notification Disconnect/Stop attempts and lock-guard checks also passed.
[Controls](../../target/android-evidence/notification-badge/notification-controls.json).
The update was installed on the SM_S936B with matching checksum and unchanged
permission grants. Android reports badges disabled for all three channels and
for the active VPN notification; the old channel is retired.
[Installation](../../target/android-evidence/notification-badge/phone-install.json).

## Download/upload sampling

Android status events can repeat the same cached byte counters during management
requests and network updates. Treating every event as a new reading erased valid
rates and used the wrong elapsed time. Counter readings now carry their native
monotonic sample time; repeated readings retain the last calculated rates. Fresh
idle readings produce zero, and reconnects or unavailable counters reset the
baseline. Notification rates also use the counter sampling interval.

The new regression failed before the fix; **16 targeted frontend tests** now
pass. **21 checks in the emulator WebView** passed exact displayed rates through
duplicate bursts, idle, reconnect and counter failure/recovery, using synthetic
readings in the separate test APK.
[Regression](../../target/android-evidence/traffic-sampling/frontend-tests.log),
[display checks](../../target/android-evidence/traffic-sampling/presentation.json).
The production frontend and universal APK build passed, as did signature/ABI/
16 KB checks; lint remains **0 errors, 88 warnings, 1 hint**.
[Package](../../target/android-evidence/traffic-sampling/package.json).
Live throughput was not verified: the emulator could not connect to its saved
authorized server using the saved transport or Direct UDP in this run.
[Attempts](../../target/android-evidence/traffic-sampling/live-attempts.json).
The checked APK was installed on the SM_S936B; its installed checksum matches
the distribution and phone permission grants are unchanged.
[Installation](../../target/android-evidence/traffic-sampling/phone-install.json).

The native notification still had a separate fixed KiB/s formatter and a
five-second throttle. It now matches the app's automatic B/s, KB/s, MB/s, GB/s
and TB/s formatting, using 1024-byte steps. Android counter sampling runs once
per second, and each fresh reading updates the notification; duplicate status
events do not repost it. Changes of counter epoch discard the previous totals.
The native regression failed on the previous APK and passes on the update:
real Android notifications reflect each one-second synthetic reading within
750 ms, scale both directions, retain rates during duplicate bursts, and reset
on reconnect. Badge suppression and the broadcast Disconnect action are checked.
[Native regression](../../target/android-evidence/notification-rates/instrumentation.log),
[previous failure](../../target/android-evidence/notification-rates/regression-before.log).
Package checks passed; lint remains **0 errors, 88 warnings, 1 hint**. The native
libraries and embedded frontend are unchanged.
[Package](../../target/android-evidence/notification-rates/package.json).
The real SystemUI Disconnect/Stop attempts and lock-guard checks also passed.
[Controls](../../target/android-evidence/notification-rates/notification-controls.json).
The update was installed on the SM_S936B with matching APK checksum and
unchanged permission grants.
[Installation](../../target/android-evidence/notification-rates/phone-install.json).

## QR scanning and mobile redesign

The scanner now uses the whole visible camera preview and an existing ZXing
multi-code detector. The previous single-code detector missed the deterministic
2,407-character test QR even when every pixel was present; an invisible central
crop also excluded finder patterns near the preview edges. The native scanner
adds continuous focus, a supported HD preview, visible guidance, flashlight and
refocus controls. Decoded values remain native; React receives an opaque handle.

Android now has a focused Home screen, separate connection details, a settings
index with individual pages, full-screen enrollment forms, touch-sized server
rows and bottom action sheets. Desktop layouts retain their existing controls.

- **195 frontend tests passed** across 40 files, plus the production build.
- **60 mobile presentation states passed**, with 106 images including scroll
  endpoints, at 390 × 844, 320 × 640 and 200% native font scale. These use fictional
  profiles in the separate test APK and do not prove VPN connectivity.
- Native QR regression passed for the 2,407-character code at the preview edge
  in normal and inverted colors, with full-frame and HD-selection assertions.
- The production scanner also read synthetic 57-, 1,207- and 2,407-character
  codes through the emulator's virtual camera. The native bridge returned only
  opaque handles. The camera input used tiled copies of the synthetic code to
  cover the emulator's crop; it contained no usable invitation. The production
  invitation form displayed “Code ready to review” and enabled Review invitation
  after scanning the 2,407-character code, with no raw code in the DOM.
- A missing registration for Tauri's generated lifecycle observer was fixed in
  `MainActivity`. The real invitation form now passes camera-permission denial,
  Home/release, return/resume and Back/cancellation checks on the emulator.
- The rebuilt universal APK passed signature, ABI and 16 KB alignment checks.
  Android lint reported **0 errors, 86 warnings and 1 hint**.

[Presentation results](../../target/android-evidence/mobile-redesign/presentation.json),
[gallery](../../target/android-evidence/mobile-redesign/index.html),
[frontend tests](../../target/android-evidence/mobile-redesign/frontend-tests.log),
[native QR test](../../target/android-evidence/mobile-redesign/qr-instrumentation.log),
[virtual-camera scan](../../target/android-evidence/mobile-redesign/camera-flow-max.json),
[invitation form](../../target/android-evidence/mobile-redesign/camera-form.json),
[camera lifecycle](../../target/android-evidence/camera-ui-emulator-5560.json),
[package check](../../target/android-evidence/mobile-redesign/package.json), and
[lint log](../../target/android-evidence/mobile-redesign/lint.log).

## Coverage accounting

The catalog contains 646 scenarios in 39 families and 1,667 original desktop
images. All 204 source hashes matched the initial checkout at revision
`5668e678`; current differences are recorded by
[the inventory check](../../target/android-evidence/parity-check.json).

| Scenario disposition | Count | Meaning |
| --- | ---: | --- |
| Implemented and verified | 22 | Named native outcome and matching UI state have evidence; scope is stated per row. |
| Adapted and verified | 22 | A tested Android equivalent replaces a desktop mechanism. |
| Implemented, not fully verified | 599 | Code exists; related tests do not prove this complete branch. |
| Platform restriction | 3 | Desktop minimize/maximize/close chrome; Android owns task/window controls. |
| Missing catalog implementation | 0 | This does not mean all Android-specific acceptance requirements are complete. |

The historical presentation baseline is counted separately: **552 passed**, **61 desktop-native snapshots**
and **33 desktop-specific workflows** requiring separate Android evidence.
That capture contains **3,594 Android images**, including scroll sequences,
with no replay failures among the 552 captured scenarios. The 94 separately
dispositioned cases are not passing screenshots. Every record has the same
capture-bundle hash. The production React UI runs with fictional APIs in a
separate test APK with WebView network loading disabled.

The [historical gallery](../../target/android-catalog-evidence/index.html)
predates the mobile redesign and does not verify the new layouts. The current
60-state capture is reported separately above; scenario runtime counts have not
been increased on the basis of presentation tests.

## Native and network evidence

Administrative/destructive tests used disposable Debian 13 guests exposed only
through host loopback, pinned SSH and fixture UUID guards. The user's invitation
was used only for authorized enrollment and ordinary Member traffic tests.
No real user VPS was administered or destroyed.

| Exercised behavior | Evidence |
| --- | --- |
| All four carriers against the isolated VPS | [transports](../../target/android-evidence/transports.json) |
| Home, UI-process SIGKILL and actual Recents swipe retain original generation and advancing counters | [lifecycle](../../target/android-evidence/lifecycle.json) |
| QS connect/disconnect and notification Disconnect without an Activity; kernel TUN and ordinary-UID traffic | [native controls](../../target/android-evidence/native-controls.json) |
| Rapid stop/start, rotation, network loss/return, VPN-process reconstruction, explicit cancellation, Force stop and OS Stop | [resilience](../../target/android-evidence/resilience.json) |
| Quality selection retains process/generation/TUN with 32 active traffic replies; injected failed handoff rolls back with 31 replies; probe leases removed | [selection](../../target/android-evidence/quality.json), [rollback](../../target/android-evidence/quality-rollback.json) |
| Full/split IPv4, LAN bypass/private routes, app inclusion/exclusion, observed IPv6 containment route | [routing](../../target/android-evidence/routing.json) |
| Controlled DNS answers, DNS failure with management reachable, automatic TUN MTU reduction to 1200 | [DNS/MTU](../../target/android-evidence/dns-mtu.json) |
| API 29 Always-on starts paused VPN; lockdown blocks excluded-app bypass; policy-owned Disconnect refused; Forget revokes consent | [policy](../../target/android-evidence/policy-emulator-5562.json) |
| Real consent denial/grant, then tile control without MainActivity | [consent](../../target/android-evidence/consent-emulator-5562.json) |
| Real reboot: Always-on traffic before MainActivity; 20-second screen-off/forced-Doze session retention | [reboot](../../target/android-evidence/reboot-emulator-5562.json), [Doze](../../target/android-evidence/power-emulator-5562.json) |
| Owner rename, peer permission, port mapping, reusable invitations/cancellation, recovery keys and rotation | [Owner](../../target/android-evidence/owner.json) |
| Encrypted recovery/device/VPS backups, wrong passwords, duplicate rejection, Member restrictions, offline Owner recovery, wrong SSH pin, repair and explicit replacement restore | [maintenance](../../target/android-evidence/maintenance.json) |
| Invalid endpoint application/publication retains working tunnel; rotation preserves active routing/MTU/restart intent | [transitions](../../target/android-evidence/transitions-emulator-5562.json) |
| SAF create/open/cancel, encrypted export, cancelled share chooser, protected password/QR windows, opaque handles, camera denial | [native flows](../../target/android-evidence/native-flows-emulator-5562.json), [camera UI](../../target/android-evidence/camera-ui-emulator-5562.json) |
| Confirmed fixture-only uninstall removes SirinVPN/profile while retaining SSH; unconfirmed request refused | [uninstall](../../target/android-evidence/uninstall-emulator-5562.json) |
| Keystore roundtrip, fresh encryption, AAD binding, tamper rejection preserving data, bounds and deletion | [vault](../../target/android-evidence/vault-emulator-5562.json) |
| 320 dp, 200% fonts, landscape draft retention, Back/unsaved preferences and modal dismissal without VPN recreation | [UI](../../target/android-evidence/ui-emulator-5562.json) |
| Factory WebView 74 displays native update explanation; WebView 133 restored | [WebView](../../target/android-evidence/webview-emulator-5562.json) |
| Notification permission denied on API 36: foreground VPN, three ordinary-UID replies and pinned management | [notification denial](../../target/android-evidence/notification-denial-emulator-5560.json) |
| APK identity/signature/version rejection and actual OS approval cancellation without replacing installed app | [APK workflow](../../target/android-evidence/apk-emulator-5562.json) |

The university's reported 443 block means obfuscated UDP is not claimed usable
there. The 21 September authorized-server retest passed Direct UDP and TLS;
TCP timed out during its WireGuard handshake in both the combined run and a
[focused retry](../../target/android-evidence/authorized-tcp-retry.json). TCP passed earlier, and all four
carriers passed locally. The mixed latest result is retained in
[authorized transports](../../target/android-evidence/authorized-transports.json),
not replaced by a blanket pass. Neither university policy nor server ports were
changed. A previous API 36 attempt also had local emulator networking failures;
the successful notification-denial check followed a cold boot.

## Regression, packaging and resources

- Frontend: **195 passed, zero failed**; TypeScript/Vite production build passed.
  [Results](../../target/android-evidence/mobile-redesign/frontend-tests.log).
- Rust workspace: **431 passed, zero failed, 16 explicitly ignored** for absent
  external/platform prerequisites. [Summary](../../target/android-evidence/workspace-tests.json).
- Workspace and Android-target Clippy with `-D warnings`, Rust formatting,
  two Python unit tests and two on-device Android Go tests passed.
- Android lint: **0 errors, 86 warnings, 1 hint**. Warnings include synchronous
  durable writes, generated Tauri code and dependency/API guidance; severity
  was not weakened. [Log](../../target/android-evidence/mobile-redesign/lint.log).
- Actual APK signature, both ABIs, six native libraries, ELF LOAD alignment
  of at least **16 KB**, and ZIP alignment passed. Acceptance fixtures/test
  components are excluded. [Package](../../target/android-evidence/mobile-redesign/package.json),
  [merged manifest](../../target/android-evidence/AndroidManifest.xml).
- Debug emulator observation: VPN CPU **0.095% idle / 0.143% with 100 ICMP probes**,
  about 21 seconds each, **211,264 KiB RSS**. This is not a battery or throughput
  benchmark. [Measurements](../../target/android-evidence/resources-emulator-5562.json).
- Maintainability: no source file over 1,000 lines.
- Privacy guard still fails on two pre-existing non-network literals: an SVG
  namespace and localhost TLS test URL. The guard was not relaxed.
  [Exact failure](../../target/android-evidence/privacy-check.log).

Evidence was gathered across successive builds on 20–21 September. Final UI
fixes have targeted checks; earlier VPN/network/maintenance suites were not
repeated for the scanner and mobile presentation changes.

## Remaining work and limits

Implemented but not fully verified: positive signed endpoint migration to a
different address, signed VPS update/rollback, complete APK download and actual
replacement/recovery, ownership transfer, all interrupted maintenance checkpoints,
and every role/error/compatibility branch in the matrix.

Native/device coverage still needed: physical ARM64/16 KB hardware, secure-PIN
locked boot and tile authentication, a competing VPN, physical Wi-Fi/mobile
handoff and OEM power policies, TalkBack/reading order, split-screen, physical
camera decoding, blocked notification channels, Wi-Fi permission/identity branches,
completed external sharing, and external IPv6 leak tests. An observed containment
route and short emulator Doze test do not establish those outcomes.

Unsaved React drafts survive the tested rotation/configuration/Back paths.
General unsaved-form restoration after actual UI process death is **not implemented**;
secrets are not persisted in WebView storage to approximate it. Navigation reload
behavior exists, but complete process-death form/navigation restoration remains
unfinished. This is not a platform restriction.

Production signing/distribution, exhaustive outbound-traffic capture, dependency
vulnerability review and a legal license-compliance audit remain outside the
obtained evidence. Attribution is supplied without claiming those audits.
The 599 unverified scenario rows must not be presented as full parity.
