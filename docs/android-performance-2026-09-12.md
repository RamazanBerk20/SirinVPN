> Historical report: this Android implementation was removed on 13 September 2026. See [reset record](android-reset-2026-09-13.md); these results do not validate a replacement.

# Android startup and Quick Connect — 12 September 2026

The connected phone now has an ARM64 **release** build: optimized Rust code, R8 enabled, and Android debugging disabled. The APK is `target/android-packages/SirinVPN_0.1.0_aarch64-release-local.apk` (37,729,974 bytes). It is signed with the existing local development certificate so it updates the installed package and preserves its encrypted profiles. This is a release compilation for local testing, not a production signing-key migration.

## Changes

- Startup opens authenticated profiles directly. Reading a profile still decrypts its protected records and verifies the binding to its private identity. Synthetic secure-storage and identity creation/deletion tests now run explicitly from Settings → Diagnostics & maintenance → Local components → Run local security checks.
- VPN status loads alongside profiles. An already active profile's preferences can begin loading immediately. Connect remains disabled until the selected profile's preferences are ready. Backgrounded WebViews no longer perform periodic status polling.
- The initial screen says “Loading your VPN…” until profile loading completes. It no longer temporarily claims that an existing installation needs to add its first VPN.
- Quick Connect retains only the validated display name in memory for tile refreshes. Each connection still authenticates the encrypted bookmark. Reconnecting reuses the unchanged bookmark and commits only the running-session record, avoiding two unnecessary encrypted writes.
- The tile reads an immediately available native status snapshot, displays pending actions promptly, and rejects obsolete pending-action completions. Notification rate updates no longer request a tile refresh every 1.5 seconds when its connection state has not changed.
- MTU and latency probes run on a separate worker. Their results are applied only if the connection, cancellation epoch, configuration, and underlying network still match. Traffic idleness is checked again before applying an automatic change.
- Disconnect waits for the controller's own VPN network to disappear. An unrelated active VPN no longer makes an idle controller's Disconnect fail. This was exposed by the isolated instrumentation package while the installed app's VPN was running.

## Verification

- Frontend suite: 46 files / 226 tests passed. The final control-readiness changes also passed all 29 tests in the three affected Android test files.
- Native Kotlin unit tests: 12 passed.
- Phone instrumentation: 3 passed, covering encrypted bookmark/session lifetimes, mismatched bookmark rejection, and ownership of the tunnel in a separate process.
- Release APK verification passed without the debug exception: `debug=false`, automatic backup disabled, expected native transport and current VPS payloads present. Its signing certificate matches the previous installation.
- Android installed the release update successfully and reports no `DEBUGGABLE` package flag. No WebView debugger socket is exposed by the release app.
- Visual inspection of the release app confirmed the retained server on Home, a connected Direct UDP tunnel, transfer counters, and a successful last path probe. The native VPN service also remained running while the interface was in the background.

## Measurement limits

Before optimization, debug-build WebView reloads reached Home in 3.5–4.7 seconds. Explicit command measurements attributed approximately 0.74 seconds to storage self-tests and 1.24 seconds to identity self-tests. After removing those tests from startup, the debug build rendered the saved-server Home view in approximately 1.4 seconds; in the disconnected case, Connect waited until preferences finished loading at approximately 2.8 seconds.

Those are debug-build measurements, not release startup benchmarks. Android's release activity launch reported 121 ms, which measures activity launch and does not establish when WebView controls are ready. Release UI and connection operation were checked, but no precise release startup or tile-connect latency is claimed. Earlier automated tile timing attempts were inconclusive because the displayed tile state lagged behind the connection.

Logs and verification records are in `target/android-performance/`. The APK SHA-256 is `be00f2e1dd3e6f5265a84a38f7fd0da914d609e4d141daf54800169244b20ac7`.

The tile refresh approach follows Android's [active tile lifecycle guidance](https://developer.android.com/develop/ui/views/quicksettings-tiles). Activity launch and usable-content timing are distinguished as described in Android's [startup measurement guidance](https://developer.android.com/topic/performance/appstartup/analysis-optimization).
