> Historical report: this Android implementation was removed on 13 September 2026. See [reset record](android-reset-2026-09-13.md); these results do not validate a replacement.

# Android background connection and Quick Access follow-up — 2026-09-13

> Historical validation of the first follow-up release. The Wi-Fi trust changes
> described below were subsequently reverted at the user’s request. All other
> changes were retained. See `android-wifi-rollback-2026-09-13.md`.

The ARM64 release was updated in place on the connected Samsung phone. Saved
profiles remain intact. This is an optimized, non-debuggable release, signed
with the existing local development certificate for update compatibility.

Changes:

- The VPN service itself now enters foreground mode, including Android system
  starts. It distinguishes app starts from Always-on starts and explicitly
  restores saved recovery for the latter. Ordinary connection recovery is
  committed before a successful connect returns to the interface.
- The tunnel controller publishes Quick Settings state transitions directly.
  Disconnect in the app updates a listening tile even after stopping the
  notification service. Action generations keep a late Connect completion from
  clearing a newer Disconnect state.
- The ongoing notification's Disconnect action declares that it has no user
  interface. Authentication is required while locked, with another lock check
  when the service executes the action. Both foreground services share one
  notification and no additional large image.
- Quick Access reads tile lifecycle callbacks and Android's app/channel
  notification settings. Completed controls are disabled and labelled as
  completed. Focus, visibility and visible-page refreshes detect changes made
  outside the app and re-enable the appropriate control.
- Trust current Wi-Fi no longer requires entering an access-point label.
  Recognition permission and network state refresh when returning to the app.
  Recognizing a secure access point still requires Android's Wi-Fi identity
  access; the change does not trust an unidentified network.
- Adaptive foreground and monochrome icon insets increased from 7.5% to 11%
  on each side: the mark is about 8% smaller than the previous release. The
  canonical mark image is unchanged.
- Settings explicitly identify Android's kill switch as **Block connections
  without VPN**, used with **Always-on VPN**. Traffic statistics now explain
  that the current VPN engine exposes byte totals and speeds, but not packet
  counts; this is not a limitation of the phone's Android version.

Validation:

- 47 frontend test files / 231 tests passed; TypeScript and the Vite production
  build passed.
- 12 native unit tests and 6 Android instrumentation tests passed. The isolated
  instrumentation package was removed after testing.
- Browser checks at 360 and 411 CSS pixels verified completed/disabled controls,
  re-enabling after external changes, and no horizontal overflow.
- ARM64 release compilation, APK privacy/native-payload checks, signature
  verification and in-place installation passed. `debuggable` is false.
  The installed package's SHA-256 matches the release artifact below.
- On the installed release, Disconnect in the app changed the Quick Settings
  tile to inactive / Connect. Quick Settings reconnected successfully.
- Both the VPN service and its supervisor were observed in foreground mode.
- Tapping the installed release's expanded notification **Disconnect** action
  stopped both services and left the Samsung notification shade open.
- Swiping SirinVPN away was tested before the change with Always-on off and
  after the change with Always-on temporarily enabled. In both cases the
  tunnel remained connected at 2, 12 and 32 seconds. The updated release's
  task was confirmed absent from Recents while both native foreground services
  remained active. The reported disconnect was not reproduced in these runs;
  longer OEM background eviction and reboot recovery were not tested here.
- The phone's original system settings were restored after the test:
  `always_on_vpn_app = null`, `always_on_vpn_lockdown = 0`.
  Switching Always-on off stopped the VPN through Android's service lifecycle.
  The VPN was reconnected; a final tap on the actual Quick Settings Connect
  tile also reconnected successfully. The phone was left with SirinVPN open,
  the VPN connected and both native foreground services active.

The diagnostics item **Provider firewall and public reachability — Not checked**
means that check has no external reachability result. A listening server socket
alone cannot verify the VPS provider's public firewall or every transport port.
A working Direct UDP session verifies that session's path, not every configured
transport. No provider firewall configuration was changed by this follow-up.

References: [Android VPN lifecycle and blocking settings](https://developer.android.com/develop/connectivity/vpn),
[Quick Settings tile lifecycle](https://developer.android.com/reference/android/service/quicksettings/TileService),
[notification action options](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Action.Builder),
[WireGuard GoBackend statistics](https://raw.githubusercontent.com/WireGuard/wireguard-android/master/tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java).

Artifact and verification output: `target/android-followup-2026-09-13/`.
APK: `SirinVPN_0.1.0_aarch64-release.apk`.
SHA-256: `512f167ccb86b7ec731709ad2a8f250c9aec8df991a96c4e0cdbb142d675e9bb`.
