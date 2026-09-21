> Historical report: this Android implementation was removed on 13 September 2026. See [reset record](android-reset-2026-09-13.md); these results do not validate a replacement.

# Android notification and launcher polish — 2026-09-13

The Android release now uses one logo in its ongoing VPN notification, gives the
launcher mark more room, removes the separate connection-alert controls, and
separates the two Quick Access buttons.

- Removed the explicit notification large image. The system app icon, small
  status icon, connection status, transfer rates, and Disconnect action remain.
- Added 7.5% insets on each side of the adaptive foreground and monochrome layers,
  rendering the mark at 85% of its previous size. Both regular and round adaptive
  icons use these resources. The shared `src/assets/sirin-mark.png` is unchanged.
  The insets use Android's [InsetDrawable resource support](https://developer.android.com/reference/android/graphics/drawable/InsetDrawable).
- Android General settings now show Interface and app updates. The obsolete
  Rust connection-alert observer and its test/permission commands are excluded
  from Android builds. Existing shared preference files remain compatible;
  desktop alerts continue to work. Native VPN notification permission remains
  available under Quick Access.
- Quick Access uses full-width stacked buttons with a 12 CSS pixel gap.

Validation passed:

- Frontend: 46 test files, 226 tests; TypeScript and production Vite build.
- Desktop Rust notification tests: 2 passed.
- Browser checks at 360, 411, and 480 CSS pixels: the gap is 12 pixels, no
  horizontal overflow, and Android's duplicate alert controls are absent even
  with the old notification preference enabled.
- ARM64 Android release build, APK privacy/native-payload verification, and
  signature verification. Packaged adaptive icon resources contain the insets.
- In-place installation on the connected Samsung phone succeeded. Installed APK
  bytes match the verified artifact; `debuggable` is false. The native VPN process
  is running, and its notification reports Connected, transfer rates, and
  Disconnect, with no large image or legacy alert IDs. Android's current
  Always-on/lockdown settings were preserved. The spacing was also observed in
  the installed release's settings screen.

Release artifact and verification output:
`target/android-ui-polish-2026-09-13/`. The APK is
`SirinVPN_0.1.0_aarch64-release.apk`, signed with the existing local development
certificate for update compatibility. SHA-256:
`6424ece2664608f43c7d35134f080cedbd253b73b94366e8e1dec0f042db492c`.
