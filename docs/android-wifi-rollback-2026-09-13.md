> Historical report: this Android implementation was removed on 13 September 2026. See [reset record](android-reset-2026-09-13.md); these results do not validate a replacement.

# Selective Android Wi-Fi rollback — 2026-09-13

The user requested reverting only the Trust current Wi-Fi fixes and retaining
the other changes from the first Android follow-up release. Further Wi-Fi work
is deferred until the user's next instructions.

Reverted the optional access-point label, permission shortcut, and Wi-Fi status
refresh changes. Also reverted the subsequent changes that allowed arming Wi-Fi
automation while connected, allowed manual connections with automation armed,
and retained the notification supervisor after Disconnect when automation was
armed. The existing Wi-Fi feature is back to its behavior before those fixes.

Retained the VPN foreground-service and recovery changes, immediate Quick
Settings tile updates, notification Disconnect behavior, Quick Access setup
awareness, smaller adaptive icon, and corrected Android protection and packet
count explanations. The earlier notification and layout polish remains intact.

The source was reconstructed from this session's saved files and exact patches.
The 25 files containing retained changes were checked against the reconstructed
version; the other seven affected source files match the pre-fix checkpoint.
No repository-wide reset was used.

Validation:

- 47 frontend test files / 229 tests passed.
- TypeScript and the Vite production build passed.
- 12 native unit tests passed.
- ARM64 release compilation, APK checks, and signature verification passed.
- The release was installed in place on the connected Samsung phone. The
  installed APK's SHA-256 matches the verified artifact and `debuggable` is
  false. App data was preserved; no device UI or network settings were changed
  for testing during this selective rollback.

Release APK: `SirinVPN_0.1.0_aarch64-release.apk`.
SHA-256: `d1715848e1506a64716b340e0c0dd41bceb809bf8831eb29f495e2cf08b4aac2`.

Source checkpoints, the Wi-Fi-only diff, and verification logs are in
`target/android-wifi-rework-2026-09-13/`.
