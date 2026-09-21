# Android reset — 13 September 2026

At the owner's explicit request, the previous Android application was removed
from this repository and uninstalled from the connected phone. An attempted native
replacement was subsequently cancelled and removed at the owner's request on the
same day. Android development is deferred until the desktop version is finished;
the [rebuild brief](android-rebuild-prompt.md) is retained only as historical reference.

## Native replacement withdrawn

The standalone `apps/android` application, Gradle project, Kotlin/Compose service
and UI, Android tests, WireGuard adapter, Rust JNI crate and generated APKs/ABI
outputs have been deleted. The Android-only shared-core feature split and workspace
member were removed. The dedicated local acceptance signing material was deleted.
No replacement source archive was made. General SDKs and development tools remain.

The connected Samsung SM-S936B was discovered through ADB. Uninstalling
`org.sirinvpn.client`, `org.sirinvpn.client.debug` and
`org.sirinvpn.client.debug.test` each returned `Success`. The current user has no
SirinVPN packages; `always_on_vpn_app` is `null` and
`always_on_vpn_lockdown` is `0`. Uninstall also removes the replacement's pending
phone enrollment keys. This removal performed no server-side revocation,
installation or policy changes.

The removal passed `./scripts/test.sh`: 421 Rust tests passed (15 ignored), 165
frontend tests passed across 37 files, and the frontend production build,
workspace Clippy, formatting, Python tests and privacy checks passed. Optional
ShellCheck was skipped because it is not installed. The fresh log is
`target/desktop-focus-regressions.log`. Content hashes for 467 desktop, server and
shared compatibility files matched their values before this removal.

The replacement never passed milestone 1 acceptance. The separate validation
table below belongs to the earlier reset, not to that replacement.

## Removed

- The Android app overrides and generated Tauri/Gradle project.
- The native VPN, secure-storage and Android transport crates, including Kotlin
  services, JNI adapters, Wi-Fi automation, tile/notification implementation and
  their tests.
- Android Tauri commands, plugin dependencies, frontend entry point, screens,
  API methods, runtime types and platform-specific styles.
- Android packaging, emulator, dependency-audit and device/performance scripts;
  Android scenarios and native adapters in the shared UI test tooling.
- Android launcher resources and the old Android build/output directories under
  `target`. Current development documentation no longer offers Android builds.

The source comparison against the pre-reset archive identified 277 removed files.
Android paths were removed from the active workspace, not restored from Git:
existing uncommitted desktop/server work was preserved.

## Preserved

The desktop UI, Linux helper, Windows service, VPS, CLI, shared cryptography,
transport implementations and server authorization contracts remain. The approved
`apps/desktop/src/assets/sirin-mark.png` and desktop icon files were not changed.
The installed desktop application and its profiles/keys were not replaced or
deleted. No VPS installation or server-side device authorization was changed.

Shared desktop initialization/invitation styles were extracted from the retired
Android stylesheets, retaining their cascade positions. Desktop builds, icon
generation and screenshot tooling no longer depend on the Android application.
The Linux fallback fixture was retained as `tests/integration/fallback-proxy.py`.
Both VPS executable payloads used by Windows packaging were preserved.

Some Android *data declarations* intentionally remain: signed release artifact
kinds and historical schema compatibility records, application-routing wire
types, and portable socket support in the shared transport crate. Removing those
would change existing protocol/backup/release behavior. They do not provide an
Android app, service, build target or installer. Desktop Devices tests can still
contain a remote device named “Android phone.”

Existing dated Android reports are marked historical. Shared Rust files with
outstanding formatting differences were formatted; their server/protocol behavior
was not changed by this reset. SDKs, NDKs and general development tools remain
available for the eventual rebuild.

## Phone

ADB device: `R5CY20JV1CL` (Samsung SM-S936B).

`pm uninstall --user 0 org.sirinvpn.client` returned `Success`. Subsequent
`pm list packages --user 0 sirinvpn` returned no packages. The current user's
Always-on package is `null` and lockdown is `0`; no orphaned SirinVPN configuration
is blocking the phone's normal networking.

Uninstall removed that phone user's saved profiles and private device keys. No
phone-key backup was taken. The next app needs fresh enrollment or a separately
existing user-created encrypted backup. Server-side device entries were left
alone; uninstalling a client is not server-side revocation.

## Recovery archive

The source snapshot and removed paths are outside the repository:

`/home/ramazan/Belgeler/AI/Code/SirinVPN-archives/android-reset-20260913-173859/`

- `source-before-reset.tar.gz`: verified pre-reset source snapshot, 1,226 files.
- `removed/`: removed Android source/resources and generated project.
- `removed-paths.json`: removal inventory.
- `build-artifacts/`: retired Android outputs, including old APKs and target trees.
- `retired-build-artifacts.json`: output inventory.

The archive directory is private and the source tarball is mode `0600`. Its SHA-256:

`277147418123b595c21f61630f3f7a7777e98fb43fe18d275df1576ba1439162`

This is recovery/history material, not the starting implementation for the new
Android client. No source archive substitutes for the phone's deleted private keys.

## Validation

| Check | Result |
| --- | --- |
| Frontend tests | 165 passed across 37 files |
| Frontend production build | Passed; TypeScript and Vite |
| Rust workspace tests | 421 passed, 15 ignored, 0 failed |
| Native Linux desktop executable build | Passed |
| Workspace Clippy, all targets, warnings denied | Passed |
| Workspace Rust formatting | Passed |
| Python unit tests | 2 passed |
| Privacy invariants | Passed |
| Maintainability inventory | Passed; no source files over 1,000 lines |
| Desktop catalog bundle | Built; 404 remaining scenarios enumerate successfully |
| Changed Python tooling | Syntax validation passed |
| Policy XML | Passed |
| Git whitespace check | Passed |
| ShellCheck | Optional check skipped: tool not installed |

Logs for this reset are under `target/android-reset-*.log`. Environment-dependent
ignored tests were not converted into passing claims. No new Windows runtime,
live-VPS acceptance or complete screenshot journey run was performed. The native
desktop build verifies the Linux executable; this reset did not install a new
desktop package or Android APK.
