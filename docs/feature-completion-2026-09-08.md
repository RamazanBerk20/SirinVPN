# Client feature completion — 8 September 2026

This follow-up implements the three concrete gaps from the previous handoff:
AppImage updates, Android app updates, and Windows executable routing. GUI review
is left to the user. Source checks and compilation do not establish native
Windows driver or Android installation acceptance.

## AppImage updates and rollback

The app-update dialog detects a supported user-owned AppImage and requests the
matching `linux_appimage` artifact from an explicitly supplied HTTPS release
directory. The first update requires a root-authorized signed copy of the exact
installed package and running version as its baseline. No default release host,
background check, account or device identifier is introduced.

An upgrade stores a validated signed transaction before replacing the file. The
replacement accepts only an owned, executable type-2 AppImage with the expected
ELF architecture, no links, and safe ancestors. It copies and hashes the complete
candidate into a private sibling file, synchronizes it, and renames atomically.
The signed installed receipt advances only after independently checking the new
installed bytes. Reopening updates reconciles an interrupted replacement.

The dialog also offers the retained previous AppImage by its exact version, with
a separate confirmation. Rollback requires a still-trusted compatible release
and preserves signed release/trust high watermarks. It changes the portable app
file; the installed VPN service remains independent. Restart the AppImage after
updating or restoring it.

Implementation: [shared client transactions](../crates/release/src/client_update.rs),
[safe file replacement](../crates/release/src/appimage_file.rs),
[desktop coordinator](../apps/desktop/src-tauri/src/release_update/appimage.rs).

## Android app updates

Android Settings now opens the same explicit release-check and confirmation
flow for the matching `android_apk` artifact. It uses an exact signed baseline
and a private transaction. Installation requires the VPN disconnected, persistent
protection disabled, and Wi-Fi automation disabled. Android can request permission
to install packages from SirinVPN before showing its system confirmation.

The native installer independently re-verifies the signed transaction through
JNI, the exact private cache path, package name, release version, strictly newer
Android version code and the existing Android signing certificate. It streams
and hashes the APK into `PackageInstaller`, requests user action, and accepts its
private result receiver as the installation authority. Merely downloading a
candidate or returning from an Activity does not commit a receipt. On restart,
the actual installed APK determines whether the transaction completed. Only the
current installer session ID is retained while needed.

Ordinary Android app downgrade is not exposed. Publisher signing-key rotation
requires a separate supported migration; the current installer requires the
same signing certificate. The operating system's confirmation requirement follows
the [PackageInstaller session API](https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams#setRequireUserAction(int)).

Implementation: [Rust coordinator](../apps/desktop/src-tauri/src/release_update_android.rs),
[native installer](../crates/android-vpn/android/src/main/java/org/sirinvpn/plugin/vpn/AppUpdateInstaller.kt),
[independent JNI verification](../crates/android-transport/src/release.rs).

## Windows executable routing

Selected-applications mode now has an owned WFP bind-redirection driver and
service integration. It supports selected native executables under the
authenticated Windows account for IPv4 TCP/UDP. Selected IPv6 and traffic outside
the tunnel are blocked. The kill switch must be on and LAN access off. Other
executables keep their ordinary routes; system DNS uses the VPS.

The service accepts a fixed local `.exe` path for routing only. It rejects remote,
device, alternate-stream and reparse paths before deriving the WFP identity.
Neither launch arguments nor process creation cross the LocalSystem boundary.
After the service verifies the current guard, the desktop starts the executable
as the ordinary user without a shell. Up to 24 current path identities stay in
the encrypted current-session record for recovery. They remain protected during
Pause, reconnect, restart and server switching. Explicit Disconnect releases the
guard and clears the current selection.

Close existing instances before selecting an application. Separate helper
executables and services do not inherit selection. Select each executable that
handles networking. Applications explicitly bound to another source address are
blocked; already bound sockets may need an application restart after switching
servers. This is not general sandboxing or automatic process-tree isolation.

The kernel driver has no named user device or IOCTL surface and retains no flow
history or packet payloads. Durable application blocks remain after the service
stops; interface permissions and bind redirection disappear with its dynamic
WFP session. Capability publication requires both the owned SCM driver running
and its registered kernel callout. The implementation uses the supported
[WFP bind-redirection layer](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
to change a socket's local source address.

The engineering driver is unsigned. Microsoft requires new kernel drivers to
go through its signing process for normal Windows loading. No signing keys were
available here and no signature-enforcement setting was changed. Consequently,
these Windows engineering packages keep application routing disabled until the
driver is appropriately signed and loaded; ordinary VPN modes remain available.
See [Microsoft's driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-).

Implementation: [driver](../packaging/windows/routing-driver/driver.c),
[path identity validation](../crates/windows-service/src/application_plan/native.rs),
[controller](../crates/windows-service/src/controller/applications.rs),
[policy](../crates/windows-service/src/firewall_plan.rs),
[installer lifecycle](../crates/windows-service/src/install/application_driver.rs).

## Verification and builds

The full local gate passed 465 Rust tests, 162 frontend tests across 33 files,
two Python unit tests, strict host Rust linting, TypeScript and frontend production
build, privacy checks and the 1,000-line source limit. Fourteen tests requiring
isolated privileged networking were left for their dedicated harness. The new
release tests cover baseline binding, interrupted replacement, installed-byte
commit, cancellation, signed rollback and independent native re-verification.
Windows policy tests cover selected executable/account scope, underlay and IPv6
blocking, durable protection, route ownership and input/state validation.

Windows desktop/service/platform test targets passed cross-target Clippy with
warnings denied. Android app/JNI code passed target Clippy with warnings denied;
all seven native plugin JVM tests passed and instrumentation sources compiled.
This does not claim an Android installer session or a signed Windows driver was
run on a device. The earlier [Linux VM acceptance](linux-acceptance-2026-09-07.md)
remains evidence for the exact earlier packages named in that report.

All heavy builds run sequentially with two Cargo jobs, at most 4 GiB RAM, no
additional swap and a 150% CPU ceiling. Production release signatures, Android
publisher keys, Windows kernel signing and native platform qualification remain
separate from these engineering builds.

All five application packages compiled and passed static inspection. The Windows
driver was rebuilt with x64 kernel stack conventions and unwind metadata; its
native PE entry point, integrity flag and imports were inspected. The Android
APKs contain the independent release verifier, private installer receiver,
explicit installation permission and both matching current VPS payloads.
The Linux packaging test repeat passed all 162 frontend tests after correcting
a test that changed an application-selection control before saved preferences
had finished loading. Final source inventory covers 685 files and 137,788 lines,
including C and PowerShell; no source file exceeds 1,000 lines.

## Fresh packages for GUI review

The copied builds are in `target/deliverables/2026-09-08/features/`. The earlier
Linux acceptance handoff remains separate. Close an older running SirinVPN GUI
before opening this AppImage so the review uses the new executable.

| Package | Build |
| --- | --- |
| [Linux x64 AppImage](../target/deliverables/2026-09-08/features/SirinVPN_0.1.0_amd64.AppImage) | Release, unsigned |
| [Linux x64 Debian](../target/deliverables/2026-09-08/features/SirinVPN_0.1.0_amd64.deb) | Release, unsigned |
| [Windows x64 installer](../target/deliverables/2026-09-08/features/SirinVPN_0.1.0_x64-setup.exe) | GNU LLVM debug, unsigned |
| [Android ARM64 APK](../target/deliverables/2026-09-08/features/SirinVPN_0.1.0_aarch64-debug.apk) | Development signing |
| [Android x86_64 APK](../target/deliverables/2026-09-08/features/SirinVPN_0.1.0_x86_64-debug.apk) | Development signing |

The same folder includes both VPS executables and the unsigned Windows routing
driver. All eight copied artifacts were verified against their inspected build
hashes. Use its [SHA256SUMS](../target/deliverables/2026-09-08/features/SHA256SUMS)
to check the copies. The [build manifest](audit/2026-09-08/feature-completion/build-manifest.json)
and [check results](audit/2026-09-08/feature-completion/checks.json) retain exact
artifact identities and validation limits. Source hashes, build logs and JVM
test results are included in the [local handoff](../target/deliverables/2026-09-08/features/README.md).

For GUI review, the new flows are in the desktop app-update dialog (AppImage
baseline, installation and retained-version rollback), Android Settings → App
updates, and Windows selected-applications mode when the signed driver is
available. Actual update execution needs a root-authorized signed baseline and
newer signed release. This engineering handoff is not an update feed.
