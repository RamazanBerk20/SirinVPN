# Implementation delivery — 7 September 2026

This is the historical seven-artifact build snapshot from 7 September. Subsequent
[Linux acceptance](linux-acceptance-2026-09-07.md) found three product bugs and
produced corrected Linux builds. Use that report for current Linux artifacts.
The Windows and Android binaries listed here predate the shared installer fix
and need rebuilding before their next acceptance run. The
[feature map](overhaul-feature-map.md) records platform capabilities and limits.

## Local deliverables

The handoff directory is `target/deliverables/2026-09-07/`. It contains the seven
artifacts below, `SHA256SUMS`, `build-manifest.json`, `source-inputs.json`, an
inspection directory and a short README. The small evidence records are also
retained under [the delivery audit](audit/2026-09-07/implementation-delivery/build-manifest.json).

| Artifact | Local file | Size |
| --- | --- | --- |
| Linux Debian | [SirinVPN_0.1.0_amd64.deb](../target/deliverables/2026-09-07/SirinVPN_0.1.0_amd64.deb) | 18.5 MiB |
| Linux AppImage | [SirinVPN_0.1.0_amd64.AppImage](../target/deliverables/2026-09-07/SirinVPN_0.1.0_amd64.AppImage) | 106.9 MiB |
| Windows installer | [SirinVPN_0.1.0_x64-setup.exe](../target/deliverables/2026-09-07/SirinVPN_0.1.0_x64-setup.exe) | 220.5 MiB |
| Android emulator | [SirinVPN_0.1.0_x86_64-debug.apk](../target/deliverables/2026-09-07/SirinVPN_0.1.0_x86_64-debug.apk) | 508.5 MiB |
| Android phone | [SirinVPN_0.1.0_aarch64-debug.apk](../target/deliverables/2026-09-07/SirinVPN_0.1.0_aarch64-debug.apk) | 382.0 MiB |
| Debian VPS x86_64 | [vps/sirinvpn-server-x86_64](../target/deliverables/2026-09-07/vps/sirinvpn-server-x86_64) | 6.4 MiB |
| Debian VPS aarch64 | [vps/sirinvpn-server-aarch64](../target/deliverables/2026-09-07/vps/sirinvpn-server-aarch64) | 5.4 MiB |

Linux and VPS executables use release compilation. Windows is an **unsigned x64
GNU LLVM debug cross-build**; it is not an MSVC or ARM64 Windows qualification.
WebView2 must already be installed. Android APKs are **debug builds signed with
the Android Debug certificate**. Their size includes native debug information.
These are engineering artifacts for acceptance testing; publisher signing,
release compilation/optimization on the final platform and production
qualification remain separate. The Android compile/target SDK is 36, minimum SDK
24; device behavior still requires platform tests.

The manifest is a checksum inventory, not a signed SirinVPN update manifest.
From the handoff directory, copied artifact bytes can be checked with:

```sh
sha256sum -c SHA256SUMS
```

## Completed implementation checks

- **451 Rust tests passed**, with zero failures. Fourteen explicitly ignored
  checks require isolated networking/root fixtures or systemd tooling and remain
  available for the acceptance phase. The exact list is in
  [Rust evidence](audit/2026-09-07/implementation-delivery/rust-checks.json).
- Workspace Clippy with warnings denied and full Rust formatting passed.
- **157 frontend tests across 32 files passed**, followed by TypeScript and Vite
  production compilation. This includes Android flows and current diagnostics.
- Seven Android native JVM policy/diagnostic tests passed at the final native
  checkpoint, and instrumentation sources compile. Both actual APK builds then
  compiled the native libraries and Kotlin application. No device execution is
  implied; see [diagnostics evidence](current-diagnostics-2026-09-07.md).
- Privacy, source-size, shell-fixture and packaging-script syntax checks passed.
  The inventory contains 653 first-party source files with none over 1,000 lines.

The final code adjustments were formatting, correct platform compilation of
Windows policy modules and Android summary helpers, and a redundant conversion
in an installer test. The packages were rebuilt after those adjustments. Builds
ran one at a time, with two Cargo jobs and Rust test threads, one Vitest worker,
and CPU/memory limits. See [resource limits](development.md#resource-limits).

## Package evidence

[Linux inspection](audit/2026-09-07/implementation-delivery/linux-packages.json)
verifies six Debian executables against their current source binaries, root
ownership and safe modes, runtime dependencies, polkit/systemd files and ELF
architecture. The only allowed GUI byte change is Tauri's three-byte bundle-type
marker. AppImage inspection checks all six executable architectures, removal of
the bundled Wayland libraries, and the exact same VPS bytes as the Debian package.

[Windows inspection](audit/2026-09-07/implementation-delivery/windows-package.json)
verifies configured resources, the expected GUI package marker, PE/ELF
architectures, pinned WireGuardNT bytes and available normal/delayed DLL imports.
It extracts the installer without executing it.

[Android x64](audit/2026-09-07/implementation-delivery/android-x86_64.json) and
[Android ARM64](audit/2026-09-07/implementation-delivery/android-aarch64.json)
inspection verifies backup/extraction restrictions, matching native ELF
architectures, the exact current transport library and both current VPS payloads
inside each application library. `apksigner verify` passed APK Signature Scheme
v2 for both files with the same Android Debug certificate. This establishes
artifact integrity and signer identity, not publisher release provenance.

[Both VPS payloads](audit/2026-09-07/implementation-delivery/vps-payloads.json)
come from Debian build containers. They have the expected x64/ARM64 ELF machine,
maximum GLIBC requirement 2.34, only the expected system runtime dependencies,
and no build-directory RPATH. The same hashes are verified inside the clients.

## Acceptance boundary

The package phase did not install a client, start a VPN, modify a live VPS or
execute privileged networking tests. Use disposable fixtures for the next pass:

1. Install, upgrade, rollback and uninstall on Linux and Windows; validate native
   privilege, protected paths, DPAPI/Keystore and interruption recovery.
2. Exercise all transports, restrictive networks, IPv4/IPv6, CIDR/application
   routing, LAN policy, DNS and packet leaks through loss, crash, reboot and roam.
3. Validate independent protection/reconnect/startup policy, Android Always-on and
   lockdown, optional Wi-Fi permissions/redaction/trust, quality and MTU changes.
4. Exercise roles and delegation, reusable invitations, expiry/schedules/limits,
   revocation, peer access, forwarding, backups/recovery and key rotation.
5. Exercise signed endpoints/migration, signed app/VPS updates, compatible
   rollback and opt-in VPS security updates with controlled signing fixtures.
6. Check actual desktop/mobile UI, tray/notifications, accessibility and startup
   behavior; qualify production dependency/signature and release-build behavior.

The detailed scenarios and opt-in commands remain in [Testing](testing.md),
[Windows acceptance](windows-integration-2026-09-07.md#windows-acceptance-still-to-run)
and [Android implementation](android-integration-2026-09-07.md). Historical audit
results apply to their original checkpoints; they do not give new artifacts a
passing runtime result.
