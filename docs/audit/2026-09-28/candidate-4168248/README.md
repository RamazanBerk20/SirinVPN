# 0.1.1 engineering candidate: 4168248

Candidate source: [`41682484b9528ddd1183d62806e258698434790a`](https://github.com/RamazanBerk20/SirinVPN/commit/41682484b9528ddd1183d62806e258698434790a).
This is development qualification, not independent security review or production
approval. The subsequent report/fixture commit does not change which source or
package bytes these results qualify.

The [draft candidate release](https://github.com/RamazanBerk20/SirinVPN/releases)
lists `v0.1.1-candidate.4168248` (release ID `397855664`) with the exact packages
and evidence archive for maintainer review. Draft assets require repository
access. GitHub changes temporary draft URLs when notes are edited; use this
release list and tag instead of the creation-time URL inside the immutable archive. [Publication metadata](publication.json) binds the
archive and uploaded files by SHA-256; the archive contains its own file manifest.
GitHub release assets preserve this evidence beyond CI's 14-day artifact window,
but remain deletable by repository maintainers. Keep a separate offline copy.

## Results and scope

| Check | Observed result | Boundary |
| --- | --- | --- |
| Hosted Linux validation | 454 Rust, 210 frontend and 16 Python tests passed | Privileged tests excluded by the shared suite remain separately identified in its raw log |
| Hosted Windows validation | 156 native Rust tests passed | Includes real child-process deletion interruption and cross-process stale-writer cases; MSVC test binaries are separate from the packaged LLVM-MinGW release binaries |
| Hosted dependency gate | Passed: 959 package records, zero blocking findings, nine reviewed advisory records | Raw OSV exit 1 and all findings retained; dispositions expire 2026-12-27 |
| Debian package | All 30 acceptance checks passed | Four transports, DNS/protection, fallback, resolver/relay failures, package lifecycle and real VM power loss |
| AppImage | FUSE and extract-run launch/close passed | Does not qualify its entire VPN lifecycle |
| Windows NSIS | All nine checks passed | Interrupted 0.1.0→0.1.1 upgrade, retry, byte-preserved profile/DPAPI, repair, GUI, tunnel use, tombstone deletion and uninstall |
| Windows release runtime | All 15 checks passed | Cross-user DPAPI/IPC negatives, authenticated service, tamper refusal, four transports, private DNS, guarded stop/restart and cleanup |
| Windows release crash/reboot | All eight checks passed | Actual process termination, new PID/counter epoch, blocked underlay probes, new Windows boot and tunnel recovery before login |
| Android API 29 | Five upgrade invocations and seven native tests passed | Same-signer debug APK; synthetic state in a fresh x86_64 AVD |
| Android API 36 | Five upgrade invocations and eight native assertions passed in separate AVDs | Later fixture/log-export failures remain failures in the enclosing collectors; see below |
| Physical Android | In-place 0.1.0→0.1.1 upgrade and all 16 lifecycle checks passed | Exact candidate APK on Samsung S25+, Android 16/ARM64/4 KiB; same development signer and existing Member profile |

[Hosted results](hosted-summary.json) link the successful
[Validate run](https://github.com/RamazanBerk20/SirinVPN/actions/runs/36351092541)
and [dependency run](https://github.com/RamazanBerk20/SirinVPN/actions/runs/36351092524).
[Artifact hashes](artifacts.json), [scope summary](summary.json), and
[source checks](frozen-source-check.json) accompany the raw archive. All 34
candidate collectors retained clean, unchanged source; that includes the failed
collectors, whose outcomes have not been rewritten.

The later [physical-phone supplement](physical-android.json) uses the same
candidate APK with clean harness source `322ca9e`. The original profile,
encrypted credential and saved policies remained byte-identical. Authenticated
management and ordinary-UID traffic verified use of the original Keystore-backed
identity after upgrading. All 16 lifecycle checks passed, including network
transitions, process termination and Always-on/lockdown. Original settings were
restored, the temporary probe app removed and the user's connection resumed.

The supplement preserves the installed 0.1.0 baseline APK by hash without
inventing a source commit. Twelve inventoried files were unchanged immediately
after installation; first launch then refreshed two cached server executables
whose hashes match the candidate APK assets. The initial overly broad file
assertion and this verified distinction are retained in the restoration record.
This is additive evidence in the draft release; the original archive is unchanged.

The exact NSIS installed payloads matched its extracted hashes. The unpackaged
desktop build output is also retained but is not the installed desktop's byte
identity; use `runtime-evidence/windows/native-installer-result.json` for the
installed payloads. The installed service/CLI/DLL/driver match the separately
exercised release components.

## DNS finding

The current candidate reproduced and attributed an absolute-counter false
positive. A zero-payload TCP ACK from `systemd-resolve` PID 312, socket FD 28,
left `ens3` for the disposable resolver after explicit Disconnect and counter
reset, **before** the pre-Connect baseline. Kernel packet time, socket ownership,
the nft trace that incremented the counter, guard events and connection phases
are retained in [the attribution record](dns-counter-attribution.json).

The counter was one before Connect and one after fallback: no new DNS packet
was counted during that interval. The corrected assertion compares against the
pre-Connect baseline, rejects decreases and every new DNS packet, and still
requires zero IPv6 packets. It exempts no TCP flags or payload sizes. Capture
starts before Disconnect and uses the VM agent so an existing guard cannot
prevent collection. Regressions cover the counter boundary.

The separate sensitivity control observed five pre-protection packets, 216 guard
drops and all three deliberately injected protected-interval escapes. No physical
packet was observed between guard installation notification and the deliberate
exception. Rule-notification timestamps are userspace receive times, not exact
kernel commit times.

**The two original counter-only observations remain unattributed.** The new
timeline proves this reproduced measurement error; it cannot recover timestamps
or processes absent from the historical records. This is not a universal
no-leak claim. Failed historical measurements remain in `runtime-evidence/history`.

## State migration and deletion

Windows deletion now records durable schema-2 intent/completion, serializes
operations per reference across processes, refuses reads/writes after deletion
starts, and permits cleanup retry. Existing unmarked DPAPI records remain
readable. Native regressions terminate child processes at deletion boundaries;
the exact installed release CLI also removed ciphertext and retained its deleted
marker. Secure erasure of storage media is not claimed.

The tested migration boundary is an **unbound development 0.1.0 installation**.
The archive preserves each old package by hash without assigning it an invented
source commit. Linux survived a real VM power cut after package unpack, then
reboot/configure retry with unchanged profile and credential bytes; encrypted
backup restore and VPS repair also passed. Windows survived termination of the
owned NSIS process tree after the new GUI payload reached disk, followed by retry.
Android staged the real PackageInstaller update, rebooted before commit,
verified the old state, abandoned the session, and retried installation.

Android checks cover exact profile/ciphertext preservation, Keystore decryption,
native profile reads, deleted references and paused connection intent. They do
not qualify a development-to-production signing-key transition or a live VPN
upgrade. Incompatible signed receipts and unsupported rollback remain rejected;
the [migration policy](../../../release-candidate.md) does not weaken that boundary.

## Retained fixture failures

API 36 first hit a boot timeout, then an old-app startup failure. A diagnostic
repeat identified an ActivityManager startup ANR before the test method, amid
boot-service CPU pressure. The first short-message-only failure has no complete
timeline of its own. Waiting for Android's broadcast barrier allowed the upgrade
assertions to pass. A later service timeout coincided with heavy memory reclaim.
The successful readiness setup used a 3,800 MiB soft limit, retaining the 4 GiB
hard cap, no swap and 150% CPU limit.

The later Wi-Fi failure had an explicit fixture cause: `AndroidWifi` was disabled
for lack of Internet and cellular was the active underlay. Reconnecting the
synthetic Wi-Fi supplied the positive control and all eight native tests passed.
Its subsequent optional logcat export exited 255, so the enclosing collector
remains failed. [Upgrade scope](android-api36-upgrade-scope.json) and
[native scope](android-api36-native-scope.json) identify the exact successful
assertions and raw log hashes. No assertion or application timeout was relaxed.

The follow-up harness retains distinct upgrade logs, drains boot broadcasts,
checks synthetic Wi-Fi readiness and uses the observed API 36 memory setting.
Those controls were exercised by the archived diagnostic fixture scripts against
the frozen APK; the later reusable-harness edit is identified separately.

Other retained failures include missing public APT cache preparation before
AppImage launch, probe dependency-selection errors before Windows execution,
and clone-only share/old-service cleanup problems before candidate installation.
Retries corrected the fixtures without changing candidate bytes. The archive
also records an incomplete supplementary private-value check; publication uses
the explicit file allowlist and separately recorded secret-scan review.

All owned AVDs, Linux/VPS guests, Windows clone storage and its private bridge
were removed. [Windows cleanup](windows-fixture-cleanup.json) leaves the original
Winboat stopped and its storage untouched. VM disks, environments, credentials,
encrypted fixture exports and private console screenshots are excluded.

## Distribution materials and remaining review

The archive includes the complete 959-record locked build-input SBOM and
hash-bound per-artifact notice ZIPs. Conservative selected inputs are Linux 401,
Windows 366 and Android 411, with **zero missing selected publisher notices**.
The full inventory still lists 122 unselected development/metadata notice review
items. These are inputs, not a claim about symbols retained by linking or R8.
The tested debug APK's external Maven artifact hashes match the exported inventory.

AppImage material identifies 201 bundled ELF files against 120 Debian packages.
Windows supplements verify the exact WireGuard and WebView2 publisher payloads;
Rust/NDK/LLVM-MinGW notices remain separate. The pinned AppImage runtime's
publisher debug companion matches its build ID/debuglink CRC and identifies
musl 1.2.5. Runtime and library source archives are preserved, but the exact
Alpine package revision/patches and complete static relinking material remain
unverified. This requires distribution review before publication.

Production approval still requires offline trust-root custody/recovery,
production Android signing and migration, Windows publisher/driver signing,
final signed-byte installation checks, remaining DNS/platform scope review,
and corresponding-source/notice review. No production key was created or
replaced and no driver-signature enforcement was bypassed. Physical-phone reboot,
camera/accessibility/overnight behavior, other OEMs, physical 16 KiB pages,
broader Windows/Linux fault matrices and independent security review remain
outside this candidate's completed scope.
