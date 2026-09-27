# Reliability remediation — 26–27 September 2026

Base: `709fdf69206f1de18a3ff5c4cf3cd8eeaf812a56`; initially clean working tree.
This is an implementation and verification record, **not an independent security
audit or production qualification**.
Results apply only to the source/artifact identified by each evidence record.

The confirmed recovery and credential defects have implementations and regression
tests. Platform acceptance is incomplete. The initial, explicitly authorized
acceptance follow-up used the connected Samsung S25+ and an isolated offline copy of Winboat.
The phone's existing Member identity/profile and original OS/network settings
were preserved during that phase. It involved no personal VPS administration,
publication, production signing or direct host firewall edits. Docker manages
its own normal container networking. The subsequent user-authorized installation
and live testing are recorded in the 27 September follow-up below.

## Finding disposition

| Finding ID | Validity | Implemented change | Regression test | Actual verification | Remaining limitation |
|---|---|---|---|---|---|
| SRV-01 | Confirmed: restoration errors were discarded; peer-only cache hid divergent rules | One transaction/recovery owner, durable bounded intent, scoped containment, complete reconciliation and truthful status | Stage failures, partial effects, warm cache, cancellation, post-rename failure, process termination; real kernel lifecycle test | Shared regressions, 17 kernel cases and three VM power cuts passed | Power cuts verify real persistence with modeled network effects; wider real-network transaction power-cut matrix remains open |
| SEC-01 | Confirmed: deletion could acknowledge keyring failure | Persistent deletion intent, independent backend attempts, verified absence, sealed references, caller error propagation | Deletion matrix, stale writes, invalid paths, incomplete AtomicFile cleanup, real duplicate keyring entries | Unit, disposable Secret Service, Android and native Windows profile/credential removal checks passed | Windows interrupted-deletion matrix remains open; secure erasure of storage media is not claimed |
| SEC-02 | Confirmed: silent fallback and missing provenance | Secure storage default, explicit file consent, public-key binding, bounded reads, migration/readback and retryable cleanup | Strict/fallback policy, corruption/conflict, migration, locking, interrupted writes; real keyring interoperability/lock | Real Secret Service fixture passed; current shared gate recorded below | Other Secret Service providers and session restart/login transitions need acceptance |
| UI-01 | Partly existing: generation filtering was present; recovery/protection states were incomplete | Native storage status, acknowledged migration/cleanup, stale-screen/read rejection, distinct server recovery warning, hidden-view unknown status | Frontend consent/duplicate click/retry/generation/read-failure tests; rendered desktop/mobile recovery fixtures | Final shared gate: 210 frontend tests passed; browser results below | Browser fixtures do not prove native enforcement or screen-reader acceptance |
| AND-01 | Existing separate VPN process and native controls retained; vault/test compatibility defects confirmed | AtomicFile durability/cleanup checks, deletion tombstones, invalid-key refusal; API 29 notification and QR framing fixed | Native vault authentication/deletion/key-invalidation, notification samples, QR decode and saved-network roaming identity | Both-ABI debug build/lint; API 29: seven tests, API 36: eight; physical S25+: 16 lifecycle/network/OS-policy checks passed | Physical camera, TalkBack, reboot, overnight power behavior, other OEMs and physical 16 KB pages remain open |
| CI-01 | Confirmed: baseline lacked workflows; reachable Actions API reported no runs | Read-only pinned workflows for shared/native checks, dependency checks, manual kernel/Android/candidate jobs | Actionlint, shellcheck, action-pin/trigger checks, shared scripts | Workflows validated locally; hosted results pending | Hosted runtime prerequisites and retained run/artifact links required |
| EVD-01 | Confirmed: historical evidence could not qualify current changes | Versioned schema, dirty-source digest, timestamps/toolchains, post-build artifact hashes, bounded recorder; VM cleanup attempts every guest and exposes failure | Missing command, nonzero exit, timeout, output bound, no overwrite, artifact binding, setup/interruption/cleanup failures | Evidence/harness regressions and local JSON records passed; follow-up adds vendored-source and notice-archive checks | Local-only artifacts; no publication/CI artifact URLs; old runs retain their own source identity |
| PLT-01 | Qualification gap; runtime tests confirmed Linux carrier/uninstall and Windows pipe/WFP verification defects | Bounded carrier recovery, verified uninstall, standard-user service authentication and strict WFP comparison allowing only the INDEXED optimization | Kernel continuity, package uninstall, native Android, Windows cross-user negative controls and four transports | 17 kernel cases, three power cuts, startup; Debian: 28 checks; AppImage launch/close; S25+: 16 checks; Windows: 108 unit tests, debug/release runtime and NSIS acceptance, debug crash/reboot | Signed routing driver, broader leak/fault and desktop/OEM matrix remain open; two earlier Linux DNS counter failures remain unattributed |
| REL-01 | Source-only release readiness gap confirmed | Pinned toolchains/locks, exact payload checks, verified GLib upstream backport, explicit compatibility block and build-input SBOM/notices | Existing signed release/tamper/rollback tests and package inspection | Local engineering builds only; exact results below | Informational advisories, complete artifact-level notices/SBOM review, production key custody, compatible upgrade strategy and remaining platform acceptance block distribution |
| MNT-01 | Focused transaction/store complexity justified improvement | Typed stages/provenance, one lock owner, short OS boundaries, bounded commands, background desktop storage operations | Rust formatting/Clippy, source-size/privacy gates; existing tests retained | Source inventory has no first-party file above 1,000 lines; final gates below | No broad controller rewrite or claim that line count measures correctness |
| DOC-01 | Current/historical claims needed separation | Updated README/security/privacy/build/test/release guidance and this ledger | Current local link/version/schema/manifest checks | Local contract checks passed | Historical raw artifacts may be unavailable; private vulnerability reporting channel is not verified |

## Root causes and compatibility

Server authorization previously treated an attempted rollback as restoration.
The periodic cache represented desired peers, so unchanged peer membership could
hide failed isolation/forwarding restoration. The new engine marks recovery dirty
before any effect, holds the existing authorization write lock, persists only a
single private intent (public document hashes, not keys or activity), and blocks
VPN data in owned recovery chains while reconciling. Management/SSH recovery
access stays scoped. The durable authorization file is authoritative after an
ambiguous rename/fsync failure. Transport peers and endpoint checkpoints must
also agree before containment is released. Recovery retries are bounded/backed
off, and API/UI state does not report a failed recovery as healthy.

The transaction is owned by the existing authorization write lock. Caller
authorization is rechecked under that lock before constructing a mutation.
The file replacement is the authority boundary; directory fsync establishes its
durability, and successful publication/release completes the API contract.

| Boundary, in order | Authority and failure semantics | Regression evidence |
|---|---|---|
| Validate caller/document; mark generation applying; persist intent | No new access is authorized; cancellation leaves dirty state. Intent contains hashes only | Cancellation, journal validation, existing in-flight demotion/revocation tests |
| Install owned containment, then enrollment quarantine | Each nftables batch is atomic; failure does not prove containment. Management remains scoped and host SSH is unaffected | Before/after-effect model faults; real IPv4/IPv6 lifecycle packets |
| Synchronize WireGuard, isolation, forwarding | Netlink can partially apply; each nft batch is atomic, but the combined operation is not. Restore all components even if an earlier restore fails | Every stage before/after faults; independent rollback faults; warm-cache and unchanged-peer regression |
| Replace authorization file and fsync directory | Before replacement, A is authoritative; after replacement, reload to determine A or B even if fsync failed. Never restore A over committed B | Post-rename failure; process exit at each modeled boundary |
| Replace memory and transport authorization; publish checkpoint | A persisted B stays authoritative if publication fails. Result explicitly says committed with recovery required; existing relay authorization checks remain active | Publication failure, exact retry, existing revoked-session tests |
| Remove intent and release containment | Healthy only after all required effects/publication and release succeed. Startup contains before reading authority and always reconstructs it | Complete-stage faults, restart/process-death model, real kernel suite |
| Periodic expiration/schedule/recovery | Dirty state bypasses the cache. Cache includes the complete document and time-dependent effective peers; failures retry with 2–32 second backoff | Warm-cache model, lifecycle schedule/suspension/expiration regressions |

The process-death fixture uses actual private persistence but modeled network
effects. The separate VM fixture now cuts power after forwarding, persistence
and checkpoint publication and checks reconstruction after boot. These three
cuts qualify real guest filesystem persistence with modeled network effects;
they do not establish real packet containment through every transaction boundary.

The full kernel run also exposed a Linux continuity defect outside the original
server/store findings: TLS and raw TCP can share the blocked endpoint port.
Trying only the next carrier then tearing down WireGuard disrupted an existing
stream even though another advertised carrier was available. The supervisor now
tries the bounded remaining plan, checking restoration of the existing local
path and protection before advancing. The packet regression deliberately chooses
TLS before blocking that shared port and requires the original WireGuard epoch
and TCP stream to survive recovery. This is a fixture observation, not a general
latency or uninterrupted-connectivity guarantee. The passing kernel fixture
observed a 53,407 ms largest echo gap during the final forced outage: the stream survived,
but packet flow was interrupted.

The exact-package test found that server uninstall returned success while
`sirinvpn_measurement` remained. The generated network teardown omitted that
table, and its verifier used `! command` under `set -e`: POSIX shells exempt
negated commands from automatic failure. A runnable regression first reproduced
success with a leftover interface. Verification now explicitly rejects managed
paths (including dangling links), interfaces, tables, service state and listeners,
and checks that observation commands work. Network teardown, installation rollback
and uninstall share cleanup for the owned handoff/measurement tables. Direct
uninstall also cleans these tables on older installations. The VM test leaves an
unrelated table in place and requires its exact rules to survive. The first shared
gate after this fix rejected two old rollback stubs that falsely failed every
`nft` query; their empty-ruleset observation now succeeds and the original rollback
assertions remain unchanged.

Linux keyring deletion errors previously disappeared when file removal succeeded.
New deletion records intent before attempting either backend; every app-owned
Secret Service entry for the reference and the fallback file must be absent
before acknowledgement. Retryable metadata survives caller failure. Successful
deletion seals the reference against stale writes. It does not revoke a remote
server identity, erase offline backups or promise physical media sanitization.

New Linux credentials require secure storage by default, as selected by the
user. File fallback requires explicit consent in Settings or `sirinvpn storage
allow-private-file`; its UI says it is unencrypted. Existing legacy files remain
readable but are marked unverified until provenance is established. Migration
verifies identity and readback before committing keyring authority, then removes
the old file. Once keyring authority is known, outages never reactivate a stale
fallback. New random references for restore/rotation respect explicit fallback
consent without misreporting unavailable legacy credentials as absent. Per-reference
try-locks serialize CLI/UI work; policy uses a separate lock. No secret values,
references or paths cross the new desktop storage API.

The pinned keyring 3.6.3 `linux-native-sync-persistent` builder actually selects
Secret Service directly; app-created entries were not a kernel-keyring cache.
The adapter retains app attributes and legacy entries while refusing interactive
unlock prompts. A real container fixture verified interoperability, duplicate
cleanup, migration and locked-store refusal. This is not evidence for every
Secret Service implementation.

Priority remains highest for SRV-01/SEC-01, high for SEC-02/UI-01/AND-01/CI-01/
EVD-01/PLT-01/REL-01, and medium for MNT-01/DOC-01. The changed code is concentrated
in these existing owners:

| Findings | Current source and executable regression entry points |
|---|---|
| SRV-01 | `crates/server/src/authorization_transaction{.rs,/}`; `access.rs`, `runtime.rs`, `measurement.rs`; stage/process tests and `tests/member_lifecycle/kernel.rs`, `tests/endpoints/kernel.rs` |
| SEC-01/SEC-02 | `crates/core/src/secrets{.rs,/}`; backup/rotation and CLI/Tauri removal/provision/recovery callers; `scripts/test-keyring.sh` |
| UI-01 | `apps/desktop/src/features/settings/CredentialStorage{.tsx,.test.tsx}`, connection state/hero, status hook; `tests/ui/remediation_smoke.py` |
| AND-01 | Tracked Android `SecretVault.kt`, `CodeScanner.kt`, vault/notification/QR/option instrumentation; `scripts/test-android-emulator.py` |
| CI-01/EVD-01 | `.github/workflows/`, `scripts/record-evidence.py`, `tests/unit/test_evidence.py`, `docs/evidence-schema.json` |
| PLT-01/REL-01 | Linux helper `policy_supervision.rs` and automatic kernel test; `tests/vm/`, package checkers, build scripts, `scripts/test-windows.ps1`, locks and compatibility declarations |
| MNT-01/DOC-01 | Focused modules above; existing shared formatting/lint/privacy/source-size gates; current README/security/privacy/development/testing/release guides |

Android keeps AES-GCM/Keystore storage in the service-owned native process.
Deletion persists a non-secret tombstone and verifies AtomicFile base/backup/new
cleanup. Missing keys cannot silently replace keys protecting existing encrypted
records. Separate `:vpn` process ownership, `stopWithTask=false`, native controls,
Always-on semantics and Wi-Fi trust decisions were preserved.

Android lint also found that a disjoint QR preview intersection retained the
original rectangle. The shared framing function now returns an empty rectangle,
with clipped/disjoint regression assertions in the existing native QR test.

The final UI review found that a failed credential-status refresh retained the
previous availability label. A read failure now removes the old snapshot and
offers Retry; its regression first establishes an available profile and then
fails the next native read. Failed mutations still fetch current state because
provenance or cleanup may have committed before the error.

State compatibility now includes Linux policy schema 1, credential provenance
schema 2, Android deletion semantics schema 2 and server recovery schema 1.
Older manifests do not declare all these families. The existing signed updater
correctly rejects incompatible bidirectional state transitions. A reviewed
bridge release/first-install strategy is required; downgrading to a client that
ignores tombstones is unsupported. No trust root or signature check was changed.

## Authorized hardware and dependency follow-up

The initial pass below predates the user's authorization to use their connected
phone and Winboat. New records are in `target/remediation-next-evidence/`; each
retains its source/artifact identity and failed attempts. A passing test in this
section does not change the status or hashes of an earlier failed run.

`shared-gates-native-followup-final` passed **452 Rust tests** (17 ignored),
**210 frontend tests in 41 files**, and **seven Python tests**, plus formatting,
Clippy, frontend build, privacy, shell/XML and source/contract checks. Only this
human ledger changed during the run; its verification digest stayed
`c6b747f7542d0c97527a5a5cbe2230575f7cbe7eb0d690564993568a2295ad61`.
`workflows-native-perl-final` passed Actionlint/ShellCheck after adding native Perl
selection on the Windows runner. No hosted workflow was run.

`shared-gates-final-packaging` later passed the same **452 Rust tests** (17
ignored), **210 frontend tests** and **seven Python tests**, plus the complete
shared gates, in 234.308 seconds. Both source-change flags were false. Its source
digest is `1a9c1f2b5fe644788447fcd6e6d77cdd727ff5e81d69d3a942606b89c8fc0eee`;
verification digest is
`3df9b917f58e820095b2ed7414878fb44cd3c8e5768e596010c035c31956689d`.
The subsequent one-line NSIS path correction has its own packaging checks. The
installer fixture subsequently stages its verified package locally to avoid an
interactive network-share warning; that change is exercised by native acceptance.

### Samsung S25+

The same-signer development APK was installed in place with `adb install -r`.
It remains 129,064,329 bytes, SHA-256
`24603a99dd1ce30e4edae982df34c0a93ff3ff1d7af714f1d634cad4247a1d29`.
The physical device is SM-S936B, Android 16/API 36, ARM64, security patch
2026-08-05, **4,096-byte pages**. No app data was cleared or app uninstalled.
Private recovery copies stayed outside the evidence bundle; a file backup does
not export Android Keystore keys. Only ordinary Member traffic reached the
existing server; no server administration or server fault injection occurred.

`android-s25-final-acceptance` passed **16 checks** in one combined run. The
existing encrypted identity authenticated successfully. Home/reopen, UI process
SIGKILL and OS task removal retained the same VPN process and session generation,
with authenticated management and three ordinary-UID private-tunnel ping replies
at each observation. Wi-Fi to mobile, complete network loss and Wi-Fi return
produced the expected waiting/reconstruction behavior. Killing only `:vpn`
created a new process/session; package force-stop stayed stopped after reopening
until an explicit Connect. These are sampled continuity/recovery observations,
not uninterrupted-packet-flow claims.

Android Always-on rejected ordinary Disconnect while traffic continued. With
lockdown enabled, a separate ordinary test UID reached the private tunnel before
interruption, then failed all three nonce probes to a controlled LAN endpoint
after the VPN package was force-stopped. The same endpoint was reachable before
lockdown and after restoration. Samsung's inspected Turkish confirmation dialog
is handled explicitly and OS policy is read back after each change. The earlier
run that missed that confirmation remains failed; cleanup restored its settings.

The separately rebuilt test APK has SHA-256
`3ea265ed03cd9893d8be0dacb89f383f01c31377496c360df8a094bb486da9f5`.
Its opt-in-only `PhysicalProbeActivity` has no VPN bridge or access to the real
profile. The test APK was removed afterwards because it was absent initially.
The real app is left disconnected/paused with its exact profile file unchanged;
Always-on is unset, lockdown is off, Wi-Fi/mobile data are on, and the original
stay-awake setting is retained. Owned ADB forwards were removed.

No reboot, physical camera, TalkBack, overnight natural battery/Doze behavior,
other OEM or physical 16 KB-page acceptance is claimed. Reproduction requires
explicit authorization and the guarded conditions in the
[physical-device guide](android/build-and-test.md#authorized-physical-device-acceptance).

### Linux and GLib

The pristine GLib 0.18.5 optimized iterator test reproduced SIGSEGV. The verified
two-line [upstream fix](https://github.com/gtk-rs/gtk-rs-core/commit/b5a4071e439bef2b5eea76c3aa25e5ae84839e34)
was backported into the checksum-verified MIT-licensed crate. The corrected
optimized run passed all **11 iterator tests**. `vendor/glib-upstream.json`
records the archive SHA-256, upstream commit and complete reviewed tree digest;
`check-vendored.py` rejects changed source, symlinks and registry fallback. Cargo's
patch keeps the GTK3-compatible version. No advisory was suppressed.

The first GLib-patched unsigned artifacts are retained under
`target/remediation-next-evidence/verified-linux-glib/`:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `verified-linux-glib/SirinVPN_0.1.0_amd64.deb` | 20,449,158 | `365c84a2a182dec9c5798f3787522eb6278cc6fff367d4a7ba817b7c51c61f00` |
| `verified-linux-glib/SirinVPN_0.1.0_amd64.AppImage` | 113,183,224 | `c9e627547d739bc0da6ea8be312fd8a2770aec7b88a2237e22f74212ef3d9d78` |

`linux-stable-source-build` subsequently rebuilt from an unchanged complete
source snapshot (`836639ff7695976adc4604336bd425b38e7cfd17b76480abe361237802e420ab`),
with the same verification digest as the final shared gate. Neither source-change
flag was set. `linux-stable-package-inspection` passed on those exact artifacts:

| Preceding artifact (preserved under `verified-linux-stable/`) | Bytes | SHA-256 |
|---|---:|---|
| `target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb` | 20,449,792 | `f6dfb7fd727c124800256eef07b0a77292ecec909b97b37395e81d056bade7ff` |
| `target/release/bundle/appimage/SirinVPN_0.1.0_amd64.AppImage` | 113,183,224 | `509c4539665223afe80686b90770e82165f8ea591a084b7e1615cb8ccad8184d` |

`linux-stable-package-runtime` passed **all 28 checks**, including three strict
fallback attempts, on that preserved Debian hash. Cleanup completed. Only this
ledger changed during the run; the verification digest stayed unchanged. The
runtime collector reports the host's default pnpm, which the guest package test
does not invoke; the package/shared build records used pinned pnpm 11.3.0.

Actual AppImage execution then exposed a packaging defect. A minimal cloud image
first lacked a desktop library (`libfribidi`). With desktop prerequisites
installed, the AppImage still panicked: the dynamically loaded host Ayatana tray
library required `g_once_init_leave_pointer`, absent from the older bundled GLib.
The tray library was absent from ELF dependency scanning because it is loaded
with `dlopen`. Packaging now stages the build-host tray library through Tauri's
[custom AppImage files](https://v2.tauri.app/distribute/appimage/#custom-files),
allowing linuxdeploy to collect its dependencies. Package inspection requires all
five tray libraries. Their publisher notices and common license texts are
preserved separately; the overall notice inventory remains incomplete.

`linux-tray-package-build` passed in 435.060 seconds with both source-change flags
false, followed by `linux-tray-package-inspection`. The final artifacts are:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb` | 20,449,706 | `d8640401914e179ac36c395186ff55d14cdbcf964d964df96223f56fee0b634a` |
| `target/release/bundle/appimage/SirinVPN_0.1.0_amd64.AppImage` | 113,359,352 | `9c4b2af53cb1a0ad1a91949131a21127ca7d679cc1619b170ff66838c5343f6d` |

Every installed Debian member, byte, mode, owner and link target matches the
28-check package preserved under `verified-linux-stable/`. The control archive
differs only in the order of `md5sums` entries; their contents are identical.
`linux-tray-debian-comparison.json` records that comparison. The 28-check runtime
record still names the preceding outer package hash; it is not rewritten.

`linux-appimage-runtime-qualified` passed actual extract-and-run launch and normal
window close in a fresh Debian 13/Xvfb guest with desktop prerequisites. It
observed launcher PID 3819 and descendant GUI PID 3820. The earlier GUI harness
incorrectly required the launcher's own PID; the corrected check verifies the
window belongs to that launcher or its observed descendant. All four AppImage
fixture attempts cleaned up. This qualifies launch/close, not FUSE mounting,
AppImage VPN lifecycle, graphical accessibility or all desktop environments.

`linux-glib-package-inspection` also passed exact payload, ownership, mode and
bundle checks for the preceding build. `linux-glib-package-runtime` passed **all 28 checks** in one fresh pair of
Debian 13 guests, including all four transports, resolver failure, real GUI close,
carrier termination, interruption policies, three automatic-fallback attempts,
hard client power loss, active purge/reinstall, server uninstall with unrelated
firewall preservation and final client removal. Cleanup completed. The package
build/runtime records retain their source-change flags: portable Windows-test,
harness and documentation edits overlapped; these flags are not rewritten.

Five earlier standalone fallback repetitions also passed. The harness now
retains bounded outgoing DNS metadata and kernel nftables trace lines without
weakening the zero-DNS/zero-IPv6 assertion. Debian's nft monitor emits text even
with `-j`; the initial parser failure is retained and the corrected parser reads
that text. Later passing intervals do **not** attribute the two historical
one-DNS-packet failures. Those intervals remain unresolved and block a universal
fallback leak-prevention claim.

### Native Windows

Winboat supplies a real Windows guest. Testing uses a separately identified,
disposable offline copy of its disk with only a dedicated acceptance directory
shared from Linux. The original guest was stopped before the snapshot; its disk
was not used for installation/fault tests. The test guest is Windows 11 Pro x64,
build 26200, QEMU/KVM, with 3 GiB guest RAM, two virtual CPUs and a bounded Docker
container. Earlier native runs used a guest clock three hours behind host UTC;
those timestamps are preserved. Later runtime runs corrected the disposable guest
clock through the console, with input latency; timestamps are not claimed to be
exactly synchronized.

Microsoft Visual C++ Build Tools 17.14.41 and isolated Rust 1.97.1 MSVC were
installed in that guest. The first native compilation found ten shared-test
compile errors caused by Unix-only permission APIs. The tests now reuse existing
cross-platform private-file/directory validators, so Windows actually checks its
DACL/ownership contract. The final source-5 build passed **108 native tests**:
core 59, platform 6, protocol 20, tunnel model 7 and Windows service 16; none
ignored. The earlier 107-test record predates the WFP regression. This includes
real user-scoped DPAPI and file-security operations, not cross-compilation.

That run then failed the CLI check because Git's MSYS Perl lacked an OpenSSL
build prerequisite. Native Strawberry Perl was installed and a native-platform/
module preflight added to Windows test/package scripts. The first failure remains
failed; the completed retry and any installer/runtime evidence are recorded
separately below. Unit tests do not qualify cross-user pipe/DPAPI isolation,
WFP packet enforcement, crash/reboot, updates or a signed application-routing
driver. Driver signature enforcement was not disabled.

The completed native build also passed the CLI check, linked real MSVC service/CLI
executables and passed native Clippy with warnings denied. The first two-account
runtime attempt exposed a separate product defect: a standard user could open the
SYSTEM-owned pipe and confirm its SCM PID, but `OpenProcess` failed with error 5.
The client now reuses the bounded SCM configuration validator to require an
own-process LocalSystem service, and binds the running PID to the SYSTEM-owned
pipe. Existing read-only service permissions suffice; no DACL was widened. The
standard-user status check now passes even while the process query is denied.
Changing only the SCM account makes authentication fail with the same pipe/PID;
restoring it restores access. A second unprivileged pipe instance is rejected.
User-scoped DPAPI decryption fails in the second account while the readable
machine-scoped control succeeds. These are actual guest observations.

The first tunnel attempt then failed its firewall verification. A temporary
fixture-only diagnostic build identified `FWPM_FILTER_FLAG_INDEXED` added by BFE:
a returned flag value of 65 was compared with the requested persistent value 1.
The production comparison now ignores only this lookup-optimization bit;
disabled, lifetime, action and unknown flags remain strict. The new native
regression includes the indexed observation and negative enforcement-flag cases.
See Microsoft's [filter flag definitions](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).
The diagnostic source changes and binary are separate from candidate builds.
The corrected source-5 MSVC build passed all **15 runtime checks**, including
the cross-user controls above, all four transports, three private ping replies
per transport, private DNS resolution, blocked ordinary-application HTTP probes
to a controlled underlay endpoint, and restored underlay after Disconnect.
Three probes stayed blocked during a guarded service stop, and restart rebuilt
the session. Native profile removal and both SCM registrations were checked
absent after cleanup. The unsigned routing driver remained stopped and the
application-routing capability remained unsupported.

An additional guarded run exercised three further conditions: forced service
process termination with SCM recovery and a new counter epoch; an actual guest
reboot with automatic startup reconstruction; and post-reboot underlay blocking.
Its eight recorded checks include five repeated setup checks. Three
underlay probes were blocked after termination and three after reboot; a SYSTEM
startup task reached the private tunnel before interactive login. This is sampled
traffic evidence, not a continuous trace of every boot interval. The disposable
guest timezone was set to UTC before this reboot. Both boot and final cleanup
reports passed; the scheduled task, test profiles and owned services were removed.

These runtime results bind to source digest
`047ab1b05b4461bd0841608bed31b77f03ce35afe26b72c3d48dedaf29f5ec00`,
archive `source5.zip` SHA-256
`ee142b3a4b11a60608a5cf6a789ee9b5e78b63e394e7fd0b4ac710c023e5d887`.
The exact debug CLI SHA-256 is
`d192fdd8f1764a5f865c72b54991ea80be2bfd850282b8975ae5c343821a59f0`;
service SHA-256 is
`37b5bbad259ebde9187f0711b4b3454eb778eb7bbfca6dbe30684aa478a3f921`.
They are retained under `target/remediation-next-evidence/windows-artifacts/`.
The diagnostic binary did not qualify these results.

Native packaging found another concrete failure: PowerShell exposes a
provider-qualified `.Path` for UNC inputs, which .NET file APIs reject. The
packaging script now uses `.ProviderPath` for filesystem inputs. Native package
and installer results are recorded separately from the debug runtime above.
The initial native packaging inputs also included stale September 8 VPS
executables from the pre-existing ignored desktop staging directory. Those
inputs cannot qualify the remediation. Final packaging selected the
remediated cross-target executables from `target/server-payloads/`, already
used by the current Android package; exact installer payload inspection verified
their hashes. The stale-input attempt remains separate in the evidence.

The native NSIS compiler then rejected the mixed separators in the embedded
helper source path. The hook now uses Windows separators consistently; both
the Linux NSIS compiler probe and the native Windows package build passed.
Source 8 differs from source 7 only in that hook. The successful bundle-only
retry reused the source-7 release compilation and verified every archived source
file against `source8.zip` before bundling. It did not rerun compilation or unit
tests. A retry warning about the bundle-type variable was checked against the
actual desktop executable: both markers already read `NSS`, with no `UNK` marker.

The final unsigned native installer is retained under
`target/remediation-next-evidence/windows-artifacts/native-release/`:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `SirinVPN_0.1.0_x64-setup.exe` | 12,048,632 | `9194f4bef6079f57a8653f9c2a2ca126a228d99daead9c37a59c3202be7ea1a6` |
| `sirinvpn.exe` | 5,343,232 | `c443f4727fdbf6e009106c1b11eeda2508039473af1a452398c3cba626971244` |
| `sirinvpn-windows-service.exe` | 3,181,056 | `ee6d9a1e72d410a5b2616abdd846f4d345e4d2e36ba22c0fc89da1ce8210b078` |
| `sirinvpn-desktop.exe` | 9,721,856 | `0e423b9b4da4ded4e429cc9fc79e7f57452c751c5e8f7bf7cf4e02f0bd2bc8c6` |

Its source digest is
`71a5dc0d85e69503b731254cb5090ccea797fe920b70efc64bfdec21afb1eb25`;
the source-8 archive SHA-256 is
`fbc2df216aa9da1fee63aa23cb359d282d58a67a9038f35a4fef455120e6f938`.
`windows-native-package-inspection` passed exact embedded executable/payload
comparison, architectures, imported libraries and the pinned WireGuardNT digest.
The x64 VPS payload is
`636aac9e31163e283a89294285ae7aa828cef8d6e0923d86e761468701db2d36`;
the ARM64 payload is
`52f71b5d8b1b1798d0d6f20f14f5001687547de15c87dcad79b38e0debe311ef`.

Native installer acceptance passed **five checks**: install/authenticated idle
status, a live desktop window, close preserving the service, same-version repair,
and uninstall removing both service registrations and installed binaries while
preserving the unrelated DNS service. Installed payload hashes match the inspected
package. The first run required confirming Windows network-share execution
warnings. The fixture now copies the package locally and verifies its digest
before starting it; the complete local-staging repeat passed in 59.456 seconds
without those prompts. Both runs and cleanup results are retained separately.

The exact release CLI/service payloads then passed the complete **15-check
native runtime suite** against a fresh disposable VPS using the same x64 server
payload embedded in the installer. All four requested transports resolved to
the intended native carrier, private pings/DNS worked, underlay probes were
blocked during protection and restored after Disconnect, cross-user negative
controls passed, and service-stop recovery and final removal passed. Cleanup
completed. The DPAPI/pipe fixture probes linked the already-qualified source-5
debug platform library; the production CLI/service under test were the exact
release executables listed above. Actual crash/reboot qualification remains
bound to the earlier debug binaries, rather than being relabeled as a release
binary test. `release-build-artifacts.json` and the runtime script manifest retain
these separate bindings.

The Winboat runtime harness is `tests/windows/winboat-runtime.ps1`, with the
DPAPI and pipe probes beside it. It requires a matching disposable-VM marker,
controlled VPS export, exact build records and a dedicated `\\host.lan\Data`
acceptance share. It refuses existing installations/profiles. It must never run
in the original personal guest. A failed cleanup attempt incorrectly parsed the
CLI's plain-text removal acknowledgement as JSON; the harness now checks the
exit status and profile absence. Subsequent recovery verified both service
registrations absent and removed the owned account/files. A separate recovery
script also exposed PowerShell's asynchronous GUI-executable invocation; the
shared Windows check now pipes output so the service executable's actual exit
status is observed. The [PowerShell behavior is documented by Microsoft](https://devblogs.microsoft.com/powershell/managing-processes-in-powershell/).
Failed records remain failed.

### Release review inputs

The 959-component scan has no unknown license labels or license-policy violations
after exact-version review against upstream Maven POMs, Go's LICENSE and the
actual target-lexicon LLVM exception. Source URLs and SHA-256 bindings are in
`osv-scanner.toml`. The target-lexicon exception is scoped to its license check;
its vulnerability checks remain enabled. The scanner still exits nonzero on nine
raw advisory records, including both aliases for the mitigated GLib finding and
seven informational maintenance notices. This is not a clean dependency gate.

`scripts/create-release-materials.py` exports a CycloneDX 1.6 **build-input**
inventory, artifact hashes, publisher-notice archive/index and explicit review
gaps. The initial export covers 959 locked components and has 185 missing
publisher notices (46 Cargo, 80 npm, 59 Maven). Rust archive contents are bound to
Cargo.lock checksums; unsafe archive paths are rejected. The inventory includes
development and other-target packages and does not claim exact shipped linkage.
The final export in `target/remediation-next-evidence/materials-final/` binds
those 959 inputs plus the final Debian, AppImage, Android, NSIS and unsigned
routing-driver artifacts. `final-schema-validation` passed the official
CycloneDX 1.6 schema with isolated jsonschema 4.26.0, unique component references,
all 1,299 indexed notice-file hashes and exact archive membership. It also checked
42 preceding collector records against the evidence schema. The 185 missing
publisher notices remain explicit. The additional five AppImage tray-library
publisher notices are separately bound to exact Debian package versions.
Complete artifact-level notice selection and review remain a distribution gate.

### Final local handoff

`final-candidate-contracts` passed the final whitespace, compatibility/version,
vendored-source, workflow and privacy checks after the NSIS path and installer
fixture changes. The full shared-suite result above remains separately bound
to its earlier source snapshot; it is not relabeled as a later rerun.

All disposable VPS and AppImage guests were removed. Both owned Windows clone
directories were removed after their marker/container/mount checks, and the
original Winboat container was restarted successfully. The original guest was
excluded from installation and fault tests; normal startup can write its disk.
Generated VPS credentials and exports were removed. The physical phone retains
the remediated development APK and its existing identity/profile, with the
recorded original OS/network settings restored.

The follow-up bundle is
`target/remediation-next-evidence/SirinVPN-remediation-followup-evidence-2026-09-26.zip`,
with expanded contents in `target/remediation-next-evidence/sanitized-bundle/`.
It retains the previous bundle's hash, allowlisted passing and failed records,
exact source inventory and reversible patch, native source/artifact bindings,
reviewed fixture procedures, build-input inventory, available publisher notices
and cleanup summaries. Raw logs, screenshots, phone backups, profiles,
credentials, VM disks and environment dumps are excluded. Everything remains
local and uncommitted; nothing was pushed or published. The readiness table
below identifies the remaining manual, external and broader platform gates.

## Initial verification record (preserved)

Local records live in `target/remediation-evidence/`; VM/AVD fixture summaries
live in the named `.cache/remediation-*` directories. These are **local-only**,
not public download links. Each recorder JSON includes base commit/tree, dirty
source SHA-256, before/after identity, exact command, toolchain, real exit code,
timing, artifact identity and limitations. A source-change flag is never erased.
Report-only edits after a run do not retroactively qualify another binary.

The intermediate `linux-final` run passed **451 Rust tests** (16 ignored),
**209 frontend tests in 41 files**, and **3 Python tests**, plus Clippy/frontend
build. It then correctly failed the privacy gate because the evidence schema's
specification URL was under the offline release directory. Moving the schema to
[documentation](evidence-schema.json) fixed the placement without relaxing the
privacy rule. Later tests/source changes require the final runs below.

`linux-gate-cleanup-final` passed **452 Rust tests** (17 ignored), **210 frontend tests in
41 files**, and **4 Python tests**, plus formatting, Clippy with warnings denied,
TypeScript/frontend build, privacy, shellcheck, XML, source-size and contract gates.
The 17 ignored tests are the 16 kernel tests and the real Secret Service case,
which require their separate isolated fixtures. The run took 195.677 seconds.
Its verification source digest is
`1dd688a74a5d808d18e468bdba2a9b15af5fdfe6af31f2b7e4c1ac32ade20e98`;
both the complete and verification source digests stayed unchanged during this run.
Earlier records, including the 451-test run before the uninstall regression,
remain separate.

After that shared run, a harness-only cleanup review added the missing failure
checks. `python-harness-final` passed all **five Python tests**. These include
setup rejection and mid-test interruption with completed cleanup, plus failed
guest shutdown and failed directory removal. Shutdown now attempts every guest;
it retains private control paths on incomplete shutdown. Cleanup failure remains
nonzero and cannot leave the Linux runtime summary marked passed. These later
harness edits do not alter packaged application code, but their source-change
flags are retained in the overlapping package-build record.

`linux-package-cleanup-build` and `linux-package-inspect-cleanup` passed with the
uninstall correction included. The build took 384.554 seconds; only VM harness/test
and ledger files changed during it, and both source-change flags remain true.
Exact unsigned engineering artifacts:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb` | 20,454,194 | `e086994e808651d551b3d1d87748f6dad4f8cffd038f7fc266d425bb8fa145d6` |
| `target/release/bundle/appimage/SirinVPN_0.1.0_amd64.AppImage` | 113,179,128 | `e52e30661a8b16e8efb1048f411a71e8201bfeeae51a506f2db6c25472be1a79` |
Inspection checks exact Debian executable/policy/service/script bytes, ownership,
modes, runtime dependencies and architecture; AppImage extraction checks its
executables, exact helper/server payloads and removal of incompatible bundled
Wayland libraries. This is static AppImage evidence, not a launch/install test.
AppImage metadata warnings remain. The initial package-runtime run passed 12
checks, then failed because its relay-crash fixture targeted the retired shared
service. The fixture now verifies and kills the active `@tls_like` service.
That failure and its completed guest cleanup are retained separately.

The next pre-correction package run passed 20 checks and failed its automatic-fallback assertion
with one DNS packet and zero IPv6 packets on the physical counter. That counter
interval included disconnected time before protection was armed; the packet's
timing was not attributed. The diagnostic repeat retained the same assertion,
added a before-connect counter observation, and passed fallback with zero counters.
It then passed hard client power loss and active client removal, reaching 24
passed checks before the server-uninstall failure described above. These failures
remain in the bundle. `linux-package-runtime-cleanup` reproduced one DNS packet
after a zero pre-connect observation on the corrected package. Its bounded
diagnostic reconnect passed with no observed outgoing DNS packets; it did not
attribute the original packet. A later pass is not proof that the earlier DNS packet was
pre-arm or harmless; controlled packet/timing attribution remains an acceptance
limitation.

On the corrected Debian hash, `linux-package-runtime-observed` passed **24 checks**,
including all four transports, resolver failure, real GUI close, relay termination,
the four interruption policies, automatic fallback, hard client power loss and
active client purge/reinstall. Its bounded observer recorded no physical DNS
packets in that passing fallback interval. The next check failed before invoking
uninstall because the new unrelated-table fixture lacked an nftables statement
separator. Correcting that fixture and running `linux-uninstall-followup` in the
same marker-verified guests passed **both remaining checks**: server removal with
exact preservation of the unrelated table, and final client purge. The original
run remains failed; this is 24 passing checks plus two separate follow-ups, not a
single green 26-check run. All guest disks, keys and control sockets were removed.
Summaries are `.cache/remediation-linux-package-observed/linux-results.json` and
`uninstall-followup.json` in the same directory. The exact earlier failing DNS
intervals remain unqualified.

`linux-startup-qualified` passed against that same Debian hash in a fresh guest:
four unmanaged NetworkManager probe cycles, real local-session Polkit control
authorization, other-user/nonlocal/administration denial, manual/native/delayed
network startup, connection without the GUI after reboot, grant persistence and
grant revocation on package purge. Manual connection was usable at 730 ms;
native and delayed startup at 359/366 ms in this fixture. These timings are
observations, not general performance guarantees. The run took 153.231 seconds;
its verification source digest stayed unchanged, and guest cleanup was verified.
Results are `.cache/remediation-linux-startup/results.json`.

`real-keyring-final` passed the final ignored-by-default integration test inside a
fresh, network-disabled GNOME Secret Service container. Its first build failed
because the new test referenced a crate not directly available; the test now
reuses the protocol's random ID type. Earlier records are retained; the final
fixture re-exercised the current deletion, migration and reference implementation.

`kernel-recovery-retry` passed the real IPv4/IPv6 lifecycle/failed-rollback case in
a disposable Debian guest. An earlier discovery-count assertion expected 15
ignored tests but the baseline had 16; the harness was corrected to 16, with the
failure retained. This focused pass is separate from full kernel qualification.

The complete `kernel-full-continuity` run passed **17 real-kernel cases covering
16 ignored-by-default Rust tests** on Debian kernel `6.12.107+deb13-cloud-amd64`.
Every case ran in a fresh network-disabled container inside the disposable guest;
guest cleanup completed. Previous full runs retained 15/17 and 16/17 results:
the missing server payload and obsolete fixed-stage-path fixture were corrected,
then the observed shared-port carrier continuity defect was fixed. The final
suite exercised both the corrected fixtures and production retry change.

`kernel-power-final` then rebuilt the three test libraries and passed all **17
kernel cases plus three VM power-cut cases** on the final application code.
Cuts followed forwarding (A must survive), durable persistence (B must survive)
and checkpoint publication (B must survive). Each recovery compared the complete
authoritative document and all modeled effects, then required healthy status and
removed containment. The QEMU process received SIGKILL, without its graceful
shutdown/flush handlers. The guest had no external networking during these cases;
cleanup completed. Input binary hashes and individual outcomes are in
`.cache/remediation-kernel-power/kernel-results.json`.

Earlier Android API 36 attempts failed during boot or APK installation, before
instrumentation. API 29 reached instrumentation and passed the two then-present
vault tests; its notification test failed because `PendingIntent.isBroadcast`
requires API 31. The test now looks up and compares the actual broadcast token
using the API 29-compatible API. Failed fixtures reported cleanup and were removed.
Rebuilt APK/emulator results are tracked separately; older APK hashes are not
reused as current qualification.

`android-ui-final-build` passed both-ABI development builds, instrumentation-package build,
package inspection and lint with JDK 17. The earlier combined invocation built
the APK but its final lint command selected host Java 27 and failed; that record
is retained as failed. The final APK is **129,064,329 bytes**, SHA-256
`24603a99dd1ce30e4edae982df34c0a93ff3ff1d7af714f1d634cad4247a1d29`.
The separate test APK is **3,581,582 bytes**, SHA-256
`87be7f051180608b7caacaf390ac84a9b453f0be9b4166455049fd234db84071`.
Inspection verifies min SDK 29/target SDK 36, ARM64/x86_64, ELF/ZIP 16 KB
alignment, exact ARM64/x86_64 VPS payload bytes, development signature and the
debuggable flag. These are engineering artifacts, not production signed releases.

On these exact APK hashes, `android-api29-final-qualified` passed **7 native tests**
and `android-api36-ui-final` passed **8 native tests**. They cover vault authentication,
invalidated-key refusal and incomplete deletion, notification actions/counter
formatting, dense QR decoding and framing, running-service preference/cancellation/
Wi-Fi-automation behavior, and package-replacement decisions. API 36 additionally
checks saved-network roaming identity. These tests do not establish an actual
package upgrade, established-tunnel task-removal continuity, carrier transitions,
Always-on/lockdown or physical-camera/OEM behavior. The fixture explicitly grants
consent/permissions and uses an unreachable synthetic endpoint for option tests.
Both AVDs and their credentials were removed. Neither run hit the hard memory
limit or an OOM event; peak memory was 3,223,367,680 bytes (API 29) and
3,673,096,192 bytes (API 36), with soft-limit reclaim events recorded. API 36 used
the documented 3,500 MiB soft-limit exception; both retained the 4 GiB hard cap,
no swap and 150% CPU cap. The final API 36 launcher first refused an existing
evidence directory before starting a device; the new run used a fresh directory
and preserved that refusal record. Final summaries are
`.cache/remediation-android29-final/results.json` and
`.cache/remediation-android36-ui-final/results.json`.

The initial Android tunnel-lifecycle harness required an established connection to
its separate 1 GiB disposable VPS. The observed API 36 emulator peak plus that
fixture exceeds the planned combined 4 GiB budget. At that stage no separate VPS or physical
device was authorized. Those emulator tunnel/lifecycle runs were not run;
`tests/android/vps_lab.py` and `tests/android/lifecycle.mjs` remain the executable
entry points for a separately provisioned, authorized fixture. The API 29 image's
factory WebView is also too old for the current frontend, so native API 29
instrumentation must not be described as current WebView qualification.

Final Android lint has **0 errors, 94 warnings and 1 hint**. The QR `CheckResult`
issue was fixed. Synchronous preference commits are intentional for saved native
control state; reported Controller references hold Application context. Generated
Tauri locale/view warnings and upstream dependency/resource/icon/idiom/layout
suggestions remain, with categories in `android-lint-final-review.json`. No blanket
suppression was added. Gradle deprecation, SDK XML-version and catalog ESM configuration warnings
also remain; no warning-free Android claim is made.

`go-native-final` passed both existing Go tests with Go 1.27.1 and the locked
module graph: malformed/unrelated probe rejection and protection against delayed
packets undoing the controller endpoint. The Android workflow now runs these
checks. `workflows-qualified` passed Actionlint and ShellCheck; the preceding
nested-shell warning remains in its failed record and was fixed using `go -C`.
No GitHub workflow was executed.

`rendered-final` passed **five scenarios**, produced **seven screenshots**, and
reported no page errors. Checks cover desktop storage at 1220×780 and 1024×680,
keyboard consent, partial cleanup and retry, migration acknowledgement, server
recovery failure, and synthetic Android layouts at 320×640 and 390×844 with
125% text/reduced motion. The desktop cleanup and enlarged mobile recovery
screenshots were visually inspected. Files are under
`target/remediation-evidence/ui-final/`; these fictional browser fixtures do not
qualify native Android enforcement or a physical screen reader. Chromium was
153.0.8010.12 (Playwright 1.63.0), recorded separately from the synthetic user agent.


The local evidence bundle is
`target/remediation-evidence/SirinVPN-remediation-evidence-2026-09-26.zip`, with
expanded files in `target/remediation-evidence/sanitized-bundle/`. It includes
this report, schema, allowlisted passing and failed run records, exact source
inventory, a complete `changes.patch` against the stated base, tool/image data,
platform summaries, dependency inventory and checksums. The patch is checked
against the working tree at the time of that bundle, before the 27 September
follow-up below. Two bounded local diagnostic
scripts are included to make the follow-up procedure reviewable; their owned VMs
have been destroyed, and the permanent full harness is the reproduction path.
Raw logs, screenshots, credentials, profiles, VM disks, packet observations and
environment dumps are excluded. This bundle remains local and was not published.
Individual run counts include retries and are not a count of independent tests.

## 27 September installation and user review

The user requested fresh Android and desktop installations, then reported and
reviewed additional UI and connection defects. Android DNS mode buttons now
accommodate wrapped labels, and private/split DNS text areas keep long examples
inside their fields. These layouts were checked in the connected Samsung S25+
WebView as well as browser fixtures. Credential fallback consent now uses the
same accessible switch as notification settings.

Concurrent Linux credential-status reads could briefly hold the per-reference
lock and cause invitation creation to fail. The shared lock now retries for a
bounded two seconds; the core regression suite passed. Secure storage remains
the default, and invitation creation does not require enabling file fallback.

Windows engineering builds now use the GUI subsystem, and custom window chrome
hides scrollbars while retaining scrolling. The package checker rejects a console
subsystem. A separate invitation failure came from acknowledging Connect before
the service created its tunnel, allowing management checks to fail immediately
and tear it down. The shared Windows IPC client now waits for tunnel setup with
a bounded deadline and rejects failed or superseded sessions. Its native Windows
readiness regression passed.

The rebuilt Windows installer was installed in the user's original Winboat guest.
Its payload hashes matched the build, invitation enrollment succeeded, and an
authenticated Direct UDP connection carried traffic. Reconnection also passed;
Allow local network was enabled for continued RDP access. The temporary invitation
backup was removed. The local evidence is under
`target/windows-join-fix-2026-09-27/`; its installer SHA-256 is
`3fe70de54b7b4abcb217b611f73025bf9a1885e7a71373b37da93a1f248e8d09`.

The user reported a quick review across the tested operating systems with no
remaining visible issues and authorized committing and pushing the changes.
This manual review and the focused follow-up checks do not replace the broader
acceptance and release requirements below. The earlier evidence bundle describes
its own source snapshot and does not qualify these later changes.

## Dependency disposition

The pinned OSV scanner checks Cargo, pnpm, Go (including stdlib version) and the
tracked Gradle release-runtime lock. The inventory currently covers 959 package
records, including development/target-specific dependencies; that is not a
count of production vulnerabilities. Scanner failures and findings return nonzero.
No advisory has a blanket ignore.

Rustls was updated from 0.23.43 to 0.23.45 for
[RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).
Go x/crypto was updated to 0.56.0 with compatible x/net/x/sys updates for the
[Go advisory](https://pkg.go.dev/vuln/GO-2026-5942).
The Android lock exposed Jackson 2.15.3 advisories. Its 2.x BOM now pins the
2.18.9 maintenance release, including the upstream
[follow-up fixes](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-5gvw-p9qm-jgwh).
The completed scan found no remaining Jackson or rustls advisory at these locked
versions, and no npm advisory. It still failed on the findings below.

The raw GLib 0.18.5 version still matches
[RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html), but the
named defect is now mitigated by the verified upstream backport described above.
The advisory remains visible and is not broadly ignored. proc-macro-error and
five unic packages have unmaintained notices. The x/crypto OpenPGP unmaintained notice is
module-level; the inspected WireGuard import graph does not include OpenPGP.
That observation is not a blanket suppression or proof for every future build.

The exact target-lexicon exception and Android/Go metadata have now been reviewed
and bound to upstream files. First-party AGPL overrides remain version-scoped
with source rationale. The exported build-input inventory and publisher notices
still require artifact-level completeness/selection review. No production release may be inferred from a passing build.

## Reproduction entry points

Use Rust 1.97.1, Node 26, pnpm 11.3.0, JDK 17, the SDK/NDK in the Android guide,
and Go matching `apps/desktop/android/wireguard/go.mod`. Install required tools;
missing tools fail the relevant gate. Run heavy tasks sequentially with the
[documented resource limits](development.md#resource-limits).

```sh
python3 scripts/record-evidence.py --suite local-new --output target/remediation-evidence -- sh scripts/test.sh
python3 scripts/check-workflows.py
python3 scripts/check-dependencies.py --android-lock apps/desktop/android/gradle.lockfile --output target/remediation-evidence/dependencies-new.json
sh scripts/test-keyring.sh
sh scripts/test-kernel.sh .cache/debian-13-genericcloud-amd64.qcow2 .cache/kernel-new
sh scripts/build-android.sh all debug
sh scripts/build-android-catalog.sh
python3 scripts/check-android-package.py apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
sh scripts/package-linux-container.sh
python3 scripts/check-linux-package.py target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb target/release/bundle/appimage/SirinVPN_0.1.0_amd64.AppImage --output target/remediation-evidence/linux-package-new.json
```

The [Android guide](android/build-and-test.md) gives the fresh-AVD command; repeat
for API 29 and API 36 with different output directories. The browser check is
`python3 tests/ui/remediation_smoke.py` with local Vite on port 1420 and pinned
Playwright/Chromium installed. Browser fixtures are synthetic. On native Windows,
run `pwsh -File scripts/test-windows.ps1`; privileged idle-service checks also
require the disposable VM marker and explicit fixture arguments documented in
that script. They do not silently qualify WFP packets or a signed application driver.
The dedicated Winboat fixtures are `tests/windows/winboat-runtime.ps1` and
`tests/windows/winboat-installer.ps1`, both requiring `-FixtureId`. Their test
control files, source/archive identities and local VM/VPS preparation procedures
are retained under `windows-controls/` in the follow-up evidence bundle. Create
a new disposable clone and dedicated share before adapting those procedures;
the scripts deliberately refuse existing services, profiles or installations.

## Release-readiness checklist and next actions

| Condition | Status | Next concrete action |
|---|---|---|
| Recovery/store regressions and current shared gate | Passed; 452 Rust, 210 frontend, seven final Python tests | Retain source/artifact bindings and failure records with these changes |
| Linux real keyring | Focused native integration passed | Test other providers and login/restart behavior in owned user sessions |
| Linux kernel/package runtime | 17 kernel cases, three power cuts, startup; Debian passed all 28 checks; final AppImage launch/close passed | Qualify wider real-network power cuts, desktop sessions/resolvers, suspend, AppImage FUSE/VPN lifecycle and accessibility |
| Automatic fallback DNS observation | Unresolved in two failed package intervals; later strict assertions passed | Attribute packets relative to guard installation/teardown with controlled timing; retain the zero-leak assertion |
| Android APK, emulator and S25+ | Debug build/lint, API 29/36 native cases and 16 physical S25+ checks passed | Qualify camera, TalkBack, reboot, overnight power behavior, other OEMs, current API 29 WebView and physical 16 KB pages |
| Native Windows | 108 MSVC unit tests; 15 debug and 15 release runtime checks; debug crash/reboot; five final NSIS install/repair/uninstall checks passed | Qualify broader IPv6/DNS/fault/update/power-state behavior, including crash/reboot with release binaries |
| Application routing driver on Windows | Not qualified | Supply and qualify the properly signed driver; keep unsupported capability disabled |
| Dependencies, notices and SBOM | GLib mitigated and metadata reviewed; raw advisory gate remains nonzero; build-input inventory/notices exported | Review informational findings and complete exact-artifact notice/SBOM selection and missing publisher materials |
| State upgrade/downgrade | Incompatible with older manifests by design | Review a bridge/first-install strategy without ignoring tombstones or weakening signed compatibility |
| Production signing and key custody | Not performed | Maintainer establishes offline custody/backups and conducts a separate authorized ceremony |
| GitHub execution | Configured and locally validated; hosted results pending | Inspect hosted results after push, satisfy runtime prerequisites and retain actual run/artifact links |
| Public disclosure channel | Private channel unverified | Maintainer configures and verifies a private reporting channel before soliciting sensitive reports |
| Independent security review | Not performed | Arrange external review before broad distribution |

Historical reports remain intact. Their dates and unavailable/local-only raw
artifacts do not establish current platform parity, production readiness or an
independent audit.
