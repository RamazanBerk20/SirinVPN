# Frontend audit remediation — 12 September 2026

Implementation of `SirinVPN_Frontend_Audit.pdf`, F01–F44 and Q01–Q14. The source
HEAD is `5668e678761690f4283451a0d226b1662d91de15`; the working tree already had
614 changed/untracked entries when implementation started. Existing work is
preserved. Baseline frontend: **41 files / 196 tests passed**.

This is a refinement of the existing React/Tauri application. Palette, local-first
storage, server authorization, packet policies and encrypted backup formats are
retained. The only new command is bounded Android local SSH-key document import;
Android application summaries gain optional local icon thumbnails. No data
migration, accounts, telemetry, activity logging or cloud service is introduced.

## Evidence and closure

Task artifacts live under `target/frontend-audit-remediation/`: baseline source
hashes and git status, build/test logs, browser captures and native/integration
results. Original captures remain under `target/screenshot-catalog-2026-09-12/`.
The new capture runner accepts `--output`; it never needs to overwrite originals.

Implementation is not release acceptance. In particular a Chromium Android-sized
viewport is not an Android WebView, and fixture results are not security evidence.
An observed finding closes only with matching visible before/after evidence and
its acceptance test. Verify findings additionally require attribution. External
Windows, physical scanner/device and live VPS checks remain explicit gates until
performed. No screenshot or fixture is represented as a production secret.

## Finding implementation ledger

| ID | Implementation / attribution | Acceptance focus |
|---|---|---|
| F01 | Shared secret QR surface and integer module scaling; opaque white backing independent of theme | Recovery QR in both layouts; real scanner/payload equality |
| F02 | Height-aware dialog layout and enlarged QR with reachable copy/close | Landscape, rotation, keyboard, enlarged text |
| F03 | Retry initialization and profile load without resetting profiles; copy sanitized summary | Failure → restored dependency → retry; no privileged calls before initialization |
| F04 | Visible Android error/retry boundary; capture asserts actual visible alert | Loading/empty/error distinction; native capture attribution |
| F05 | App-session update candidate survives closing and settings navigation; explicit discard and completion cleanup | Connected start → prerequisites → same verified candidate → installation |
| F06 | Unsupported, unknown, off and verified Android protection states distinguished | Unsupported capability and settings return |
| F07 | Explicit connect/disconnect operation stage; cancel shown for connection attempts | Disconnect hold never exposes cancel-connection action |
| F08 | Incomplete Android protection uses warning icon and accurate text | Connected/unprotected vs protected |
| F09 | Handshake inactivity does not imply reconnecting; current controller recovery remains authoritative | Paired desktop/Android state and actual traffic tests |
| F10 | Application-routing verification is labelled independently from kill switch | Selected-applications vs firewall enforcement |
| F11 | Active transport visible on Android Home | Automatic preference vs active fallback |
| F12 | Local desktop server search by name/endpoint preserves order | Match, no match, favorite order |
| F13 | Sidebar names wrap to two lines rather than early single-line truncation | Ordinary/long names and compact windows |
| F14 | Android endpoint explicitly identified as SSH or VPN; connection status on separate line | Owner/member and active/inactive profiles |
| F15 | Existing native local deletion exposed separately for installed Android Owners | Local identity removal leaves VPS/other device functional; recovery acknowledgement |
| F16 | Existing policy editor exposed in populated device/member menus as well as empty members | Owner/Admin paths for zero/one/many devices and forbidden roles |
| F17 | Android Devices page title matches membership scope | Current-device badge remains local |
| F18 | Action scope labels separate device, member and ownership actions | Target and scope visible before commitment |
| F19 | Ownership confirmation displays the complete destination fingerprint | Similar prefixes and multiple destination devices |
| F20 | Shared native confirmation helper supplies action-specific commit and Cancel labels | Real native dialogs and cancellation; no command after cancel |
| F21 | SSH credential promise reflects Remember selection and desktop wallet retention | Remember on/off, stored-login flow |
| F22 | Four first-launch choices form a balanced two-column grid | Compact desktop and long labels |
| F23 | Android reuses independent-console fingerprint verification guide | Match, mismatch and changed identity |
| F24 | New bounded native local SSH-key import; encrypted/plain PEM/OpenSSH envelope checks | File cancellation/error, stale completion, no key text in errors |
| F25 | Recovery instructions use platform-specific labels | Fresh-client recovery path |
| F26 | Separated Admin recovery policy, readable selection rows and commit identity summary | Zero/many/long-name Admins |
| F27 | Explicit retained-material acknowledgement and finish; navigation/close guard; no plaintext persistence | Save cancel/error, deliberate abandonment, Back and app close |
| F28 | Android restore now warns about reviving revoked authorization; direct member review | Stale backup before/after restore |
| F29 | Old VPN data plane vs old host/control endpoint retirement distinguished; manual signed-code fallback | Reachable/unreachable old host |
| F30 | Restore asks for the original backup password | Export vs restore copy |
| F31 | Operation result surface replaces committed Android maintenance form, clears SSH secrets and shows next actions | Repair/restore/update success vs reconnection |
| F32 | Shared “Move devices to a new VPS address” terminology and direct restore action | Follow next step literally |
| F33 | Structured UTC day/time rows and date-specific local preview; overnight splitting | Sunday wrap, midnight, multiple/unrestricted intervals |
| F34 | Policy field errors and submit guard/focus; original parser constraints retained | Limit, expiry, malformed/overlapping schedules |
| F35 | Shared checkbox spacing, full-row labels and focus treatment | Long labels, keyboard Space and touch |
| F36 | Forwarding empty state distinguishes permissions/support/eligible devices; management route | No devices, suspended devices, Member restrictions |
| F37 | Public/device port errors identify the offending field; reserved-port server feedback associated | Independent and simultaneous invalid values; no unsafe write |
| F38 | Close-port action includes protocol/public port/destination in its accessible name | Remove one of two forwards |
| F39 | Selected Android apps resolve local labels/icons; package/profile identity and unavailable fallback retained | Duplicate names, uninstalled apps, discovery failures |
| F40 | Task-specific DNS view over the existing verified-SSH repair operation; transport fields omitted | Review exact DNS scope and service restart impact |
| F41 | Persistent Android maintenance operation/SSH target, final review and keyed task reset | Switch target/task; no stale credentials/results |
| F42 | Compact mobile chrome and duplicate heading spacing refined | First actionable control and larger text |
| F43 | Disabled action reasons visible beside controls and in menus | Connection/recovery/permission prerequisites |
| F44 | Version, size, source and readiness lead; signature material under disclosure | Verified/invalid/incompatible/rollback states |

## Test gap ledger

| ID | Required evidence / current implementation |
|---|---|
| Q01 | Viewport/clip/overlay assertions and settled layout; menu captures preserve open menus; target evidence captures |
| Q02 | Contextual local storage/document/password/application/signature/network failure fixtures |
| Q03 | Ownership fixture preserves prior Owner as Admin; verify authoritative transitions in integration tests |
| Q04 | Real OS dialogs/permissions/file pickers must supplement harness previews |
| Q05 | Windows cross compilation plus actual Windows shell, tray, update and rollback acceptance |
| Q06 | Keyboard and focus/error association automation plus TalkBack/manual assistive technology |
| Q07 | Short portrait/landscape, larger text, keyboard and complete QR assertions |
| Q08 | Native Android settings return, denial, rotation, sleep/resume and process recreation |
| Q09 | Isolated packet-policy tests plus live direct/fallback/DNS/IPv6/routing/reconnect acceptance |
| Q10 | Synthetic-secret lifetime, clipboard/backgrounding/export cancellation and storage inspection |
| Q11 | Recovery/backup integrity, wrong password/binding, duplicate identities, interruption and retry |
| Q12 | Signature/target enforcement, actual installation readback, failure and rollback on each OS |
| Q13 | Application loading/error scenarios actually open the picker; empty/search/selection/discovery coverage |
| Q14 | Visible running states, duplicate-action guard, stale completion, cancellation and safe retry; committed operations require readback |

## Reproduction

- Frontend: `pnpm --dir apps/desktop test`; `pnpm --dir apps/desktop build`.
- Native import: `cargo test --locked -p sirinvpn-desktop --lib ssh_key_document`.
- Catalog server: run Vite from `apps/desktop` with `--config ../../tests/ui/catalog/vite.config.ts`.
- Browser catalog: use the existing `.cache/status-stream/venv/bin/python` environment
  to run `tests/ui/catalog/capture.py desktop` or `android`, with `--browser` and
  `--output target/frontend-audit-remediation/captures`.
- Network tests use the repository's `tests/network/run-*.sh` disposable Docker
  containers. Never run the ignored namespace/firewall tests directly on the host.

## Executed validation

The implementation and local validation are complete. External release acceptance
remains open as listed below. The final source inventory is
[`source-changes.json`](../target/frontend-audit-remediation/source-changes.json):
62 frontend/catalog files changed from the task baseline, 18 new frontend/catalog
files, and six explicitly recorded native source/capability files. Native files
had no task-start content hashes; their existing Git changes must not be attributed
entirely to this task.

| Check | Result | Evidence under `target/frontend-audit-remediation/` |
|---|---|---|
| Frontend unit/component suite | **46 files, 221 tests passed**; baseline was 41 / 196 | `tests-accepted-final.log` |
| TypeScript and production Vite build | Passed, including the final QR height calculation | `android-apk-accepted-final.log` (`beforeBuildCommand`) |
| Desktop browser journeys | **404 / 404**, 1,168 current capture references | `captures-final/desktop-results.jsonl` |
| Android browser journeys | **375 / 375**, 1,567 current capture references | `captures-final/android-results.jsonl` |
| Responsive and interaction checks | **22 / 22**: startup retry, small/landscape QR, 200% text, invalid policy submission, overnight UTC save, keyboard menu focus, recovery acknowledgement/clear and local-only removal | `responsive/results.json`, `responsive-accepted.log` |
| Native renderer and bridge checks | **12 / 12 Linux**, **20 / 20 Android emulator**; two additional ownership-dialog probes passed | `native/*-checks.json`, `native-ownership/*-checks.json` |
| Final QR native rechecks | **2 / 2 Linux**, **3 / 3 Android**, including actual emulator rotation | `native-qr-final/*-checks.json` |
| QR raster decoding | **21 / 21** original screenshots decoded to the exact synthetic payload; hashes recorded without logging payloads | `qr-decoding-final.json` |
| Android SSH-key document validator | Rust unit check passed | `rust-ssh-import.log` |
| Android native compilation | Rust cross check, Kotlin unit tests and instrumentation-test compilation passed | `android-rust-check.log`, `kotlin-tests.log` |
| Android APK | Final x86_64 debug build and installation passed; normal production startup, without fixture injection, read platform/security/identity/profile/VPN status successfully | `android-apk-accepted-final.log`, `android-install-accepted.log`, `android-production-boot.json` |
| Linux native build | Passed | `linux-native-build-final.log` |
| Windows compilation | Cross compilation with tests enabled passed; Windows execution was not performed | `windows-cross.log` |
| Disposable network suites | **6 / 6 passed**: recovery authority, member lifecycle/storage rollback, old-host handoff, split DNS, reusable invitation policy, atomic packet-policy replacement | `network-{recovery-policy,member-lifecycle,endpoint-handoff,split-dns,invitation-policy,policy-kernel}.log` |
| Scoped whitespace check | Passed | `diff-check.log` |

The 779 browser journeys cover 32 desktop and 31 Android application families and
produce **2,735 current capture references**. They do not represent a rerun of all
43 families in the original archive, which also contains native/manual material.
Result logs are append-only: use the **last record for each scenario ID**. Earlier
failed runs remain for diagnosis; corrected captures supersede them. DNS captures
now enter through the ordinary DNS task, and populated member-menu captures keep
the menu open. Fixtures reject contradictory ownership transitions and unexercised
operation/error states. Text visibility checks target the actual text element,
rather than accepting a containing tab panel. A failed journey returns a nonzero
CLI exit code, including resumed runs; an intentional missing-operation probe
verified that failure cannot be reported as a successful command.

Native confirmation lifetime uses the current server, connection and access role.
Background membership polling does not silently cancel an open confirmation;
switching server, disconnecting, changing access or unmounting invalidates it.
All eight access-controller tests passed, including five focused lifetime cases
(`tests-confirmation-final.log`).

The [before/after gallery](../target/frontend-audit-remediation/evidence.html)
contains 44 finding references with 88 checked image links. Its
[Markdown index](../target/frontend-audit-remediation/evidence.md) and
[JSON index](../target/frontend-audit-remediation/evidence-index.json) preserve
traceability to the untouched original captures. These are local linked artifacts;
keep both capture directories beside the gallery when sharing it.

Native UI journeys use the production components with fictional API responses.
The native bridge is used for OS confirmations, application discovery, document
selection/import, settings return and lifecycle checks. The real Android discovery
probe found 18 applications with 18 bounded icons; no application inventory was
written to the report. SAF imported a synthetic SSH-key document exactly and
rejected a raw file URI. Its envelope is test data, not an authenticated SSH key.
The final production startup check used no fixtures and had zero saved profiles;
it does not establish connected-session recovery.

The final APK rebuild needed an explicit `RANLIB_x86_64_linux_android` pointing
to the installed NDK's `toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib`.
The first retry's missing-tool error is retained in
`android-apk-toolchain-retry.log`; it was a build-environment issue.

## Remaining acceptance gates

| Environment / evidence needed | Outstanding work |
|---|---|
| Disposable live VPS, controlled clients and SSH access | Direct/fallback transports, DNS/IPv6/routing enforcement, reconnect, authoritative role readback, local removal leaving other clients functional, recovery and stale-backup restore/migration. The six Docker suites provide isolated kernel evidence, not a live deployment result. |
| Actual Windows installation | Native shell/tray, dialogs and file selection, service interaction, signed installation/readback and rollback. Cross compilation cannot close Q05 or Q12. |
| Physical Android and external camera/scanner | Camera-to-payload equality, hardware-specific rotation/keyboard behavior, permission denial, background/recreation during connection and secret workflows, TalkBack navigation. Emulator rotation, raster decoding and settings return cover only their recorded cases. |
| Controlled signed update and backup environments | Real interrupted installation/rollback, wrong-password/binding recovery, export cancellation and clipboard/background/storage lifetime across supported operating systems. Frontend state tests and native document probes do not close the complete Q10–Q12 matrices. |

No test VPS, Windows runtime or physical device was supplied during this run.
These gates are explicitly unexecuted; no finding is declared production-certified
from fixture screenshots alone.

Additional focused reproduction commands (with the catalog server running):

```bash
SIRINVPN_CATALOG_URL=http://127.0.0.1:1423 .cache/status-stream/venv/bin/python tests/ui/catalog/remediation_checks.py
SIRINVPN_CATALOG_URL=http://127.0.0.1:1423 .cache/status-stream/venv/bin/python tests/ui/catalog/capture.py desktop --browser --output target/frontend-audit-remediation/captures-final
SIRINVPN_CATALOG_URL=http://127.0.0.1:1423 .cache/status-stream/venv/bin/python tests/ui/catalog/capture.py android --browser --output target/frontend-audit-remediation/captures-final
.cache/status-stream/venv/bin/python tests/ui/catalog/native_remediation.py desktop
.cache/status-stream/venv/bin/python tests/ui/catalog/native_remediation.py android
```

Native scripts require the isolated Tauri/WebKit inspector on port 9238, Android
CDP forwarding on port 9244 and the fictional native catalog bundle. They must not
be pointed at a personal or production client. The APK is at
`apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk`.
