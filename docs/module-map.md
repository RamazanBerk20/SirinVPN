# Source ownership after the overhaul

The public Rust interfaces, Tauri command names, CLI commands, and persistent
schemas are preserved. Modules group existing behavior by responsibility; changing
a file boundary does not change which process owns an operation or its secrets.

## Interface

| Location under `apps/desktop/src` | Responsibility |
| --- | --- |
| `App.tsx` | Platform selection, desktop profile selection, navigation, top-level dialogs |
| `hooks/useDesktopStatus.ts` | One current local/remote snapshot, bounded polling cadence, stale-response rejection |
| `hooks/usePageNavigation.ts` | Page-only navigation history, including Android Back |
| `components/` | Local branding, navigation, fields, metrics, errors, dialog focus restoration |
| `features/onboarding/` | SSH provisioning, invitation redemption, encrypted device import |
| `features/connection/` | Connection state/actions, Home, transport/routing options, metrics, maintenance entry points |
| `features/devices/` | Membership, invitations, peer access, forwarding |
| `features/settings/` | Backup, repair, uninstall, key rotation, migration, explicit releases |
| `features/dns/` | Typed recursive/DoT/DoH and private-record inputs |
| `platform.ts`, `hooks/useAndroidBack.ts` | Android native bridge selection and platform navigation |
| `styles/mobile-native.css` | Mobile layout, touch targets and bottom navigation |
| `styles/` | Component styles and concept theme; import order remains explicit in `styles.css` |

The controllers retain a single owner for operation state. Presentation components
receive that controller's typed model. This avoids separate copies of connection,
rotation, enrollment, or dialog state becoming inconsistent. The native layer
continues to authorize every privileged action; interface gating is additional
guidance, not an authorization mechanism.

Only page names enter browser history. Profiles, invitations, credentials, and
connection history are never serialized into navigation state. Dialogs restore
focus to the control that opened them. Android operation state belongs to the
native controller and is exposed through current snapshots.

Base and component CSS preserve the established form and operation states.
Theme sheets define the shared palette; `styles/mobile-native.css` adapts the
layout and controls for Android. Keep the cascade explicit when consolidating a
selector. Illustrations, fonts and the mark are bundled; no CDN serves app assets.

`apps/desktop/android/src/main/java/org/sirinvpn/client/MainActivity.kt` owns
Android's window appearance. `scripts/prepare-android.py` reapplies the tracked
overlay after project generation.

## Native code

| Component | Internal ownership |
| --- | --- |
| Installer | `ssh`: pinned sessions and bounded output; `validation`: input/artifact/state checks; `transaction`: staging/rollback; `install_script`, `dns`, `verification`, `uninstall`: generated installation and verification steps |
| Server | `api`/`access`: routes and caller checks; `membership`, `enrollment`, `endpoint_transition`, `forwarding_api`: operations; `initialization`, `configuration`, `backup`: persistent state; `runtime`: TLS/listeners; `network_policy`: kernel changes; `metrics`: current samples; `diagnostics`: bounded service/network/DNS/resource checks |
| Linux helper | `lifecycle`/`tunnel`: connection changes; `routing`: policy generation; `ownership`/`cleanup`: owned resources; `persistence`/`reconnect`: guard and recovery; `system`: command execution and integration |
| Tauri adapter | Platform-specific profile/enrollment/tunnel modules; shared provisioning, backup, endpoint, management, diagnostics and release adapters |
| Windows platform/service | Authenticated named pipes, DPAPI/ACL storage, WireGuardNT, IP Helper, WFP, current quality, recovery and signed updates |
| Tunnel model | Shared current intent/status, route policy, quality and diagnostic adapters |
| Android VPN/transport | Kotlin foreground controller, plan/permission/network state, QR and private probes; Activity-independent native protected carriers |
| CLI | Arguments, provisioning, profiles, connection, membership, maintenance, output, and helper modules |
| Protocol | Shared facade plus DNS and management contracts |
| Android profile store | `crates/android-runtime/` profile operations and Kotlin `SecretVault.kt` Keystore-backed encrypted storage |
| Transport/release/core | Oversized test modules separated from runtime code; existing state machines remain cohesive |

Private modules may share their parent's implementation types through `super`.
The crate facade re-exports the established public interface. Do not turn an
internal helper into a new public contract just to make a cross-module call.

## Size policy

`scripts/check-maintainability.py` inventories tracked and new non-ignored
`.rs`, `.ts`, `.tsx`, `.css`, `.kt`, `.sh`, `.py`, `.mjs`, and `.js` files. The local
gate rejects any file over 1,000 lines. Build output, generated Android projects,
dependencies, screenshots, and caches are excluded through Git ignore rules.

Prefer roughly 200–500 lines when a responsibility fits that size. Some cohesive
existing code remains larger: transport framing/lifecycle, release receipt/trust
transactions, key rotation, backup/endpoint validation, integration scenarios,
and the Android operation controller. The installer shell template remains one
transactional script so shell traps, staging, and rollback retain their lexical
scope. These files are below the enforced limit; the measured largest-file list
is retained with the audit evidence. A size check is a guardrail, not a complexity
or security measurement.

Existing Rust test names were compared before and after the moves: none were
removed. Test modules now live beside the behavior they exercise. Keep shared
fixture helpers in their test parent rather than copying security-sensitive setup
into each test file.
