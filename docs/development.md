# Development

## Toolchain

- Rust 1.97.1, pinned by `rust-toolchain.toml`
- Node.js 26
- pnpm 11.3.0, pinned by `packageManager`
- Linux Tauri 2 build dependencies, including WebKitGTK 4.1, librsvg, OpenSSL headers, and D-Bus headers
- WireGuard tools, nftables, systemd/resolvectl, polkit, and Unbound for end-to-end testing

Install frontend dependencies:

```sh
cd apps/desktop
pnpm install --frozen-lockfile
```

Build the Rust workspace:

```sh
cargo build --workspace
```

Start the desktop development application:

```sh
cd apps/desktop
pnpm tauri dev
```

Debug builds may use `SIRINVPN_SERVER_BINARY` and `SIRINVPN_HELPER_PATH` to select local development binaries. Release builds deliberately ignore these variables before invoking privileged operations.

## Android

The Android client shares the React interface and runs its native VPN runtime in
a separate `:vpn` process. Tracked Kotlin, resources and build configuration live
in `apps/desktop/android/`; `scripts/prepare-android.py` applies them to the
generated Tauri project. Do not edit generated files under `src-tauri/gen/`.

Follow the [Android build and test guide](android/build-and-test.md) for JDK,
SDK/NDK, Go, Rust target and VPS payload prerequisites, then use
`sh scripts/build-android.sh all debug`. See the [Android overview](android/README.md)
for the feature matrix and current verification limits.

## Windows

Use `scripts/package-windows.ps1` on Windows with the selected MSVC architecture,
Visual C++ tools, Perl, Node, pnpm and both trusted Debian VPS payloads. The script
verifies pinned WireGuardNT files and builds the service, CLI and NSIS package.
[Windows implementation](windows-integration-2026-09-07.md) documents protected
paths, pipe/SID ownership, WFP and DPAPI lifecycles, manual updates and acceptance.
The Linux LLVM-MinGW cross-check script provides compilation/package evidence
only; it does not qualify the MSVC installer or Windows runtime.

## Resource limits

Run one native/package build at a time. Build scripts default to two Cargo jobs
and two Rust test threads; Vitest runs one file/worker at a time. Docker build
containers cap CPU at 1.5 cores, RAM at 4 GiB with no additional swap, and processes
at 256. They require no privileged mode, host networking or network capabilities.
On this Linux development host, place host builds in a user scope as well:

```sh
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 \
  systemd-run --user --scope --quiet \
  -p MemoryHigh=3G -p MemoryMax=4G -p MemorySwapMax=0 \
  -p CPUQuota=150% -p TasksMax=256 nice -n 10 ./scripts/test.sh
```

Container packaging can reuse a verified local image with
`SIRINVPN_REUSE_BUILD_IMAGE=1`. `SIRINVPN_CARGO_REGISTRY` may point to only the
public Cargo registry directory for offline reuse; never mount Cargo credentials.
`SIRINVPN_TAURI_CACHE` may reuse downloaded bundler tools.
`SIRINVPN_DEPENDENCIES_READY=1` skips dependency installation only when the exact
lockfile is already installed; it still runs frontend tests and the production
build. Do not overlap package builds that write the shared staged binaries.

## Coding constraints

Use the [source module map](module-map.md) and [feature preservation
map](overhaul-feature-map.md) when extending the interface. The local gate checks
a 1,000-line ceiling for first-party source files, rejects unused frontend locals,
and exercises shell cleanup assertions with fake OS commands. Prefer focused
modules over adding another responsibility to a large controller or transaction.

Release signing, root-policy rotation/revocation, explicit HTTPS retrieval, installed-receipt procedures, and the P2V/P2W/P2X/P2Y Debian update boundaries are documented separately in [Signed releases](releases.md). Keep every release private key outside this repository and build environment; the root private key belongs in encrypted offline custody and should sign policies only. P2V may replace only an already bound same-target `.deb`, under the release and network-operation locks, from a re-hashed root-owned cache with a durable interruption journal; health must pass before the receipt commits last, and failure must restore or retain enough authenticated state to recover the old package. P2W policy updates use that same release-state lock, never permit revocation rollback, and allow a receipt key change only with a root-authorized strict release upgrade. P2X networking must remain in the unprivileged fetcher: require an explicit identifier-free HTTPS directory, fixed bounded requests, no proxy/redirect/referer, root verification before artifact transfer, exact artifact authentication, private staging, and atomic no-clobber publication. P2Y may coordinate that path only after an explicit user check, keep one private session candidate, disclose authenticated public metadata, and require a separate exact-package confirmation plus disconnected Debian state before fixed-path privilege. Do not add a built-in release source, AppImage replacement, automatic desktop release checks or dependency fetching without designing and testing that lifecycle. Signed VPS updates and their opt-in security timer are a separate implemented boundary; preserve their independent trust state through Repair.

- Keep server and desktop production paths silent during normal success.
- Do not add logging, analytics, crash reporting, automatic desktop update checks, remotely hosted fonts, or web assets.
- Do not put passwords, passphrases, or private keys in CLI arguments, environment variables, filenames, diagnostics, or error messages.
- Use stdin for secret-bearing subprocess input and `Zeroizing`/`Zeroize` for native secret buffers.
- Add only SirinVPN-owned nftables tables, policy rules, interfaces, and systemd drop-ins. The sole interoperability exception is a bounded set of exact, comment-tagged `DOCKER-USER` continuation rules scoped to the SirinVPN interface/CIDR and discovered public interface. Same-interface continuation is safe only after SirinVPN's earlier both-endpoint nftables decision; it must never become the authorization layer. Never flush a host ruleset, change its policy, or remove an untagged rule.
- Keep the protection lifecycle fail closed while preserving independent kill-switch, reconnect and startup choices: boot guard before networking, reconnect only after the guard, bounded retries, and explicit recovery through disconnect. Persistent Automatic may carry at most four unique installed candidates with the authenticated selection first; manual modes must remain pinned. A successfully observed missing physical route must hold state without rebuild churn. A route return/change may shorten the established handshake window only after one in-memory pre-change baseline and must require a strictly newer authenticated WireGuard handshake; observation errors preserve prior context. Prove owned cleanup before switching, atomically replace the single exact endpoint exception, retain current selection only under `/run`, and preserve the candidate flag through key rotation. Never persist the root route fingerprint/epoch, network identity, failures, timings, attempts, history, or a management key.
- Keep Linux destination split routing helper-owned: normalize at the unprivileged boundary, revalidate 1–32 canonical non-default CIDRs as root, route the private DNS address independently, and never derive destinations from DNS activity. Selected persistent protection must drop selected destinations plus system DNS off-tunnel while leaving unrelated traffic alone; the local-network exception must never bypass the private DNS route. Preserve the exact policy across candidate cycling/reboot and retain a legacy full-tunnel recovery request. Disconnect before a deliberate helper downgrade.
- Keep server peer isolation device-scoped and default-deny. Admit tunnel-to-tunnel forwarding only when both exact current endpoint addresses are in the derived allow sets; enabling one device must not expose an isolated destination. Every role or delegated mutation must reuse the authorization boundary, synchronize WireGuard and nftables before the atomic authorization commit, and roll runtime state back on persistence failure. Boot and server stop must leave the sets empty. Preserve management, private DNS, and ordinary VPS internet forwarding, and do not reinterpret this setting as client LAN access, pairwise/group policy, discovery, or P2N's separate public mapping policy.
- Keep public port forwarding explicit, bounded, current-state-only, and IPv4-only until a separately reviewed expansion. Accept one exact TCP/UDP public-port-to-current-device-port mapping at a time, cap the set at 32, reserve low/SSH/management/DNS/VPN transport ports, and apply the current role and delegated target boundary to both creation and removal. Rebuild DNAT plus admission atomically before authorization persistence; on error restore every prior runtime component. Exact admission must precede Docker, only that admission may set the continuation packet mark, marked stale flows must be dropped before ordinary established replies, and all remaining unsolicited external-to-tunnel traffic must be denied. Flush filter admission before DNAT whenever the daemon stops. Preserve the documented gateway SNAT behavior for split-tunnel replies and do not imply original-source visibility, provider-firewall management, ranges, source allowlists, UPnP/NAT-PMP, hostname routing, discovery, or IPv6 ingress.
- Keep IPv6 capability explicit and monotonic during ordinary repair: enable it only after a globally routable VPS address plus default route are discovered, derive ULA addresses from the random server ID and existing IPv4 host IDs, preserve router advertisements when forwarding is enabled, never silently disable an enabled server, and retain the IPv6 block when capability is absent. Every apply/rollback/ownership check must cover both routing families without probing a SirinVPN or analytics service.
- Keep management bound to the tunnel address and keep certificate pinning, mTLS, TLS 1.3, HTTPS-only, and no-proxy behavior together.
- Persist current configuration and authorization only. Do not add timestamped event tables or historical metrics.
- Keep live metrics aggregate and current: read kernel state without helper commands, retain no more than one bounded prior sample in RAM, and never log, persist, or associate samples with a member/device or destination.
- Keep transport selection in `sirinvpn-transport` and transport identity/profile enums in `sirinvpn-protocol`. A local preference must resolve to concrete transport kinds before crossing the privileged boundary. Automatic candidates require authenticated tunnel readiness, teardown before fallback, and immediate stop on uncertain cleanup. Network policy may retain only one salted current-network success with a coarse bounded expiry: never persist SSID/BSSID or raw platform/default-route identity, failures, timings, counters, attempt order, or network history; keep it separate from profiles, backups, invitations, helper state, and every VPS schema, and preserve corrupt/future documents without overwrite. Do not add a UI choice until its implementation owns authenticated setup, effective WireGuard/outer endpoints, kill-switch and reconnect allowances, readiness, replay/probe behavior, resource bounds, and teardown. Unknown kinds must fail before privileged changes, Direct UDP's omitted/default encoding must remain readable across helper upgrades and rollbacks, and authenticated-wrapper persistent requests must retain legacy-readable fail-closed guard representations. TCP runtime configuration must stay tagged so helper v5 rejects rather than treats it as UDP. Reuse a reviewed protocol construction rather than designing a new handshake or AEAD composition; keep protocol prologues distinct when one transport identity serves multiple wrappers.
- Keep replacement distinct from ordinary provisioning: require verified privileged SSH plus an explicit destructive choice, snapshot before identity removal, revoke all old SirinVPN access, and never include unrelated VPS paths in the replacement set.
- Keep local removal and remote uninstall separate. Only an exact Owner certificate/server-ID match may uninstall; arm rollback before teardown, verify absence before commit, delete local state only after remote success, and never remove generic packages or unowned VPS state.
- Keep repair distinct from replacement and release retrieval. Require a disconnected current Owner, pinned privileged SSH, strict read-only identity/schema preflight, candidate validation against intact private/public bindings, and the existing rollback transaction. Preserve server/device identity and local state, retain the root-owned authorization-loss marker, verify the installed digest and complete live service/network boundary before commit, and never regenerate missing cryptographic/required authorization state during repair.
- Keep server-state export/restore distinct from device backup and Repair. Export requires a disconnected current Owner, pinned privileged SSH, current packaged-candidate validation, fixed state-file bounds/permissions, and an exact current Owner/server binding. Stream a zeroizing snapshot directly into the server-backup-specific authenticated envelope; never put plaintext state in a remote file, remote command, log, diagnostic, or non-zeroizing long-lived buffer. Keep the encrypted destination mode 0600, atomic, bounded, and no-clobber. Restore must authenticate/decrypt and profile-bind locally before SSH, require explicit replacement for occupied SirinVPN state, arm the existing rollback guard before replacement, and send plaintext only to the current candidate's bounded stdin reader. Reconstruct generated state through the transactional installer and update only the initiating local profile after verified remote commit; never untar/copy fields blindly into `/etc` or mutate the old VPS during restore. Cross-host restore may record one exact pending predecessor for the Owner's later explicit endpoint handoff. Keep that handoff public-key signed, server/device/identity/capability bound, strictly monotonic and predecessor-exact; block it during invitation/enrollment/key-rotation transitions, retain only the latest server state, require candidate WireGuard plus pinned-mTLS proof before local commit, and clean up before preserving the old profile on failure. Explicit publication must persist a read-only handoff-source marker on the old clone and reject every enrollment/authorization/key mutation there while keeping authenticated retrieval available. Never silently publish, skip a generation, uninstall the old VPS, or turn current recovery state into migration/activity history.
- Keep DNS policy typed and transaction-owned. Accept only Recursive or one/two validated exact-IP plus TLS-authentication-name endpoints; DoH also owns one canonical absolute path. Never accept raw Unbound/shell input, custom ports, URI authorities/query strings, or certificate paths. DoT retains the fixed root zone, system trust bundle, TCP/853, and `forward-first: no`. DoH retains HTTPS/443 POST `application/dns-message`, native CA/name verification, exact-IP resolution, no proxy/redirect/bootstrap lookup, bounded messages/concurrency/timeouts, sequential failover, loopback-only UDP/TCP service, and exact systemd egress allowlisting. Private records remain a complete bounded vector of no more than 64 canonical multi-label names mapped only to usable A/AAAA addresses; generate static local zones/data rather than accepting record syntax. Omitted Repair input preserves policy/records, explicit input replaces them, and clear removes records. Every path must pass validation, `unbound-checkconf`, exact directive/count/service/listener verification, and rollback before commit. Empty Recursive/DoT/DoH use schemas 1/2/4; records use schema 3 for Recursive/DoT and 5 for DoH. Contract to the destination schema before server rollback. Typed split zones remain inside the same transaction and exact listener/upstream validation. Service activation is not an active upstream query check; explicit current diagnostics may issue bounded queries without logging DNS or reachability history.
- Keep current-device key rotation self-only and expand-first. Generate both private keys locally, retain the old peer until possession of the pending certificate commits, bound pending public state by expiry and exact device/rotation identity, and authorize that certificate for no ordinary endpoint. Journal references/public state before ambiguity, verify the new tunnel before deleting old secrets, keep retry idempotent, and preserve the previous protection policy. Do not silently rotate server identities, another device, or a damaged/missing identity.
- Update the current platform feature map, README, privacy boundary and dated evidence whenever a capability changes. Preserve historical audit claims as historical; compilation never implies runtime acceptance.

## Packaging

`scripts/package-linux.sh` builds the five native binaries, including the separate unprivileged release fetcher and offline privileged release coordinator, stages them into the Tauri bundle, runs frontend tests/build, and produces `.deb` and AppImage targets.

Use `scripts/package-linux-container.sh` for release candidates. It builds against Debian Bookworm so the resulting binaries have a conservative glibc baseline for Debian 13. Build separately on `x86_64` and `aarch64`; the installer rejects an artifact whose ELF architecture does not match the VPS.

Engineering packages are unsigned unless real publisher credentials are supplied. AppImage replacement uses the verified client transaction; see the release documentation.
