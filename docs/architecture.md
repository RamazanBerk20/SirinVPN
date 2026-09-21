# Architecture

SirinVPN separates installation, the VPN data plane, the private management plane, and local presentation. There is no shared backend.

The current file and component boundaries are documented in the [source module
map](module-map.md); the [feature preservation map](overhaul-feature-map.md) shows
where each implemented capability lives. Dated evidence distinguishes compilation and focused checks from platform acceptance.

```text
Linux desktop UI / CLI
  |-- local profile store (public connection material)
  |-- local network policy (one salted current success)
  |-- Linux Secret Service or 0600 fallback (private identities)
  |-- SSH provisioner -------------------------------> VPS SSH daemon
  |-- transport engine -> Direct UDP / Obfuscated UDP / TLS fallback / TCP fallback
  |     `-- stdin + polkit -> privileged network helper
  |                     |-- WireGuard interface
  |                     |-- authenticated loopback UDP/TCP relay (when selected)
  |                     |-- policy routing
  |                     |-- owned nftables tables
  |                     `-- systemd-resolved link DNS
  |
  `-- TLS 1.3 + mTLS over sirinvpn0 -----------------> management daemon
                                                        |-- current authorization
                                                        |-- authenticated public UDP/TCP relays
                                                        |-- live kernel state
Internet traffic <============== WireGuard =============|-- Unbound DNS
                                                        `-- owned nftables/NAT
```

## Workspace ownership

| Component | Responsibility | Privilege |
| --- | --- | --- |
| `sirinvpn-protocol` | Versioned local/API data types and validation | None |
| `sirinvpn-release` | Offline signed-manifest creation/verification, artifact authentication, rollback-safe state planning, and Linux installed-release receipt ownership | None for release creation/verification; root for fixed system receipt state |
| `sirinvpn-release-fetch` | Explicit bounded HTTPS retrieval into a verified private no-clobber candidate bundle | Unprivileged user; never installs or writes system release state |
| `sirinvpn-transport` | Select Direct/Obfuscated/TLS/TCP endpoints and implement the authenticated client/server relays | Client relay receives only `CAP_NET_ADMIN` for its marked outer socket; server relays run in the existing daemon |
| `sirinvpn-core` | Per-server identities, profile storage, bounded local network policy, secrets, pinned mTLS client | User |
| `sirinvpn-installer` | Host-key-pinned SSH discovery and transactional VPS setup | Remote root through SSH/sudo |
| `sirinvpn-server` | Private status, diagnostics, configuration, invitations, and current authorization | Dedicated `sirinvpn` user with `CAP_NET_ADMIN` for peer updates and `CAP_NET_BIND_SERVICE` for UDP+TCP/443; mutable access is confined to `/etc/sirinvpn/authorization` |
| `sirinvpn-linux-helper` | Local interface, routes, DNS, and owned firewall tables | Root through polkit |
| `sirinvpn-cli` | Headless adapter over the same core operations | User plus polkit for network changes |
| Tauri desktop | Native command boundary and product UI | User plus polkit for network changes |

| `sirinvpn-tunnel-model` | Shared connection intent, status, routing, quality and diagnostics model | None |
| `sirinvpn-platform` | Platform boundary with native Windows pipe, storage and networking adapters | User or service according to operation |
| `sirinvpn-windows-service` | Serialized WireGuardNT, IP Helper, DNS, WFP and recovery lifecycle | LocalSystem |

## Android ownership

The Android client shares the React interface through Tauri. A separate `:vpn`
process owns the Kotlin controller, native Rust runtime and Go WireGuard engine;
the Activity and WebView do not own the tunnel. Same-UID Binder calls carry
commands and current snapshots across the process boundary. Native protected
inputs keep secret values out of WebView state.

Android owns VPN consent, Always-on and lockdown policy. Credentials use
Keystore-protected app storage; current counters and network observations stay
in memory. See the [Android architecture contracts](android/README.md#architecture-contracts)
and [platform boundaries](android/security-and-platform.md) for lifecycle and
verification limits. Earlier Android implementations and their audit reports are
historical.

## Windows ownership

The GUI and CLI are ordinary user processes. A protected LocalSystem service owns
WireGuardNT, routes, addresses, DNS, WFP guards and authenticated carriers.
Named-pipe peers authenticate each other; impersonation binds the active session
to the caller SID. User secrets use user-scoped DPAPI. The service's one encrypted
machine-scoped session contains current intent and exact resource ownership.

Persistent filters retain the configured protection across crashes. Dynamic
adapter/carrier permissions exist only for a current service session. Recovery
separates pause, disconnect, service restart, new boot, reconnect and startup
policy. Underlay observations and private-server quality/MTU probes remain
volatile. The signed app-update coordinator stages and verifies its package under
administrator ACLs and retains interrupted work for retry. See [Windows
implementation and acceptance boundary](windows-integration-2026-09-07.md).

## Current policy and diagnosis

Shared current authorization enforces member/device limits, suspension, expiry,
UTC schedules, delegated permissions and bounded reusable invitations. Encrypted
recovery and signed endpoint checkpoints retain only current recovery state.
DNS policy owns typed split zones, private records and recursive/DoT/DoH upstreams.
The installer owns discovered NAT/address facts, port conflicts and rollback.
Signed VPS updates have independent public trust/receipt state and compatible
rollback; opt-in security checks run on that VPS under a dedicated download user.

`sirinvpn-core::diagnostics` combines validated current connection state, bounded
private DNS and pinned management requests. `sirinvpn-server::diagnostics`
collects current service/network/DNS/resource evidence with fixed commands,
bounded output and concurrency. The client accepts recognized codes and local
messages only. The desktop report is volatile and explicitly copyable.
Unavailable evidence never becomes a healthy reading; packet-level enforcement
requires acceptance tests. See the [current feature map](overhaul-feature-map.md)
and [diagnostics design](current-diagnostics-2026-09-07.md).

## Provisioning transaction

1. The client connects over SSH and displays the presented host-key fingerprint.
2. Provisioning continues only with the caller-supplied fingerprint pin.
3. The server is checked for Debian 13, a supported architecture, the active SSH port, a safe IPv4 default interface, and an IPv4 route. IPv6 is enabled only when discovery also finds a safe IPv6 default interface with a `2000::/3` globally routable address.
4. A locally built server executable and the public owner certificate are uploaded to a mode 0700 temporary directory and SHA-256 verified.
5. Missing Debian packages only are installed.
6. Any prior unfinished SirinVPN rollback is completed. Existing SirinVPN-owned files and relevant service state are copied to a root-owned mode-0700 maintenance backup that survives reboot until recovery or commit cleanup.
7. A five-minute systemd rollback timer is armed before network changes.
8. A normal reinstall proves that the requesting device certificate and WireGuard key belong to the sole current Owner in the VPS authorization document. Legacy installations without that document fall back to the original bootstrap Owner certificate. An explicit SSH-authorized replacement instead stops SirinVPN services and removes only the old SirinVPN identity/authorization after the backup and rollback timer exist.
9. After rejecting conflicts on the configured transport ports, the server identities (including a separate X25519 transport key and its derived pinned TLS certificate), WireGuard interface, private DNS, isolated nftables tables, forwarding settings, public UDP relay, shared raw/TLS TCP/443 relay, and sandboxed services are applied. An IPv6-capable installation also preserves router advertisements on its uplink, adds the server ULA, and installs scoped NAT66.
10. The still-open SSH session verifies all services, the interface, private management listener, transport-key binding, and both public transport listeners.
11. On success the guard and backup are removed. On detected failure rollback runs immediately; if the process or connection disappears, the timer runs it.

The installer does not flush, replace, or change the policy of the host's existing firewall tables and does not change the SSH daemon configuration. Docker's later `FORWARD` drop policy would otherwise override an earlier nftables accept, so when `DOCKER-USER` already exists the firewall lifecycle inserts one exact `sirinvpn-forward-*` pair for IPv4 and, when enabled, one `sirinvpn-forward6-*` pair for the SirinVPN ULA. They accept only tunnel egress to the discovered interface and established replies in reverse. Start is idempotent; stop and rollback delete only those exact comment-tagged rules. Package installation is not rolled back, but installed packages are limited to the required Debian components.

## Removal and uninstall transaction

Local removal deletes only the selected profile and its device identity. Admin and Member profiles have no remote-uninstall path. A current Owner may separately request clean VPS uninstall while disconnected; this starts a new privileged SSH session, pins the presented host key, and checks that the authorization document binds the local device certificate to its sole Owner and that its server ID matches the local profile. The immutable schema-1 certificate in `server.json` remains only the legacy bootstrap claim after an in-band ownership transfer.

The uninstall transaction completes any older rollback first, snapshots the exact SirinVPN-managed paths plus service/forwarding state under a root-owned reboot-persistent maintenance directory, and arms a five-minute systemd guard. It then stops/disables only the three SirinVPN units, invokes their owned firewall/network teardown, removes the SirinVPN server/configuration, Unbound drop-in, sysctl file, and service units, reloads systemd, and restarts Unbound without the SirinVPN binding. Commit occurs only after the interface, owned nftables tables, comment-tagged Docker rules, private listener, services, and paths are proven absent. Failure restores the snapshot; success disarms the guard before the desktop deletes the local profile/key. Generic dependency packages and all unrelated VPS paths, services, containers, firewall policy, and SSH configuration remain untouched.

## Offline repair/update transaction

Repair is available only from a disconnected current Owner. It stages the locally packaged candidate for validation while preserving an authenticated installed server version and release watermark; replacement is a separate destructive operation. A fresh pinned SSH session first reads a bounded set of `/etc/sirinvpn` identity/configuration files without mutation. The fixed tunnel layout, WireGuard endpoint/key, pinned TLS certificate, current sole Owner certificate/WireGuard key, supported schema, and authorization server ID must match the local profile. A legacy schema-1 P0 configuration may omit the separate authorization document—and therefore has no stored server ID to compare—so its original Owner certificate plus server WireGuard/TLS identities form the preflight binding before authorization is expanded. Expansion writes `/etc/sirinvpn/authorization-required` as a root-owned mode-0600 authorization-loss barrier; a missing authorization document thereafter stops current-version startup and repair. Missing, corrupt, future-schema, or mismatched cryptographic state stops here.

The candidate artifact is uploaded to a mode-0700 temporary directory, SHA-256 checked after transport, and executed from staging with `validate-state`. This proves the stored server WireGuard private/public binding, TLS certificate/private-key binding, certificate roots, and authorization compatibility before the normal install transaction can touch managed state. Repair then reuses the provisioning backup and five-minute rollback guard to replace the server executable and reconstruct SirinVPN-owned services, scripts, Unbound/sysctl configuration, permissions, interface, firewall, NAT, and transport listeners while preserving `/etc/sirinvpn` identities and authorization. A server without either authenticated transport capability receives one new independent transport key during this migration; UDP and TCP use distinct Noise prologues with that same pinned key, and subsequent repairs preserve it exactly.

After initialization, bootstrap output must still match every existing cryptographic/endpoint binding and return valid UDP and TCP transport capabilities. Commit additionally requires the installed binary digest and management-certificate digest, exact owner/modes, enabled and active units, configured IPv4/IPv6 tunnel addresses and peer routes, live WireGuard key/port, both public transport ports, isolated nftables filter/NAT tables, forwarding, private DNS listener, private management listener, and original SSH session. Any failure invokes immediate rollback; interruption leaves the timer armed. Success may update the profile's public IPv6, Obfuscated UDP, and TCP fallback capability data but never changes the local secret or an existing server/device identity. If an existing server is already dual-stack but discovery no longer finds the required VPS route/address, repair stops before mutation instead of silently contracting it. No release lookup, artifact download, signing decision, general configuration migration, or VPS migration occurs in this slice.

## Local encrypted device backup

The core crate owns one interoperable backup path used by CLI and desktop. Export loads exactly one local profile and its separately stored device secret, validates the Ed25519 certificate/private-key binding and both WireGuard keys, then applies Argon2id v19 with fixed 64-MiB/three-pass/one-lane parameters and a random 16-byte salt. XChaCha20-Poly1305 encrypts the payload with a random 24-byte nonce and authenticates the canonical envelope header. Legacy schema 1 contains the profile and identity; schema 2 may additionally carry the Owner SSH port as encrypted recovery metadata. Current readers accept both, while a legacy reader rejects schema 2 without mutation. The JSON envelope is limited to 256 KiB and exposes no server-specific metadata outside ciphertext.

Linux completes the bytes with directory fsync, mode 0600, and no replacement.

## Current-device key rotation

Rotation is a two-identity transition over the already connected private management plane. The client first validates its stored certificate/private-key and WireGuard private/public bindings, generates a completely fresh local identity, and stages two fresh secret references: a transitional identity combines the old WireGuard key with the new management private key, while the final identity contains both new private keys. A mode-0600 journal records only those references, the original profile, replacement public identity, persistent-protection and Automatic-fallback choices, random rotation ID, and phase.

The old authenticated device prepares that rotation on the VPS. Authorization retains the current device and peer unchanged while adding a ten-minute pending record. TLS trusts the pending certificate so possession of its new private key can commit or cancel the matching transition, but normal handlers still resolve only current device certificates and reject it. Preparation is idempotent for the same device/ID/public material, rejects duplicate identity material and recent enrollment receipts, and expiration simply removes the pending public state.

Before commit, the client durably marks the local transition ambiguous. It then opens mTLS with the new certificate through the still-working old WireGuard tunnel. Commit replaces both public identities on the same device record and uses the normal `wg`-first, authorization-write, old-peer-restore-on-write-failure transaction. The response may disappear when the old peer is removed, so the client never treats response loss as failure: it reconnects with the final identity and verifies the returned caller device ID and certificate fingerprint. If that fails, it retries the original identity; a confirmed old identity retains the journal for an idempotent retry, while an unconfirmed state retains both candidates and fails visibly. Only verified activation updates the profile, restores persistent protection, deletes the old/transitional secrets, and removes the journal.

## Data plane and protection

The VPS uses `sirinvpn0` and `10.77.0.1/24`; the first Owner uses
`10.77.0.2/32`. Permanent devices and temporary enrollment peers have separate
bounded address ranges. A server-ID-derived private IPv6 `/64` maps each device's
IPv4 host number into its IPv6 `/128`. The VPS forwards only that owned prefix
and uses NAT66 when its uplink supports IPv6. IPv4 or IPv6 outer endpoints can
carry the inner tunnel independently; public-prefix delegation is not provided.

On Linux, the helper owns WireGuard fwmark/table `51820`, exact policy rules,
interface addresses, link DNS and nftables guards. Full routing selects defaults;
CIDR selection admits only canonical non-default prefixes plus the private DNS
route. Optional LAN bypass never captures that DNS route. The helper revalidates
all unprivileged input and removes only demonstrably owned state. Explicit
[application launches](linux-application-routing-2026-09-07.md) use a dedicated
namespace, private DNS and an unprivileged child; executable arguments are not
retained as activity history.

The shared transport engine chooses concrete capabilities before any privileged
apply. Direct UDP reaches the configured WireGuard endpoint. Obfuscated UDP,
raw TCP and TLS use separate loopback relay ports and distinct Noise IK protocol
bindings. Current authorized X25519 identities authenticate the wrapper while
WireGuard independently protects its payload. Framing, padding, replay windows,
handshake deadlines, connection counts and idle cleanup are bounded. Linux outer
sockets carry the protected mark; Windows binds its own
physical carrier sockets through their platform boundaries.

Pinned TLS supports legacy framing and [HTTPS WebSocket
transport](https-transport-2026-09-06.md). HTTPS authenticates Noise before the 101
upgrade, masks client frames and serves bounded static cover responses to ordinary
web requests. A generated or explicitly imported matching certificate is pinned;
renewal cannot silently change that pin. Browser-identical fingerprints and
universal censorship resistance are not claimed. [Signed endpoint
checkpoints](endpoints-and-outer-ipv6-2026-09-06.md) bind current ports, alternate
addresses and public identities; catch-up and background discovery preserve the
pinned server identity and current protection/routing intent.

Transport preference is local policy. Manual selection remains pinned; Automatic
tries only advertised candidates and stops on uncertain teardown. Initial
readiness requires authenticated management through the tunnel. The optional
local network policy retains a named preference, one salted current success and
explicit trusted-network settings, never a visited-network or attempt history.
Private-server quality/MTU probes keep current samples only. Voluntary comparisons
require protection and idle conditions and restore the prior working candidate
when a trial fails. See [quality and Wi-Fi](transport-quality-and-wifi-2026-09-06.md)
and [MTU](mtu-handling-2026-09-06.md).

Kill switch, automatic reconnect and connect on startup are independent Linux
policies. A root-private desired record contains only current intent, native
WireGuard/transport material, endpoint descriptors, routing and MTU settings.
All four transports can be retained. The boot guard precedes networking; the
supervisor honors pause/reconnect/startup choices, observes current physical
routes, requires a fresh handshake after underlay change, and uses bounded
backoff. An unavailable route holds the configured guard without rebuild churn.
Explicit Disconnect clears retained intent and removes owned resources. Schema
versions and legacy guards fail closed for incompatible readers; disconnect
before a deliberate helper downgrade.

Full protection blocks ordinary off-tunnel traffic. Selected protection guards
its selected destinations and system DNS while leaving intentional bypass traffic
available. Exceptions for outer transport, endpoint discovery and endpoint DNS
are marked and bounded; IPv6 neighbor discovery and LAN exceptions have explicit
scope. A failed apply or uncertain cleanup never becomes a healthy connection.
Windows uses native WFP for the analogous scope. Platform acceptance must verify actual packet behavior.

The VPS owns separate filter/NAT tables and exact comment-tagged Docker
continuation rules. Peer communication requires both current endpoint addresses
in authorization-derived allow sets. Public IPv4 forwards require a current exact
mapping and matching admission before established replies; stale mappings cannot
inherit admission. Stop clears dynamic admission. Temporary enrollment peers can
reach only their private enrollment endpoint. No host-wide firewall flush occurs.

Unbound listens only on loopback/tunnel addresses. Typed recursive, DoT and DoH
policies have no plaintext/recursive fallback when secure forwarding is selected.
Private records and [split zones](split-dns-2026-09-06.md) are generated from
bounded typed data. The DoH adapter uses pinned endpoint resolution and normal
CA/name verification, no proxy/redirects, bounded wire messages and a restricted
service. Current diagnostics can query the configured paths without recording
user DNS queries or reachability history.

## Management plane

The management client uses only the enrolled server certificate as its trust
store, disallows redirects, referers, proxies, and implicit retries, and bounds
both declared and streamed response bodies to 1 MiB. The server caps concurrent
management sockets at 512, TLS handshakes and HTTP/1 headers at ten seconds, and
HTTP/2 streams at sixteen per connection. These resource limits reduce stalled
connection exposure; they are not a general denial-of-service guarantee.

The management daemon binds to the private tunnel endpoint (default `10.77.0.1:8443`); it is not exposed on the VPS public address. Its self-signed, `serverAuth`-limited certificate is pinned in every local profile. The server dynamically trusts only current device certificates plus unexpired temporary invitation certificates and requires one during the TLS 1.3 handshake. Every handler rechecks current authorization, so revocation also closes the authorization window for already-open TLS connections.

The read endpoints expose current status, diagnostics, and configuration to authorized devices, including the configured DNS upstream, private-record set, peer-isolation/port-forward capabilities, each device's current peer permission, and the current exact port-forward set for managers. Status includes the authenticated caller's live role, device ID, and current certificate fingerprint so a promoted, demoted, transferred, or rotated device does not rely on stale local bindings. It also reads aggregate CPU/memory state and SirinVPN-interface byte totals from procfs. A daemon-wide sampler keeps exactly one prior snapshot in RAM and accepts deltas only between 250 milliseconds and 30 seconds, so the optional CPU and rate fields remain absent for an initial, reset, too-fast, or stale sample. The desktop schedules the next poll four seconds after the previous one completes and measures that private status request locally as control-plane latency. Manual refreshes supersede older requests; late replies cannot restore an obsolete server snapshot. No metric, DNS-query, or configuration history is created. Membership and mutation endpoints enforce the current role and explicitly delegated permissions; self-key-rotation is separately available to every current device. The Owner can manage every member/device and is the only role that can promote or demote Admins or transfer ownership. An Admin can create/cancel ordinary Member invitations and rename, revoke, change peer permission, or direct a public port to ordinary Member devices, but cannot manage the Owner or another Admin. A Member can change only their own permitted peer/forwarding scope when explicitly delegated. The last Owner device is protected. Ownership transfer names an existing destination device, is re-authorized under the same write lock as the transition, rejects active/recent additional-device enrollment for either affected member, promotes the destination member and all of its devices, and retains the former Owner as an Admin in one atomic authorization replacement. The enrollment endpoint accepts only the temporary identity bound into an active invitation or its short retry receipt. The daemon validates all keys, addresses, and ports before applying exact `wg set` peer arguments or replacing the exact nftables set/chain contents. An authorization transaction synchronizes WireGuard, peer-isolation, and port-forward runtime state before atomically replacing the document, restoring every previous runtime component if persistence fails. It cannot read the root-owned WireGuard private key or modify root-owned network scripts.

## Invitation and enrollment path

An authorized Owner/Admin or explicitly delegated Member device generates a random bearer token and temporary bootstrap WireGuard/mTLS identity locally. It sends only their public material and the token hash through the private API. The VPS allocates addresses and signs the canonical invitation claims with its pinned Ed25519 management key. The long code contains the signed claims, raw token, and temporary bootstrap secret; it contains no permanent device private key. The desktop can also Deflate and base64url-encode that same bounded invitation as a locally rendered QR payload. Both representations are bearer secrets and no QR or invitation service is contacted.

The recipient verifies the signature, server binding, expiration, token hash, bootstrap key bindings, and optional existing-member/access binding before changing the network. It then opens a transient bootstrap tunnel, generates a fresh permanent identity locally, and submits only that permanent public material to the VPS. A new-member redemption atomically adds the member and first device; an additional-device redemption attaches the new device identity to the signed existing member without copying an existing private key. Single-use redemption consumes the invitation; reusable redemption decrements its bounded remaining uses and assigns independent permanent identities. Short exact-request receipts resolve lost responses without consuming another use. Current issuer scope, member/device limits and expiry are revalidated at redemption. Expiration, cancellation, and revocation of a just-enrolled device remove the corresponding temporary access.

## Persistent compatibility and updates

The canonical current state-family read/write ranges are declared in
[`release/state-compatibility.json`](../release/state-compatibility.json).
They cover shared profiles, authorization/configuration, backups, recovery,
endpoint/invitation claims, Linux helper/runtime/release state and Windows service/update state. Historical
Android state declarations remain for compatibility with existing signed metadata;
they do not establish migration support for the current port. Consult the current
[Android platform notes](android/security-and-platform.md) for its storage boundaries.
Feature-bearing writers select the required schema; unknown versions fail closed.
Do not infer a safe downgrade from an older historical milestone's schema number.

Signed release transitions require compatible readers in both directions, exact
artifact authentication and monotonic policy/release high watermarks. Linux
Debian updates use an offline root-owned package transaction with authenticated
rollback; Windows uses a protected installer worker and service health check.
The unprivileged fetcher has no default source and runs only after an explicit
client request. AppImage replacement uses the private signed client transaction.
See [release ownership](releases.md).

[VPS signed updates](signed-vps-updates-2026-09-06.md) use a separate executable
transaction and trust state. Repair preserves an authenticated installed version
and its high watermark. The opt-in security timer runs under a dedicated download
account and retains one current outcome/candidate. Maintenance recovery runs
before VPS network startup; temporary private snapshots exist only while their
transaction or cleanup is pending. No update or activity timeline is retained.

## Extension seams

The protocol, transport engine, installer, data-plane helper, management client, and authenticated backup envelope are separate ownership boundaries so later transports, richer roles, and coordinated migration work do not have to replace the WireGuard core. A future transport must own its complete authenticated setup, endpoint, firewall/reconnect allowance, readiness, and teardown lifecycle before it can join selection. Future migration work may add explicit old-VPS retirement and bounded multi-hop recovery without weakening P2I's local validation, destination replacement contract, installer rollback boundary, or P2J's signed monotonic endpoint chain. Unimplemented options remain absent rather than appearing as nonfunctional switches.
