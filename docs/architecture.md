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
3. The server is checked for Debian 13 or Ubuntu 24.04 LTS, a supported architecture, the active SSH port, a safe IPv4 default interface, and an IPv4 route. IPv6 is enabled only when discovery also finds a safe IPv6 default interface with a `2000::/3` globally routable address.
4. A locally built server executable and the public owner certificate are uploaded to a mode 0700 temporary directory and SHA-256 verified.
5. Only missing distribution packages are installed. Ubuntu's needrestart apt hook is suspended for that step so it cannot restart unrelated services.
6. Any prior unfinished SirinVPN rollback is completed. Existing SirinVPN-owned files and relevant service state are copied to a root-owned mode-0700 maintenance backup that survives reboot until recovery or commit cleanup.
7. A five-minute systemd rollback timer is armed before network changes.
8. A normal reinstall proves that the requesting device certificate and WireGuard key belong to the sole current Owner in the VPS authorization document. Legacy installations without that document fall back to the original bootstrap Owner certificate. An explicit SSH-authorized replacement instead stops SirinVPN services and removes only the old SirinVPN identity/authorization after the backup and rollback timer exist.
9. After rejecting conflicts on the configured transport ports, the server identities (including a separate X25519 transport key and its derived pinned TLS certificate), WireGuard interface, private DNS, isolated nftables tables, forwarding settings, public UDP relay, shared raw/TLS TCP/443 relay, and sandboxed services are applied. An IPv6-capable installation also preserves router advertisements on its uplink, adds the server ULA, and installs scoped NAT66.
10. The still-open SSH session verifies all services, the interface, private management listener, transport-key binding, and both public transport listeners.
11. On success the guard and backup are removed. On detected failure rollback runs immediately; if the process or connection disappears, the timer runs it.

The installer does not flush, replace, or change the policy of the host's existing firewall tables and does not change the SSH daemon configuration. Docker's later `FORWARD` drop policy would otherwise override an earlier nftables accept, so when `DOCKER-USER` already exists the firewall lifecycle inserts one exact `sirinvpn-forward-*` pair for IPv4 and, when enabled, one `sirinvpn-forward6-*` pair for the SirinVPN ULA. They accept only tunnel egress to the discovered interface and established replies in reverse. Start is idempotent; stop and rollback delete only those exact comment-tagged rules. Package installation is not rolled back, but installed packages are limited to the required distribution components. When `unattended-upgrades` is missing, the installer adds it and enables the daily security run through the standard `20auto-upgrades` file and APT timers; an existing configuration, enabled or not, is left unchanged, and the VPS is never restarted automatically. An active UFW is reported by preflight and left unchanged.

## Removal and uninstall transaction

Local removal deletes only the selected profile and its device identity. Admin and Member profiles have no remote-uninstall path. A current Owner may separately request clean VPS uninstall while disconnected; this starts a new privileged SSH session, pins the presented host key, and checks that the authorization document binds the local device certificate to its sole Owner and that its server ID matches the local profile. The immutable schema-1 certificate in `server.json` remains only the legacy bootstrap claim after an in-band ownership transfer.

The uninstall transaction completes any older rollback first, snapshots the exact SirinVPN-managed paths plus service/forwarding state under a root-owned reboot-persistent maintenance directory, and arms a five-minute systemd guard. It then stops/disables only the SirinVPN units (including the DNS blocklist path and timer), invokes their owned firewall/network teardown, removes the SirinVPN server/configuration, Unbound drop-in, sysctl file, and service units, reloads systemd, and restarts Unbound without the SirinVPN binding. Commit occurs only after the interface, owned nftables tables, comment-tagged Docker rules, private listener, services, and paths are proven absent. Failure restores the snapshot; success disarms the guard before the desktop deletes the local profile/key. Generic dependency packages and all unrelated VPS paths, services, containers, firewall policy, and SSH configuration remain untouched.

## Offline repair/update transaction

Repair is available only from a disconnected current Owner. It stages the locally packaged candidate for validation while preserving an authenticated installed server version and release watermark; replacement is a separate destructive operation. A fresh pinned SSH session first reads a bounded set of `/etc/sirinvpn` identity/configuration files without mutation. The fixed tunnel layout, WireGuard endpoint/key, pinned TLS certificate, current sole Owner certificate/WireGuard key, supported schema, and authorization server ID must match the local profile. A legacy schema-1 P0 configuration may omit the separate authorization document—and therefore has no stored server ID to compare—so its original Owner certificate plus server WireGuard/TLS identities form the preflight binding before authorization is expanded. Expansion writes `/etc/sirinvpn/authorization-required` as a root-owned mode-0600 authorization-loss barrier; a missing authorization document thereafter stops current-version startup and repair. Missing, corrupt, future-schema, or mismatched cryptographic state stops here.

The candidate artifact is uploaded to a mode-0700 temporary directory, SHA-256 checked after transport, and executed from staging with `validate-state`. This proves the stored server WireGuard private/public binding, TLS certificate/private-key binding, certificate roots, and authorization compatibility before the normal install transaction can touch managed state. Repair then reuses the provisioning backup and five-minute rollback guard to replace the server executable and reconstruct SirinVPN-owned services, scripts, Unbound/sysctl configuration, permissions, interface, firewall, NAT, and transport listeners while preserving `/etc/sirinvpn` identities and authorization. A server without either authenticated transport capability receives one new independent transport key during this migration; UDP and TCP use distinct Noise prologues with that same pinned key, and subsequent repairs preserve it exactly.

After initialization, bootstrap output must still match every existing cryptographic/endpoint binding and return valid UDP and TCP transport capabilities. Commit additionally requires the installed binary digest and management-certificate digest, exact owner/modes, enabled and active units, configured IPv4/IPv6 tunnel addresses and peer routes, live WireGuard key/port, both public transport ports, isolated nftables filter/NAT tables, forwarding, private DNS listener, private management listener, and original SSH session. Any failure invokes immediate rollback; interruption leaves the timer armed. Success may update the profile's public IPv6, Obfuscated UDP, and TCP fallback capability data but never changes the local secret or an existing server/device identity. If an existing server is already dual-stack but discovery no longer finds the required VPS route/address, repair stops before mutation instead of silently contracting it. No release lookup, artifact download, signing decision, general configuration migration, or VPS migration occurs in this slice.

## Local encrypted device backup

The core crate owns one interoperable backup path used by CLI and desktop. Export loads exactly one local profile and its separately stored device secret, validates the Ed25519 certificate/private-key binding and both WireGuard keys, then applies Argon2id v19 with fixed 64-MiB/three-pass/one-lane parameters and a random 16-byte salt. XChaCha20-Poly1305 encrypts the payload with a random 24-byte nonce and authenticates the canonical envelope header. Legacy schema 1 contains the profile and identity; schema 2 may additionally carry the Owner SSH port as encrypted recovery metadata; schema 3 is any payload whose identity carries a WireGuard preshared key, with or without that metadata. Current readers accept all three and reject a key-bearing identity labelled 1 or 2, while older readers reject newer schemas without mutation instead of dropping the key. The JSON envelope is limited to 256 KiB and exposes no server-specific metadata outside ciphertext.

Linux completes the bytes with directory fsync, mode 0600, and no replacement.

## Current-device key rotation

Rotation is a two-identity transition over the already connected private management plane. The client first validates its stored certificate/private-key and WireGuard private/public bindings, generates a completely fresh local identity, and stages two fresh secret references: a transitional identity combines the old WireGuard key with the new management private key, while the final identity contains both new private keys. A mode-0600 journal records only those references, the original profile, replacement public identity, persistent-protection and Automatic-fallback choices, random rotation ID, and phase.

The old authenticated device prepares that rotation on the VPS. Authorization retains the current device and peer unchanged while adding a ten-minute pending record. TLS trusts the pending certificate so possession of its new private key can commit or cancel the matching transition, but normal handlers still resolve only current device certificates and reject it. Preparation is idempotent for the same device/ID/public material, rejects duplicate identity material and recent enrollment receipts, and expiration simply removes the pending public state.

Before commit, the client durably marks the local transition ambiguous. It then opens mTLS with the new certificate through the still-working old WireGuard tunnel. Commit replaces both public identities on the same device record and uses the normal `wg`-first, authorization-write, old-peer-restore-on-write-failure transaction. The response may disappear when the old peer is removed, so the client never treats response loss as failure: it reconnects with the final identity and verifies the returned caller device ID and certificate fingerprint. If that fails, it retries the original identity; a confirmed old identity retains the journal for an idempotent retry, while an unconfirmed state retains both candidates and fails visibly. Only verified activation updates the profile, restores persistent protection, deletes the old/transitional secrets, and removes the journal.

## WireGuard preshared keys

A device generates its 256-bit preshared key next to its other private keys and keeps it in the same `SecretIdentity` record, so each platform's existing secret store and the encrypted device backup carry it. A device offers a key only where a lost response is already resolved by retrying the same request:

- **Invitation enrollment.** The pending enrollment stores the permanent identity, including a fresh key, before the first request, so retries offer the same key. The VPS stores it on the new device record and sets `preshared_key` in the result; a replayed request must offer the key that record already holds. If the result lacks that confirmation (an older VPS ignored the field), the client moves the identity without the key to a new secret reference before committing the profile, because stored references are immutable.
- **Key rotation.** When `/v1/configuration` advertises `preshared_keys_enabled`, the final staged identity gets a fresh key, sent in the prepare request beside the new public keys. The transitional identity keeps the original key because commit still travels through the original peer. Commit installs the new public key and the offered key together; a rotation that offers none leaves the new peer without one. The existing reconnect-and-verify recovery decides the outcome, as for the keys themselves. This is also how an existing device gains a key without re-enrolling.

Owner recovery and SSH provisioning never offer a key: older servers reject unknown recovery fields, and SSH key exchange is classical. Those devices, and devices enrolled before keys existed, gain a key at their first rotation, which every client offers rather than runs. `preshared_key_rotation_recommended` is true when the stored identity has no key and `/v1/configuration` advertises both `key_rotation_enabled` and `preshared_keys_enabled`. While connected with no pending rotation, the desktop and Android Home shows an Add preshared key prompt that opens the existing rotation dialog, and the CLI prints the `sirinvpn server rotate-keys` command after `connect` and in `status` (`preshared_key_rotation_recommended` in `status --json`). Rotation never starts by itself: it reconnects, can end in `RecoveryRequired`, which blocks ordinary connects until resumed, and retires the keys in any device backup exported before it.

The VPS keeps keys in authorization schema 6. After each peer batch, it reads `wg show <interface> preshared-keys` and runs one `wg set … preshared-key /dev/stdin` (or `/dev/null` to remove) per peer whose kernel key differs, so a key never appears in a process argument. The Linux helper applies the key with a second stdin `wg set` before the link comes up, the Windows service sets `WIREGUARD_PEER_HAS_PRESHARED_KEY` in the WireGuardNT peer, and the Android runtime adds a hex `preshared_key=` UAPI line that the wireguard-go bridge passes through staging, commit and endpoint updates unchanged. A `TunnelConnectRequest` carries the key as an optional field at any schema; helpers older than this change reject it through `deny_unknown_fields`.

## WireGuard-only devices

A device that cannot run SirinVPN, such as an iPhone, a Mac or a router with the official WireGuard app, joins through a standard WireGuard configuration instead of an invitation. The issuing Owner, Admin or delegated Member device generates the X25519 key pair and a preshared key locally and sends only the public key and preshared key to `POST /v1/wireguard-devices`, under the same authority rules as invitation creation: a new ordinary Member (with a policy no wider than a delegated issuer's) or an existing member the caller may manage or, with `add_own_devices`, its own. The VPS allocates a member address and stores an ordinary device record without a management certificate. The issuer renders the configuration (device address and derived IPv6 address, preshared key, profile endpoint and server public key, `10.77.0.1` as DNS, `AllowedIPs = 0.0.0.0/0, ::/0`) and shows it once: a locally rendered QR code and, when chosen, a mode-0600 no-clobber file. The private key is never stored or sent to the VPS. A lost response leaves a device the manager can revoke.

The device gets Direct UDP access only. With no certificate it is absent from the mTLS trust store and can never call the management API, and the UDP/TCP/TLS relays leave its key out of their authorized peer set. Everything else is the existing lifecycle: rename, peer permission, port forwards, suspension, schedules, device limits, revocation and member removal, and Owner recovery removes it together with the other Owner devices. It cannot rotate keys or follow a signed endpoint update, so a lost file or a new endpoint means revoking it and adding it again. It never counts as an Owner device: the last managed Owner device cannot be revoked beside it, and ownership cannot move to it. A record without a certificate must carry a preshared key and moves the document to authorization schema 7, which earlier readers reject; the installer's repair, uninstall, backup and update preflights read schemas 1–7 and never match such a record as the Owner. See [WireGuard-only devices](wireguard-devices.md).

## Subnet routes

The Owner can assign up to 16 canonical private IPv4 ranges of at most a `/20`, across the server, to the Owner's own devices (`PUT /v1/devices/{id}/subnet-routes`). They live on the device record and move the authorization document to schema 8. A range is live while its device is active and allows mutual access; the VPS then adds it to that peer's AllowedIPs and as a `proto static` kernel route on `sirinvpn0`, and admits it in the runtime `port_forward` chain only from the `peer_communication4` set. A tunnel-source guard in the server's `inet sirinvpn_handoff` table, which survives server stop and firewall reloads, limits any `sirinvpn0` source outside `10.77.0.0/23` to answers back into the tunnel. A range whose kernel route collides with another VPS route stays inactive, is retried every 10 seconds and is listed as inactive in membership snapshots. Each device reads its own live ranges and the ranges it may reach from `/v1/status` and caches them in its profile. On Linux, a router forwards and masquerades the ranges it shares and keeps them on its own network; every platform tunnels the ranges it reaches ahead of Allow local network (on Linux, the helper's own marked sockets keep the physical link for them). Windows and Android only consume. See [Subnet routes](subnet-routes.md).

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
upgrade, masks client frames and answers ordinary web requests with nginx's stock
404/400 pages. A generated or explicitly imported matching certificate is pinned;
renewal cannot silently change that pin. Without an HTTPS name, clients connect by
address and send no TLS name (SNI), so there is no fixed name to match. A new TLS
identity on a server with a public endpoint, which every installer-provisioned server
has, gets its own self-signed certificate: a random P-256 key and serial, the name
`localhost` and ten years of validity from its creation. It is stored like an imported
HTTPS certificate, travels in VPS backups and marks server configuration schema 9.
Servers installed earlier keep their derived Ed25519 certificate for `www.example.com`,
because every existing pin depends on it; TLS 1.3 hides it from passive observers, but
an active probe can read it. Turning HTTPS off later gives such a server a generated
certificate too. Browser-identical fingerprints and universal censorship resistance
are not claimed. Opt-in [CDN mode](https-transport-2026-09-06.md#cdn-mode) sends
only the HTTPS transport through a CDN under the Owner's domain when the VPS
address is blocked: the device resolves the signed hostname outside the tunnel,
verifies the CDN's WebPKI certificate instead of the origin pin, and still
authenticates the server with Noise IK. Such a server uses configuration schema
10, which older servers cannot read. [Signed endpoint
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
scope. HTTPS through a CDN gets no wider exception: the helper resolves the signed
hostname through the same scoped endpoint DNS, and only marked carrier sockets may
reach that one CDN address, on the HTTPS port. A failed apply or uncertain cleanup never becomes a healthy connection.
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

Opt-in [DNS blocking](dns-blocking.md) adds one generated `local-zone` include.
Managers store the policy in the authorization document through
`/v1/dns-blocklist`; the unprivileged daemon cannot touch Unbound. A sandboxed
root task, started by a path unit on that document and a daily timer,
downloads lists as the non-login update-fetch account, parses and bounds them,
swaps the zone file atomically and runs `unbound-control reload` after
checking the configuration as the `unbound` user. Any failure keeps the last
good file and is reported in diagnostics. No query or refresh history exists.

## Leak test

Run diagnostics also runs an on-demand leak test while connected. It uses only
the user's own VPS and reports pass, fail or not applicable for IPv4, IPv6 and
DNS. The VPS keeps no per-check state: nothing is stored, counted or logged, so
there is nothing to bound or expire.

- **IPv4 and IPv6.** The client sends one pinned mTLS request to
  `GET /v1/leak-test` at a documentation address, `192.0.2.77:8443` or
  `[2001:db8::77]:8443`, without binding its tunnel address, so the operating
  system's own route decides the path. The daemon adds `leak_test_prerouting`
  and `leak_test_input` chains to its runtime `sirinvpn_measurement` table:
  traffic arriving on `sirinvpn0` for those addresses is redirected to the
  private management listener (`10.77.0.1:8443`, or a second listener on the
  server's private IPv6 address when the IPv6 tunnel is on). Sent anywhere else,
  the public internet drops documentation addresses and the VPS never sees the
  request. TLS checks the pinned certificate by its `sirinvpn.local` name, so a
  network that answers those addresses cannot fake a pass. The handler returns
  only the TCP source address of that same request; the client passes the family
  when it equals the device's tunnel address. If the request does not arrive, a
  UDP socket connected to the same address (which sends nothing) shows whether
  the system routes that family outside the VPN, and the failure says so without
  printing the local address.
- **IPv6 without an IPv6 tunnel.** The VPS cannot observe IPv6. The family is not
  applicable when the device has no IPv6 route or the kill switch reports IPv6
  blocked, and fails when an IPv6 route exists outside the VPN without that block.
- **DNS.** The client resolves `<random>.resolver-check.internal` through the
  system resolver. The installer's `sirinvpn-leak-test.conf` Unbound include
  answers every name in that private-use zone with `10.77.0.1`; no public
  resolver answers it, so only an answer from the VPS resolver passes. Private
  records, split zones and blocklists cannot claim that zone. The check proves the
  system's answer came from the VPS; it cannot see an extra copy the operating
  system also sends to another resolver, which the kill switch blocks.

Selected subnets and applications leave other traffic outside the VPN by design,
so those families are not applicable instead of sending a test request to the
normal network. `/v1/configuration` advertises `leak_test_enabled` only when the
redirect rules applied and the Unbound include exists; an older or partly updated
VPS reports every family as not applicable until repair. Android appends the same
checks to its VPS report. It reads the routing mode from the preferences the active
tunnel was requested with, and IPv6 state from the profile, as the tunnel itself
does. The test runs in the `:vpn` process, which is inside its own VPN: the app
never excludes itself, and selected-application routing adds it. Its sockets
without `protect()` therefore follow the VPN routes, and its system lookups use the
VPN's DNS server, as the app-UID DNS and routing emulator tests show.

## Speed test

The Owner or an Admin can measure throughput through the tunnel to their own VPS
from the CLI (`sirinvpn speed-test`), the desktop or Android diagnostics dialog.
It is labeled as tunnel-to-VPS throughput over one TCP connection, not internet
speed, and no third-party server is involved.

- **Client.** After five idle timings of `GET /v1/speed-test/latency`, it reads
  `GET /v1/speed-test/download` for eight seconds, then streams generated zeros to
  `POST /v1/speed-test/upload` for eight seconds; each direction also stops at
  1 GiB, so a faster link finishes sooner. Rates start once the transfer
  connection is ready; the upload rate uses the byte count the VPS returns. A
  second management connection times small requests every 250 ms during each
  transfer, so the medians show latency under load. The result is returned to the
  caller and kept nowhere.
- **VPS.** All three routes sit on the private, pinned-mTLS management listener
  and require a manager. One transfer runs at a time on the VPS; a device may
  replace its own, because its download connection can outlive the switch to
  upload. A stalled client holds the slot for at most 15 seconds. Each transfer
  ends after 15 seconds or 1 GiB, and each device waits 60 seconds between
  transfers in the same direction. Upload bytes are counted and discarded; the
  router's 64 KiB limit covers only parsed bodies. Nothing is logged: the daemon
  keeps the running transfer and each device's last start time in memory for one
  cooldown, and a restart clears them.
- **Why managers only.** A test fills the VPS link for everyone for up to about
  20 seconds and runs in the management daemon. Owner and Admins already manage
  the server; a Member setting would need new authorization state for little gain.

## Management plane

The management client uses only the enrolled server certificate as its trust
store, installs aws-lc-rs as the process rustls provider so TLS 1.3 negotiates
hybrid X25519MLKEM768 with the VPS (earlier clients fell back to ring and plain
X25519), disallows redirects, referers, proxies, and implicit retries, and bounds
both declared and streamed response bodies to 1 MiB. The server caps concurrent
management sockets at 512, TLS handshakes and HTTP/1 headers at ten seconds, and
HTTP/2 streams at sixteen per connection. These resource limits reduce stalled
connection exposure; they are not a general denial-of-service guarantee.

The management daemon binds to the private tunnel endpoint (default `10.77.0.1:8443`); it is not exposed on the VPS public address. Its self-signed, `serverAuth`-limited certificate is pinned in every local profile. The server dynamically trusts only current device certificates plus unexpired temporary invitation certificates and requires one during the TLS 1.3 handshake. Every handler rechecks current authorization, so revocation also closes the authorization window for already-open TLS connections.

The read endpoints expose current status, diagnostics, and configuration to authorized devices, including the configured DNS upstream, private-record set, peer-isolation/port-forward capabilities, each device's current peer permission, and the current exact port-forward set for managers. Status includes the authenticated caller's live role, device ID, and current certificate fingerprint so a promoted, demoted, transferred, or rotated device does not rely on stale local bindings. It also reads aggregate CPU/memory state and SirinVPN-interface byte totals from procfs. A daemon-wide sampler keeps exactly one prior snapshot in RAM and accepts deltas only between 250 milliseconds and 30 seconds, so the optional CPU and rate fields remain absent for an initial, reset, too-fast, or stale sample. The desktop schedules the next poll four seconds after the previous one completes and measures that private status request locally as control-plane latency. Manual refreshes supersede older requests; late replies cannot restore an obsolete server snapshot. No metric, DNS-query, or configuration history is created. Membership and mutation endpoints enforce the current role and explicitly delegated permissions; self-key-rotation is separately available to every current device. The Owner can manage every member/device and is the only role that can promote or demote Admins or transfer ownership. An Admin can create/cancel ordinary Member invitations and rename, revoke, change peer permission, or direct a public port to ordinary Member devices, but cannot manage the Owner or another Admin. A Member can change only their own permitted peer/forwarding scope when explicitly delegated. The last Owner device is protected. Ownership transfer names an existing destination device, is re-authorized under the same write lock as the transition, rejects active/recent additional-device enrollment for either affected member, promotes the destination member and all of its devices, and retains the former Owner as an Admin in one atomic authorization replacement. The enrollment endpoint accepts only the temporary identity bound into an active invitation or its short retry receipt. The daemon validates all keys, addresses, and ports before applying exact `wg set` peer arguments or replacing the exact nftables set/chain contents. An authorization transaction synchronizes WireGuard, peer-isolation, and port-forward runtime state before atomically replacing the document, restoring every previous runtime component if persistence fails. It cannot read the root-owned WireGuard private key or modify root-owned network scripts.

## Invitation and enrollment path

An authorized Owner/Admin or explicitly delegated Member device generates a random bearer token and temporary bootstrap WireGuard/mTLS identity locally. It sends only their public material and the token hash through the private API. The VPS allocates addresses and signs the canonical invitation claims with its pinned Ed25519 management key. The long code contains the signed claims, raw token, and temporary bootstrap secret; it contains no permanent device private key. The desktop can also Deflate and base64url-encode that same bounded invitation as a locally rendered QR payload. Both representations are bearer secrets and no QR or invitation service is contacted.

The recipient verifies the signature, server binding, expiration, token hash, bootstrap key bindings, and optional existing-member/access binding before changing the network. It then opens a transient bootstrap tunnel, generates a fresh permanent identity locally, and submits only that permanent public material plus the device's new WireGuard preshared key to the VPS. A new-member redemption atomically adds the member and first device; an additional-device redemption attaches the new device identity to the signed existing member without copying an existing private key. Single-use redemption consumes the invitation; reusable redemption decrements its bounded remaining uses and assigns independent permanent identities. Short exact-request receipts resolve lost responses without consuming another use. Current issuer scope, member/device limits and expiry are revalidated at redemption. Expiration, cancellation, and revocation of a just-enrolled device remove the corresponding temporary access.

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
