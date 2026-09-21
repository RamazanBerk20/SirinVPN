# Signed endpoints and IPv6 outer transport

Install, repair, CLI and desktop flows now accept configurable Direct UDP,
obfuscated UDP and shared TCP/TLS ports, a public VPN address, and up to three
alternate hostnames or IPv4/IPv6 addresses. All addresses must reach the same
server identity. Repair retains the original TLS port for authenticated
discovery when the data port changes.

Server initialization and repair publish signed endpoint checkpoints. Version 2
binds the server ID, WireGuard key, management certificate, transport identities,
complete previous/current descriptors and access fingerprint. Clients can
advance to any higher valid generation. Modified, stale, conflicting or
differently pinned checkpoints cannot replace a profile. Only the latest
checkpoint and current migration predecessor are retained.

The helper cycles addresses in a stable order, retains a cached address, and
refreshes DNS through marked, bounded sockets. DNS exchanges validate the
question/response binding and support IPv4/IPv6 UDP with TCP fallback. Guard
exceptions permit only marked transport, endpoint-control and configured DNS
traffic. IPv6 neighbor discovery has narrowly scoped rules. An IPv6 outer
transport can carry an IPv4 tunnel while IPv6 inside the tunnel is disabled.

Discovery uses TLS and pinned Noise IK authentication. Its replaceable outer
certificate permits renewal while the transport and signed management
identities remain pinned. VPN data still requires the exact certificate pin.
Discovery has separate protocol binding, replay protection, size/deadline limits
and generic unauthenticated cover responses. The retained discovery listener
does not relay VPN data.

Automatic reconnect enables background checks. Established sessions prefer a
quiet handoff interval, bounded by one minute after learning a checkpoint.
Paused sessions stay paused; established sessions with automatic reconnect
disabled make no background queries or offers. Explicit updates preserve
kill-switch, routing and MTU preferences, including when paused. Local device
keys, names and favorites remain intact.

An Owner can publish to the previous VPS through encrypted control while
connected to the destination. Publication verifies current Owner authority, the
signed predecessor and matching access state. The old source then serves only
migration control: an independent nftables guard blocks VPN input and forwarding
except private management. It is installed before WireGuard comes up on boot
and survives ordinary firewall replacement. Failed state writes restore the
earlier policy. A destination receiving its own checkpoint through an alias does
not become a handoff source. Old-VPS removal remains explicit.

Public-address observation examines only the VPS's current interface addresses.
It signs a change only when the old public literal was previously assigned
there and exactly one suitable same-family replacement exists. Private/NAT,
temporary, ambiguous and manually configured hostname cases do not infer a
public mapping. No external address service or history is involved. Clients
need a reachable known address, retained discovery endpoint, updated DNS record
or explicit signed code to discover a move.

Compatibility covers configuration 8, authorization 5, helper request 10, desired
connection 5, runtime 4, signed endpoint 2, invitation claims 3 and recovery
claims 2. Legacy endpoint version 1 retains sequential validation. Android
persistence and Windows networking are tracked separately.

Focused validation completed:

- Core 46, helper 71, server 64 and installer 20 unit tests passed. Release 33
  and transport 33 tests passed, including actual TLS/Noise discovery,
  publication, probe/replay rejection and IPv6 loopback exchanges.
- TypeScript checking and 11 focused desktop tests passed, including retention
  of the current session on an invalid checkpoint.
- The isolated kernel handoff test proved IPv4/IPv6 data blocking, management
  reachability, failed-write rollback and startup reconstruction.
- The complete isolated helper packet matrix passed. Atomic guard replacements
  observed zero leaks in 557,042 and 528,546 packet attempts. Marked IPv6
  endpoints and DNS worked while unmarked IPv4/IPv6/DNS were blocked. Real
  WireGuard over IPv6 carried IPv4 with kill switch enabled and disabled.
- Workspace Clippy with warnings denied, privacy, source-size and diff checks
  passed. Fixtures used disposable containers with no host/VPS routes. Release
  artifact and platform acceptance remain separate work.
