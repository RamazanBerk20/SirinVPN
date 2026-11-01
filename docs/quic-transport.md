# QUIC transport

QUIC is a fifth transport for networks that block or throttle WireGuard and
unclassifiable UDP, such as some networks in Turkey, Russia and Iran. It runs on
UDP at the TCP/TLS port number (443 by default) and looks like HTTP/3 to deep
packet inspection: a standard QUIC version 1 connection with TLS 1.3 and the
`h3` application protocol.

## How it works

- **Camouflage, not trust.** QUIC's TLS 1.3 checks the same certificate pin as the
  TLS transport. On the first QUIC stream the device then runs a Noise IK exchange
  with the same server transport key and its own WireGuard key, under its own
  prologue (`SirinVPN QUIC transport v1`). The server forwards nothing until that
  exchange names a current authorized device, and the device trusts nothing until
  the server proves the pinned Noise key. Each connection gets one Noise attempt,
  as each TCP connection does, so a probe cannot buy key exchanges by opening
  streams. The existing replay cache, timestamp window, per-source probe budget (12
  per 10 seconds), global budget of 1,024 new connections per second, 1,024
  concurrent connections and three-second handshake deadline apply. Revocation
  closes a running connection within ten seconds.
- **Address validation and limits.** A new connection whose source address is not
  yet proven gets a QUIC Retry first, so spoofed packets cannot take connection
  slots or use up another address's probe budget. This costs one extra round trip.
  Until a device authenticates, the server buffers at most 4 KiB per stream, 16 KiB
  per connection and 128 KiB of datagrams, and accepts three unidirectional streams
  (an HTTP/3 control stream and two QPACK streams) and eight requests at a time. A
  device may hold four QUIC connections; a fifth replaces its oldest, so a carrier
  that stopped without closing (a killed process, a lost network) does not lock the
  device out until the 60-second idle timeout.
- **Datagrams.** WireGuard packets then travel as QUIC DATAGRAM frames (RFC 9221),
  one per packet, with a two-byte length and up to 64 bytes of padding when the
  packet leaves room. Loss and reordering stay end to end, so there is no
  TCP-over-TCP collapse. A packet that does not fit the current path is dropped,
  as Obfuscated UDP does.
- **MTU.** The tunnel MTU is 1,280 bytes. The first UDP payload is 1,352 bytes,
  enough for a full 1,280-byte tunnel packet. Path MTU discovery may raise it to
  1,452, so a manual MTU can go up to 1,380.
- **No CDN.** QUIC always goes to the VPS address. With CDN mode on it sends no
  name, because pairing the CDN name with the origin's address would reveal the
  origin. With HTTPS mode on (no CDN) it sends the HTTPS name as SNI, like a
  browser opening that site over HTTP/3. Otherwise it sends no name, like a
  client connecting to a bare address.
- **Probes.** A probe that completes the QUIC handshake meets an HTTP/3 server: it
  opens a control stream with a SETTINGS frame, and every request, including a
  failed or replayed Noise exchange, gets a 404 (`HEADERS` with QPACK `:status
  404`), after which the server stops reading the request with `H3_NO_ERROR`. Three
  seconds after the handshake, unless a device authenticated, the server sends a
  GOAWAY and closes the connection with `H3_NO_ERROR`. A probe over budget gets no
  answer at all.
- **Rust crates.** The carrier uses `quinn` 0.11 with `rustls` and the aws-lc-rs
  provider, the TLS stack the other transports already use. `quinn` was already in
  `Cargo.lock` through `reqwest`, so the lockfile gains no package; the transport
  crate now depends on it directly (without default features).

## Automatic order

| Network profile | Order |
|---|---|
| Automatic, Normal | Direct UDP, Obfuscated UDP, QUIC, TLS, TCP |
| Restricted | QUIC, Obfuscated UDP, TLS, TCP, Direct UDP |
| Extreme | TLS, QUIC, TCP, Obfuscated UDP, Direct UDP |

Protocol-allowlisting censors pass HTTP/3 more often than unclassifiable UDP, so
Restricted tries QUIC first. Extreme keeps TLS first, because some networks block
all QUIC. Session recovery may now hold five candidates instead of four. QUIC is
not part of the legacy persistent-reconnect bundle, which predates the TLS
transport too.

## Kill switch

QUIC is a UDP carrier like Obfuscated UDP:

- **Linux:** the guard admits only the marked carrier socket, to the VPS address
  on UDP at the TLS port number. The relay runs as
  `sirinvpn-transport@quic.service` on `127.0.0.1:51827`. Helper protocol 21.
- **Windows:** the WFP permit for the SYSTEM carrier names protocol 17 and the VPS
  address and port. The permit used to say TCP for every carrier except Direct and
  Obfuscated UDP; it now matches every kind explicitly.
- **Android:** the carrier socket is protected and bound to the underlying network
  before QUIC uses it.

## Servers

- **New installations** answer QUIC on UDP at the TCP/TLS port. Obfuscated UDP
  moves from UDP 443 to UDP 51821 by default, because two listeners cannot share
  one UDP port. The firewall gains `udp dport <TCP/TLS port> accept`, the network
  preflight checks that UDP port for other listeners, and installation checks the
  listener and the rule.
- **Existing servers** get QUIC only when the Owner asks for it. A repair that
  changes no transport (such as a DNS change), a CLI repair without transport
  options and a restore keep the server's ports and QUIC setting exactly. In the
  Repair transport form the Owner turns on "Answer QUIC (HTTP/3) on UDP"; for a
  server installed earlier, whose Obfuscated UDP is on UDP 443, this moves
  Obfuscated UDP to 51821 in the same form, before confirming. The CLI takes
  `--quic true` and moves a shared Obfuscated UDP port the same way, with a note.
  QUIC with Obfuscated UDP on the TCP/TLS port number is rejected. Repair publishes a
  new signed endpoint checkpoint, which devices pick up through catch-up or
  background discovery. Devices that have not caught up find QUIC on the old
  Obfuscated UDP port and fall through to the next transport. A signed release
  update replaces only the binary, so it does not open a UDP port or change the
  endpoint.
- The flag travels as `"quic": true` inside the signed TLS endpoint metadata. It is
  omitted when false, so existing profiles, checkpoints, invitations and recovery
  keys keep their bytes. Older apps verify signatures over re-serialized claims, so
  they reject checkpoints, invitations and recovery keys that carry the flag:
  update devices before repairing the server.
- A server with QUIC uses configuration schema 11, which older servers cannot read
  (they would drop the flag and then fail to verify their own signed endpoint).
  QUIC requires a public endpoint, which every installer-provisioned server has.
  Schema 11 may also carry a generated certificate or CDN mode. Member port forwards
  cannot use the QUIC UDP port.

## What QUIC does and does not hide

It helps against:

- protocol classifiers that pass QUIC/HTTP/3 on UDP 443 and block WireGuard,
  OpenVPN or unclassifiable UDP;
- WireGuard signatures: message types and the fixed handshake sizes (148, 92 and 64
  bytes) are inside QUIC encryption, and small packets are padded;
- simple active probes, which see an HTTP/3 server answering 404.

It does not:

- **Hide the ClientHello.** QUIC Initial packets are protected with keys derived
  from the visible connection ID, so any observer can decrypt them. The ClientHello
  shows the SNI (when sent), the `h3` ALPN and a TLS and QUIC transport-parameter
  fingerprint that belongs to rustls and quinn, not Chrome or Firefox. It also
  advertises DATAGRAM support. A censor that fingerprints QUIC clients, or blocks
  QUIC without SNI, can tell this connection apart from a browser.
- **Hide the certificate from probes.** A probe can read the server's generated
  self-signed or imported certificate, as with the TLS transport.
- **Imitate a specific web server.** The HTTP/3 behavior is minimal: an empty
  SETTINGS frame, a bare 404 without headers, and a connection that a probe cannot
  keep open: it always ends with GOAWAY three seconds after the handshake, although
  the transport parameters advertise a 60-second idle timeout. A probe that compares
  it with nginx, Caddy or Cloudflare can see the difference.
- **Resist traffic analysis.** One long-lived connection carries steady two-way
  traffic, 25-second keepalives and many near-MTU packets.
- **Get past networks that block QUIC.** Some networks block or throttle all QUIC
  to push browsers to TCP, and some read the decrypted Initial to filter by SNI.
  Automatic then falls through to TLS and TCP.
- **Get past an IP block.** QUIC goes to the VPS address. CDN mode covers only the
  HTTPS transport.

## Junk packets (AmneziaWG style): evaluated, not implemented

AmneziaWG changes WireGuard itself. It sends junk datagrams before each handshake,
adds junk prefixes to handshake messages and replaces the fixed message-type
headers. In SirinVPN:

- **Direct UDP** uses unmodified WireGuard: the Linux kernel module on the VPS and
  Linux clients, WireGuardNT on Windows, and the Go bridge on Android. Junk packets
  would need a patched WireGuard on every one of them. Direct UDP would then stop
  working with standard WireGuard (including WireGuard-only devices), and the VPS
  would lose kernel WireGuard. Not worth it: Obfuscated UDP and QUIC already remove
  the WireGuard signature.
- **Obfuscated UDP** has no WireGuard signature to hide: every datagram is Noise
  encrypted, with random-length padding. Junk datagrams would only add decoy
  traffic before a handshake. That works against heuristics that look at the first
  packets of a flow, such as "fully encrypted" or entropy checks, but a censor can
  adapt to it, and nothing here measures whether it helps on real networks.

**Follow-up:** add optional junk datagrams to Obfuscated UDP, measured on real
blocked networks before turning them on by default. Sketch: the client sends 1–5
random-length datagrams (40–1,200 bytes) before each Noise handshake. The server
drops them silently, as it already drops unparseable datagrams, without counting
them against the source's handshake budget, and the handshake length range widens.
This needs no schema or descriptor change if the server tolerates junk
unconditionally. A second follow-up is shaping QUIC's ClientHello and transport
parameters toward a common browser profile.

## Evidence

- `crates/transport/src/tcp/tests/quic_carrier.rs` uses real QUIC sockets. An
  authorized device round-trips a full 1,312-byte WireGuard packet at the 1,280
  MTU and a keepalive, and the server records the QUIC transport. An unknown device
  and a wrong certificate pin never become ready, and nothing reaches WireGuard. A
  probe sees `h3`, SETTINGS and a 404.
- Unit tests cover the Automatic orders, selection (relay port, MTU, pin, no CDN
  name), descriptor rejection of a shared UDP port, padding bounds, server
  configuration schema 11, installer firewall and verification output, the Linux
  guard rule and the Windows permit protocol.
- The two-VM lab (Debian 13 client and VPS, DNS over TLS to Quad9, HaGeZi Multi
  Light) passed all 32 checks on 1 November 2026 with package `6ca7f524…`
  (`.cache/linux-acceptance-quic-2026-11-01b`):
  - A fresh install wrote configuration schema 11 with QUIC on, moved Obfuscated
    UDP to 51821 and listened on UDP 443.
  - The per-transport loop connected over QUIC with the kill switch armed, exited
    at the VPS, resolved through the VPS and counted no DNS or IPv6 leaks, then
    disconnected cleanly.
  - With Direct, Obfuscated and QUIC UDP blocked (14 packets dropped), Automatic
    cleaned up each failed candidate and connected over TLS.
