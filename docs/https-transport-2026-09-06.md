# HTTPS transport and port configuration

The TLS transport now supports an HTTPS WebSocket mode. Its public hostname and
path travel with the pinned TLS certificate and Noise server key in profiles,
signed invitations, recovery keys and endpoint updates. Legacy profiles retain
their existing TLS framing and certificate identity.

Setup and guarded VPS repair expose the Direct UDP port, Obfuscated UDP port, and
shared TCP/TLS port. The CLI exposes the same settings with `--wireguard-port`,
`--obfuscated-udp-port`, `--tcp-tls-port`, `--https-server-name`, and `--https-path`.
Private DNS/management ports and conflicting direct/wrapped ports are rejected.
The installer verifies the requested ports and preserves server/device keys.

HTTPS can use a generated pinned certificate for the chosen DNS hostname or a
certificate chain and matching private key already on the VPS. The optional CLI
flags are `--https-certificate-path` and `--https-private-key-path`. The app has
equivalent fields. Imports validate the DNS SAN, current certificate validity,
and key match. The daemon keeps a private copy, so an external certificate renewal
does not silently replace a client pin. An expired existing certificate does not
invalidate the separately pinned server identity; renewals should be imported
through the guarded update flow. `--disable-https` restores legacy TLS framing.

The HTTPS exchange uses a standard HTTP/1.1 WebSocket upgrade and masked client
frames. A Noise IK message in the Authorization header authenticates the device
before the server sends 101. The Noise prologue separates this exchange from raw
TCP and legacy TLS. Ordinary requests, unknown paths and unknown or replayed
identities all receive nginx's stock 404 page, and a malformed request its stock
400 page, with `Server: nginx` and a current `Date`. A probe sees an ordinary web
server rather than a page only SirinVPN serves. The server does not proxy
requests to an external website or resolver.

Headers are limited to 8 KiB and 32 fields, with a three-second read deadline.
WebSocket frames/messages, write buffers and stream buffers are bounded. Existing
connection, per-device, per-IP and replay limits remain in force. Each WebSocket
binary message carries one existing authenticated, padded tunnel record.
Revocation and idle cleanup retain the existing transport behavior. No request,
destination or browsing history is recorded.

New HTTPS server configurations use schema 7. A server with a public endpoint uses
schema 8, or 9 when it stores a generated certificate without HTTPS. Imported certificate keys require
server-backup snapshot schema 2. Linux helper protocol 14 advertises HTTPS support;
requests containing HTTPS metadata require schema 9 and saved desired state uses
schema 4. The app checks helper support before starting the connection. Existing
requests and snapshots remain readable.

Focused evidence on 6 September:

- Transport tests use real TLS sockets and WebSocket parsing. They check ordinary
  web responses, authorization before upgrade, replay rejection, Ping/Pong,
  rejection of unmasked frames and absence of unauthorized backend traffic.
- A simulated restrictive TCP edge rejects raw TCP and requires the configured
  TLS SNI. HTTPS transports 32-, 1,280- and 1,472-byte UDP payloads in both directions.
- Server tests change ports, generate/import a named certificate, reject a
  mismatched hostname before key mutation, preserve server keys, and round-trip
  the imported certificate through an encrypted VPS backup and restore.
- A helper test covers fallback metadata, restart persistence and rejection of
  downgraded request/state schemas. UI tests cover port collisions, reserved ports,
  hostname/path validation and paired certificate paths.

This establishes HTTPS protocol behavior and the simulated edge case. It does
not establish a browser-identical TLS fingerprint or universal censorship
resistance. Actual network and platform qualification belongs to the final
acceptance run. Alternate endpoints, signed automatic publication and catch-up
are tracked separately in the remaining implementation checklist.

## CDN mode

CDN mode is for when the VPS address itself is blocked. It is off by default and
set per server: setup and repair have a "Reach HTTPS through a CDN" option, and
the CLI takes `--https-cdn true` or `--https-cdn false` beside
`--https-server-name`. The flag travels in the signed endpoint descriptor
(`"cdn": true` inside the HTTPS settings). It is omitted when off, so existing
profiles and checkpoints keep their exact bytes. A server with CDN mode on uses
configuration schema 10. It needs a public endpoint, and the HTTPS hostname must
differ from the public and alternate addresses, which devices reach directly:
otherwise every transport, and publication to an old server, would reach the CDN.
Repair, the CLI and the app reject such a name. The CLI and the app also warn about
a TCP/TLS port that Cloudflare does not proxy, and the CLI warns when
`--https-server-name` without `--https-cdn true` turns CDN mode off.

With CDN mode on, only the HTTPS transport changes, and only on devices:

- The device resolves the HTTPS hostname with the network's normal DNS, outside
  the tunnel, and connects to that address. On Linux and Windows the privileged
  helper or service does this through the same scoped DNS exceptions it uses for
  endpoint names and keeps one address, IPv4 first; an app-supplied address is
  discarded, and a failed lookup keeps the last address only while the signed
  name is unchanged. Android, which has no separate privileged service, resolves
  the name in its VPN service on the underlying network. Direct UDP, Obfuscated UDP and raw TCP still go to the
  VPS address, so Automatic falls through to the CDN when that address is blocked.
- TLS is verified against the operating system's WebPKI roots and the hostname
  (rustls-native-certs; Android's Conscrypt or system CA directory) instead of the
  origin pin, because the device now meets the CDN's certificate. The hostname is
  sent as SNI and as the HTTP `Host`, as it already was in HTTPS mode.
- Noise IK inside the WebSocket still authenticates the server's static key and
  encrypts every tunnel record end to end. A CDN, a certificate authority or a
  network that installs its own root can carry or refuse the connection, but cannot
  impersonate the server or read the tunnel.
- The kill switch admits only the carrier to that one CDN address on the HTTPS
  port: on Linux a rule for marked carrier sockets, on Windows a permit for the
  service's SYSTEM carrier to that address and port, on Android the carrier's
  protected socket. Nothing else gains a path to the CDN. Every Linux path that
  starts a carrier, live transport handoff included, sends HTTPS through a CDN to
  that address, and while a session runs through the CDN the guard keeps no
  discovery exception for the VPS. Windows adds no host route for a CDN address,
  because it is shared anycast and a route would take every other site on it out
  of the tunnel; the carrier connects before tunnel routes exist and its socket
  stays on the physical interface through `IP_UNICAST_IF`.
- Background endpoint discovery follows the current transport: while the session
  runs through the CDN, the checkpoint request goes to the CDN address on the
  HTTPS port, so the device never probes a VPS address that may be blocked or
  watched. Discovery during invitation and recovery also tries the hostname.
  Discovery to the CDN verifies its WebPKI certificate, like the transport, so a
  network that answers the name with a fake server never receives a SirinVPN
  request. Discovery at the VPS still accepts its replaceable certificate (Noise IK
  authenticates the response) and still uses the retained discovery port for
  devices that know only an older one. Owner publication to a previous VPS stays
  on that VPS's own address: a CDN hostname follows the current origin, so it
  would reach the new server, not the one being retired.

The VPS keeps serving its generated or imported certificate. The request headers a
CDN adds are ignored and never stored. Behind a CDN every connection comes from a
shared edge address that anyone can make connect, so the listener skips its
per-source probe budget (12 connections per 10 seconds), which would otherwise let
one client lock everyone out of that edge. The global budget of 1,024 new
connections per second, 1,024 concurrent connections, four connections per device
and the three-second handshake deadline still apply. A quiet
tunnel survives CDN idle timeouts (Cloudflare closes WebSockets after about 100
seconds without data) because every client already sets a 25-second WireGuard
persistent keepalive (Linux `wg set … persistent-keepalive 25`, Windows peer
keepalive 25, Android `persistent_keepalive_interval=25`), so a record crosses
the CDN at least every 25 seconds. The server's own 180-second idle cleanup is
unchanged.

### What the Owner configures

The steps below are for Cloudflare; other CDNs need the same four things: proxied
HTTPS for the hostname, WebSockets, TLS to the origin that accepts its certificate,
and no challenge pages.

1. Add the domain to Cloudflare and create an `A` (and `AAAA`, if the VPS has
   IPv6) record for the HTTPS hostname pointing at the VPS, with proxy status
   **Proxied**.
2. Set SSL/TLS encryption mode to **Full** for that hostname (a Configuration Rule
   can scope it). Full accepts the VPS's self-signed certificate. Use **Full
   (strict)** only after importing a publicly trusted or Cloudflare Origin CA
   certificate for the name.
3. Leave **WebSockets** on (Network settings; on by default).
4. Keep the TCP/TLS port on one Cloudflare proxies for HTTPS: 443 (the default),
   2053, 2083, 2087 or 2096. SirinVPN reserves 8443. Another port needs an Origin
   Rule that rewrites the destination port.
5. Exempt the hostname from challenges: no "I'm Under Attack" mode, and if devices
   get 403 responses, turn off Bot Fight Mode and Browser Integrity Check for it or
   add a WAF skip rule for the HTTPS path. The client is not a browser.
6. In SirinVPN, run repair (or setup) with HTTPS on, the same hostname and "Reach
   HTTPS through a CDN" checked. Devices learn the new signed checkpoint through
   discovery while the VPS is still reachable, or through an endpoint update code.

### Limits

- The CDN sees connection metadata: device IP addresses, connection times and
  duration, traffic volume, the hostname and path, and the upgrade request
  including the opaque Noise token. It never sees tunnel contents. See
  [PRIVACY.md](../PRIVACY.md).
- Without the per-source budget, a flood that reaches the VPS address directly is
  bounded only by the global limits above.
- The origin still answers anyone who reaches its address directly with the same
  nginx-style cover; restricting it to CDN address ranges is not done.
- Trust roots come from the operating system. A Debian package depends on
  `ca-certificates`. On Windows, rustls-native-certs reads the machine's root store
  as present; Windows adds some roots only on demand when its own APIs first need
  them, so a fresh installation may lack the CDN's root and CDN mode then fails
  closed until that root is installed (any HTTPS visit in a browser that uses the
  Windows store usually adds it). Bundling roots is not done.
- Not run on a real Windows client: the Windows changes have passed only the CI
  build and its tests.
- One CDN address is kept per lookup. A network that reaches the CDN only over the
  other IP family fails HTTPS until the next lookup returns a usable address.
- Older clients cannot read a descriptor with CDN mode on (`HttpsTransport` rejects
  unknown fields), so update devices first. Server configuration schema 10 is
  outside older servers' declared read range, so the signed VPS updater refuses to
  roll back to one until CDN mode is turned off.
- Linux helper protocol 19 adds the CDN address to the helper-owned part of the
  request. Apps leave it empty and the helper replaces it with its own lookup.

Evidence on 31 October: a simulated CDN edge terminates TLS with its own
certificate from a test root, checks the SNI, opens a new TLS connection to the
origin that accepts any certificate (as Cloudflare Full does), adds proxy headers
and forwards the WebSocket. The client carries 32-, 1,280- and 1,472-byte
payloads both ways, and the edge's plaintext view contains the upgrade request but
no tunnel packet. CDN mode refuses the pinned origin certificate, a WebPKI
certificate for another name and a valid edge with the wrong server Noise key.
Helper tests cover the CDN-address validation, the guard rule that admits only the
CDN address on the HTTPS port, the helper's own lookup replacing an app-supplied
address, the relay configuration, a live handoff to the CDN transport and
discovery following the transport. Transport tests show that one edge address is
not limited per source, and that discovery to a CDN address refuses the origin's
own certificate. Server tests cover schema 10, backup and a proxied name reused as
a direct endpoint. Real Cloudflare has not been tested yet.

The implementation uses the [WebSocket protocol](https://www.rfc-editor.org/rfc/rfc6455.html)
through tokio-tungstenite, and [rustls certificate/key validation](https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html#method.with_single_cert).
