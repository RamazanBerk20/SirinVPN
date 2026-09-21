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
TCP and legacy TLS. Unknown or replayed identities receive the same 404 response
as an unknown path. Ordinary GET/HEAD requests to `/` receive a small static web
page. The server does not proxy requests to an external website or resolver.

Headers are limited to 8 KiB and 32 fields, with a three-second read deadline.
WebSocket frames/messages, write buffers and stream buffers are bounded. Existing
connection, per-device, per-IP and replay limits remain in force. Each WebSocket
binary message carries one existing authenticated, padded tunnel record.
Revocation and idle cleanup retain the existing transport behavior. No request,
destination or browsing history is recorded.

New HTTPS server configurations use schema 7. Imported certificate keys require
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

The implementation uses the [WebSocket protocol](https://www.rfc-editor.org/rfc/rfc6455.html)
through tokio-tungstenite, and [rustls certificate/key validation](https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html#method.with_single_cert).
