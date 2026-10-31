# WireGuard-only devices

iPhone, iPad, Mac and routers (OpenWrt, GL.iNet, FritzBox) can join a SirinVPN
server through the official WireGuard app or the router's built-in WireGuard
client. Such a device gets a standard `.conf` instead of an invitation.

## Who can add one

The same people who can invite: the Owner, an Admin (for ordinary Members), and
a Member whose policy allows inviting members (new members, with at most the
Member's own policy) or adding their own devices (to their own member).

- **Desktop:** **Devices → Add WireGuard device** creates a new member;
  **Add WireGuard device for …** in a device's menu adds one to that member.
  Choosing a file is optional; the QR code is always shown. The desktop shows
  the action only when the VPS advertises `wireguard_devices_enabled`.
- **CLI:**

  ```sh
  sirinvpn server add-wireguard-device <server> --member-name "Ayşe" --device-name "iPhone" --output iphone.conf --qr
  sirinvpn server add-wireguard-device <server> --member-id <id> --device-name "Router" --output router.conf
  ```

  `--policy-file` sets a new member's policy, as for `invite`. `--qr` prints
  the configuration as a terminal QR code (to stderr with `--json`).
- **Android:** not available yet. The Android runtime has no command for it,
  so the action is hidden there.

The configuration is shown once. SirinVPN never stores the private key or sends
it to the VPS. If the QR code or file is lost or shared, revoke the device and
add it again.

## What the configuration contains

```ini
[Interface]
PrivateKey = <generated on the issuing device>
Address = 10.77.0.9/32, <server IPv6 prefix>::9/128
DNS = 10.77.0.1

[Peer]
PublicKey = <VPS WireGuard key from the profile>
PresharedKey = <generated on the issuing device>
Endpoint = <profile endpoint>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

The IPv6 address appears only when the VPS has its IPv6 tunnel. `::/0` is
always routed into the tunnel so IPv6 traffic cannot bypass it. The resolver is
the VPS's, so private records, split DNS and [DNS blocking](dns-blocking.md)
apply. The suggested file name is at most 15 characters from
`[A-Za-z0-9_=+.-]`, because wg-quick uses it as the interface name.

## What the device can and cannot do

It is an ordinary device in the member list, marked **WireGuard app or router,
Direct UDP only**. Rename, peer communication, port forwards, suspension,
schedules, device limits, revocation and member removal work as for any device.

It has no management certificate, so it cannot open the management API and does
not appear in the VPS's mTLS trust store. The Obfuscated UDP, TCP and TLS relays
do not authorize its key. It cannot rotate its keys or follow a signed endpoint
update: after an endpoint change, revoke it and add it again. It never counts as
an Owner device, so the last SirinVPN Owner device cannot be revoked beside it
and ownership cannot be transferred to it. Owner recovery removes the Owner's
WireGuard-only devices together with the others.

## Storage

The VPS stores the device's public key, preshared key and address in the
authorization document. Any such device moves the document to schema 7, which
older SirinVPN servers reject instead of misreading; see
[the migration note](release-candidate.md#wireguard-only-device-migration).

## Verification (2026-10-31)

- `scripts/test.sh` passed: 531 Rust tests (19 ignored), 243 Vitest, 16 Python,
  privacy and shell checks.
- Unit tests for configuration rendering, response binding, file mode and
  no-clobber (`sirinvpn-core`), the schema-7 document rules, relay and trust
  exclusion and ownership limits (`sirinvpn-server`), handler permissions and
  input checks, the installer's schema range, and the desktop dialog and list.
- Disposable-container kernel test
  `kernel_wireguard_only_device_connects_with_its_exported_configuration_until_revoked`
  (run with `tests/network/run-member-lifecycle.sh <name>`): the handler adds the
  device, stock `wg-quick strip` and `wg setconf` apply the exported file, IPv4
  and IPv6 reach the VPS with the preshared key in the kernel, and revocation
  removes the peer and blocks the device.
- Not verified: the official iOS/macOS apps, routers, the desktop dialog against
  a real VPS, and Windows compilation of the desktop command.
