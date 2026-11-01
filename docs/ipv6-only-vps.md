# IPv6-only VPS

SirinVPN installs on a VPS that has a global IPv6 address and no IPv4, such as
an IPv6-only plan that saves the cost of an IPv4 address.

## What changes on such a VPS

- **Discovery.** A VPS needs an IPv4 default route or an IPv6 default route
  with a `2000::/3` address; a multipath default route counts by its first
  next hop. Without IPv4, the IPv6 uplink becomes the external interface for
  every rule the installer writes; the IPv4 rules on it never match. IPv6
  inside the tunnel is always on, because it is the only way out. Repair on a
  VPS that has lost its IPv4 route keeps the installed IPv4 uplink instead of
  moving IPv4 forwarding to the IPv6 one.
- **Firewall.** As for IPv4, only replies come in from the IPv6 uplink to
  members; a new inbound IPv6 connection to a member's tunnel address is
  dropped.
- **Diagnostics.** The VPS routes check accepts an IPv6 default route only on
  an uplink with no IPv4 address, so a dual-stack VPS that lost its IPv4 route
  still reports the failure.
- **SSH and the endpoint.** Enter the VPS's IPv6 address as it is
  (`2a01:4f8:c0c:1::4`), or a hostname with an AAAA record. SSH, the public
  endpoint, every transport and the WireGuard `.conf` export already handle IPv6
  literals. The server listens on `[::]`, so all four transports answer over
  IPv6.
- **Devices.** A device connects only from a network with IPv6, or through a
  CDN: in HTTPS CDN mode the CDN has IPv4 addresses and reaches the IPv6-only
  origin itself. No client change was needed: the Linux and Windows kill
  switches already permit an IPv6 endpoint, its discovery port and the endpoint
  DNS servers per address family, and IPv6 neighbour and router discovery for
  the carrier; the Linux carrier keeps fwmark 51820 so it bypasses the tunnel's
  IPv6 routes. Android protects both the IPv4 and IPv6 WireGuard sockets and
  every relay socket from the VPN, and routes `::/0` into the tunnel.
- **DNS on the VPS.** The VPS resolves through DNS-over-TLS or DNS-over-HTTPS
  with IPv6 resolver addresses, for example `2620:fe::fe#dns.quad9.net`.
  Recursive resolution is refused: many authoritative nameservers have only
  IPv4 addresses, so names behind them would fail. Private split-DNS zones may
  keep IPv4 servers, since a subnet route can reach them.
- **Port forwards** stay IPv4-only, so they cannot receive traffic on such a
  VPS.

The network check before installation shows a note, `ipv6_only`, that states
these trade-offs.

## IPv4 websites: NAT64 is the Owner's choice

Members still need IPv4-only websites, which an IPv6-only VPS cannot reach
directly. SirinVPN supports NAT64 with DNS64, as an explicit Owner opt-in:

- The Owner enters a NAT64 prefix (a `/96`, such as the well-known
  `64:ff9b::/96`) in the setup screen, which offers the field only for a VPS
  without IPv4, or with **Repair → IPv4 websites through NAT64**, or
  `sirinvpn server install --nat64-prefix` / `server repair --nat64-prefix` /
  `--no-nat64`.
- The VPS's Unbound then runs `dns64` with that prefix: a name with only an A
  record gets a synthesized AAAA inside the prefix, and members reach it over
  the tunnel's IPv6, out of the VPS's IPv6 uplink, to the NAT64 gateway. A real
  AAAA always wins.
- A name whose IPv4 address is not global (RFC 1918, shared `100.64.0.0/10`,
  link-local, loopback, `0.0.0.0/8`) gets no AAAA: Unbound's `respip` module
  answers NODATA for any AAAA synthesized from those ranges. LAN names from a
  private split-DNS zone or the Owner's private records therefore stay on IPv4
  inside the tunnel, and the NAT64 operator never sees them.
- Without a prefix, nothing goes to a NAT64 service. IPv4 inside the tunnel
  fails at once with an unreachable error, so applications move to IPv6
  instead of waiting for a timeout, and IPv4-only websites do not work.

The prefix comes from the hosting provider, if it runs NAT64, or from a public
NAT64 service. Either way that operator sees the VPS's IPv6 address, the IPv4
destinations and ports members reach, timing and volume, and any unencrypted
content; `PRIVACY.md` lists it. SirinVPN does not choose or suggest an
operator.

Repair keeps the VPS's current choice unless the Owner sets or turns it off;
it reads the choice back from the `dns64-prefix` line of SirinVPN's Unbound
configuration. A VPS with IPv4 refuses a NAT64 prefix. A server backup does not
carry the choice, so after restoring onto an IPv6-only VPS run Repair to turn
NAT64 on again.

A backup restores only onto a VPS that can run its DNS settings, and restore
has no way to change them. A backup that uses recursive DNS, the default, or
IPv4 secure-DNS servers is refused on an IPv6-only VPS. Change the original
server's DNS to DNS-over-TLS or DNS-over-HTTPS with IPv6 resolver addresses
and export a new backup, or restore onto a VPS with IPv4.

### Why not the alternatives

- **Refusing IPv6-only VPSes** keeps IPv4 egress simple, but the point of the
  feature is to run on them.
- **IPv6-only egress without NAT64** stays available (leave the prefix empty),
  but on its own it fails a large share of the web, so the note names NAT64.
- **NAT64 or 464XLAT on the VPS itself** cannot work: the VPS has no IPv4 to
  translate to.
- **Detecting a provider's NAT64 automatically** (RFC 7050) would route
  members' traffic through a third party without an explicit choice.

## Limits

- Applications that connect to IPv4 literals, not names, cannot use DNS64.
- Members whose device validates DNSSEC itself see synthesized AAAA records as
  unsigned, as with any DNS64.
- The VPS's own downloads (packages, blocklists, signed updates) use its own
  resolver and network. A source without IPv6 needs NAT64 configured on the
  VPS itself, by its provider or Owner; the SirinVPN prefix applies to members.
- Only `/96` prefixes are accepted, which covers the well-known prefix and the
  public services.
- Unbound's own lookups do not use NAT64 (`do-nat64` would also translate the
  loopback DNS-over-HTTPS proxy and private split-DNS servers), which is why
  recursive DNS stays refused.
- Router advertisements: the installer turns on IPv6 forwarding, which makes
  the kernel ignore router advertisements unless `accept_ra=2`, so it sets
  that on the IPv6 uplink. systemd-networkd, used by the Debian 13 and Ubuntu
  24.04 cloud images, handles router advertisements itself and keeps doing so
  with forwarding on.

## Evidence (2026-11-01)

- Unit tests: discovery, compatibility and DNS policy on an IPv6-only VPS,
  NAT64 prefix validation, the generated nftables and Unbound configuration
  (`crates/installer/src/tests/ipv6_only.rs`), the `ipv6_only` preflight note,
  and the setup and Repair NAT64 fields (Vitest).
- `sh tests/network/run-ipv6-only.sh`: the installer's generated nftables and
  Unbound configuration on a VPS namespace without IPv4, a WireGuard member on
  an IPv6-only network, and an internet namespace with a DNS-over-TLS resolver,
  an IPv6 site and a stand-in NAT64 gateway. Unbound synthesizes AAAA only for
  the IPv4-only name with a global address, never for a private answer
  (`192.168.1.10`) or a private record (`10.1.2.3`); member IPv6 and
  NAT64-prefix traffic leaves masqueraded to the VPS's address; a new inbound
  IPv6 connection to a member is dropped; member IPv4 fails immediately.
- The same DNS64 and `respip` configuration on the distributions' own Unbound
  (Debian 13: 1.26.2, Ubuntu 24.04: 1.19.2, and 1.17.1): global IPv4-only
  names get a synthesized AAAA, while names with RFC 1918 and `100.64.0.0/10`
  addresses get NODATA, both fresh and from the cache. Without the
  `response-ip` lines, `192.168.1.10` became `64:ff9b::c0a8:10a`.
- Router advertisements after a reboot: Debian 13 and Ubuntu 24.04 cloud
  images in QEMU with only RA-configured IPv6 (`ipv4=off`), the installer's
  `90-sirinvpn.conf` applied and the VM rebooted. Both came back with an
  RA-learned default route (`proto ra`).
- `sh tests/network/run-policy-kernel.sh kernel_endpoint_ipv6_dns`: the
  production Linux helper connects to a real WireGuard peer over an IPv6
  endpoint with the kill switch, now also with IPv6 inside the tunnel: the
  marked carrier stays on the physical link while other IPv6 goes into the
  tunnel.
- Not run: a two-VM lab with an IPv6-only VPS guest. The lab's user-mode QEMU
  network needs the host's IPv6 for package downloads, and the test machine
  had none. A real NAT64 gateway and Windows/Android on an IPv6-only network
  were not exercised.
