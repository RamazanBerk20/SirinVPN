# Subnet routes (local networks)

An Owner can let one of their own devices share its local network, such as a
home LAN `192.168.1.0/24`. The Owner's other devices, and any device allowed to
reach that device, then reach hosts on that LAN (a NAS, a printer, a camera)
through the VPS.

## Who can set it up

Only the Owner, and only on the Owner's own devices. Forwarding opens the
device's own network, so nobody can open another member's LAN. Moving
ownership clears every route; the new Owner decides again.

- **Desktop and Android:** **Devices → the device's menu → Local networks**.
  One network per line; an empty list stops sharing. The action appears when
  the VPS advertises `subnet_routes_enabled`.
- **CLI:**

  ```sh
  sirinvpn server set-subnet-routes <server> <device-id> --route 192.168.1.0/24
  sirinvpn server set-subnet-routes <server> <device-id>   # remove all routes
  ```

- **API:** `PUT /v1/devices/{device_id}/subnet-routes` with
  `{"routes": ["192.168.1.0/24"]}` replaces the device's list.

## Rules

- Canonical private IPv4 networks only: inside `10.0.0.0/8`, `172.16.0.0/12` or
  `192.168.0.0/16`, written as the network address (`192.168.1.0/24`, not
  `192.168.1.7/24`). IPv6 is not supported yet.
- At most a `/20` (4,096 addresses), which covers ordinary home and office
  LANs. A wider range such as `192.168.0.0/16` would override Allow local
  network on every device that reaches the router, sending its printer, NAS
  and router traffic to the Owner's LAN, and would add routes nobody chose in
  Selected routes mode.
- Never the tunnel ranges `10.77.0.0/24` and `10.77.1.0/24` (so not
  `10.0.0.0/8` either), never a default route, and no overlap with another
  route on the same server.
- At most 16 routes per server.
- The VPS refuses a network it already routes through another interface (a
  provider's private network, a Docker bridge), so it never takes over or hides
  one. If such a route appears later, the shared range stays inactive and other
  changes keep working. The VPS retries every 10 seconds while a range is
  inactive and restores it once the other route is gone; the Owner's device
  list (and `sirinvpn server members`) marks it as inactive meanwhile.

## Who can reach the network

The existing mutual-access permission decides: a device reaches the LAN while
both it and the router allow mutual access, or while a
[device pair](device-pairs.md) lets it start connections to the router. The
LAN hosts can answer but never start connections into SirinVPN, to devices or
to the VPS itself, and nothing they send leaves the VPS through any other
interface, also while the SirinVPN server is stopped. Turning off the router's
mutual access, revoking the router, or suspending a consuming member (or its
schedule window closing) stops the traffic when that policy is applied.
Revoking the router deletes its routes with its device record.

## The router device

A Linux device running SirinVPN (desktop app or CLI) in **Full tunnel** or
**Selected routes** mode forwards for its peers:

- traffic from the tunnel to the shared ranges is accepted and masqueraded, so
  LAN hosts see the router's LAN address and need no route back;
- the shared ranges stay on the router's own network: a rule ahead of the
  tunnel sends them to the main table, and the kill switch allows them, so the
  router keeps its own LAN under a full-tunnel kill switch;
- DNS stays protected: ordinary DNS and DoT to the LAN are still blocked;
- in Selected routes mode the tunnel range `10.77.0.0/24` is added to the
  router's WireGuard and routes, so forwarded peers' answers return.

The host must allow IPv4 forwarding once; SirinVPN never changes this host-wide
setting, because restoring it later could break Docker or other routers:

```sh
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/90-sirinvpn-router.conf
sudo sysctl --system
```

A host firewall (ufw, firewalld) may also need to allow forwarding from
`sirinvpn0` to the LAN interface.

Windows and Android devices cannot be routers; they only consume routes. A
**WireGuard-only** device (for example an OpenWrt router) can be a router: the
VPS side is the same, and the router forwards and masquerades with its own
settings.

## Consuming devices

Each device learns the ranges it may reach from `GET /v1/status`
(`caller_subnet_routes`) and caches them in its profile:

| Mode | Behavior |
| --- | --- |
| Full tunnel | Already sends everything to the VPS. With Allow local network on, the shared ranges still use the tunnel (Linux rules ahead of the local-network rules; Windows routes and a WFP block above the LAN permit; Android routes). |
| Selected routes | The shared ranges are added to the routes, WireGuard AllowedIPs and kill-switch protection. |
| Selected applications | Not routed; only the chosen applications use the tunnel, and they reach the ranges as part of it. |

**Overlap rule: the shared network wins.** On a consuming device the shared
ranges always go through the tunnel, even when the device's own local network
uses the same addresses and Allow local network is on. Hosts on the overlapping
part of the local network are unreachable while connected. Give the shared LAN
a distinct range (for example `192.168.77.0/24`) to avoid this. The router's
own shared range always stays on its local network.

**When changes apply.** Routes reach a device through the tunnel, so a change
takes effect the next time each device connects. The desktop and Android app
refresh the cache with every status read; `sirinvpn connect` refreshes it right
after connecting and prints a hint when it changed.

## Implementation

- **Authorization.** `DeviceRecord.subnet_routes` (canonical, sorted). Any
  route moves the document to authorization schema 8, which older readers
  reject instead of silently dropping the routes; removing every route returns
  it to the earlier schema. `release/state-compatibility.json` reads and writes
  1–8; the installer's repair/uninstall/backup/update preflights and the
  client's VPS backup reader accept 1–8.
- **VPS.** A live route (active device, mutual access or a pair that lets
  another device start connections to it, not a migrated source)
  is added to the router peer's WireGuard AllowedIPs and as a kernel route
  `dev sirinvpn0 proto static`. The forward rules live in the runtime chain
  `inet sirinvpn_filter port_forward`, which every installed forward chain
  already jumps to before peer isolation, so a binary update is enough:

  ```nft
  iifname "sirinvpn0" oifname "sirinvpn0" ip saddr @peer_communication4 ip daddr { <ranges> } accept
  iifname "sirinvpn0" oifname "sirinvpn0" ip saddr { <ranges> } ip daddr @peer_communication4 ct state established,related accept
  ```

  Everything else from a LAN host is dropped by a tunnel-source guard that does
  not depend on the current ranges. The router peer's AllowedIPs admit LAN
  source addresses, so the guard confines any `sirinvpn0` source outside
  `10.77.0.0/23` to answers that go back into the tunnel, in the input and the
  forward hook:

  ```nft
  # inet sirinvpn_handoff, input (priority -31)
  iifname "sirinvpn0" ip saddr != 10.77.0.0/23 ct state != { established, related } drop
  # inet sirinvpn_handoff, forward (priority -31)
  iifname "sirinvpn0" ip saddr != 10.77.0.0/23 oifname != "sirinvpn0" drop
  iifname "sirinvpn0" ip saddr != 10.77.0.0/23 ct state != { established, related } drop
  ```

  It lives in the server's own `inet sirinvpn_handoff` table, which
  `sirinvpn-server network-guard` installs before WireGuard comes up and every
  commit refreshes. Neither `firewall.sh isolate-runtime` (server stop) nor a
  firewall reload touches that table, so the guard holds while the peer and its
  `proto static` route outlive a stopped server, and existing installations
  need no Repair for it. Base-chain drops are final, so it also covers Docker
  and anything else forwarding later. The `/23` keeps the latency probes
  (`10.77.1.0/24`) working.

  A failed kernel route add is remembered in memory. While any range is
  inactive, the reconcile loop retries every 10 seconds without an
  authorization change; with nothing inactive it costs nothing. Membership
  snapshots list such ranges in `inactive_subnet_routes`.

  Stopping the server flushes the runtime chain (`firewall.sh isolate-runtime`).
  On a VPS with Docker, run **Repair** once after updating: the new firewall
  script adds a `DOCKER-USER` accept for `sirinvpn0` to `sirinvpn0`, behind the
  SirinVPN chains that already dropped everything else.
- **Clients.** `TunnelConnectRequest.subnet_routes` carries `announced` (Linux
  only) and `reachable` ranges. It is optional at every schema; helpers before
  protocol 20 reject it through `deny_unknown_fields`. The Linux helper adds
  `ip rule` entries at priority 9989 (ranges it shares to `main`, ranges it
  reaches to table 51820) and deletes every rule at that priority on cleanup.
  Each reached range first gets `to <range> fwmark 51820 lookup main`, so the
  helper's own marked sockets keep the physical link: a resolver or the VPS
  endpoint inside a shared range (a member's home LAN `192.168.1.0/24` with its
  router `192.168.1.1` as DNS) is still reached directly to resolve and
  reconnect. `not fwmark` cannot express this: it inverts the whole rule,
  destination included. Rules at one priority match in insertion order.

## Rollback

An older VPS release cannot read schema 8, and the updater refuses that
rollback. Remove every route first, then roll back.

## Evidence (2026-11-01)

- Unit tests: route validation (canonical form, private ranges, the `/20`
  limit, tunnel and default overlap, overlaps, bound), schema 8 and
  serialization, Owner-only assignment and handler errors, live/reachable routes
  under peer permission, suspension, transfer and revocation, AllowedIPs,
  kernel-route diffing, VPS route conflicts, nft rules, Linux guard/NAT/rules
  (the marked-socket rule ahead of each reached range)/AllowedIPs, Windows
  routes and WFP, the desktop dialog, menu and inactive-range fact.
- Kernel lab, VPS side (`tests/network/run-member-lifecycle.sh
  kernel_subnet_routes_reach_a_router_lan_only_from_peer_enabled_devices`): a
  real WireGuard VPS with the installer's forward chain and the production
  handlers and guard. The peer-enabled device reaches the LAN host; an isolated
  device does not; the LAN host reaches neither a peer, the VPS (`10.77.0.1`)
  nor the internet, also after the runtime chain and peer sets are flushed as
  on server stop; a range the VPS routes elsewhere is refused, and one that
  appears later leaves the range inactive while other commits succeed, shows
  up in the membership snapshot, and returns through the runtime retry once
  the other route is gone; turning off the router's mutual access and revoking
  it remove the route. Turning the tunnel-source guard's drops into accepts
  makes the test fail (the LAN host reaches the internet).
- Kernel lab, router side (`tests/network/run-policy-kernel.sh
  kernel_subnet_router_forwards_its_lan_and_keeps_reaching_it`): the production
  Linux helper as a full-tunnel router with the kill switch, also reaching
  another device's range that its own uplink routes. It reaches its own LAN, a
  peer reaches that LAN through it, the reached range uses the tunnel while
  marked sockets to it and to the endpoint use the uplink, and disconnect
  removes the rules and NAT. Removing the forward accept, or the marked-socket
  rule, makes the test fail.
- Android clippy for `x86_64-linux-android`; Windows cross clippy
  (`scripts/check-windows-cross.py --tests --clippy`), both before the review
  fixes; CI's Windows build passes with them.
- Two-VM lab (`tests/vm/linux_acceptance.py`, 2026-11-01, all 30 checks pass):
  the step "Owner shares a LAN behind this device through the CLI" runs the
  packaged CLI against a fresh Debian 13 VPS. The hardened VPS service adds the
  kernel route and AllowedIPs, the client reaches its LAN under the kill switch,
  the VPS reaches the LAN host through it, and removing the route stops that.
- Not verified: Windows and Android on real devices, a real home router, a VPS
  with Docker, a host firewall on the router.
