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
- Never the tunnel ranges `10.77.0.0/24` and `10.77.1.0/24` (so not
  `10.0.0.0/8` either), never a default route, and no overlap with another
  route on the same server.
- At most 16 routes per server.
- The VPS refuses a network it already routes through another interface (a
  provider's private network, a Docker bridge), so it never takes over or hides
  one. If such a route appears later, the shared range stays inactive until it
  is gone; other changes keep working.

## Who can reach the network

The existing mutual-access permission decides, with no second permission: a
device reaches the LAN while both it and the router allow mutual access. The
LAN hosts can answer but never start connections into SirinVPN, and their
traffic cannot leave through the VPS to the internet. Turning off the router's
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
- **VPS.** A live route (active device, mutual access, not a migrated source)
  is added to the router peer's WireGuard AllowedIPs and as a kernel route
  `dev sirinvpn0 proto static`. The forward rules live in the runtime chain
  `inet sirinvpn_filter port_forward`, which every installed forward chain
  already jumps to before peer isolation, so a binary update is enough:

  ```nft
  iifname "sirinvpn0" oifname "sirinvpn0" ip saddr @peer_communication4 ip daddr { <ranges> } accept
  iifname "sirinvpn0" oifname "sirinvpn0" ip saddr { <ranges> } ip daddr @peer_communication4 ct state established,related accept
  iifname "sirinvpn0" ip saddr { <ranges> } drop
  ```

  Stopping the server flushes that chain (`firewall.sh isolate-runtime`). On a
  VPS with Docker, run **Repair** once after updating: the new firewall script
  adds a `DOCKER-USER` accept for `sirinvpn0` to `sirinvpn0`, behind the
  SirinVPN chains that already dropped everything else.
- **Clients.** `TunnelConnectRequest.subnet_routes` carries `announced` (Linux
  only) and `reachable` ranges. It is optional at every schema; helpers before
  protocol 20 reject it through `deny_unknown_fields`. The Linux helper adds
  `ip rule` entries at priority 9989 (ranges it shares to `main`, ranges it
  reaches to table 51820) and deletes every rule at that priority on cleanup.

## Rollback

An older VPS release cannot read schema 8, and the updater refuses that
rollback. Remove every route first, then roll back.

## Evidence (2026-11-01)

- Unit tests: route validation (canonical form, private ranges, tunnel and
  default overlap, overlaps, bound), schema 8 and serialization, Owner-only
  assignment and handler errors, live/reachable routes under peer permission,
  suspension, transfer and revocation, AllowedIPs, kernel-route diffing, VPS
  route conflicts, nft rules, Linux guard/NAT/rules/AllowedIPs, Windows routes
  and WFP, the desktop dialog and menu.
- Kernel lab, VPS side (`tests/network/run-member-lifecycle.sh
  kernel_subnet_routes_reach_a_router_lan_only_from_peer_enabled_devices`): a
  real WireGuard VPS with the installer's forward chain and the production
  handlers. The peer-enabled device reaches the LAN host; an isolated device
  does not; the LAN host can neither reach a peer nor the internet through the
  VPS; a range the VPS routes elsewhere is refused, and one that appears later
  leaves the range inactive while other commits succeed; turning off the
  router's mutual access and revoking it remove the route. Removing the LAN-source drop
  rule makes the test fail.
- Kernel lab, router side (`tests/network/run-policy-kernel.sh
  kernel_subnet_router_forwards_its_lan_and_keeps_reaching_it`): the production
  Linux helper as a full-tunnel router with the kill switch. It reaches its own
  LAN, a peer reaches that LAN through it, and disconnect removes the rules and
  NAT. Removing the forward accept makes the test fail.
- Android clippy for `x86_64-linux-android`; Windows cross clippy
  (`scripts/check-windows-cross.py --tests --clippy`).
- Not verified: the two-VM lab step "Owner shares a LAN behind this device
  through the CLI" (`tests/vm/linux_acceptance.py`), which also covers the
  hardened VPS service unit running `ip route`. Both runs on 2026-11-01 timed
  out installing the client guest's Debian packages, before any SirinVPN step.
  Also not verified: Windows and Android on real devices, a real home router, a
  VPS with Docker, a host firewall on the router.
