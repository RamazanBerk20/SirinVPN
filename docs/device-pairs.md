# Device pairs

Devices are isolated from each other by default. The mutual-access switch on a
device ("peer communication") lets it reach every other device that has the
switch on too. A **pair** is narrower: it lets exactly two devices reach each
other, whatever their switches say.

- **Both ways:** either device may start connections to the other.
- **One way:** the first device may start connections; the second only answers
  them. It cannot start a connection to the first.

The switch keeps working as before, as "all my peers that have it on too".
Pairs add to it and never take access away.

## Who can pair

A pair opens both devices, so the caller needs the switch authority over each
of them, the same rule as for the switch itself:

- the **Owner** pairs any two devices;
- an **Admin** pairs devices of ordinary Members (not their own, another
  Admin's or the Owner's devices);
- a **Member** whose policy allows "manage own peer communication" pairs only
  their own devices.

Removing a pair needs the same authority. Members see the pairs that involve
their own devices, including pairs with devices they cannot otherwise see
(shown as "another member's device"), so they know who may reach them.

- **Desktop and Android:** **Devices → the device's menu → Device pairs**. The
  dialog lists the device's pairs, removes those the caller manages and adds a
  pair with one of the caller's manageable devices in a chosen direction. The
  device details list its pairs. The action appears when the VPS advertises
  `device_pairs_enabled`.
- **CLI:**

  ```sh
  sirinvpn server pair-devices <server> <device-id> <peer-device-id>             # both ways
  sirinvpn server pair-devices <server> <device-id> <peer-device-id> --one-way   # peer only answers
  sirinvpn server unpair-devices <server> <device-id> <peer-device-id>
  ```

  `sirinvpn server members` lists the pairs.
- **API:** `PUT /v1/device-pairs` with `{"device_id": …, "peer_device_id": …,
  "one_way": true}` adds the pair or replaces the one between the same two
  devices; `DELETE /v1/device-pairs/{device_id}/{peer_device_id}` removes it in
  either order. Both answer with the membership snapshot, whose `device_pairs`
  lists the current pairs.

## Rules

- One pair per two devices; setting it again in either order replaces it.
- A device cannot be paired with itself. At most 256 pairs per server.
- A pair is active while both devices' members are active (not suspended, and
  inside their schedule and expiry). Suspension keeps the pair for
  reactivation; it does nothing meanwhile.
- Revoking a device, or all of a member's devices, removes their pairs.
- Pairs are server policy like the switch, so they survive ownership transfer.
  The new Owner sees and can remove every pair.

## Pairs and subnet routes

A device that a pair lets start connections to a router (an Owner device that
shares [local networks](subnet-routes.md)) also reaches the router's LAN. So
does a device whose switch is on, when the router's switch is on too.

- `X ↔ Router` or `X → Router` (one way, X starts): X reaches the router and
  its LAN; LAN hosts only answer.
- `Router → X` (one way, the router starts): X can only answer the router and
  does not reach its LAN.
- A router with the switch off still shares its ranges with paired devices; a
  device with the switch on does not reach them through the switch alone.

Each device learns the ranges it may reach from `caller_subnet_routes` as
before, so a pair change takes effect on the consuming device when it next
connects.

## Implementation

- **Authorization.** `AuthorizationDocument.device_pairs` (`DevicePair {
  device_id, peer_device_id, one_way }`). Any pair moves the document to
  authorization schema 9, which older readers reject instead of dropping the
  pairs; removing the last pair returns it to the earlier schema.
  `release/state-compatibility.json` reads and writes 1–9; the installer's
  repair/uninstall/backup/update preflights and the client's VPS backup reader
  accept 1–9. Pairs are part of the authorization file, so encrypted VPS
  backups carry them and a restore brings them back.
- **VPS.** The rules live in the runtime chain `inet sirinvpn_filter
  port_forward`, which every installed forward chain jumps to before peer
  isolation drops tunnel-to-tunnel traffic, so a binary update is enough and no
  Repair is needed. One rule admits the flows that may start, one admits the
  answers of one-way pairs, and IPv6 gets the same two when the tunnel has it:

  ```nft
  iifname "sirinvpn0" oifname "sirinvpn0" ip saddr . ip daddr { <a> . <b>, <b> . <a>, <c> . <d> } accept
  iifname "sirinvpn0" oifname "sirinvpn0" ip saddr . ip daddr { <d> . <c> } ct state established,related accept
  ```

  A router's ranges are live while its switch is on or a pair lets another
  device start connections to it. The switch's LAN rule now names only the
  ranges of routers whose switch is on, and each router a pair opens gets its
  own two rules for exactly the paired starting devices:

  ```nft
  iifname "sirinvpn0" oifname "sirinvpn0" ip saddr { <x> } ip daddr { <router ranges> } accept
  iifname "sirinvpn0" oifname "sirinvpn0" ip saddr { <router ranges> } ip daddr { <x> } ct state established,related accept
  ```

  Removing a pair removes its rules in the same commit, so its established
  flows stop too. Stopping the server flushes the chain
  (`firewall.sh isolate-runtime`) and every pair closes with it. Suspension,
  schedules and expiry change the desired WireGuard peers, so the reconcile
  loop recommits and the rules follow.

## Rollback

An older VPS release cannot read schema 9, and the updater refuses that
rollback. Remove every pair first, then roll back.

## Evidence (2026-11-01)

- Unit tests: schema 9 and back, serialization, unknown and self pairs, one
  pair per two devices, the 256 bound, direction (`pair_permits`), live and
  reachable router ranges through pairs and the switch, suspension, ownership
  transfer, device and member revocation, exact nft rules for IPv4 and IPv6 and
  the router ranges, handler authority for Owner, Admin and Member with and
  without the permission, the member's snapshot filter, the desktop dialog,
  menu and device facts.
- Kernel lab (`tests/network/run-member-lifecycle.sh
  kernel_device_pairs_admit_paired_devices_and_one_way_answers`): a real
  WireGuard VPS with the installer's forward chain and the production handlers,
  every device's switch off. A Member pairs their own two devices and they
  reach each other both ways while an unpaired device reaches neither and
  neither reaches it; the Owner's one-way pair lets the Admin reach a Member
  device whose answers return, while that device cannot start a connection to
  the Admin; a one-way pair with an Owner router gives the starting device the
  router and its LAN, and nobody else, while the router and the LAN host cannot
  start connections to it; suspending that member closes the pair and the
  router's kernel route and reactivating restores them; flushing the runtime
  chain as on server stop closes pairs; unpairing in reverse order and revoking
  a device remove access. Admitting one-way answers as new connections makes
  the test fail (the answering device reaches the Admin).
- Not verified: a VPS with IPv6 tunnel addresses in the lab (the IPv6 rules
  are unit-tested only), Windows and Android on real devices, the two-VM lab.
