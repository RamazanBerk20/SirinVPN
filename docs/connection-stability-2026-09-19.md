# Linux connection stability and automatic transport selection

The repeated mode changes came from voluntary quality comparisons: a healthy,
quiet tunnel was deleted so each candidate could be measured. The kill switch
correctly blocked traffic during those deliberately created gaps. Linux now
measures candidates with a different temporary WireGuard identity and changes
the active peer endpoint without recreating the application tunnel.

## Behavior

- An established connection is not replaced because it is idle, one probe fails,
  ICMP is filtered, or its last handshake is old. Recovery requires repeated
  failed checks spanning at least 15 seconds without authenticated receive or
  handshake progress. The private management TCP port supplies health evidence
  even when ICMP is unavailable. Physical-network loss pauses mode cycling.
  A long observation gap also discards old failure evidence after suspend/resume.
- Candidate quality measurements never move the active peer. Two comparisons
  must both improve delivery or the existing latency/jitter score, with no worse
  delivery. Optimization has a ten-minute cooldown. These measurements do not
  estimate download throughput or prove the presence of DPI.
- A new carrier is prepared before changing the current WireGuard endpoint.
  Interface identity, addresses, routes, DNS and application sockets survive a
  successful handoff. An unsuccessful optimization restores the previous
  endpoint and MTU once. Confirmed failure still follows the user's independent
  automatic-reconnect preference and existing bounded fallback/backoff.
  Handoffs verify that the kernel endpoint has settled; supervision corrects
  delayed old-carrier packets that attempt to roam it back afterward.
- Only marked privileged sockets can use the configured carrier ports on the
  current VPS. Keeping these narrowly scoped permissions allows the supervisor
  and candidate worker to operate concurrently without rewriting each other's
  firewall allowance. Unmarked IPv4, IPv6 and DNS traffic remain protected.
- Pending MTU/quality measurements run outside the operation lock and cannot
  publish after the session, transport, interface or observed network changes.
  Connection state is published before measurements. Initial traffic starts
  immediately, handshake observation uses 100 ms intervals while connecting,
  and the desktop refreshes promptly. Successful mode changes update the
  existing network-specific transport preference for future connects.
  Explicit connects restart supervision so a previous polling/backoff wait
  cannot add several seconds to publication of the new connection.

## Compatibility and private state

The Linux desktop uses `connect-managed` with helper protocol 17. Native recovery
and optimization continue after closing the app. The helper keeps the current
management identity in a root-only file, removes it on Disconnect, and uses it
only for the pinned private VPS management API.

The VPS advertises `isolated_measurement_enabled` and implements authenticated
`POST`/`DELETE /v1/measurements`. Each device can hold one temporary peer lease
for 120 seconds. Its address belongs to `10.77.1.0/24`; it can only send ICMP echo
to the private VPS address. It cannot access management, other services, peers,
or the internet. Leases are memory-only, bounded by active devices, and disappear
on restart or authorization loss. A conflicting server route disables this
optional capability without preventing normal VPN service.

Older servers retain stable recovery-only selection and current-path quality
readings. Isolated live comparisons require the kill switch to be enabled.
Windows live optimization is unchanged; shared types remain compatible.
Automatic sessions start with the lowest configured candidate MTU so existing
TCP sockets negotiate segments that fit every carrier. Manual transport mode
keeps its own MTU ceiling. A session opened by an older helper with a larger MTU
retains recovery-only behavior until reconnecting. The lower current MTU is
retained during a live handoff. New carriers use independent systemd instances under
`sirinvpn-transport@.service`; the helper installer and Debian bundle include it.

## Validation

The isolated packet test is runnable with:

```sh
SIRINVPN_SOAK_SECONDS=1800 sh tests/network/run-automatic-transport.sh
```

It runs real WireGuard and all four production carrier implementations, a real
VPS management API, authenticated leases, a continuing TCP stream, IPv4/DNS and
IPv6 UDP exchanges, and forced carrier blocking. It checks interface identity,
rollback, probe access restrictions and unencrypted underlay rejection. It also
benchmarks 20 repeat direct connections. The harness simulates systemd and
resolved commands; its timings do not include desktop startup or an OS
authorization prompt. Final results are recorded with the delivery artifacts.

No running workstation tunnel or VPS is changed by these tests. Applying the
client/helper update fixes disruptive selection with existing servers; enabling
live comparisons also requires the updated VPS executable. Use the application's
existing VPS maintenance workflow to install that executable separately.
