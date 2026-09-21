# VPS address and conflict preflight

Install, repair and restore inspect the VPS over its pinned, authenticated SSH
connection before replacing services or configuration. The same inspection is
available independently in desktop setup after host-key verification and through
`sirinvpn server add --preflight-only` with the usual SSH and transport options.
Inspection does not install software or change the VPS network.

The report includes the selected public VPN address, resolved endpoint IPs,
current assigned VPS addresses and exact required incoming UDP/TCP ports,
including the retained endpoint-discovery port during repair. It distinguishes
an assigned public endpoint from a private endpoint and a possible provider
NAT/proxy mapping. The latter is an inference, not proof of port forwarding:
SSH reachability cannot establish that VPN ports are forwarded. The user can
configure a separate public VPN hostname/address and transport ports.

Occupied public ports, SSH TCP collisions, conflicting private DNS/management
listeners, foreign ownership of `sirinvpn0`, and specific overlapping
`10.77.0.0/24` routes block installation with actionable errors. Existing owned
WireGuard and transport listeners remain eligible for repair. TCP and UDP
conflicts are evaluated separately. Wider overlapping private routes, other VPN
interfaces, active nftables tables, Docker/UFW/firewalld and existing dropping
firewall policies appear for review. SirinVPN preserves those configurations.
The normal installation transaction and exact service/listener checks still
handle failures or changes occurring after inspection.

No public-IP lookup service, external probe service, telemetry identifier or
history is involved. Address and listener observations remain in the current
operation's memory and returned report. Installation results expose the report
so provider-port/NAT requirements remain visible after successful setup.
The server still requires IPv4 Internet forwarding; clients support IPv6 outer
connections as described in the endpoint implementation record.

Focused validation: 25 installer unit tests passed; the isolated kernel preflight
test detected a real listener and overlapping route and proved inspection left
assigned addresses unchanged. The full desktop suite passed 121 tests; after
adding reports to completion screens, TypeScript and nine focused tests passed.
Workspace Clippy with warnings denied, privacy, source-size and diff checks
passed. No live VPS was used as a fixture.
