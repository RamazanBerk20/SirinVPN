# Isolated Linux policy test

`SIRINVPN_SOAK_SECONDS=1800 sh tests/network/run-automatic-transport.sh` runs
the four real carriers and an authenticated VPS in the same isolated lab. It
checks temporary measurement-peer isolation, retained TCP/UDP flows, the actual
WireGuard endpoint, rollback, live optimization and forced carrier failure.
Set `SIRINVPN_FAULT_ONE_WAY=1` to block only outgoing carrier packets. The test
also reports 20 repeat connection timings; systemd and resolved are simulated,
so these measurements exclude desktop startup and OS authorization prompts.

`sh tests/network/run-leak-test.sh` checks the leak-test redirect over a real
WireGuard link: from a full-tunnel member namespace, pinned requests to the IPv4
and IPv6 leak-test addresses must reach the in-process management server and
report the member's tunnel addresses.

Run `tests/network/run-policy-kernel.sh` from a Linux development host with
Docker, Python 3, and the workspace Cargo dependencies already fetched
(`cargo fetch --locked`). The script builds the Debian test image when needed.
Image construction downloads build dependencies; compilation and packet tests
run with `--network none`.

The test receives network administration capabilities only inside its disposable
container. It refuses to run outside Docker or with preexisting non-loopback
interfaces. It creates a private veth pair and peer namespace; no host interfaces,
VPS endpoints, or host firewall rules are changed. Do not substitute host networking
or run the ignored Rust test directly on a workstation.

The production guard builder is exercised against real nftables and IPv4/IPv6
packets, including DNS, LAN and selected-route exceptions, marked reconnect
traffic, malformed transactions, unrelated rules, and continuous packet traffic
during transport-rule replacement. The supervisor's four kill-switch/reconnect
combinations, failures, migration, pause/resume, and startup intent are tested
separately in `crates/linux-helper/src/tests/policy_tests.rs` using a mock runner.
This is not a full WireGuard handshake, live transport, or systemd reboot test.

`run-member-lifecycle.sh [test-name]` runs one ignored kernel test per
container, by default the member lifecycle test. Pass
`kernel_preshared_keys_gate_handshakes_and_keyless_peers_keep_working` to check
that the VPS applies device preshared keys: synthetic clients with the matching
key, a missing key, a different key and no key at all must handshake only where
the keys agree.

Pass `kernel_subnet_routes_reach_a_router_lan_only_from_peer_enabled_devices`
for subnet routes on the VPS: a real WireGuard VPS with the installer's forward
chain, a router namespace with a LAN host, two peers and an internet host. The
production handlers assign, refuse, disable and revoke routes while the probes
check that only the peer-enabled device reaches the LAN and that the LAN host
cannot reach peers or the internet.

`run-policy-kernel.sh kernel_subnet_router_forwards_its_lan_and_keeps_reaching_it`
runs the production Linux helper as a full-tunnel subnet router: it must reach
its own LAN under the kill switch, forward and masquerade a peer's traffic to
it, and remove its rules and NAT on disconnect.

`run-installer-release-guards.sh` runs the installer release-staging guard in an
ordinary container with no network, added capabilities or privileged mode. It
caps compilation at 8 GiB and four CPU cores, then runs the root ownership checks
at 1 GiB and one core. The test proves that changed artifact bytes or VPS
receipt/signing-policy state cannot execute a candidate, and that replacing the
SSH user's source after verification cannot replace root's private staged copy.
It does not start systemd or touch workstation services.
