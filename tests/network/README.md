# Isolated Linux policy test

`SIRINVPN_SOAK_SECONDS=1800 sh tests/network/run-automatic-transport.sh` runs
the four real carriers and an authenticated VPS in the same isolated lab. It
checks temporary measurement-peer isolation, retained TCP/UDP flows, the actual
WireGuard endpoint, rollback, live optimization and forced carrier failure.
Set `SIRINVPN_FAULT_ONE_WAY=1` to block only outgoing carrier packets. The test
also reports 20 repeat connection timings; systemd and resolved are simulated,
so these measurements exclude desktop startup and OS authorization prompts.

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

`run-installer-release-guards.sh` runs the installer release-staging guard in an
ordinary container with no network, added capabilities or privileged mode. It
caps compilation at 4 GiB and 1.5 CPU cores, then runs the root ownership checks
at 1 GiB and one core. The test proves that changed artifact bytes or VPS
receipt/signing-policy state cannot execute a candidate, and that replacing the
SSH user's source after verification cannot replace root's private staged copy.
It does not start systemd or touch workstation services.
