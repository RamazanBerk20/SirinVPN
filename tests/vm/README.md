# Disposable Linux acceptance

`startup_authorization.py` runs a focused single-VM regression for NetworkManager
probe exclusion, real Polkit grants (local/active account only), native startup,
delayed network readiness, reboot persistence and package-purge revocation. It
uses the existing disposable-guest implementation and requires the same tools
and resource limits below. Run it after compilation with a fresh output path:

```sh
systemd-run --user --scope --quiet \
  -p MemoryHigh=3G -p MemoryMax=4G -p MemorySwapMax=0 \
  -p CPUQuota=150% -p TasksMax=256 \
  python3 tests/vm/startup_authorization.py \
    --base .cache/debian-13-genericcloud-amd64.qcow2 \
    --package target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb \
    --output .cache/startup-authorization
```

The guest creates a local PAM login session for the Polkit checks. Initial grant
creation is performed by the guest administrator; no password dialog is automated.
The NetworkManager check verifies absence of probe activation events, rather than
rendering a desktop notification. All keys, grants and network mutations stay
inside the disposable guest.

`run-linux-acceptance.sh` runs the packaged CLI and helper against a fresh VPS
in two Debian 13 QEMU guests. It checks provisioning, pinned SSH, guest Polkit,
actual WireGuard traffic, all four transports, native DNS, DNS failure, IPv6
blocking, all four kill-switch/reconnect combinations, helper-supervisor restart,
process termination, automatic fallback, restart protection and removal. It also
opens the packaged desktop in guest-only Xvfb, closes its real window and verifies
that the tunnel remains connected. This covers window-close behavior, not the
full desktop workflow or a physical network or another OS.

The launcher requires an ordinary host user with KVM access, QEMU, xorriso,
OpenSSH, Python 3 and a systemd user session with cgroup v2 controllers. Supply a
Debian 13 generic-cloud qcow2 base and a built Debian package:

```sh
sh tests/vm/run-linux-acceptance.sh \
  --base .cache/debian-13-genericcloud-amd64.qcow2 \
  --package target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb \
  --output .cache/linux-acceptance
```

Use a new output directory for each run. An optional `--installer-tests PATH`
runs the installer library's isolated root staging regression in the VPS guest.
The executable must be built for a glibc version supported by that guest.

Both guests, their control process and the local test endpoints share a limit
of 4 GiB RAM, no swap and 150% CPU. Each guest has one virtual CPU. Run compilation
and this lab sequentially. The launcher refuses to run as host root or without
the resource limits. Host networking uses ordinary loopback sockets and QEMU
user networking; there are no host tunnel devices, bridges, firewall changes or
privileged networking containers.

Each guest gets fresh SSH and host keys, a unique fixture marker and a temporary
disk overlay. The host keys are pinned before SSH use. The test account has
passwordless sudo inside its guest. The client's test Polkit rule grants only
the installed SirinVPN helper action to that account. The QEMU guest-agent
channel permits observation during kill-switch blocking without exempting
management SSH from the product firewall.

The same synthetic HTTP destination reaches different QEMU guestfwd responders
from the client and the VPS. Each connection starts a bounded stdin/stdout HTTP
handler inside the lab's host cgroup. Responses identify the exit and this run. A
separate guest IPv6 responder establishes that physical IPv6 worked before
connecting. Guest nftables counters observe synthetic DNS and IPv6 probes after
the product's output filters; they do not collect packet payloads or browsing
history. Public HTTPS is also checked through the connected tunnel.

Automatic-fallback diagnostics also run a root-only observer in the synthetic
client VM for at most 180 seconds and 4 MiB of metadata. It records kernel packet
timestamps, interface, addresses/ports, TCP flags and payload size, available
socket ownership, firewall trace/rule events and allowlisted transport state.
It records no DNS question or payload. Firewall event timestamps are userspace
receive times, not exact kernel commit times. The strict packet-counter
assertion remains; failures retain the timeline for attribution.

The full run exercises that recorder; `--dns-attribution-only` stops after the
attribution controls. They use a known process sending
synthetic DNS before connection, throughout forced UDP fallback, and through a
narrowly scoped deliberate firewall exception. It verifies both real drops and
detection of a protected-interval escape. The exception is removed in cleanup.
This proves the recorder works and reproduces a counter-boundary false positive;
it cannot retrospectively attribute older counter-only observations.

`--upgrade-from /absolute/path/to/older.deb` provisions a synthetic profile using
that older development package first. It verifies an encrypted backup, cuts VM
power after unpacking the candidate but before configuration, retries package
configuration and compares profile/credential bytes. The candidate must restore
the old backup and repair the fixture VPS with its own payload before the normal
network tests run. This covers unbound development installations and one real
interruption boundary. It does not declare older signed manifests compatible.

Results and bounded setup/error logs remain in the output directory. Guest
disks and temporary keys are deleted on normal completion and handled failures.
For development, `--keep-failed-seconds 1800` retains failed fixtures for at most
30 minutes under the same resource limits. Creating `stop-fixtures` in that
run's output directory ends the diagnostic hold and cleans up. The temporary
`active-fixtures.json` identifies the owned guest-agent sockets and markers;
verify the guest marker before issuing diagnostic commands.

`run-kernel-acceptance.sh` separately runs the deferred installer, helper and
server library tests inside fresh containers in a single disposable VM. It
takes `--base`, `--image` (the saved `Dockerfile.kernel` image), `--artifacts`
(Cargo JSON records for the three test binaries built under `/workspace`) and
`--output`. Application routing runs with IPv6 forwarding both disabled and
enabled; server-policy cases use the forwarding settings installed on a VPS.
The guest's Docker privileges apply only to its kernel. After guest setup,
external networking is disabled for these kernel cases.
The 16 deferred tests produce 17 cases because application routing runs with both
IPv6 forwarding settings. The executable-staging regression gets an actual
`noexec` mount at `/run` inside its disposable guest container.

The complete kernel launcher also cuts power to its owned QEMU process with
SIGKILL after authorization forwarding, durable persistence and checkpoint
publication. A test-only worker pauses at each boundary; after boot, the production
recovery engine must reconstruct the expected authoritative document and every
modeled effect. These three cases verify real guest filesystem durability with
modeled network effects, separately from the 17 packet/kernel cases. Use
`--power-loss-only` to repeat just those boundaries; `--filter TEXT` selects only
matching kernel tests. Guest overlays and keys are removed after handled failures.
