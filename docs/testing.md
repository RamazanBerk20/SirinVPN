# Testing

The [26 September remediation ledger](remediation.md) is the current source of
qualification status. Results below are historical unless explicitly dated
otherwise; their local `target/` artifacts are not public downloads and do not
qualify a rebuilt candidate. The current dependency gate has unresolved findings.

Run `sh scripts/test.sh` with the pinned toolchain for shared checks and
`python3 scripts/check-workflows.py` for workflow validation. Missing required
tools fail these gates. `scripts/test-keyring.sh` creates a disposable Secret
Service container. `scripts/test-kernel.sh` uses the isolated Debian guest.
`scripts/test-android-emulator.py` owns a fresh AVD and separate ADB server;
it never selects a connected personal phone. `scripts/test-windows.ps1` requires
native Windows and distinguishes unit/build checks from privileged acceptance.
Wrap a check with `scripts/record-evidence.py --suite NAME --output
target/remediation-evidence -- COMMAND` to retain source identity and failures.

The [Linux acceptance report](linux-acceptance-2026-09-07.md) records 15 isolated
kernel cases and 22 packaged Debian CLI/helper checks, including fault injection,
reboot recovery and uninstall. It identifies the three product fixes and the
exact accepted Debian artifact. The [feature map](overhaul-feature-map.md) records
platform boundaries. The [current ledger](remediation.md) adds exact-package,
Samsung S25+ and native Windows results, with their remaining limitations.
Earlier results below belong to their
stated checkpoints and do not qualify subsequent changes.

Run one heavy task at a time using the [development resource limits](development.md#resource-limits).
The build containers have no privileged networking. Opt-in network, crash,
reboot and installation tests below are acceptance operations, not build steps.

## Local gate

Run the local gate and Linux container packaging sequentially: they share `target`
and the frontend output directory, and the container restores generated-file
ownership when it exits. ShellCheck, xmllint and the pinned package manager are
required; missing tools fail the gate.

The local gate includes two Python cleanup-regression tests, with twenty subcases
covering successful cleanup, failed status proofs, and individual leftover
interfaces/services/firewall tables. They run the integration script's actual
assertion with fake OS commands in both ordinary and conditional shell callers.
They never create a tunnel or modify the host firewall.
Two recorder tests cover command failure, timeout, missing tools, output bounds,
artifact binding and refusal to overwrite evidence. A fifth Python test exercises
VM setup rejection, interruption and shutdown/file-cleanup failures using fake
guests; it never launches QEMU.

Run:

```sh
./scripts/test.sh
```

The gate checks Rust formatting, Clippy with warnings denied, all default Rust tests, frontend tests, the production frontend build, privacy invariants, ShellCheck, XML syntax and local compatibility contracts. Ignored platform tests require their separate isolated fixtures.

The `sirinvpn-release` tests additionally generate ephemeral Ed25519 root/release keys, create canonical signed manifests and root policies, authenticate bounded artifacts, and plan forward/rollback-compatible transitions. They exercise a missing-state first install, read-only preflight, private atomic receipt/cache/trust creation, exact retries, compatible existing-receipt trust adoption, same-manifest artifact rebinding, normal upgrade, explicit same-key rollback with a retained signed high watermark, overlap rotation to a successor release key, permanent old-key revocation, and restoration of the exact high release. A fake Debian package boundary proves current/candidate preflight, network-operation exclusion, candidate installation, health-before-receipt ordering, root-authorized key transition, authenticated previous-package restoration after install or health failure, retained state after rollback failure, idempotent old-receipt restoration, already-committed candidate finalization, no-op retry, explicit package rollback/high-watermark recovery, and journal/cache cleanup. Tests reject manifest/signature/key/cache/journal/policy tampering, noncanonical or unknown JSON, wrong trust roots, revoked or unauthorized keys, policy downgrade/sequence reuse/un-revocation, key removal without revocation, explicit-key bypass after adoption, unsafe cross-key rollback/rebind, incompatible trust adoption, unsafe paths, symlinks and hard links, incorrect state modes, changed artifact bytes, release-sequence reuse, below-watermark upgrades, implicit downgrade, mismatched version/sequence movement, missing transaction/trust compatibility, forward-incompatible schemas, rollback-incompatible writes, output overwrite, and partial paired output. The checked-in `release/state-compatibility.json` must parse as the exact canonical contract, including `linux_release_receipt`, `linux_release_transaction`, and `linux_release_trust` schema 1. These tests make no network request and retain no key, receipt, policy, journal, or artifact after their temporary directory closes.

The separate `sirinvpn-release-fetch` tests use an in-process loopback TLS 1.3 server with an ephemeral CA, root, release key, policy, manifest, and artifact. They prove the exact four-metadata/one-artifact request order, identifier-free fixed headers, root and release authentication before artifact transfer, channel/slot selection, response bounds, redirect refusal, same-length artifact tamper rejection, private file/directory modes, atomic no-clobber publication, and complete ordinary-error cleanup. They make no external request and retain no fixture identity, URL, result, or artifact after each temporary directory closes.

Desktop P2Y tests prove that no update check occurs automatically, the source is supplied only by the explicit form submission, the returned verifier paths/channel/target and private layout are strictly bound, unknown output is rejected, only authenticated public metadata reaches the UI, and installation stays disabled until a second exact-package confirmation. They also keep installation locked while a tunnel is active and verify that closing the dialog invokes candidate discard. The native tests run only against temporary files and development binaries, so they never invoke `pkexec` or alter installed release state.

The 2026-09-04 P2Y local gate passed 259 Rust tests and 42 frontend tests, warning-free formatting and Clippy, the production frontend build, and all privacy/shell/XML checks. The pinned Debian Bookworm container then rebuilt both release bundles; the `.deb` contains root-owned-mode `0755` `/usr/bin/sirinvpn-desktop`, `/usr/lib/sirinvpn/sirinvpn-release-fetch`, and `/usr/lib/sirinvpn/sirinvpn-release`, while the AppImage contains the corresponding internal sidecars. Current RustSec and production npm audits found no vulnerability-class advisory; the same 17 documented transitive informational Rust warnings remain.

The same day, a human-visible fresh-Debian-13 KVM gate installed and initialized the exact packaged 0.1.0 release, then disabled guest internet access before launching `/usr/bin/sirinvpn-desktop` as an unprivileged user. The rendered update UI contacted only a guest-loopback HTTPS source, displayed the pre-production-root-authenticated 0.1.1 candidate and both signed sequence values, and kept installation disabled until the separate exact-package checkbox was selected. The fetched tree was owned by the desktop user with mode `0700` directories, mode `0600` single-link files, and no persistent source setting. A disposable exact-program Polkit rule authorized the otherwise-real `/usr/bin/pkexec /usr/lib/sirinvpn/sirinvpn-release` calls from UID 1000; the journal recorded separate `apply-trust` and `install-debian` invocations with the fixed coordinator path and no shell. The UI visibly reported success. Debian then reported configured version 0.1.1 with empty `dpkg --verify`, coordinator version 0.1.1, active/high release sequence 2, one root-owned authenticated 0.1.1 cache package, no transaction journal, no fetched candidate, and a still-disconnected helper with persistence disabled. Closing the old process and reopening the application started the installed desktop whose executable bytes matched `/usr/bin/sirinvpn-desktop`. The ephemeral leaf/TLS keys, signed source, VM overlay, and packages were destroyed after the gate; the pre-production root private key never entered the guest. This closes P2Y's packaged desktop-install acceptance, but it is not a substitute for establishing offline production-root custody and performing the real release-signing ceremony before public distribution.

Before publishing a real Linux release, separately run the offline create/verify/plan procedure in [Signed releases](releases.md) against the exact container-built `.deb` and AppImage. Exercise the previous and candidate full packages with the disposable Debian 13 release-update VM gate documented below. The local fake boundary proves ordering and the small-package container proves fixed `dpkg` semantics; neither substitutes for the full-package hard-reboot test.

The opt-in bundled-root gate requires access to the pre-production root private key and an exact confirmation because ordinary test runs must not touch that authority:

```sh
env \
  SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY=/absolute/offline/path/root-private.pem \
  SIRINVPN_RELEASE_TRUST_CONFIRM=exercise-preproduction-release-root \
  ./tests/integration/release-trust-root.sh
```

It creates two ephemeral release keys, proves the bundled root accepts an initial policy and an overlap policy, verifies releases signed by each authorized key, then installs a third policy containing only the successor and a permanent revocation for the old key. The successor remains valid and the old release must fail specifically as revoked. All work stays in an ignored temporary directory, no installed state is touched, no network request is made, and every ephemeral release key/policy/artifact is removed at exit.

Exercise the actual packaged-root fetch path against a proper ephemeral local CA/server certificate and HTTPS server with a second exact confirmation:

```sh
env \
  SIRINVPN_RELEASE_TRUST_ROOT_PRIVATE_KEY=/absolute/offline/path/root-private.pem \
  SIRINVPN_RELEASE_FETCH_CONFIRM=exercise-preproduction-release-fetch \
  ./tests/integration/release-fetch-https.sh
```

This gate signs an ephemeral release key policy with the pre-production root, serves the resulting release from loopback HTTPS, and invokes the real `sirinvpn-release-fetch` binary through native CA verification. It proves bundled-root verification, bounded artifact download, private atomic output, exact re-verification by the offline coordinator, no-clobber behavior, tamper rejection, and cleanup. It sends no packet outside loopback, changes no installed state, and removes its CA/server/release private keys and all fetched bytes at exit.

Build the release-mode coordinator in the Debian toolchain image, then exercise its fixed production `dpkg` boundary inside a fresh network-disabled container:

```sh
./tests/integration/linux-release-debian-container.sh
```

The gate creates ephemeral signed fixture packages, installs and binds release A, installs B, explicitly rolls back to A without lowering the high watermark, restores B, and installs an unhealthy C whose helper check forces automatic B restoration. Every committed/rolled-back phase requires exact `dpkg-query`, receipt active/high sequences, one content-addressed cache digest, and no journal. The container is destroyed at exit and neither the host package database nor `/var/lib/sirinvpn-release` is mounted. This proves real Debian command/output semantics without network access and complements the full-package reboot gate below.

## Android verification

The current port has isolated emulator, instrumentation and presentation checks.
Follow the [Android build and test guide](android/build-and-test.md) and read the
[verification report](android/progress.md) for exact coverage and remaining gaps.
The scenario inventory is not a claim that every scenario has passed end to end.
Earlier Android reports apply only to their named implementations and builds.
Generated APKs and local evidence under `target/` are not included in Git.

## Linux restrictive-network fault-injection gate

`tests/integration/linux-fallback-vps.sh` exercises the complete Linux Automatic order against one already managed, otherwise idle Debian 13 VPS. It first accepts Direct UDP on the unrestricted path, then installs PID-scoped VPS input faults to force authenticated Obfuscated UDP and pinned TLS. For the final transient phase it transactionally moves the shared TLS/raw-TCP listener to an internal port and places the bounded test proxy on the public port; the proxy rejects a TLS first record and forwards raw TCP. Exact nftables and proxy counters prove every forced rejection. Every accepted phase must return matching concrete local/server transport, authenticated management readiness, healthy private DNS, the full-tunnel address/routes/rules, reachable private gateway, correct IPv6 disposition, and observed VPS egress.

The second transaction starts persistent Automatic on Direct UDP, schedules a remote Direct fault, proves a private-gateway packet is rejected, and removes the local WireGuard interface. While the interface is absent the gate requires an intact default-drop guard and proves an ordinary public IPv4 socket cannot escape. It checks that guard throughout recovery and accepts only authenticated Obfuscated UDP with the kill switch, reconnect intent, and bounded candidate plan still enabled.

Run it locally from the disconnected Owner device. The SSH identity must already be loaded, and `sudo -v` must succeed in the same terminal. The VPS must have no active invitations, enrollment receipts, key rotations, or port mappings. Independently verify the ED25519 fingerprint before supplying it:

```sh
sudo -v
env \
  SSH_AUTH_SOCK=/path/to/unlocked/agent.sock \
  SIRINVPN_LINUX_FALLBACK_SERVER_ID=00000000-0000-0000-0000-000000000000 \
  SIRINVPN_LINUX_FALLBACK_HOST_KEY='SHA256:independently-verified-ed25519-fingerprint' \
  SIRINVPN_LINUX_FALLBACK_CONFIRM=fault-inject-disposable-vps \
  ./tests/integration/linux-fallback-vps.sh
```

Each VPS transaction arms an independent 15-minute rollback timer before injecting a fault. Normal exit, failure, or interruption disconnects the client, removes the test table/proxy/units/files, restores the byte-for-byte server state and local `network-policy.json`, validates all three production listeners, and proves no local interface, service, or nftables table remains. Do not reboot either endpoint or kill the harness while it runs; the persistent phase deliberately causes a brief local outage. If the host process is killed and persistent protection remains armed, recover locally with `pkexec /usr/lib/sirinvpn/sirinvpn-helper disconnect`; the VPS timer remains the independent remote fallback.

The 2026-09-04 P2O run passed the complete Direct UDP -> Obfuscated UDP -> pinned TLS -> raw TCP chain and the established persistent Direct -> guarded Obfuscated recovery. The transient phases observed both rejected UDP candidates, one rejected TLS connection, one forwarded raw-TCP connection, private DNS, the private gateway, and VPS-forwarded public traffic. The persistent phase observed the scheduled Direct drop before interface removal, prevented public IPv4 escape throughout the missing-interface window, retained the default-drop guard, and recovered with all protection flags active. Final cleanup restored seven VPS configuration/authorization/identity/operational/artifact hashes plus the local network-policy hash exactly, left the server healthy, and left the client disconnected. The same repository state passed 206 Rust tests, 40 frontend tests, warning-free Clippy and formatting, the production frontend build, and the privacy gate.

## Linux tunnel-impairment and carrier-loss gate

`tests/integration/linux-impairment-vps.sh` exercises all four manual Linux transports while a root-only helper applies `tc netem` to the managed VPS's `sirinvpn0` egress. The profile is fixed at `120 ± 30 ms` normally distributed delay plus `10%` random loss. Each phase requires authenticated matching transport state, healthy private DNS, the complete full-tunnel topology, public IPv4 reachability, at least 15 of 30 private-gateway replies, a measurable delay/jitter increase over an unshaped Direct control, and the exact 1420/1320/1280/1280 transport MTU. An exact-MTU IPv4 `DF` packet must pass while a packet one byte larger must fail locally. Qdisc statistics prove shaped server-to-client traffic and at least one drop; an isolated nftables counter proves client-to-public forwarding.

After restoring that transaction to baseline, the gate independently installs exact-tuple nftables rules on the VPS public interface. They match only the current SSH peer's canonical IPv4 address and Direct UDP, Obfuscated UDP, or shared TLS/raw-TCP server port, then deterministically drop packet 20 and every twentieth packet thereafter in both directions. This leaves SSH and unrelated traffic unmatched and avoids manufacturing a first-packet authentication failure. Each manual transport must retain authenticated state before and after 60 private-gateway samples, deliver at least 30, preserve private DNS/full-tunnel egress and its MTU boundary, and increment both its ingress and egress seen/drop counters. TLS and raw TCP share rules but must each independently observe at least 20 packets and one drop per direction.

Run it from the disconnected sole authorized Owner device. The SSH identity must already be loaded, `sudo -v` must succeed in the same terminal, and the VPS must have no active invitations, enrollment receipts, key rotations, or port mappings. Independently verify the ED25519 host fingerprint before supplying it:

```sh
sudo -v
env \
  SSH_AUTH_SOCK=/path/to/unlocked/agent.sock \
  SIRINVPN_LINUX_IMPAIRMENT_SERVER_ID=00000000-0000-0000-0000-000000000000 \
  SIRINVPN_LINUX_IMPAIRMENT_HOST_KEY='SHA256:independently-verified-ed25519-fingerprint' \
  SIRINVPN_LINUX_IMPAIRMENT_CONFIRM=impair-disposable-vps \
  ./tests/integration/linux-impairment-vps.sh
```

The gate refuses any non-default qdisc or existing `netem`, records whether `sch_netem` was already loaded, and arms a fresh 12-minute remote rollback timer before each impairment transaction. Cleanup restores seven VPS configuration/authorization/identity/operational/artifact hashes plus the exact qdisc and module state, removes the scoped nftables table/timer/files, restores the local network-policy file byte-for-byte, and requires a disconnected clean client. The inner transaction proves VPN data-plane behavior and configured client MTU enforcement; the public-interface transaction proves bounded loss handling for the exact tested carrier tuples. Neither proves outer-path PMTU discovery, throughput, congestion behavior, packet reordering, a particular real carrier, or censorship resistance.

The 2026-09-04 P2P run passed Direct UDP with 25/30 replies at 155.487 ms average, Obfuscated UDP with 26/30 at 186.096 ms, pinned TLS with 27/30 at 169.653 ms, and raw TCP with 27/30 at 182.465 ms. Every phase retained authenticated status, private DNS, full-tunnel egress, and its exact MTU boundary. Final cleanup independently confirmed the client disconnected with no owned interface/services and the VPS healthy at its original `noqueue` state with `sch_netem` absent and no test files, tables, or units. The same repository state passed 206 Rust tests, 40 frontend tests, warning-free Clippy and formatting, the production frontend build, and the privacy gate.

The 2026-09-04 P2Q extension reran the inner transaction successfully: Direct UDP delivered 29/30 samples at 151.574 ms average, Obfuscated UDP 26/30 at 142.447 ms, pinned TLS 28/30 at 155.649 ms, and raw TCP 26/30 at 155.538 ms. Under exact 5% bidirectional public-interface loss, Direct delivered 57/60 samples with 6/132 ingress and 5/103 egress packets dropped; Obfuscated delivered 54/60 with 6/131 and 5/107 dropped; pinned TLS delivered 60/60 with 19/381 and 16/328 dropped; raw TCP delivered 60/60 with 20/400 and 18/363 dropped. Every phase retained authenticated state, private DNS, full-tunnel egress, and the exact MTU boundary. Both remote transactions rolled back cleanly, restoring the original `noqueue`/module state and all seven VPS hashes while leaving no local or remote test resource. The resulting repository state passed 206 Rust tests, 40 frontend tests, warning-free Clippy and formatting, the production frontend build, and all privacy/shell/XML checks.

## Linux DNS-failure and interception gate

`tests/integration/linux-dns-fault-vps.sh` exercises the existing managed DNS-over-TLS path without changing its providers or the client resolver configuration. A Direct UDP full tunnel is established first. In the upstream transaction, PID-scoped VPS rules reject TCP/853 to every configured resolver address. A fresh uncached name must fail while the private gateway, authenticated management state, and public TCP by IP remain available. Counters must prove both a tunnel-private port-53 request and an exact configured DoT rejection, while independent client-output, VPS-output, and tunnel-forward counters prove no alternate UDP/TCP port 53 or new TCP port 853 path was used. Existing DoT FIN/ACK teardown remains admissible so fault installation cannot manufacture retransmission traffic.

The resolver transaction starts from a restored baseline, stops Unbound, and requires another fresh uncached name to fail without losing IP connectivity or using an alternate DNS path. Restarting Unbound and the management server must restore both name resolution and authenticated Direct status without reconnecting the tunnel.

Run the gate from a disconnected Owner device. The profile must already use one or two validated DNS-over-TLS endpoints. Its SSH identity must be loaded, `sudo -v` must succeed in the same terminal, and the VPS must have no active invitations, enrollment receipts, key rotations, or port mappings. Independently verify the ED25519 host fingerprint before supplying it:

```sh
sudo -v
env \
  SSH_AUTH_SOCK=/path/to/unlocked/agent.sock \
  SIRINVPN_LINUX_DNS_SERVER_ID=00000000-0000-0000-0000-000000000000 \
  SIRINVPN_LINUX_DNS_HOST_KEY='SHA256:independently-verified-ed25519-fingerprint' \
  SIRINVPN_LINUX_DNS_CONFIRM=dns-fault-disposable-vps \
  ./tests/integration/linux-dns-fault-vps.sh
```

Each remote transaction records the active resolver/server state and arms an independent 10-minute systemd rollback timer before installing its nftables table or stopping a service. Cleanup disconnects the client, restores the local network-policy file and exact local/remote table sets, restores seven VPS hashes, validates the server, and removes every scoped timer, runtime directory, and helper. The rules expose aggregate packet counts only; query contents are never captured or retained. This gate is bounded to the configured DNS-over-TLS path and does not claim DNS-over-HTTPS, recursive-resolver, malicious-resolver, DNS-traffic-analysis, or universal interception coverage.

The 2026-09-04 P2R run observed three private query packets and 20 rejected configured DoT packets during encrypted-upstream failure, with no alternate DNS egress. Stopping Unbound caused DNS to fail privately while private-gateway and public-IP traffic remained usable; restarting it restored DNS and authenticated status in place. Final cleanup restored all seven VPS hashes and both nftables baselines, left both VPS services active and valid, and left the client disconnected with no SirinVPN interface or persistent service. The repository state passed 206 Rust tests, 40 frontend tests, the production frontend build, and all privacy checks.

## Linux outbound-network privacy audit gate

`tests/integration/linux-outbound-audit-vps.sh` dynamically audits the production Linux client and managed VPS without capturing packets. The script re-executes itself in a dedicated cgroup-v2 user scope so nftables can separate its CLI/control sockets from other applications owned by the desktop user. Exact counter-and-return rules classify the gate's pinned SSH control channel, private mTLS management, each marked VPS carrier tuple, the three wrapped-transport loopback ports, and systemd-resolved's private DNS path. Any other scoped TCP/UDP packet, marked physical-link packet, or physical DNS delta during the fresh protected test query fails the run.

The VPS observer uses the dedicated `sirinvpn-server.service` and `unbound.service` cgroups. It admits and counts only the selected client's public transport replies, private management/DNS responses, exact WireGuard/relay loopback bridge, configured DNS-over-TLS endpoints, local resolver IPC, and replies on the public listeners. A new daemon or resolver TCP/UDP path outside those documented functions and a WireGuard packet to an unexpected public peer increment failing counters. Direct, Obfuscated, TLS, and raw-TCP phases each require positive client/server carrier counts, positive management and private-DNS counts, matching authenticated status, full-tunnel topology, and a reachable private gateway; all wrapped phases additionally require client and VPS loopback relay activity.

Run it from a disconnected sole authorized Owner device on cgroup v2. The current bounded lane requires canonical IPv4 profile addresses and one or two configured DNS-over-TLS endpoints. The SSH identity must already be loaded, `sudo -v` must succeed in the same terminal, and the VPS must have no active invitations, enrollment receipts, key rotations, or port mappings. Independently verify the ED25519 host fingerprint before supplying it:

```sh
sudo -v
env \
  SSH_AUTH_SOCK=/path/to/unlocked/agent.sock \
  SIRINVPN_LINUX_OUTBOUND_SERVER_ID=00000000-0000-0000-0000-000000000000 \
  SIRINVPN_LINUX_OUTBOUND_HOST_KEY='SHA256:independently-verified-ed25519-fingerprint' \
  SIRINVPN_LINUX_OUTBOUND_CONFIRM=audit-disposable-vps \
  ./tests/integration/linux-outbound-audit-vps.sh
```

The observers have accept policy and retain only aggregate in-memory counters; no packet payload, DNS name, discovered destination, or connection history is captured. A 12-minute root-owned VPS timer independently removes the remote observer after interruption. Every exit disconnects the client and requires restoration of seven VPS hashes, the exact local and remote nftables table sets, active valid services, the byte-identical local network-policy cache, and absence of all scoped runtime/timer resources.

The 2026-09-04 P2S run passed with zero unexpected counters. Direct observed 93 client/49 server carrier packets, Obfuscated UDP 103/61, pinned TLS 228/147, and raw TCP 187/162. Each phase independently observed 22 private-management packets and two private-DNS packets, while the complete run observed configured encrypted upstream traffic. Exact cleanup passed. The same repository state passed 206 Rust tests, 40 frontend tests, warning-free formatting and Clippy, the production frontend build, and the static privacy gate. This proves the current Linux manual-transport and DNS-over-TLS ownership map together with the static privacy scan; Android, IPv6, DNS-over-HTTPS, recursive DNS, provisioning, repair, backup/restore, and future signed-update traffic require their own dynamic audit lanes.

## Disposable Debian 13 VM

`tests/vm/debian13.sh` provisions a disposable cloud-image VM, installs SirinVPN, and verifies service health and reinstall rollback. It requires QEMU, either `cloud-localds` or `xorriso`, `ssh`, `ssh-keygen`, `ssh-agent`, either `jq` or Python 3, and a local Debian 13 generic cloud qcow2 image.

```sh
SIRINVPN_DEBIAN13_IMAGE=/absolute/path/to/debian-13-genericcloud-amd64.qcow2 \
  ./tests/vm/debian13.sh
```

The VM uses a temporary SSH identity, local port forwarding, an isolated XDG configuration directory, and a copy-on-write disk. It is destroyed when the test ends. For a host whose libc is newer than Debian 13, run the container package build first and set `SIRINVPN_TEST_SERVER_BINARY` to that staged Debian-compatible server binary.

Disposable overlays default to the repository's ignored `.cache` directory so a small tmpfs cannot corrupt the guest. Set `SIRINVPN_VM_WORK_ROOT` to another absolute path when needed; allow several gigabytes of free space.

For installer diagnosis, `SIRINVPN_TEST_CLI_BINARY` can select a debug CLI. Remote command output is bounded, and remote stderr is withheld from errors in both debug and release builds because it may echo credentials.

### Full-package release interruption gate

`tests/vm/debian13-release-update.sh` accepts two normal, full x86_64 SirinVPN `.deb` builds with increasing canonical SemVer values. It creates an ephemeral test signing key, signs and plans those exact package bytes, installs and binds release A in a fresh Debian 13 overlay, then disables guest internet access for every update and recovery phase. The default path builds a separate Debian-compatible coordinator with the non-default `test-release-fault-injection` feature; neither input package contains an enabled crash hook.

```sh
env \
  SIRINVPN_DEBIAN13_IMAGE=/absolute/path/to/debian-13-genericcloud-amd64.qcow2 \
  SIRINVPN_RELEASE_VM_PACKAGE_A=/absolute/path/to/SirinVPN_1.0.0_amd64.deb \
  SIRINVPN_RELEASE_VM_PACKAGE_B=/absolute/path/to/SirinVPN_1.1.0_amd64.deb \
  SIRINVPN_RELEASE_VM_VERSION_A=1.0.0 \
  SIRINVPN_RELEASE_VM_VERSION_B=1.1.0 \
  ./tests/vm/debian13-release-update.sh
```

The pre-commit fault terminates after candidate installation and health verification but before receipt replacement. An immediate hard QEMU power cut follows; after reboot, the gate requires an old receipt, both authenticated packages and the journal to survive, then proves `recover-debian` reinstalls release A and cleans candidate state. The post-commit fault terminates after the candidate receipt has been atomically replaced and synced but before journal cleanup, again followed immediately by a hard power cut. Recovery must finalize release B without reinstalling either package, as proved by an unchanged `dpkg` log. Both paths require a Debian 13 amd64 guest, configured exact package versions, empty `dpkg --verify` output, exact active/high receipt state, content-addressed caches, correct journal permissions, and idempotent second recovery.

The first boot alone has internet access so `apt` can install the full package's declared dependencies. Subsequent QEMU boots use `restrict=on`, while SSH remains reachable only through localhost forwarding. The overlay, ephemeral SSH/release keys, signed copies, and guest fault-coordinator copy are deleted on exit. The base image and caller-supplied packages are read only as copy sources and never modified. `SIRINVPN_RELEASE_FAULT_BINARY` may select a prebuilt instrumented coordinator; otherwise `scripts/build-release-fault-tool-container.sh` builds one in the ignored `target/release-fault` cache with the existing Debian builder image and restores host ownership afterward.

The 2026-09-04 gate passed with full `0.1.0` and independently rebuilt `0.1.1` packages. The pre-commit crash restored `0.1.0` after a hard reboot; the post-commit crash finalized `0.1.1` after a hard reboot; both ended with one authenticated package, no journal, and `nothing_pending` on repeated recovery.

## Named VPS gate

The real-VPS gate changes the named machine by installing SirinVPN. Use only a disposable Debian 13 VPS or a restorable snapshot. It requires an SSH agent identity already loaded and a fingerprint verified independently through the provider console.

```sh
export SIRINVPN_TEST_HOST=203.0.113.10
export SIRINVPN_TEST_USER=root
export SIRINVPN_TEST_PORT=22
export SIRINVPN_TEST_HOST_KEY='SHA256:verified-out-of-band-value'
export SIRINVPN_TEST_CONFIRM=provision-disposable-vps
./tests/integration/debian13-vps.sh
```

The script provisions the server, uses the default Automatic preference and verifies that Direct UDP wins on an unrestricted path with persistent protection, waits for bounded aggregate CPU/memory/interface-rate samples, verifies live status and private DNS, checks either configured IPv6 routing or the IPv4-only IPv6 block according to discovered capability, attempts a conflicting owner reinstall, repairs from the selected local artifact, connects both authenticated fallbacks with persistent protection, rotates the Owner device's two keys without changing the selected transport, regresses forced Direct UDP, and runs authenticated diagnostics throughout. It disconnects locally on exit but intentionally leaves the server and local profile for inspection.

Never put an SSH password or private-key passphrase in these environment variables. The gate supports SSH agent authentication only.

## P1B2 authorization gate

After installing the P1B2 server binary on an existing disposable test VPS, run the opt-in authorization gate from the original Owner device:

```sh
SIRINVPN_P1B2_SERVER_ID=LOCAL_SERVER_ID \
SIRINVPN_P1B2_CONFIRM=test-disposable-vps \
./tests/integration/p1b2-vps.sh
```

The gate keeps bearer invitations in a mode-0700 temporary directory and passes codes only over stdin. It creates isolated Admin, Member, additional-Member-device, and additional-Owner-device profiles; checks the permission matrix, live promotion/demotion, ordinary-Member self-key-rotation, peer-policy defaults and Owner/Admin/Member mutation boundaries, atomic ownership transfer and transfer-back, local role convergence, receipt handoff, and last-Owner protection; then uses the restored original Owner to revoke every test device and invitation. It deletes the isolated local profiles/secrets and leaves the original tunnel disconnected. The cleanup trap retries these removals after a failure, but the target must still be disposable because abrupt host/process failure can interrupt cleanup.

## Manual release checks

- Connect with the packaged desktop using Direct UDP and wait through two four-second refreshes. Confirm the active local transport reports `Direct UDP`, control latency, CPU, RAM, and server inbound/outbound rate become numeric without a page reload, traffic changes affect the rates, and disconnect makes remote values unavailable. Confirm the first new-server sample may show `Sampling`, an older server shows `Update server`, and no raw network identity, metric history, transport history, or related service output is created on either machine.
- Repair an older disposable server, confirm the same WireGuard/TLS/device/authorization identities remain and one stable transport key plus profile capability are added, then select Obfuscated UDP. Confirm local and authenticated server status both report it, WireGuard targets `127.0.0.1:51821`, the outer socket uses the VPS UDP/443 endpoint, private DNS and IPv4/IPv6 leak checks still pass, and malformed/unauthorized UDP probes receive no response. Exercise transient and persistent sessions, app closure, relay restart, client reboot, key rotation, explicit disconnect, and a final Direct UDP regression. Confirm transport/session/probe state never appears in service output or a history file.
- With all transport capabilities present and no matching cache, use the Normal profile and confirm it selects Direct, Restricted and confirm it selects Obfuscated UDP, and Extreme and confirm it selects TCP. On a disposable client path, block only the VPS Direct UDP port and confirm the failed Direct state is removed before Obfuscated succeeds. Block both UDP ports and confirm both failed candidates are cleaned before TCP succeeds. Finally block TCP/443 too and confirm selection reports failure with the normal network restored. Repeat a successful Automatic fallback with persistent protection and confirm root reconnect state stores the selected concrete legacy-readable request first plus exactly the installed bounded candidates, but no network identifier, failure, timing, counter, or history.
- Complete one successful profile-driven connection, disconnect, and confirm `network-policy.json` is mode 0600 and contains exactly one salted fingerprint/server/transport/coarse-expiry entry but no raw NetworkManager UUID, interface/gateway identity, SSID, BSSID, failed attempt, timing, counter, or history array. Reconnect with Automatic and confirm that installed cached transport is tried first. Change the network or server and prove a later success overwrites rather than appends; advance the test clock past seven days in unit coverage and prove the old entry is ignored. Confirm manual transport choices neither read nor update the entry, profile removal clears a matching server entry, device backup excludes the file, and corrupt/future documents remain byte-for-byte unchanged while connection uses the default plan.
- Select TCP fallback manually and confirm local and authenticated server status report `TCP fallback`, WireGuard targets `127.0.0.1:51822`, the outer connection reaches VPS TCP/443, DNS/leak tests pass, and malformed, unauthorized, and replayed handshake connections receive no application bytes. Confirm persistent reconnect survives client relay restart and reboot. Block both UDP ports and confirm Automatic reaches TCP only after cleaning both failed UDP candidates; then block TCP/443 as well and confirm ordinary networking is restored for a transient attempt. Verify setup refuses a disposable unrelated listener on TCP/443 without stopping or replacing it.
- Select TLS fallback manually without persistent protection and confirm local and authenticated server status report `TLS fallback`, WireGuard targets `127.0.0.1:51823`, the outer connection completes TLS 1.3 on VPS TCP/443, pinned management readiness passes, and DNS plus IPv4/IPv6 leak checks pass. Confirm raw TCP still connects through that same listener after TLS disconnects. Change only the stored certificate fingerprint in an isolated test profile and prove the TLS attempt fails with complete route/DNS/relay cleanup; unauthenticated or replayed inner handshakes must not reach WireGuard. Confirm the desktop disables persistence for TLS, the CLI rejects `--persistent --transport tls`, and persistent Automatic excludes TLS while retaining Direct/Obfuscated/raw-TCP candidates. This is TLS-shaped encrypted transport, not proof of browser fingerprint parity or an HTTP decoy.
- From a disconnected Owner profile, independently verify the VPS SSH fingerprint and run Repair from both the CLI and desktop. Confirm the server/Owner identities, authorization memberships/devices, all local profile fields except the public IPv6-capability flag, and the local secret reference are unchanged while the installed server SHA-256 equals the packaged candidate. (The daemon may canonically rewrite authorization while pruning expired invitations/receipts.) Delete one SirinVPN-owned service/network/firewall/DNS file at a time and prove repair reconstructs it and passes live VPN/DNS/management checks.
- On a disposable VPS, first provision Recursive and confirm `server.json` remains schema 1, the SirinVPN Unbound file has no forwarding stanza, and the desktop reports `Recursive` only after connected status is available. Repair without a DNS choice and prove the policy is unchanged. Then choose one or two independently documented DNS-over-TLS IP/certificate-name endpoints: confirm every server/device/authorization identity is unchanged, `server.json` is schema 2, `unbound-checkconf` succeeds, the exact `@853#name` directives plus `forward-tls-upstream: yes` and `forward-first: no` exist, and tunnel DNS resolves through the selected provider. In one bounded firewall test, block VPS egress to those TCP/853 endpoints and prove DNS fails without UDP/TCP-53 recursive fallback while established non-DNS tunnel traffic remains usable; the current UI is expected to show service activation, not synthetic-query health. Finally Repair with explicit Recursive, confirm schema 1 and all forward directives are removed, and prove resolution plus every identity still works. Invalid endpoints, a mismatched schema/policy pair, invalid Unbound syntax, or a failed service verification must roll back to the byte-for-byte prior policy.
- From that disconnected Owner state, Repair to one or two independently documented DoH endpoints such as `IP#TLS_NAME/dns-query`. Confirm schema 4, unchanged identities, exact configuration returned through the private API, `sirinvpn-doh` active/enabled before Unbound, loopback UDP and TCP listeners only on `127.0.0.1:5053`, `IPAddressDeny=any` plus only loopback/configured-IP allows, no capabilities or service output, and one exact Unbound loopback forward with no TLS/plaintext fallback directives. Resolve through both UDP and forced TCP, then temporarily block only the configured TCP/443 endpoint and prove DNS fails while non-DNS tunnel traffic remains usable. Repair without DNS input and prove byte-for-byte policy preservation; Repair back to the prior DoT or Recursive policy and prove the DoH unit is inactive/disabled and removed, port 5053 is absent, destination schema is 1/2, and all identities remain unchanged. Invalid paths, TLS failure, redirects, wrong media type/status/transaction, an occupied loopback port, service failure, or interrupted Repair must fail/roll back without leaking into system DNS/proxy resolution or leaving partial service state.
- Provision a disposable VPS with one A and one AAAA private record, connect, and query both names through `10.77.0.1`; confirm exact answers, a 60-second TTL, schema 3 for Recursive/DoT or schema 5 for DoH, and that the resolver still refuses the public VPS interface. Confirm status/configuration returns the same normalized set only through authenticated management. Repair with no record choice and prove the set and every identity remain unchanged, replace it with a different complete set, switch among upstream modes while records remain and verify the exact schema 3/5 transition, then explicitly clear it and prove every `local-zone`/`local-data` directive is absent and the schema contracts to 1, 2, or 4 for the retained upstream. Reject malformed/single-label/localhost names, loopback/link-local/multicast/reserved addresses, exact duplicates, 65 records, mismatched schema, or altered generated directives; any post-mutation failure must restore the prior Unbound file and `server.json` byte-for-byte.
- Try repair from an Admin/Member, while any SirinVPN tunnel is active, with the wrong host-key pin, wrong VPS/server ID, wrong current Owner, mismatched server certificate/key, missing private key, corrupt authorization, future schema, wrong-architecture candidate, and modified uploaded digest. Each must stop without identity rotation or local mutation. Interrupt after the rollback guard is armed and prove the prior executable/configuration/service/network state returns within five minutes; repeat across a client disconnect and VPS reboot during the transaction.
- Rotate keys from an Owner, Admin, and ordinary Member device. Confirm each keeps its device/member IDs, name, tunnel address, access, other devices, persistent-protection choice, and Automatic-fallback choice while both public fingerprints change and the former WireGuard/mTLS identities stop authenticating. Reject missing confirmation, duplicate/reused public material, the wrong pending private certificate, and rotation during the 60-second enrollment receipt window.
- Interrupt rotation before prepare, after prepare, during commit, after a lost commit response, and after final profile replacement. Confirm the journal is mode 0600 and contains no private key; rerunning Resume keys must select the verified new identity or restore/retry the old one without creating another device. Let an uncommitted transition exceed ten minutes and prove only its pending public state disappears. Corrupt the journal and confirm both staged secret references are retained for explicit recovery rather than guessed or deleted.
- Export an encrypted backup to a new path and confirm mode 0600, no server name/address/private key appears in cleartext, choosing the same path again is refused, wrong passwords and a one-byte ciphertext change fail identically, and an edited version/KDF declaration is rejected without using its cost. Restore on an isolated clean client and confirm the profile connects with its original device authorization while receiving a fresh local secret reference. A second restore, a copied identity under another server ID, and a different identity with the same server ID must all stop without changing local state. Revoke the device on the VPS and prove restoring the backup does not reauthorize it.
- While disconnected as the current Owner, capture hashes of every VPS private identity, authorization document, configuration, installed server, and generated operational file; then export a VPS backup through independently pinned SSH. Confirm the local file is mode 0600, bounded, no known server/profile/key marker appears in cleartext, the same destination is refused, and no snapshot or staged candidate remains on the VPS. Confirm services were neither restarted nor reconfigured and every captured VPS hash is unchanged, including authorization whose expired records are pruned only inside the encrypted snapshot. Repeat the refusal checks as an Admin/Member, with an Owner mismatch, future/corrupt configuration, unsafe state-file mode, wrong pin, active tunnel, and pending rotation.
- Restore that fresh encrypted server backup in place on the disposable VPS. First omit explicit replacement and prove refusal occurs before any target hash/service/local-profile change. Then independently pin the destination, opt into replacement, and confirm the previous target state is snapshotted and guarded before private-state replacement. Prove restored server configuration, WireGuard/management/transport identities, authorization, and permissions match the backup; generated services/network/firewall/NAT/DNS state and installed candidate digest pass exact verification; SSH survives; no plaintext snapshot/staging/rollback residue remains after commit; and the local member/device/secret reference/tunnel address are unchanged. Repeat with a wrong password, tamper, future version, wrong local profile/Owner, IPv6-incompatible target, and interrupted post-guard transaction, proving target rollback and no local endpoint mutation. For migration to another disposable VPS, confirm only this Owner profile adopts the new endpoint after remote commit while the old VPS and other devices remain unchanged.
- With both migration VPSes running and at least one additional authorized device still on the old endpoint, connect the restored Owner and create generation 1. Prove active invitations, enrollment receipts, or key rotations block creation; otherwise confirm both servers store the same valid signed response after explicit old-VPS publication. Confirm the old authorization records its handoff-source marker: status/membership/transition reads and existing VPN traffic still work, while invitation/enrollment, rename/revoke/access/ownership, and key-rotation writes fail without changing either clone. From the additional device, first alter one code byte, substitute a different server profile, and replay an already applied generation; each must fail before local mutation. Then retrieve through the old tunnel, apply, and prove SirinVPN disconnects the old path, reaches the candidate through Automatic selection, authenticates the same device and pinned server identity, atomically adopts the endpoint/capabilities, and remains transiently connected. Force candidate transport and management-proof failures and confirm the old profile survives with complete network cleanup. Move every device before creating a second migration, and confirm a generation-zero device cannot skip directly to generation 2. Verify neither VPS authorization nor client storage accumulates endpoint history, and do not treat the old VPS as retired until a separate explicit teardown is completed.
- Verify the SSH fingerprint screen is readable and cannot be bypassed by the primary action.
- Remove a disconnected local Owner profile and confirm its device key is deleted while the VPS remains installed. Re-enter the same VPS without replacement and confirm it fails before mutation with an existing-owner explanation. Select replacement, confirm both destructive warnings, and verify a fresh Owner/profile is created while old SirinVPN devices fail and unrelated services remain unchanged. Interrupt one replacement after identity removal and prove rollback restores the former identity and service activation state.
- From an Admin and a Member device, confirm removal offers local deletion only and leaves the VPS unchanged. From the Owner, select remote uninstall, verify the pinned fingerprint and destructive confirmation, and confirm the local profile/key are retained if the Owner certificate or server ID mismatches. On success, prove every SirinVPN path/unit/interface/table/comment-tagged rule/listener is absent while SSH, unrelated firewall state, Docker containers, and other services are unchanged. Interrupt teardown before commit and prove the five-minute guard restores the installation.
- Cancel the polkit prompt and confirm no interface, rule, DNS override, or nftables table remains.
- Disconnect and confirm `sirinvpn0`, table `51820`, both policy rules, `sirinvpn_client`, `sirinvpn_client6`, and the link DNS override are removed.
- On an IPv6-capable VPS, confirm provisioning/repair enables the profile, the UI reports `IPv6 route: Tunneled`, `::/0` uses table `51820`, the deterministic client ULA `/128` is on `sirinvpn0`, IPv4 and IPv6 egress both use the VPS, and DNS reaches `10.77.0.1` without an ISP resolver. On an IPv4-only VPS, confirm the capability remains false, IPv6 egress is blocked for the full connected session, and IPv4/private DNS still pass.
- On Linux, select two controlled non-default CIDRs and confirm WireGuard `AllowedIPs` plus table `51820` contain exactly those ranges and `10.77.0.1/32`, with no default route or suppress-default rule. Prove one selected IP exits through the VPS, an unselected IP keeps the physical path, and `resolvectl` still assigns `~.` to private DNS. Reject an empty list, `/0`, malformed input, 33 entries, and IPv6 input on an IPv4-only profile before any route changes. Enable `Allow local network` and confirm the fixed private/link-local/multicast rules precede tunnel policy while `10.77.0.1/32` still resolves through SirinVPN; then disconnect and prove every reserved rule priority is gone.
- For a dual-stack server, verify `sirinvpn_nat6`, IPv6 forwarding, the server ULA/peer `/128`, Unbound's ULA binding, and uplink `accept_ra=2`. Remove the VPS IPv6 default route after capability is enabled and confirm Repair refuses before mutation rather than rewriting the profile/server to IPv4-only; restore the route and repair successfully. Exercise an interrupted enablement and prove rollback restores the previous server configuration, forwarding, router-advertisement value, tables, services, and identities.
- On a VPS with running Docker containers and a Docker-owned `FORWARD` drop policy, snapshot the existing rules and container list, then start `sirinvpn-firewall`. Confirm exactly one `sirinvpn-forward-out` and one `sirinvpn-forward-in` rule precede Docker's return, VPN egress works, and the containers remain running. Stop the firewall and confirm those two rules disappear while Docker's policies, chains, untagged rules, and containers remain unchanged.
- Enable persistent protection and verify `sirinvpn_guard` has a drop output policy with only loopback, `sirinvpn0`, DHCPv4, and the marked VPS endpoint allowed.
- Repeat with selected-route persistent protection and verify the guard uses an accept policy but drops every selected CIDR off `sirinvpn0`, the tunnel-private DNS address, and UDP/TCP 53/853. Delete `sirinvpn0` inside the bounded recovery harness: selected destinations and system DNS must fail while an unselected IP remains reachable. Restart the supervisor and reboot to prove the exact CIDR/LAN policy returns. Before a deliberate helper downgrade, disconnect; separately deserialize the retained desired record with the legacy fixture and prove its fallback is full-tunnel rather than split or unprotected.
- A forced-loss check intentionally stops all ordinary network access. Warn the operator first, keep a local terminal open, and run the interruption as one bounded transaction whose cleanup trap always restarts `sirinvpn-reconnect.service`; never leave the supervisor paused while waiting for manual checks.
- Within that bounded check, start persistent Automatic, delete `sirinvpn0`, and confirm ordinary IPv4, IPv6, and physical-interface DNS fail. Confirm the first failed attempt receives its 30-second handshake grace, the guard's marked exception changes atomically to the next candidate without broadening, status reports that candidate, and diagnostics recover. Repeat until TCP is reached, then restore reachability and confirm cycling can return to the preferred transport. A manual persistent session must instead retry only its selected transport.
- With persistent Automatic healthy, switch between two operator-controlled networks without stopping the supervisor. Confirm the existing transport remains selected when WireGuard produces a post-change handshake inside 30 seconds. In a separate bounded forced-loss run, make the new physical route unable to reach the active outer endpoint and confirm the first transport change occurs only after the 30-second roaming grace, the guard stays closed, and the existing candidate cycle recovers. Remove the physical default route entirely and confirm the helper does not repeatedly delete/recreate `sirinvpn0`; restore it and confirm recovery resumes. Repeat the failed-route case with a manual persistent selection and confirm it rebuilds only that transport. Inspect `/var/lib/sirinvpn`, `/run/sirinvpn`, profile/policy files, and service output to confirm no route fingerprint, transition timestamp, SSID/BSSID, public IP, or network timeline was persisted or logged.
- Restart `sirinvpn-reconnect.service` and verify the tunnel remains protected throughout. Reboot a disposable client and verify the guard is installed before networking and the tunnel reconnects without opening the desktop.
- Run `sirinvpn disconnect`; verify both systemd units are disabled/inactive, `/var/lib/sirinvpn/desired-connection.json` is absent, the guard is removed, and normal networking returns.
- Confirm the management port is absent on the public VPS address and available only at `10.77.0.1:8443` with the enrolled client certificate.
- Upgrade an existing P0 owner in place and confirm the server signing key, Owner identity/profile bindings, and authorization remain unchanged. On an IPv6-capable VPS, permit only the optional capability field to be added to `server.json` and the local profile; on an IPv4-only VPS, their legacy serialized shape remains unchanged.
- Create a one-hour invitation, redeem it from an isolated clean client profile, and confirm the new permanent keys differ from the bootstrap and owner keys.
- Confirm a second redemption with different permanent keys fails, then cancel an unused invitation and confirm its bootstrap peer and TLS identity stop working.
- Rename the enrolled device, revoke it, and confirm both WireGuard traffic and private management access stop without creating a history record.
- Display a QR invitation and decode it with an offline QR reader; redeem the decoded `sirq1.` payload on a clean profile and confirm the same invitation cannot then be redeemed through its long code.
- Promote a Member to Admin and confirm live status changes without rewriting the local profile. Verify the Admin can invite/cancel ordinary Members and rename/revoke ordinary Member devices, but cannot create another Admin or modify Owner/Admin devices. Demote the Admin and confirm those controls disappear and server-side requests are denied.
- Add a second independently keyed device to an existing Member and to the Owner. Confirm both devices share the intended member ID, each has unique WireGuard/mTLS material and address, and the final Owner device cannot be revoked.
- From the Owner, select a specific existing Member device and confirm ownership transfer. Verify the destination member's devices become Owner devices in one authorization state, the previous Owner becomes an Admin, both local profiles converge from live status, and the previous Owner cannot transfer again. Use the new Owner to transfer back, then confirm reinstall/uninstall identity checks accept only the restored current Owner.
- While a device invitation is active or its 60-second retry receipt exists, confirm changing that member's Admin level is rejected. Revoke a just-enrolled device and confirm its retry/bootstrap identity is removed immediately.
- Enroll a second test device and confirm both devices begin internet-only. Verify direct tunnel traffic remains blocked when neither or only one endpoint has peer access, becomes bidirectional only after both are enabled, and stops immediately when either is disabled or revoked. Throughout, verify private DNS, management access, and normal VPS internet egress remain available. Confirm a Member cannot change its own setting, an Admin can change only an ordinary Member device, and the Owner can change every device. Inspect the exact IPv4/IPv6 nftables sets after each mutation; stop the server and prove both sets empty, restart it and prove current authorization is restored. Repeat the address-family traffic check on a dual-stack VPS; the current IPv4-only managed VPS cannot supply that IPv6 release proof.
- For rollback proof, cancel/expire advanced invitations, wait at least 70 seconds after the final additional-device enrollment, confirm `active_invitations` and `enrollment_receipts` are empty, start the P1B1 server binary, and confirm enrolled devices retain VPN access while Admins safely lose management authority. Restore P1B2 afterward.
- Inspect `/etc/sirinvpn` permissions and confirm normal SirinVPN services produce no stdout/stderr history.
- Inspect package contents and verify the helper, server, CLI, polkit policy, desktop binary, and generated icons are present.
- Run the desktop at 760 by 620, 1220 by 780, and a wide layout; check keyboard focus, dialog focus trapping, empty/loading/error/degraded states, and reduced-motion behavior.
