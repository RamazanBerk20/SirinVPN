# Linux acceptance, 7–8 September 2026

The Linux Debian CLI/helper acceptance phase passed: **15 kernel cases and all
22 packaged checks**, including setup, fault injection, reboot and removal.
Three product bugs found during testing were fixed and verified in a fresh run
of the rebuilt package, without diagnostic overrides. This is not whole-product
or production certification.

## Accepted artifacts

The [Linux handoff](../target/deliverables/2026-09-08/README.md) contains:

| Artifact | Qualification |
| --- | --- |
| [Debian package](../target/deliverables/2026-09-08/SirinVPN_0.1.0_amd64.deb) | Static inspection and the complete packaged CLI/helper VM run |
| [AppImage](../target/deliverables/2026-09-08/SirinVPN_0.1.0_amd64.AppImage) | Rebuilt and statically inspected; AppImage runtime/GUI acceptance remains pending |

Both are unsigned release builds. The accepted Debian SHA-256 is
`0a9909f03b4cceade1d9453bfda12398c0dd9e8bd03a52761ceee3c519e0fbf2`.
The handoff includes checksums, source-file hashes and evidence records.

All privileged test operations run inside disposable Debian 13 QEMU guests.
The workstation's VPN, firewall, routes, Polkit rules and sudo configuration
are not test fixtures. The lab runs as the ordinary host user, with a combined
4 GiB memory limit, no swap and 150% CPU. Compilation runs separately under
equivalent limits. See the [lab instructions](../tests/vm/README.md).

## Kernel results

All 14 deferred installer, helper and server tests passed across 15 cases on
Debian kernel `6.12.107+deb13-cloud-amd64`. Each case ran in a fresh container
inside the VM, with external networking disabled after setup. The extra case
tests application routing with global IPv6 forwarding both disabled and enabled.
The [result record](audit/2026-09-07/linux-acceptance/kernel-results.json) includes
input hashes and individual outcomes.

The initial run exposed missing IPv6 forwarding prerequisites in the new runner.
Server-policy fixtures now match the forwarding settings installed on a VPS.
On this older kernel, application IPv6 must remain blocked when forwarding was
initially disabled; with forwarding enabled, IPv6 delivery and address rotation
must work. Both cases require ordinary host networking and the global forwarding
setting to remain unchanged. These were fixture corrections.

## Fresh provisioning bug

The original Debian deliverable installed successfully and its helper passed
guest Polkit authorization, but provisioning a fresh VPS failed during release
state inspection. An absent optional release record produced an empty SSH reply,
which the shared binary reader correctly rejected for required artifacts.

The installer now distinguishes absence with an explicit byte marker. Existing
records retain their size, ownership, mode and symlink checks; malformed presence
markers and empty required responses still fail. The installer unit suite passed
31 tests with four isolated checks excluded from that ordinary run. Clippy passed
for all installer targets with warnings denied, and 157 frontend tests passed
during the Linux rebuild. See the [regression record](audit/2026-09-07/linux-acceptance/installer-regression.json).

The rebuilt package passed static inspection. In fresh guests, provisioning then
succeeded and the extended root staging regression passed, including rejection of
empty, oversized and symlinked records. The original seven-artifact delivery
remains a historical build snapshot. Its Windows and Android binaries predate
this shared installer fix and need rebuilding before their acceptance run.

## Packaged runtime checks

The runtime run passed direct UDP, obfuscated UDP, TLS and TCP transport checks:
actual VPS exit, native DNS, physical IPv6 blocking, direct DNS suppression and
network restoration after disconnect. Public HTTPS and resolver-loss recovery
passed on direct WireGuard. TLS recovered after its relay process was killed.

Blocked-UDP testing found that `sirinvpn-reconnect.service` could not save its
connection state under `ProtectSystem=strict`. Its first privileged connection
worked, but recovery repeatedly exited when writing `/var/lib/sirinvpn`. The
service now grants write access to that directory. The final package recovered
through TLS in 58 seconds after 10 observed dropped UDP packets, with no guest
override.

Removing the active Debian package then left the tunnel, firewall and desired
connection behind after deleting the helper executable. The package now invokes
Disconnect from `prerm`, while the helper and its units still exist, and refuses
removal if cleanup fails. Installation and removal hooks reload systemd's unit
definitions. The package inspector verifies all three maintainer scripts.

The final [22-check record](audit/2026-09-07/linux-acceptance/linux-results.json)
also passed abrupt client power loss, blocking while the VPS remained unreachable,
automatic recovery when access returned, explicit disconnect, active package
removal, reinstall for owner cleanup, VPS uninstall and final client removal.
The observed physical DNS and IPv6 probe counters stayed at zero during the
protected checks. All guest disks and temporary keys were cleaned up.

An early HTTP probe failure came from the test responder's lifetime TCP stream,
not DNS resolution: the native resolver returned the correct VPS record. The
fixture now starts a bounded responder for each QEMU guestfwd connection. Each
response identifies the exit and the particular test run.

Both guests share the workstation's external connection. Separate synthetic exit
responders prove which VM forwarded the traffic; they do not demonstrate a change
of public IP or real-world censorship resistance. The restart probes run after
the guest-agent channel becomes available and do not capture every early-boot
packet. The kernel matrix and packaged sequence provide distinct evidence.

The desktop GUI, physical network roaming, Windows and Android runtime acceptance,
remaining platform features, dependency review, production signing and broader
release qualification remain separate work.
