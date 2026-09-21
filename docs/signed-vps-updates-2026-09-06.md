# Signed VPS updates — 6 September 2026

The Owner can check an explicitly chosen HTTPS release directory, review a
verified server release, install its exact manifest, recover an interrupted
update, or confirm rollback to the retained previous release. The desktop VPS
Update dialog and `sirinvpn server release` use the same pinned SSH and current
Owner-identity checks. SSH credentials do not enter the update policy or release
records. Restarting operations require the local VPN and persistent protection
to be disconnected, with no pending device-key rotation.

## Trust and the initial baseline

The existing compiled offline root authenticates the release-key policy. The
policy authenticates the manifest and selected `server_elf` artifact for
`x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu`. VPS state is separate
from desktop package state, under `/var/lib/sirinvpn-server-release`.

A baseline receipt is registered only when the installed executable exactly
matches authenticated artifact bytes. For an older installation, the desktop can
download and review a signed baseline on the computer, then install it through
guarded SSH repair. The installer retains immutable verified bytes, compares the
incoming policy against any root-signed policy already remembered by the VPS,
and rechecks the inspected receipt/policy under the maintenance locks. Only then
does it copy the candidate into root-private staging, verify its digest and
execute its compatibility checks. Changing the SSH user's staging files cannot
change that private executable.

An existing signed receipt makes ordinary repair preserve the exact committed
server artifact from the authenticated VPS cache. An older desktop therefore
cannot downgrade a newer signed server while changing DNS or repairing its
configuration. A damaged receipt/cache is an error. A remembered signing policy
without a baseline requires verified baseline installation before executable
repair; the unsigned bundle cannot bypass that policy.

First-baseline registration follows the guarded installation. If registration
fails, the result says so; checking the matching installed signed release can
retry registration. Production root custody and publication signing remain the
release-engineering requirements described in [Signed releases](releases.md).
No production signing key is needed by the ordinary test suites.

## Updates and recovery

Manual installation is bound to the reviewed manifest SHA-256. The root updater
reverifies signatures, the current signing policy, artifact bytes, release
sequence, version, target and server-state compatibility. A manual upgrade must
respect the highest accepted release; explicit rollback preserves that high
watermark. Revoked release keys cannot authorize new installation or rollback.
Cross-key rollback remains unsupported by the schema-1 receipt.

Both releases must read all relevant server state the other can write. VPS
planning excludes unrelated Android and Windows state formats. The signed
contract and executable capability report require the handoff firewall guard,
persistent maintenance guard, release transaction and security-policy support.
The candidate also validates actual configuration and authorization before
replacement. Live authorization is quiesced for the final compatibility checks.

A durable journal retains the authenticated previous and candidate releases.
The server executable is atomically replaced; health checks require a stable
systemd process, its actual management and transport listeners, WireGuard's
configured port, and the required network, firewall and DNS services. After
receipt commit, the independent recovery coordinator is refreshed and the
previous artifact is retained for eligible rollback. If an update fails before
commit, recovery restores the previous executable without rewinding identity,
authorization, policy revocations or release high watermarks. If commit already
occurred, recovery finalizes the candidate. An unresolved recovery retains the
journal and necessary authenticated artifacts.

`network.sh up` resolves a pending executable transaction before creating the
VPN interface. SSH install/repair/removal uses a separate persistent guard under
`/var/lib/sirinvpn-maintenance`. A boot dependency blocks the VPN network until
pending maintenance restoration succeeds. Backups are taken after authorization
writers stop. Repair rollback retains the latest authorization, including
revocations accepted during candidate health checks or a partially failed
rollback. A synced commit marker prevents a reboot during cleanup from undoing
a completed operation. Completed recovery or commit removes the temporary
private backups, guard units and owned dependency drop-in.

## Optional security schedule

Automatic VPS security updates are **off by default** and have no default URL.
The Owner must explicitly save a source and enable the daily VPS timer. Only a
stable release carrying the signed security-update flag and a sequence strictly
above the highest accepted release is eligible. The timer cannot immediately
undo an explicit rollback by replaying the previously accepted release.

Downloads run as a dedicated non-login account without access to VPN private
state. The fetcher rejects URL credentials, queries, fragments, redirects and
proxies, and reuses the bounded public-metadata/artifact protocol. Root imports
and verifies the resulting files again. The VPS stores only its current policy
and latest outcome, with no event history or diagnostic upload. Disabling the
schedule stops the timer. See [Privacy](../PRIVACY.md).

## Focused validation and acceptance boundary

The release tests cover signature/cache tampering before execution, compatible
upgrade and explicit rollback, release high watermarks, signing-key revocation,
incompatible state, missing guards, failed health, and interruptions at every
host boundary before and after receipt commit. Separate policy tests exercise
the stable/security/high-watermark eligibility conditions.

Installer tests execute the generated rollback shell against isolated files,
including interruption after old files are restored, authorization changes after
a failed restart, incomplete snapshots, and committed cleanup. Service commands
are simulated in these tests. `systemd-analyze verify` validates the generated
recovery dependency graph without starting services. The ordinary-container
root staging test checks source tampering and receipt/policy races:

```sh
./tests/network/run-installer-release-guards.sh
```

That runner has explicit CPU, memory and process limits, no networking, no added
capabilities and no privileged container mode. Full systemd/ELF listener health,
hard-reboot recovery and the complete UI-to-VPS flow still require acceptance on
the final artifacts in a disposable VM or designated test VPS. The library and
file tests do not establish that platform acceptance. No live VPN or VPS was
used for these focused checks.

CLI operations are `status`, `check --source … --channel stable`,
`install --manifest-sha256 …`, `rollback --confirmed`, `recover`, and
`configure --enabled --source …`. Omit `--enabled` to disable the schedule.
`bootstrap --bundle /absolute/verified/bundle --manifest-sha256 …` installs a
reviewed local baseline bundle when the VPS has no signed receipt. Each command
uses `sirinvpn server release SERVER --host-key FINGERPRINT` and the normal SSH
authentication options.
