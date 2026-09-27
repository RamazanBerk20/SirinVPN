# 0.1.1 candidate qualification

This is the qualification and migration policy for the next engineering
candidate. It does not authorize a public release. Observed results, remaining
limitations, source commits and package hashes are recorded in
[the remediation ledger](remediation.md). A passing test of another commit or
another package is supporting history, not qualification of this candidate.

## Freeze and preserve evidence

Commit implementation, tests, packaging inputs and notice provenance before
building the candidate. Run `scripts/record-evidence.py --frozen-source` for its
builds and checks. `--artifact` names a build output; `--tested-artifact` names
an existing input and rejects any change to its bytes during the check. Include
the installer/APK/AppImage itself, not just an extracted executable, when
recording package acceptance. Preserve build profile and signing category.

All qualifying records must name the same source commit, a clean source tree,
unchanged source during execution, and the appropriate exact artifact hashes.
Native unit tests and native installed-package acceptance establish different
claims. Keep them separately identifiable. Cross compilation is a build check.
A debug-signed Android APK or an unsigned Windows driver is an engineering
artifact regardless of optimization level.

Keep compact, sanitized reports and their input/output hashes in version
control. Preserve the corresponding synthetic raw logs and package files in a
durable candidate archive. CI's 14-day artifacts are a transfer mechanism;
their successful upload is not long-term preservation. A later evidence-only
commit may describe an earlier frozen candidate, but must retain that
candidate's original commit and hashes. Rebuilding requires new artifact
records and affected acceptance checks.

## Supported first-public-release migration

There has been no qualified production release. The supported boundary is a
first production installation, including an **unbound development installation**
whose existing profile formats are understood. Do not invent a backwards
compatibility declaration for an old binary or weaken the signed updater.

| Existing state | Candidate behavior |
| --- | --- |
| Linux legacy identity file or keyring entry | Read the existing identity; retain provenance/availability reporting. Keyring migration remains explicit and verifies readback before removing the old file. |
| Android existing encrypted identity | Retain the existing package identity and Keystore keys during a same-signer OS update; preserve deletion journals/tombstones. |
| Windows existing DPAPI identity without a marker | Read the original encrypted format. New deletion records durable schema-2 intent before removing the blob, and seals the reference against later writes. |
| Interrupted Windows deletion | Refuse reads and writes to that reference; retry cleanup. Process termination and separate-process writer regressions run on native Windows. |
| Server without a recovery intent | Read the existing authorization/configuration formats normally. A retained recovery intent must reconcile before mutations resume. |
| Older signed receipt missing required state families | Reject the transition, including an explicitly requested incompatible rollback. Do not delete or rewrite the receipt to force installation. |

An installation already bound to an incompatible experimental signed receipt
needs a separately reviewed migration. It is not covered by this first-install
qualification. The current updater cannot add a missing state family through
an ordinary expand/read/write transition. The reader/writer checks must remain
intact.

Before replacing a development installation, verify an encrypted backup and
its recovery path in an isolated fixture. Keep the old installation disconnected
while exercising a restored identity. Preserve profile and credential data
through in-place installation and interrupted-install retry tests; compare
their contents without exporting secret values into reports. Do not uninstall
or clear application data as part of an in-place upgrade test.

Android additionally requires the same signing identity for an in-place update.
Changing from the development signer to a production signer needs an explicit
backup/restore migration into the new installation; a successful debug update
does not qualify that migration. Do not remove the old app before validating
the backup/recovery path. Once a deletion has been recorded, an older binary
that ignores its marker is an unsupported rollback target on every platform.

## DNS acceptance boundary

Retain the original counter failures. Their counter-only records cannot recover
packet timestamps, processes or firewall decisions after the fact. Successful
repeats and a constructed counter false positive do not attribute those events.

`tests/vm/dns_attribution.py` operates only in disposable marked VMs. It records
bounded packet metadata, kernel packet timestamps, nftables trace/rule events,
allowlisted connection-state transitions and synthetic-probe process identity.
It exercises a disconnected negative control, forced UDP fallback with a probe
bound to the physical interface, and a narrowly scoped deliberate escape to
verify that the detector catches a protected-interval violation. It removes
its injected rule afterwards. It captures no packet payload or real user's DNS
history. An nftables notification timestamp is an upper bound on rule
installation, not the exact kernel commit timestamp; preserve this limitation
when interpreting the trace.

Ordinary fallback capture begins before Disconnect and retains its pre-Connect
counter snapshot. Require **zero new DNS packets** from that snapshot through
completed fallback, including the interval before the guard is armed; an
already nonzero disconnected count is not itself a connection leak. Counter
decreases also fail. IPv6 remains at zero. No TCP flags or payload size are
exempted from this gate. Keep the original absolute-counter failures separately.

Do not mark the historical DNS issue explained unless the retained evidence
supports the explanation. If an actual protection failure is reproduced, fix
its owner and retain the reproducing test. If a measurement error is proven,
state the corrected boundary and retain controls that fail when real protected
traffic escapes.

## Distribution materials and signing review

`scripts/create-release-materials.py` keeps the full locked build inventory and
also exports per-artifact selected inputs, missing-notice review items and a
notice ZIP bound to each artifact hash. The target-specific dependency closure
is conservative: it does not claim that every dependency symbol survives
linking or Android R8. Supplemental notices in
[`release/publisher-notice-sources.json`](../release/publisher-notice-sources.json)
bind to exact dependency bytes and publisher source evidence. Missing evidence
is not silently treated as permission to omit a notice.

AppImage packaging also runs `scripts/collect-appimage-notices.py` in its Debian
builder. It identifies bundled system ELF files using the builder's package
database and ELF build IDs, retains original and bundled hashes, and embeds
package copyright files plus the referenced Debian common licenses. Application
dependencies, the launcher/runtime and external SDK payloads remain separately
identifiable. Include the applicable source/notice material with distribution;
an inventory alone is not completion of its distribution obligations.

Before public signing, review the offline release-root custody and recovery,
production Android signer and migration, Windows publisher/driver signing,
final dependency dispositions, artifact notices/source obligations, and any
unresolved acceptance findings. Use the existing offline signing workflow in
[releases.md](releases.md). Do not create a replacement trust root or call a
development signature production approval. Sign the reviewed files, then
record and verify the final signed bytes and repeat affected installation
checks before publication.
