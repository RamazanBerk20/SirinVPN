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

## WireGuard-only device migration

A device record without a management certificate is new in `server_authorization`.
A schema-6 reader would fail on it at load, so the writer moves to schema 7
whenever such a device exists and back down when the last one is removed:

| State | Before | Now | Shape |
| --- | --- | --- | --- |
| `server_authorization` | reads 1–6, writes 1–6 | reads 1–7, writes 1–7 | explicit schema 7 whenever a device has no `management_certificate_pem` |

Server authorization without such devices is read and written unchanged, and
existing devices serialize exactly as before, so the endpoint authorization
fingerprint of an unchanged document is stable. As with the preshared key
migration, a signed VPS transition to or from a release that cannot read
schema 7 is refused in both directions.

## WireGuard preshared key migration

The per-device preshared key changes four declared state families. Each
older reader would have accepted the new shape and silently dropped the key,
which leaves that device's peer and client disagreeing and its handshake
failing, so each family moves to a schema an older reader rejects:

| State | Before | Now | Shape |
| --- | --- | --- | --- |
| `linux_identity_record`, `windows_identity_record`, `android_identity_record` | reads 1–2, writes 2 | reads 1–3, writes 2–3 | implicit schema 3: `SecretIdentity` may carry `wireguard_preshared_key` |
| `device_backup_payload` | reads 1–2, writes 2 | reads 1–3, writes 2–3 | explicit schema 3 whenever the identity carries a key |
| `server_authorization` | reads 1–5, writes 1–5 | reads 1–6, writes 1–6 | explicit schema 6 whenever a device or pending rotation carries a key |

`TunnelConnectRequest` (and the Linux desired/runtime records and Windows
session that embed it) keeps its schema numbers; the key is an optional
field that helpers before this change reject through `deny_unknown_fields`.
Signed client updates already refuse that rollback through the identity
families above, which ship in the same artifact.

| Existing state | Candidate behavior |
| --- | --- |
| Device identity without a key | Read unchanged and written back in the same shape. The tunnel runs without a key, exactly as before. |
| Server authorization without keys | Read unchanged; it stays at its previous schema until a device first stores a key. Peers without a key keep working beside peers with one. |
| Device backup schema 1 or 2 | Imported unchanged. A key-bearing identity labelled 1 or 2 is rejected as malformed. |
| Existing device on an upgraded VPS | Gains a key at its next key rotation over the pinned management channel; re-enrollment is not needed. |
| New client, older VPS | The VPS ignores the offered key and does not confirm it; the client drops the key before saving the profile (enrollment) or never offers one (rotation, gated on `preshared_keys_enabled`). |
| Owner provisioned over SSH or recovered offline | Starts without a key; rotate once to add one. |

The updater still requires both readers to cover both writers, so a signed
transition between this release and one that predates the key is refused in
both directions, on the client and the VPS. This matches the first-install
boundary above: there is no qualified release to upgrade from. After a
release is qualified, a further format change of this kind needs the
expand-then-write sequence in [releases.md](releases.md).

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
