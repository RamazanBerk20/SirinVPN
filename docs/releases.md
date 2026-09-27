# Signed releases

This describes the release mechanism, not a currently qualified production
release. Consult the [remediation release checklist](remediation.md) before
building or distributing a candidate. The new credential tombstone/provenance
formats and server recovery intent add state requirements. Existing signed
manifests with older state families are intentionally incompatible under the
current bidirectional compatibility check. A reviewed bridge/first-install
strategy is required; do not weaken validation to force an upgrade or downgrade.
Local development APK signing and unsigned Linux engineering packages do not
establish production signing custody or native Windows qualification.

SirinVPN's P2T/P2U/P2V/P2W release coordinator is deliberately offline. It creates and verifies an Ed25519-signed canonical manifest for local release artifacts, authenticates release signing keys beneath a bundled offline root, plans configuration-compatible transitions, maintains root-owned trust and installed-package state, and can transactionally replace an already bound Debian package. P2X adds a separate unprivileged HTTPS fetcher that can create one authenticated local candidate bundle without giving network access to that coordinator. P2Y adds a manual desktop review and Debian-install confirmation around those two existing boundaries. The separate [signed VPS updater](signed-vps-updates-2026-09-06.md) now binds server ELF artifacts, supports compatible rollback, and provides an explicitly enabled security-update schedule on the VPS.

## Release trust hierarchy

The immutable public root in `release/release-trust-root.pub` is compiled into `sirinvpn-release`. Its SHA-256 key ID is:

```text
0ff86fa15621859d9145a63b4d3690fd7de3ec4946f8ca7d0645b870ceec954b
```

`sirinvpn-release trust root` prints the compiled value. This checked-in key is a pre-distribution bootstrap anchor generated during development. Its private half is not in the repository, but it must be moved to encrypted offline storage and backed up—or the public anchor must be deliberately replaced—before the first public release. Replacing it after distribution is a binary migration, not a policy update.

The root private key signs release-key policies only. Ordinary releases use separate, replaceable Ed25519 keys. Generate each key on an offline encrypted system; the command refuses to replace either output and creates the private key with mode `0600`:

```sh
mkdir -m 0700 /secure/path/sirinvpn-release-key
cargo run --locked -p sirinvpn-release -- keygen \
  --private-key /secure/path/sirinvpn-release-key/private.pem \
  --public-key /secure/path/sirinvpn-release-key/public.pem
```

Create the first canonical trust policy with the root private key and one active release public key:

```sh
cargo run --locked -p sirinvpn-release -- trust create \
  --sequence 1 \
  --release-key /secure/path/sirinvpn-release-key/public.pem \
  --root-private-key /offline/root/private.pem \
  --policy /trusted/policy/sirinvpn-release-trust.json \
  --signature /trusted/policy/sirinvpn-release-trust.sig.json
```

The policy sequence is a positive global trust-policy counter, independent of stable/preview release sequences. A policy contains 1–16 canonical active release public keys and up to 128 sorted revoked key IDs. The root key cannot appear in either set. Both outputs are bounded, strict canonical JSON; the detached Ed25519 signature uses a trust-policy-specific domain distinct from release manifests.

Back up every private key separately and never add one to this repository, a build image, an application package, or CI output. A release bundle may carry the public root-signed policy because its authenticity does not depend on the download location.

Verify a policy with the root compiled into the exact binary that will consume it:

```sh
cargo run --locked -p sirinvpn-release -- trust verify \
  --policy /trusted/policy/sirinvpn-release-trust.json \
  --signature /trusted/policy/sirinvpn-release-trust.sig.json
```

## Build and sign Linux artifacts

Build release-compatible Linux packages first:

```sh
./scripts/package-linux-container.sh
mkdir -p target/signed
env \
  SIRINVPN_RELEASE_TRUST_POLICY=/trusted/policy/sirinvpn-release-trust.json \
  SIRINVPN_RELEASE_TRUST_SIGNATURE=/trusted/policy/sirinvpn-release-trust.sig.json \
  ./scripts/sign-linux-release.sh \
    /secure/path/sirinvpn-release-key/private.pem \
    1 \
    target/signed/0.1.0 \
    stable
```

The sequence is a positive, globally monotonic number for that channel. Mark a release that contains a security fix by adding `security` as the final argument. Preview versions must use the `preview` channel; stable manifests reject SemVer prereleases.

The signing script refuses an existing destination, copies exactly one `.deb` and one AppImage into a staging directory, hashes their complete bytes, and creates `sirinvpn-release.json` plus `sirinvpn-release.sig.json`. When both public trust-policy environment paths are set, it also stages them under their canonical names and proves the bundled root authenticates the policy and that the policy authorizes the release signer. Supplying only one path fails. It does not copy or print either private key. Omitting both trust paths retains the legacy externally pinned engineering bundle format; do not publish that form as a production update.

## Verify a release

Verify a production-form directory through the root-signed policy it carries:

```sh
cargo run --locked -p sirinvpn-release -- verify-trusted \
  --manifest target/signed/0.1.0/sirinvpn-release.json \
  --signature target/signed/0.1.0/sirinvpn-release.sig.json \
  --trust-policy target/signed/0.1.0/sirinvpn-release-trust.json \
  --trust-signature target/signed/0.1.0/sirinvpn-release-trust.sig.json \
  --artifact-directory target/signed/0.1.0
```

Verification first authenticates the policy with the compiled root, rejects a revoked or absent release signer, then requires canonical bounded release JSON; the exact product, channel, SemVer, and sequence shape; a strict Ed25519 signature; safe single-component artifact names; exact sizes and SHA-256 digests; unique target slots; and regular non-symlink files. Unknown fields and malformed or noncanonical values fail closed. The legacy `verify --trusted-public-key` command remains available for pre-policy engineering bundles only.

## Fetch a candidate over HTTPS

Linux packages include `/usr/lib/sirinvpn/sirinvpn-release-fetch` as a separate unprivileged process. SirinVPN has no compiled default update host: provide an explicit HTTPS directory that represents the desired channel and contains the four canonical metadata files plus every artifact named by its manifest. The URL must end in `/` and cannot contain credentials, a query, or a fragment:

```sh
/usr/lib/sirinvpn/sirinvpn-release-fetch --json \
  --source https://updates.example/sirinvpn/stable/ \
  --channel stable \
  --artifact-kind linux_deb \
  --artifact-target x86_64-unknown-linux-gnu \
  --output /absolute/existing-parent/sirinvpn-candidate
```

The fetcher makes these requests in order:

```text
sirinvpn-release-trust.json
sirinvpn-release-trust.sig.json
sirinvpn-release.json
sirinvpn-release.sig.json
<the selected signed artifact filename>
```

It authenticates the first pair with the bundled root and the second pair with an active, non-revoked policy key before requesting the artifact. It also requires the requested channel and exact artifact kind/target. The client uses native CA verification, direct HTTPS with no environment/system proxy, no redirects or referer, identity response encoding, a 10-second connect timeout, 30-second per-read timeout, and 15-minute total timeout per request. Metadata retains its existing 256 KiB/128 KiB/8 KiB limits; an artifact cannot exceed the signed length or the global 1 GiB release limit. HTTP status other than 200 fails.

`--output` must be a normalized absolute path below an existing real directory and must not exist. Bytes first enter a random private sibling staging directory. Only after the selected artifact's signed size and SHA-256 pass are every file and directory synced and the complete tree atomically renamed without replacement. The resulting bundle directory and its `artifact/` child have mode `0700`; all four metadata files and the artifact have mode `0600`. Ordinary errors remove staging and never expose the requested output. Forced process or machine termination may leave only a mode-`0700` `.sirinvpn-release-fetch.*` staging directory in that parent; it is not a valid candidate and may be removed after confirming no fetch process owns it.

The returned bundle is not installed and does not modify `/var/lib/sirinvpn-release`. Feed its two trust files to `state apply-trust`, then use its manifest/signature and `artifact/` directory with `state plan` or `state install-debian`. Those root-owned commands independently revalidate the complete chain and enforce installed policy and release high watermarks. A source can therefore withhold a release or replay older authentic bytes, but cannot make the installed path accept a forged or rolled-back release.

One explicit fetch necessarily reveals the client's source IP, request timing, channel directory, and selected artifact filename to the chosen source and normal DNS/network infrastructure. The requests contain no account, device, installation, VPS, server, user, analytics, or random request identifier; their paths contain no query; the stable user agent contains no software or device-specific value; and no source/check history is retained. Use a trusted mirror or self-hosted static HTTPS directory when avoiding a project-operated endpoint is important.

## Check and install from the Linux desktop

Open **App updates**, select Stable or Preview, and enter the same explicit HTTPS directory described above. The application performs no launch or background check and stores no source. It invokes the packaged unprivileged fetcher, retains one verified candidate in a private session temporary directory, and displays its authenticated version, release/policy sequences, target, root/release signer IDs, package name, size, and SHA-256. Discarding the dialog, starting another check, or ordinary exit removes that candidate. Hard termination can leave only a private `sirinvpn-desktop-release.*` tree in the system temporary directory; after confirming no check is active, it can be removed like the fetcher staging residue described above.

The Debian **Install authenticated update** action is deliberately separate. It is enabled only for a newer candidate while SirinVPN is fully disconnected with persistent protection disabled, and only when the running app is `/usr/bin/sirinvpn-desktop` from the installed Debian package with a safe root-owned coordinator. The user confirms the exact candidate, then the desktop invokes fixed `/usr/bin/pkexec` and `/usr/lib/sirinvpn/sirinvpn-release` paths without a shell. The coordinator independently applies the root-signed trust policy and runs `state install-debian`; it does not trust the webview's summary. Supported user-owned AppImages use the separate rootless replacement flow described in [client update completion](feature-completion-2026-09-08.md).

Trust-policy application and package installation are separate root operations. A valid newer policy may remain installed if authorization is cancelled or the later package transaction fails. That does not advance the package receipt: the coordinator attempts authenticated rollback, and if it cannot prove completion it retains both packages plus the journal for explicit or idempotent recovery. Retrying the same candidate is safe. The desktop never passes `--allow-rollback`. As with the CLI transaction, the installation must already have a P2U/P2W trust baseline, receipt, and authenticated current-package cache; release engineering must initialize that baseline before publishing desktop-consumable updates.

## Rotate or revoke a release key

Use an overlap policy for planned rotation:

1. Generate the successor release key offline.
2. Create policy sequence `N+1` with one `--release-key` for the old public key and another for the successor. Apply it before distributing a successor-signed release.
3. Sign a strictly newer release above the installed high watermark with the successor key. The trusted installed-state path may then move the receipt's single schema-1 key pin to the successor.
4. Create policy sequence `N+2` with only the successor active, repeat every previously revoked ID, and add `--revoke-key-id OLD_KEY_ID`. Apply it after the successor release is active.

For emergency revocation, a newer root-signed policy may immediately revoke the compromised key as long as at least one successor remains active. A removed active key must enter the revoked set, and installed state never permits an older policy, changed policy bytes at the same sequence, or omission of an earlier revocation. Root policy signatures therefore cannot silently restore a retired key. Cross-key release rollback and same-manifest rebind are rejected; use a new forward release signed by an active key. Replacing the bundled root itself is deliberately outside P2W.

## Plan an update or rollback

The standalone `plan` command is the legacy single-key engineering planner: both installed and candidate manifests must be signed by its explicitly supplied key. The candidate artifacts must also be present and valid. Policy-authorized cross-key planning happens through `state plan` after `state apply-trust`.

```sh
cargo run --locked -p sirinvpn-release -- plan \
  --current-manifest /trusted/installed/sirinvpn-release.json \
  --current-signature /trusted/installed/sirinvpn-release.sig.json \
  --candidate-manifest target/signed/0.2.0/sirinvpn-release.json \
  --candidate-signature target/signed/0.2.0/sirinvpn-release.sig.json \
  --trusted-public-key /trusted/path/public.pem \
  --candidate-artifact-directory target/signed/0.2.0
```

Version and sequence must both increase. Selecting an older pair also requires `--allow-rollback`. The current and candidate manifests must declare the same persistent-state set. For every state, the candidate reader must cover every schema the current release may write, and the current reader must cover every schema the candidate may write. This second condition is the rollback guarantee.

Use an expand/migrate/contract sequence for a format change:

1. Expand readers while continuing to write the old schema.
2. In a later release, write the new schema only after the previous release can read it.
3. Contract obsolete readers only after the transition window.

The authoritative current declarations are in `release/state-compatibility.json`. `linux_identity_record` names the current unwrapped `SecretIdentity` JSON shape as implicit schema 1 so it cannot be forgotten during a future envelope migration. `linux_release_receipt` covers the P2U root-owned receipt, `linux_release_transaction` covers P2V's cached package and interruption journal, and `linux_release_trust` covers P2W's current root-signed policy. Change declarations only with the matching reader/writer implementation and migration tests; signed transitions reject adding or removing a persistent-state family.

## Linux installed trust and release receipt

Linux packages include `/usr/lib/sirinvpn/sirinvpn-release`. Its `state` commands always use `/var/lib/sirinvpn-release`, require root authorization, and never accept an alternate production state path. Apply the root-signed policy first:

```sh
sudo /usr/lib/sirinvpn/sirinvpn-release state apply-trust \
  --policy /trusted/candidate/sirinvpn-release-trust.json \
  --signature /trusted/candidate/sirinvpn-release-trust.sig.json
```

This creates or atomically replaces canonical mode-`0600` `trust.json` under the existing mode-`0700` release-state directory and receipt lock. `state inspect-trust` reports only its public sequence, digest, root ID, active IDs, and revoked IDs. Exact reapplication is byte-preserving. A newer policy must retain every earlier revocation and must explicitly revoke every active key it removes.

First preflight then validates the manifest with an active policy key and only the exact artifact kind/target being installed without creating receipt/package state:

```sh
sudo /usr/lib/sirinvpn/sirinvpn-release state plan \
  --manifest /trusted/candidate/sirinvpn-release.json \
  --signature /trusted/candidate/sirinvpn-release.sig.json \
  --artifact-directory /trusted/candidate \
  --artifact-kind linux_deb \
  --artifact-target x86_64-unknown-linux-gnu
```

Only after the exact first package operation succeeds, repeat the verification and commit its binding:

```sh
sudo /usr/lib/sirinvpn/sirinvpn-release state commit-installation \
  --manifest /trusted/candidate/sirinvpn-release.json \
  --signature /trusted/candidate/sirinvpn-release.sig.json \
  --artifact-directory /trusted/candidate \
  --artifact-kind linux_deb \
  --artifact-target x86_64-unknown-linux-gnu
```

Use the build host target printed by `rustc -vV` for `--artifact-target`; choose `linux_appimage` for the signed AppImage. A trusted release must declare read/write support for `linux_release_trust` schema 1 and read support for `linux_release_receipt` schema 1; the ordinary transition planner separately constrains what either release may write. A pre-P2U/P2W binary is not a valid rollback target after this initialization. The first receipt commit pins the active policy-authorized public key and creates a canonical mode-`0600` receipt plus a mode-`0700` package-cache directory containing one independently re-hashed mode-`0600` copy of the selected artifact. The receipt embeds the active manifest/signature and selected artifact plus the independently signed highest accepted manifest/signature. It contains no timestamp or installation, device, server, account, request, network, or activity identifier.

Every later plan and commit revalidates the installed root policy, existing receipt, candidate signature, selected artifact bytes, release track, monotonic version/sequence relationship, and bidirectional schema compatibility. Exact retries return `already_bound` without replacing the receipt. A different declared artifact for the same manifest returns `rebind` only under the same release key. A new release must exceed the highest sequence; reusing an active/highest sequence for different signed bytes is rejected. A different active policy key may replace the receipt pin only on a strict upgrade above that watermark.

An older same-key release requires `--allow-rollback` on both preflight and commit. Rollback changes only the active binding and retains the signed high watermark, so a silent replay cannot redefine the newest accepted release. The exact high-watermark release may be installed again; an intermediate sequence below that watermark is not treated as a normal upgrade. Cross-key rollback is rejected even when both keys remain active.

Inspect the validated summary with:

```sh
sudo /usr/lib/sirinvpn/sirinvpn-release state inspect
```

Trust, receipt, and package-cache replacement are serialized and use flushed temporary files, atomic state rename, no-clobber content-addressed package placement, and directory fsync. Unknown or noncanonical JSON, future schema, changed signatures or cached bytes, unauthorized/revoked key replacement, invalid active/highest relationships, symlinks, hard links, and incorrect owner/mode fail closed. Missing receipt state remains a supported first-install condition after policy initialization. Once `trust.json` exists, supplying `--trusted-public-key` is rejected rather than treated as an override. The flag remains available only for legacy state with no policy; an existing receipt may adopt its first policy only when both retained manifests already support trust schema 1 and that policy authorizes its pinned key. Root can ultimately replace the application and state and is outside this local anti-rollback boundary.

## Offline transactional Debian update

The transactional command accepts only the signed `.deb` already present in the caller-selected directory. It requires an existing receipt whose active artifact is a same-target `.deb`; this is intentional because an unbound installation has no authenticated package to restore. Disconnect first and turn off persistent protection, then run:

```sh
sudo /usr/lib/sirinvpn/sirinvpn-release state install-debian \
  --manifest /trusted/candidate/sirinvpn-release.json \
  --signature /trusted/candidate/sirinvpn-release.sig.json \
  --artifact-directory /trusted/candidate \
  --artifact-target x86_64-unknown-linux-gnu
```

Add `--allow-rollback` only when deliberately installing an older compatible signed release. The command takes the receipt lock and `/run/sirinvpn/operation.lock`, so receipt mutation and tunnel connect/disconnect cannot overlap the package transaction. It rejects active, degraded, connecting, or persistent-reconnect state. Both manifests must read and write `linux_release_transaction` schema 1.

Before invoking `dpkg`, the coordinator revalidates the installed root policy, pinned receipt/key and current package cache, copies and re-hashes the candidate into root-owned state, verifies both `.deb` control records as package `sirin-vpn` with the exact manifest version and `amd64`/`arm64` architecture implied by the signed Rust target, and atomically records `/var/lib/sirinvpn-release/debian-update.json`. It invokes fixed `/usr/bin/dpkg` with a sanitized noninteractive environment and no shell.

Candidate health requires the exact package to be configured at the expected version, no output from `dpkg --verify`, five fixed root-owned non-group/world-writable executables, the expected output from the newly installed release tool's `--version`, and a still-disconnected helper with no persistent desired connection. Only then is the receipt atomically advanced as the final commit marker. Completion removes the journal and prior package; no update list is retained.

Any failed install or candidate health check immediately reinstalls and verifies the authenticated previous package. The command exits unsuccessfully even when that rollback succeeds, making the failed update visible while leaving the old receipt/package active. If rollback or final cleanup cannot be proven, it retains both packages and the canonical journal. Resolve that state idempotently with:

```sh
sudo /usr/lib/sirinvpn/sirinvpn-release state recover-debian
```

Recovery reads no caller-selected artifact: an old receipt causes the old cached package to be reinstalled, while an already advanced receipt causes the healthy candidate to be finalized. A later `install-debian` invocation performs the same pending recovery before evaluating its candidate. If the installed release executable itself is unavailable after an abrupt `dpkg` interruption, an operator must first use Debian's package tools with the authenticated `.deb` retained under `/var/lib/sirinvpn-release/packages/`; automatic boot wiring is not part of P2V.

The opt-in full-package gate in [Testing](testing.md#full-package-release-interruption-gate) proves both receipt interpretations across hard Debian 13 VM reboots. Its exact crash points exist only behind the non-default `test-release-fault-injection` feature and run from a separate test coordinator; normal packaged binaries contain no enabled fault path.

## Current boundary

P2T/P2U/P2V/P2W/P2X/P2Y prove offline provenance, root-authorized release-key rotation/revocation, explicit bounded HTTPS retrieval, manual desktop review/confirmation, compatibility planning, exact package-artifact binding, durable policy/release high-watermark behavior, and transaction/recovery ordering for an already bound Debian package. Existing legacy installations without policy state remain usable through the explicit-key engineering path, but the first production trust baseline must be initialized before policy-authorized replacement. The fetcher has no default source and the desktop invokes it only on demand. The desktop Debian updater remains manual. AppImage destination ownership/replacement is implemented in the 8 September client-update follow-up. Immutable-root migration, dependency retrieval, desktop update notifications and download resumption remain outside the current manual update flow. VPS signed updates, compatible server rollback, repair version preservation, recovery before VPS network startup and opt-in VPS security updates are implemented separately; their behavior and focused evidence are recorded in [signed VPS updates](signed-vps-updates-2026-09-06.md).


## Windows and Android delivery

Windows uses `windows_installer` artifacts and an administrator-only native
coordinator with the shared release-root policy, artifact authentication and
state compatibility declarations. A protected worker continues installation
after the GUI exits; the receipt advances only after the expected service/version
health check. See [Windows updates and packaging](windows-integration-2026-09-07.md).
Windows cross-built debug packages are engineering artifacts and do not establish
MSVC, Authenticode or platform runtime acceptance.

Android's in-app coordinator verifies a root-authorized release and an exact
installed baseline before requesting the system APK installer. Native code
independently revalidates the journal, package identity, version code and existing
Android signing certificate. AppImage updates atomically replace a verified,
user-owned file and retain one compatible signed rollback. See the
[8 September client update implementation](feature-completion-2026-09-08.md). Exact current
state-family declarations are in `release/state-compatibility.json`; historical
P2 schema descriptions above are not a substitute for that complete current set.
