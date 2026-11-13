# Release checklist: 1.0.0-rc.1

The exact sequence for publishing SirinVPN `1.0.0-rc.1`: a GitHub pre-release
on the `preview` channel and the AUR packages `sirinvpn`, `sirinvpn-git` and
`sirinvpn-bin`. Run the steps in order from the repository root. Each step says
what it produces and how to check it.

**Who runs each step.** Steps marked **Owner** need the root-key passphrase,
the release-key passphrase or the AUR key passphrase, or they publish under
your name; only you can run them. An assistant can run the steps marked
**Assistant** when you ask. It must never read anything under `/run/media`.

Ledger for this release (record it with the release):

| Item | Value |
| --- | --- |
| Version (SemVer, manifest, app) | `1.0.0-rc.1` |
| Debian package version | `1.0.0~rc.1` (sorts before `1.0.0`) |
| Arch `pkgver` | `1.0.0rc1` (`vercmp 1.0.0rc1 1.0.0` is `-1`) |
| Android `versionCode` | `999901` (final `1.0.0` gets `1000000`) |
| Channel | `preview` (stable manifests reject prereleases) |
| Preview release sequence | `1` (first preview release) |
| Trust policy sequence | `1` (first policy) |
| Git tag | `v1.0.0-rc.1` |

## 0. Before you start (Assistant)

1. The nine translations are finished, so these pass:

   ```sh
   pnpm --dir apps/desktop i18n:check
   pnpm --dir apps/desktop lint
   pnpm --dir apps/desktop test
   ```
2. The full local gate passes: `./scripts/test.sh`. It requires the pnpm `11.3.0`
   pinned by `apps/desktop/package.json` (`pnpm --version` inside `apps/desktop`
   must print `11.3.0`; newer global pnpm releases switch to the pin there).
3. The AUR names are free: `sirinvpn`, `sirinvpn-git` and `sirinvpn-bin` do not
   exist on aur.archlinux.org (search the package list in a browser).
4. Shared values for the shell you will use from here on:

   ```sh
   cd ~/Belgeler/AI/Code/SirinVPN
   umask 077
   KEYDIR="/run/user/$(id -u)/sirinvpn-signing"
   MEDIA=/run/media/ramazan/Ventoy
   findmnt -no FSTYPE "/run/user/$(id -u)"   # must print tmpfs
   cargo build --locked --release -p sirinvpn-release
   TOOL="$PWD/target/release/sirinvpn-release"
   "$TOOL" trust root    # root key ID bcf4ee209e88153b7ac8dd0c26b4f4e929f9b44eef4a767ac8984c645937ead5
   ```

   `KEYDIR` is memory-backed. Decrypted keys go there and nowhere else. If this
   machine has swap, memory pages can reach it; `cryptroot` is encrypted, so
   check that swap is too (`swapon --show`, `lsblk`) or turn it off for the
   session (`sudo swapoff -a`).

## a. Generate the release signing key (Owner)

No release key exists yet. `keygen` writes an **unencrypted** PEM with mode
`0600` and refuses to overwrite anything. Choose where it lives:

- **Option 1: this machine, memory only, encrypted onto the removable media.**
  Generate into `KEYDIR`, encrypt with a new passphrase onto the Ventoy media,
  shred the plaintext. Convenient, and the plaintext never touches a disk. But
  this machine is online, so malware here could copy the key while it is in
  memory, now and every time you sign. The same is true of the root key in
  step b.
- **Option 2: a separate offline system** (for example a live USB with
  networking off) that generates and encrypts the key onto the media. This is
  what [releases.md](releases.md) asks for. Signing (step e) then also happens
  there or uses a decrypted copy brought to this machine for the session,
  which gives back most of Option 1's exposure.
- Not recommended: keeping `private.pem` unencrypted on the Ventoy media. Its
  file system keeps no Unix permissions and anyone holding the stick holds the key.

Whatever you choose, keep a second encrypted copy on separate media, like the
root key. Option 1:

```sh
install -d -m 0700 "$KEYDIR" "$MEDIA/sirinvpn-release-key"
"$TOOL" keygen \
  --private-key "$KEYDIR/release-private.pem" \
  --public-key "$KEYDIR/release-public.pem"
gpg --no-symkey-cache --symmetric --cipher-algo AES256 \
  --output "$MEDIA/sirinvpn-release-key/release-private.pem.gpg" \
  "$KEYDIR/release-private.pem"
cp "$KEYDIR/release-public.pem" "$MEDIA/sirinvpn-release-key/release-public.pem"
# Prove the encrypted copy decrypts to the same key before deleting the plaintext.
gpg --no-symkey-cache --decrypt "$MEDIA/sirinvpn-release-key/release-private.pem.gpg" \
  | cmp - "$KEYDIR/release-private.pem"
shred -u "$KEYDIR/release-private.pem"
```

Produces: `release-private.pem.gpg` and `release-public.pem` on the media, and
`$KEYDIR/release-public.pem` for step b. Check: the `cmp` prints nothing.

## b. Create and verify trust policy sequence 1 (Owner)

```sh
cmp "$MEDIA/sirinvpn-root-key/root-public.pem" release/release-trust-root.pub
gpg --no-symkey-cache --decrypt \
  --output "$KEYDIR/root-private.pem" \
  "$MEDIA/sirinvpn-root-key/root-private.pem.gpg"
"$TOOL" trust create \
  --sequence 1 \
  --release-key "$KEYDIR/release-public.pem" \
  --root-private-key "$KEYDIR/root-private.pem" \
  --policy release/sirinvpn-release-trust.json \
  --signature release/sirinvpn-release-trust.sig.json
shred -u "$KEYDIR/root-private.pem"
"$TOOL" trust verify \
  --policy release/sirinvpn-release-trust.json \
  --signature release/sirinvpn-release-trust.sig.json
```

Produces: `release/sirinvpn-release-trust.json` and
`release/sirinvpn-release-trust.sig.json` (public; they are committed).
Check: `trust verify` succeeds with the compiled root and lists one active key,
the ID of `release-public.pem`; `ls "$KEYDIR"` no longer shows
`root-private.pem`. Unmount the media now if you chose Option 2 for signing.

## c. Embed the policy as the trust floor (Assistant)

The two files from step b are already where the build embeds them. Before any
release build:

```sh
cargo test --locked -p sirinvpn-release
cargo run --locked -q -p sirinvpn-release -- trust root
```

Check: the tests pass (they fail if the embedded policy does not verify under
the bundled root) and the output says `Embedded trust policy floor: sequence 1`.

## d. Commit, then build and package (Assistant, on request)

The build must come from a committed, clean tree.

```sh
git add -A
git status --short          # review: no keys, no target/, nothing under /run
git commit                  # message of your choice
rm -rf target/release/bundle   # the signing script needs exactly one .deb and one AppImage
# The reviewed AppImage runtime (sha256 1cc49bcf…aebbf) is no longer what upstream's
# "continuous" URL serves, so the container must reuse the cached reviewed copy.
# Mount a copy, not ~/.cache/tauri itself: the container writes there as root.
mkdir -p target/tauri-cache && cp -a ~/.cache/tauri/. target/tauri-cache/
SIRINVPN_TAURI_CACHE="$PWD/target/tauri-cache" ./scripts/package-linux-container.sh
python3 scripts/check-linux-package.py \
  target/release/bundle/deb/SirinVPN_1.0.0-rc.1_amd64.deb \
  target/release/bundle/appimage/SirinVPN_1.0.0-rc.1_amd64.AppImage \
  --output target/remediation-evidence/linux-package-inspection.json
```

Produces: `SirinVPN_1.0.0-rc.1_amd64.deb` (Debian `Version: 1.0.0~rc.1`),
`SirinVPN_1.0.0-rc.1_amd64.AppImage`, and both VPS payloads in
`target/server-payloads/{x86_64,aarch64}-unknown-linux-gnu/release/sirinvpn-server`.
Check: the inspection passes, and

```sh
target/release/sirinvpn-release --version     # sirinvpn-release 1.0.0-rc.1
target/release/sirinvpn-release trust root     # Embedded trust policy floor: sequence 1
```

To keep build evidence, wrap the container build in
`scripts/record-evidence.py --frozen-source` as `.github/workflows/candidate.yml` does.

## e. Sign on the preview channel (Owner)

```sh
install -d -m 0700 "$KEYDIR"
gpg --no-symkey-cache --decrypt \
  --output "$KEYDIR/release-private.pem" \
  "$MEDIA/sirinvpn-release-key/release-private.pem.gpg"
printf '%s\n' 'First public release candidate of SirinVPN 1.0 for Linux. Preview channel: please report problems on GitHub.' \
  >"$KEYDIR/release-summary.txt"
mkdir -p target/signed
env \
  SIRINVPN_RELEASE_TRUST_POLICY=release/sirinvpn-release-trust.json \
  SIRINVPN_RELEASE_TRUST_SIGNATURE=release/sirinvpn-release-trust.sig.json \
  SIRINVPN_RELEASE_NOTES="$KEYDIR/release-summary.txt" \
  ./scripts/sign-linux-release.sh \
    "$KEYDIR/release-private.pem" \
    1 \
    target/signed/1.0.0-rc.1 \
    preview
shred -u "$KEYDIR/release-private.pem"
rm -f "$KEYDIR/release-summary.txt" && rmdir "$KEYDIR"
```

Arguments: release sequence `1` (the first `preview` release; every later
preview release must use a larger number), channel `preview`, no `security`
flag. Produces in `target/signed/1.0.0-rc.1/`: the `.deb`, the AppImage,
`sirinvpn-server-x86_64`, `sirinvpn-server-aarch64`, `sirinvpn-release.json`,
`sirinvpn-release.sig.json`, `sirinvpn-release-trust.json`,
`sirinvpn-release-trust.sig.json` and `sirinvpn-release-notes.json`.
Check: the script ends with `Signed Linux release written to …` (it already
ran `verify-trusted`), and `$KEYDIR` is gone.

## f. Verify the signed bundle (Assistant)

```sh
D=target/signed/1.0.0-rc.1
"$TOOL" verify-trusted \
  --manifest "$D/sirinvpn-release.json" \
  --signature "$D/sirinvpn-release.sig.json" \
  --trust-policy "$D/sirinvpn-release-trust.json" \
  --trust-signature "$D/sirinvpn-release-trust.sig.json" \
  --artifact-directory "$D"
cmp "$D/sirinvpn-release-trust.json" release/sirinvpn-release-trust.json
(cd "$D" && sha256sum -- * > ../SHA256SUMS && mv ../SHA256SUMS .)
```

Check: verification succeeds, and the manifest says what this release is:

```sh
python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print(m["release_version"], m["channel"], m["release_sequence"]); [print(a["kind"], a["target"], a["file_name"]) for a in m["artifacts"]]' "$D/sirinvpn-release.json"
```

prints `1.0.0-rc.1 preview 1` and four artifacts: `linux_appimage` and
`linux_deb` for `x86_64-unknown-linux-gnu`, and `server_elf` for x86_64 and
aarch64. `SHA256SUMS` lists every file in `$D`.

Distribution notices: `scripts/create-release-materials.py --scan <osv-scanner
JSON> --output target/release-materials --artifact <each artifact>` exports the
build inventory and notice ZIP. Attach the notice ZIP to the release; its
missing-notice list is a review item, not an approval.

## g. Tag, push and publish the GitHub pre-release (Owner, or Assistant on request)

```sh
git tag -a v1.0.0-rc.1 -m "SirinVPN 1.0.0-rc.1"
git push origin main v1.0.0-rc.1
D=target/signed/1.0.0-rc.1
gh release create v1.0.0-rc.1 --repo RamazanBerk20/SirinVPN \
  --verify-tag --prerelease \
  --title "SirinVPN 1.0.0-rc.1" \
  --notes-file docs/release-notes-1.0.0-rc.1.md \
  "$D/SirinVPN_1.0.0-rc.1_amd64.deb" \
  "$D/SirinVPN_1.0.0-rc.1_amd64.AppImage" \
  "$D/sirinvpn-server-x86_64" \
  "$D/sirinvpn-server-aarch64" \
  "$D/sirinvpn-release.json" \
  "$D/sirinvpn-release.sig.json" \
  "$D/sirinvpn-release-trust.json" \
  "$D/sirinvpn-release-trust.sig.json" \
  "$D/sirinvpn-release-notes.json" \
  "$D/SHA256SUMS"
```

Check: `gh release view v1.0.0-rc.1 --repo RamazanBerk20/SirinVPN` shows
*Pre-release* and the ten assets.

The GitHub release is **not** an in-app update source: its asset URLs answer
with a redirect, and `sirinvpn-release-fetch` follows none. Publish the same
ten files in one static HTTPS directory (for example GitHub Pages) if you want
"Check for updates" and "Install signed VPS baseline" to use this release.

## h. AUR checksums and push (Owner)

```sh
scripts/update-aur-checksums.sh
for p in sirinvpn sirinvpn-git sirinvpn-bin; do
  (cd "packaging/aur/$p" && makepkg -f --cleanbuild && namcap PKGBUILD ./*.pkg.tar.zst)
done
(cd packaging/aur/sirinvpn-git && makepkg --printsrcinfo > .SRCINFO)   # after makepkg updated pkgver
git add packaging/aur && git commit -m "Fill AUR checksums for 1.0.0-rc.1"
```

`update-aur-checksums.sh` takes the `.deb` and payload sums from the
release's `SHA256SUMS`, refuses any that differs from the signed manifest,
hashes the GitHub source archive and `LICENSE`, and regenerates each
`.SRCINFO`. Check: `grep -r FILL_FROM_RELEASE packaging/aur` prints nothing;
each build succeeds; `namcap` shows no errors. A clean chroot build
(`extra-x86_64-build` from `devtools`) is the stronger check.

Then push each package (unlock `~/.ssh/aur` with `ssh-add ~/.ssh/aur`;
`~/.ssh/config` already selects it for `aur.archlinux.org`):

```sh
for p in sirinvpn sirinvpn-git sirinvpn-bin; do
  work=$(mktemp -d)
  git clone "ssh://aur@aur.archlinux.org/$p.git" "$work/$p"
  cp -L "packaging/aur/$p/PKGBUILD" "packaging/aur/$p/.SRCINFO" \
    "packaging/aur/$p/sirinvpn.install" "$work/$p/"
  (cd "$work/$p" && git add PKGBUILD .SRCINFO sirinvpn.install \
    && git commit -m "Initial import: $p 1.0.0rc1" && git push origin master)
done
```

`cp -L` copies the shared `sirinvpn.install` (a symlink in this repository) as
a file. Check: each package page on aur.archlinux.org shows `1.0.0rc1-1`
(`sirinvpn-git` shows its git version).

## i. After publishing (Assistant)

1. Download every release asset into an empty directory, run
   `sha256sum -c SHA256SUMS`, then `verify-trusted` as in step f against that
   directory.
2. Install the `.deb` on a fresh Debian 13 VM: `dpkg -s sirin-vpn` shows
   `Version: 1.0.0~rc.1`; the app starts; Settings shows version `1.0.0-rc.1`.
3. Install `sirinvpn-bin` from the AUR on a fresh Arch VM, then remove it with
   the kill switch on: networking keeps working afterwards.
4. In the AUR-installed app, check for updates against a static mirror: it
   shows the release and "Update with your package manager", never an install
   button.
5. Keep the ledger above, `SHA256SUMS` and the build evidence with the release.
