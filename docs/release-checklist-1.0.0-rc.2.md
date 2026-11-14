# Release checklist: 1.0.0-rc.2

The exact sequence for publishing SirinVPN `1.0.0-rc.2`: a GitHub pre-release
on the `preview` channel, now with an Android APK, and the AUR packages
`sirinvpn`, `sirinvpn-git` and `sirinvpn-bin`. It follows the
[rc.1 checklist](release-checklist-1.0.0-rc.1.md); only what differs is
explained here. Run the steps in order from the repository root.

**Who runs each step.** Steps marked **Owner** need a key passphrase or publish
under your name; only you can run them. An assistant can run the steps marked
**Assistant** when you ask. It must never read anything under `/run/media`,
and never creates, reads or copies a signing key or keystore.

Ledger for this release:

| Item | Value |
| --- | --- |
| Version (SemVer, manifest, app) | `1.0.0-rc.2` |
| Debian package version | `1.0.0~rc.2` |
| Arch `pkgver` | `1.0.0rc2` (`vercmp 1.0.0rc2 1.0.0` is `-1`) |
| Android `versionCode` | `999902` |
| Channel | `preview` |
| Preview release sequence | `2` (rc.1 was `1`) |
| Trust policy sequence | `1`, unchanged (`release/sirinvpn-release-trust.json` is not touched) |
| Android signing certificate SHA-256 | record it in step c (first release with an APK) |
| Git tag | `v1.0.0-rc.2` |

No release key or trust policy is created for this release: the rc.1 release
key and policy 1 sign it.

## 0. Before you start (Assistant)

1. These pass: `pnpm --dir apps/desktop i18n:check`, `pnpm --dir apps/desktop lint`,
   `pnpm --dir apps/desktop test`, and `./scripts/test.sh`.
2. `cargo +1.100.0 clippy --workspace --all-targets -- -D warnings` is clean.
3. Shared values, as in rc.1 step 0:

   ```sh
   cd ~/Belgeler/AI/Code/SirinVPN
   umask 077
   KEYDIR="/run/user/$(id -u)/sirinvpn-signing"
   MEDIA=/run/media/ramazan/Ventoy
   findmnt -no FSTYPE "/run/user/$(id -u)"   # must print tmpfs
   cargo build --locked --release -p sirinvpn-release
   TOOL="$PWD/target/release/sirinvpn-release"
   "$TOOL" trust root    # bcf4ee20…ead5, Embedded trust policy floor: sequence 1
   BT="$HOME/Android/Sdk/build-tools/36.0.0"
   ```

## a. Commit, then build Linux packages and payloads (Assistant, on request)

Exactly rc.1 step d, with `1.0.0-rc.2` in the file names. Check:
`target/release/sirinvpn-release --version` prints `sirinvpn-release 1.0.0-rc.2`.

## b. Build the unsigned Android release APK (Assistant)

Needs the server payloads from step a (the APK bundles them).

```sh
./scripts/build-android.sh all release
U=apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk
python3 scripts/check-android-package.py --unsigned "$U"
```

Check: the package check passes and prints `"debuggable": false`.

## c. Android signing key, once, and sign the APK (Owner)

**Once, before the first APK release.** The key signs every future APK:
Android installs an update only from the same signer. Losing it means every
user must uninstall and reinstall; keep two encrypted copies on separate media,
like the release key.

```sh
install -d -m 0700 "$KEYDIR" "$MEDIA/sirinvpn-android-key"
"${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk}/bin/keytool" -genkeypair \
  -keystore "$KEYDIR/sirinvpn-android.p12" -storetype PKCS12 \
  -alias sirinvpn -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=SirinVPN"
gpg --no-symkey-cache --symmetric --cipher-algo AES256 \
  --output "$MEDIA/sirinvpn-android-key/sirinvpn-android.p12.gpg" \
  "$KEYDIR/sirinvpn-android.p12"
gpg --no-symkey-cache --decrypt "$MEDIA/sirinvpn-android-key/sirinvpn-android.p12.gpg" \
  | cmp - "$KEYDIR/sirinvpn-android.p12"
shred -u "$KEYDIR/sirinvpn-android.p12"
```

`keytool` asks for a new keystore password; `gpg` for a passphrase (they can
differ). Check: `cmp` prints nothing. Copy the `.gpg` to the second medium.

**Each release.** Align, sign, verify:

```sh
install -d -m 0700 "$KEYDIR"
gpg --no-symkey-cache --decrypt --output "$KEYDIR/sirinvpn-android.p12" \
  "$MEDIA/sirinvpn-android-key/sirinvpn-android.p12.gpg"
mkdir -p target/android
"$BT/zipalign" -P 16 -f 4 "$U" "$KEYDIR/aligned.apk"
"$BT/apksigner" sign --ks "$KEYDIR/sirinvpn-android.p12" --ks-key-alias sirinvpn \
  --out target/android/SirinVPN_1.0.0-rc.2_android.apk "$KEYDIR/aligned.apk"
shred -u "$KEYDIR/sirinvpn-android.p12" "$KEYDIR/aligned.apk"
"$BT/apksigner" verify --print-certs --min-sdk-version 31 target/android/SirinVPN_1.0.0-rc.2_android.apk
python3 scripts/check-android-package.py target/android/SirinVPN_1.0.0-rc.2_android.apk
```

Check: `apksigner verify` succeeds; record its `certificate SHA-256 digest` in
the ledger. Every later release must print the same digest.

## d. Sign on the preview channel with sequence 2 (Owner)

As rc.1 step e, with three differences: sequence `2`, output
`target/signed/1.0.0-rc.2`, and the APK:

```sh
install -d -m 0700 "$KEYDIR"
gpg --no-symkey-cache --decrypt --output "$KEYDIR/release-private.pem" \
  "$MEDIA/sirinvpn-release-key/release-private.pem.gpg"
printf '%s\n' 'Updates now come from GitHub by default, and the release includes an Android APK. Preview channel.' \
  >"$KEYDIR/release-summary.txt"
env \
  SIRINVPN_RELEASE_TRUST_POLICY=release/sirinvpn-release-trust.json \
  SIRINVPN_RELEASE_TRUST_SIGNATURE=release/sirinvpn-release-trust.sig.json \
  SIRINVPN_RELEASE_NOTES="$KEYDIR/release-summary.txt" \
  SIRINVPN_ANDROID_APK=target/android/SirinVPN_1.0.0-rc.2_android.apk \
  ./scripts/sign-linux-release.sh \
    "$KEYDIR/release-private.pem" 2 target/signed/1.0.0-rc.2 preview
shred -u "$KEYDIR/release-private.pem"
rm -f "$KEYDIR/release-summary.txt" && rmdir "$KEYDIR"
```

Check: no `note: SIRINVPN_ANDROID_APK is unset` line; the script ends with
`Signed Linux release written to …`.

## e. Verify the signed bundle (Assistant)

As rc.1 step f with `D=target/signed/1.0.0-rc.2`. The manifest line prints
`1.0.0-rc.2 preview 2` and six artifacts: `android_apk` for
`aarch64-linux-android` (`SirinVPN_1.0.0-rc.2_android.apk`) and
`x86_64-linux-android` (`SirinVPN_1.0.0-rc.2_android_x86_64.apk`, same
SHA-256), `linux_appimage` and `linux_deb` for `x86_64-unknown-linux-gnu`,
and `server_elf` for x86_64 and aarch64. `cmp` against
`release/sirinvpn-release-trust.json` succeeds (policy 1, unchanged).

## f. Tag, push and publish the GitHub pre-release (Owner, or Assistant on request)

```sh
git tag -a v1.0.0-rc.2 -m "SirinVPN 1.0.0-rc.2"
git push origin main v1.0.0-rc.2
D=target/signed/1.0.0-rc.2
gh release create v1.0.0-rc.2 --repo RamazanBerk20/SirinVPN \
  --verify-tag --prerelease \
  --title "SirinVPN 1.0.0-rc.2" \
  --notes-file docs/release-notes-1.0.0-rc.2.md \
  "$D/SirinVPN_1.0.0-rc.2_amd64.deb" \
  "$D/SirinVPN_1.0.0-rc.2_amd64.AppImage" \
  "$D/SirinVPN_1.0.0-rc.2_android.apk" \
  "$D/SirinVPN_1.0.0-rc.2_android_x86_64.apk" \
  "$D/sirinvpn-server-x86_64" \
  "$D/sirinvpn-server-aarch64" \
  "$D/sirinvpn-release.json" \
  "$D/sirinvpn-release.sig.json" \
  "$D/sirinvpn-release-trust.json" \
  "$D/sirinvpn-release-trust.sig.json" \
  "$D/sirinvpn-release-notes.json" \
  "$D/SHA256SUMS"
```

Check: `gh release view v1.0.0-rc.2 --repo RamazanBerk20/SirinVPN` shows
*Pre-release* and the twelve assets. It must be a pre-release: preview builds
look only at GitHub pre-releases, and stable builds only at full releases.
All files must sit in this one release; the apps fetch them from its
`releases/download/v1.0.0-rc.2/` folder.

## g. AUR checksums and push (Owner)

As rc.1 step h. The PKGBUILDs already say `pkgver=1.0.0rc2` (and
`_payload_tag=v1.0.0-rc.2` for `sirinvpn-git`) with `FILL_FROM_RELEASE`
placeholders, which `scripts/update-aur-checksums.sh` fills. Commit message:
`Fill AUR checksums for 1.0.0-rc.2`; push message: `Update to 1.0.0rc2`.
Check: each package page shows `1.0.0rc2-1`.

## h. After publishing (Assistant)

1. Download every asset into an empty directory, `sha256sum -c SHA256SUMS`,
   then `verify-trusted` as in step e.
2. From the published release, without any typing: the fetcher finds it.

   ```sh
   out="$(mktemp -d)/candidate"
   target/release/sirinvpn-release-fetch --json --source github --channel preview \
     --artifact-kind linux_deb --artifact-target x86_64-unknown-linux-gnu --output "$out"
   ```

   prints `"release_version": "1.0.0-rc.2"` and `"release_sequence": 2`.
3. Install the rc.1 `.deb` on a fresh Debian 13 VM, then the rc.2 `.deb` by
   hand (rc.1 cannot update in-app). In rc.2, **Check release** with no typing
   shows "Signature verified" for 1.0.0-rc.2 and offers no install (not newer).
4. On an Android 12+ device without SirinVPN, install
   `SirinVPN_1.0.0-rc.2_android.apk` by hand; App updates › Check release
   offers **Verify version** (binds the installed APK). Updating it in-app is
   tested with rc.3.
5. In an AUR-installed rc.2, **Check release** shows the release and "Update
   with your package manager", never an install button.
6. Keep the ledger, `SHA256SUMS` and the build evidence with the release.
