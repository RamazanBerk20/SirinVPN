# SirinVPN 1.0.0-rc.1

The first public release candidate of SirinVPN 1.0. It is a **pre-release on the
preview channel**: test it before relying on it.

## What SirinVPN is

SirinVPN is a self-hosted WireGuard VPN. You set up a server you control (a
Debian 13 or Ubuntu 24.04 LTS VPS, over SSH or by creating one on Hetzner
Cloud), connect your devices to it, and share access with signed join codes.
There is no SirinVPN account, hosted control service or built-in analytics:
the apps talk only to your VPS.

## What this release contains

| File | What it is |
| --- | --- |
| `SirinVPN_1.0.0-rc.1_amd64.deb` | Linux desktop app, CLI, privileged helper, Polkit policy and systemd units for Debian and Ubuntu (x86_64). Its Debian version is `1.0.0~rc.1`, so the final 1.0.0 upgrades it normally. |
| `SirinVPN_1.0.0-rc.1_amd64.AppImage` | The same app as a portable AppImage (x86_64). |
| `sirinvpn-server-x86_64`, `sirinvpn-server-aarch64` | The VPS server for each processor type, also included in both packages. |
| `sirinvpn-release.json`, `.sig.json`, `sirinvpn-release-trust.json`, `.sig.json`, `sirinvpn-release-notes.json` | The signed release manifest, the root-signed trust policy and the signed summary. |
| `SHA256SUMS` | Checksums of every file above. |

Arch Linux packages are in the AUR: `sirinvpn` (built from this release's
source), `sirinvpn-bin` (this release's `.deb`, repackaged) and `sirinvpn-git`
(built from the latest source). They conflict with each other; install one.

Every file is listed with its size and SHA-256 in the manifest, which is signed
by a release key that the offline root key authorizes through trust policy 1.
To check a download:

```sh
sha256sum -c SHA256SUMS
/usr/lib/sirinvpn/sirinvpn-release verify-trusted \
  --manifest sirinvpn-release.json --signature sirinvpn-release.sig.json \
  --trust-policy sirinvpn-release-trust.json --trust-signature sirinvpn-release-trust.sig.json \
  --artifact-directory .
```

The root key ID is
`bcf4ee209e88153b7ac8dd0c26b4f4e929f9b44eef4a767ac8984c645937ead5`
(`sirinvpn-release trust root` prints it).

## Platform status

- **Linux:** the `.deb` and AppImage are the tested path. The Rust and
  frontend test suites pass, and the packages are built in the Debian Bookworm
  container and inspected by `scripts/check-linux-package.py`. AUR installs use
  the same binaries and layout; their in-app update check shows new releases
  and leaves installing them to pacman.
- **Windows:** the code is cross-compiled and checked, but this release
  candidate was never run on Windows and no installer is published. Executable
  routing also needs a signed driver.
- **Android:** not part of this release. The Android app builds and starts on
  one test phone, but nothing beyond that was tested and there is no
  production-signed APK; publishing a
  debug- or test-signed APK would lock testers into a signer they would have to
  uninstall to leave.
- **VPS:** Debian 13 and Ubuntu 24.04 LTS, x86_64 and ARM64 server payloads.
  ARM64 servers are cross-built and not yet verified on real ARM64 hardware.

## Languages

The interface is available in ten languages: English, Turkish, Spanish, French,
German, Russian, Arabic, Simplified Chinese, Japanese and Korean. The nine
non-English translations are machine translations awaiting review by native
speakers; corrections are welcome.

## Known limitations

- **Installing the AUR package over a hand-installed helper.** If you ever ran
  `install-system` from a source build or an earlier AppImage, the helper, its
  systemd units, the Polkit policy and the NetworkManager file are already on
  the system and belong to no package, so pacman refuses to install over them
  ("exists in filesystem"). Disconnect the VPN, then install once with:
  `--overwrite '/usr/lib/sirinvpn/*,/usr/lib/systemd/system/sirinvpn-*,/usr/share/polkit-1/actions/org.sirinvpn.network.policy,/usr/lib/NetworkManager/conf.d/90-sirinvpn-probe.conf'`.
  From then on the package owns those files.

From [SECURITY.md](https://github.com/RamazanBerk20/SirinVPN/blob/v1.0.0-rc.1/SECURITY.md):

- SirinVPN does not protect against a compromised client or VPS, a malicious
  VPS provider or destination, traffic analysis at the VPS, or blocking of every
  available transport. Selected-route and selected-app modes deliberately leave
  other traffic on the normal network.
- New Linux credentials need the system Secret Service keyring; an unencrypted
  file fallback exists only with explicit consent.
- Relay carriers trust a fixed loopback source port. On Windows, Android, or
  Linux with a lowered unprivileged-port limit, a local process that takes that
  port first can stop the tunnel (never read it). A local user holding a relay's
  loopback port pauses the session with the kill switch kept on, instead of
  falling back to another carrier.
- A recorded carrier handshake can be replayed in narrow windows (after a server
  restart, within 24 hours of its timestamp). A replay cannot read or send
  traffic; it only holds an idle connection until it times out.
- The boot guard blocks all traffic for a selected-routes session that reaches
  other devices' LANs when its saved request cannot be used.
- No independent security audit has been done.

Open items from the pre-release security review, accepted for this candidate:

- Typed secrets and SSH-key grants are bound to a field or purpose, not to a host.
- When the desktop app installs its user-owned helper, the helper's SHA-256 is
  shown only on standard error, after approval.
- Signed VPS baseline installation is not journaled.
- A fresh installation has a trust-policy floor but no release-sequence floor;
  each installation's own high watermark bounds replays after that.

Release and update limits:

- The GitHub release is not an in-app update source: GitHub serves its files
  through a redirect, which the update fetcher refuses by design. "Check for
  updates" and "Install signed VPS baseline" need the release files in one
  static HTTPS directory, such as a mirror on GitHub Pages.
- The first production trust policy (sequence 1) ships in this release and is
  compiled into it as the trust floor.

## Upgrading

None: this is the first public release. Development builds from before this
candidate were never published; their state formats are read as described in
[the first-release migration policy](https://github.com/RamazanBerk20/SirinVPN/blob/v1.0.0-rc.1/docs/release-candidate.md). Back up before
replacing a development installation.
