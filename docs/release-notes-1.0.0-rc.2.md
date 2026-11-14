# SirinVPN 1.0.0-rc.2

The second release candidate of SirinVPN 1.0. Like rc.1 it is a **pre-release
on the preview channel**: test it before relying on it.

## What's new

- **Updates come from GitHub by default.** "Check for updates" now needs no
  typing on Linux (Debian package and AppImage), Windows and Android: it looks
  up the newest release for your channel on this project's GitHub Releases,
  downloads it, verifies it and installs it inside the app. A preview build
  such as this one checks GitHub pre-releases; a stable build checks full
  releases. A typed HTTPS mirror is still available under **Use a custom
  source**. The VPS update dialog offers the same built-in source.
- **An Android APK is part of the release.** It is listed in the signed
  manifest like every other file, and the app installs newer signed APKs
  through Android's own installer after verifying the manifest and the APK's
  digest and signer. If "Install unknown apps" is off for SirinVPN, the app
  opens that setting and asks you to tap Install again.
- Rate limits, lost connections and "no release for this channel yet" are
  reported as such, in your language.
- When 1.0.0 is final, it will also be published as a preview release, so
  this release candidate is offered 1.0.0 without changing any setting.

The trust model is unchanged: GitHub only tells the app which release folder
to try. Every file is still verified against the offline root key, the
root-signed trust policy (still sequence 1) and the release signature, with the
same sequence, rollback, size and format checks as before.

## Updating from 1.0.0-rc.1

**rc.1 cannot update itself to rc.2.** Its update check refuses the redirects
GitHub uses for every download, and it has no built-in source. Update once by
hand; from rc.2 on, the in-app check works.

- **AUR (`sirinvpn`, `sirinvpn-bin`, `sirinvpn-git`):** update with your AUR
  helper or `makepkg` as usual. AUR installs keep leaving installation to
  pacman; the app shows the new version and says so.
- **Debian package:** download `SirinVPN_1.0.0-rc.2_amd64.deb` and install it
  with `sudo apt install ./SirinVPN_1.0.0-rc.2_amd64.deb`. Disconnect first.
- **AppImage:** download `SirinVPN_1.0.0-rc.2_amd64.AppImage` and replace the
  old file.
- **VPS:** an rc.1 server does not know the built-in source and refuses it.
  After updating the app, bring the server to rc.2 once: with "Install signed
  VPS baseline" (the app downloads and verifies the release itself, so the
  built-in source works there), with Repair (which installs the server bundled
  with the app), or by checking a typed mirror. After that, VPS maintenance ›
  Update VPS checks GitHub too.
- **Android:** rc.1 had no APK. Install `SirinVPN_1.0.0-rc.2_android.apk` by
  hand. If you had a development build installed, uninstall it first: it is
  signed with a different key, and Android refuses to replace an app with one
  from another signer. Later releases install from inside the app.

## What this release contains

| File | What it is |
| --- | --- |
| `SirinVPN_1.0.0-rc.2_amd64.deb` | Linux desktop app, CLI, privileged helper, Polkit policy and systemd units for Debian and Ubuntu (x86_64). Debian version `1.0.0~rc.2`. |
| `SirinVPN_1.0.0-rc.2_amd64.AppImage` | The same app as a portable AppImage (x86_64). |
| `SirinVPN_1.0.0-rc.2_android.apk` | The Android app (Android 12 or later, ARM64 and x86_64 in one APK). |
| `SirinVPN_1.0.0-rc.2_android_x86_64.apk` | The same APK under the name the manifest gives the x86_64 slot. Download the other one. |
| `sirinvpn-server-x86_64`, `sirinvpn-server-aarch64` | The VPS server for each processor type, also included in the packages. |
| `sirinvpn-release.json`, `.sig.json`, `sirinvpn-release-trust.json`, `.sig.json`, `sirinvpn-release-notes.json` | The signed release manifest, the root-signed trust policy and the signed summary. |
| `SHA256SUMS` | Checksums of every file above. |

To check a download by hand:

```sh
sha256sum -c SHA256SUMS
/usr/lib/sirinvpn/sirinvpn-release verify-trusted \
  --manifest sirinvpn-release.json --signature sirinvpn-release.sig.json \
  --trust-policy sirinvpn-release-trust.json --trust-signature sirinvpn-release-trust.sig.json \
  --artifact-directory .
```

The root key ID is
`bcf4ee209e88153b7ac8dd0c26b4f4e929f9b44eef4a767ac8984c645937ead5`.

## Privacy

An update check is still made only when you ask for it. With the built-in
source it contacts `api.github.com`, `github.com` and GitHub's download
servers (`objects.githubusercontent.com`, `release-assets.githubusercontent.com`),
which see your IP address, the time and which package you download. No token,
account or identifier is sent. GitHub allows about 60 checks per hour from one
IP address; a shared network can hit that limit, and the app then says so. Use
a custom source to avoid GitHub. See [PRIVACY.md](https://github.com/RamazanBerk20/SirinVPN/blob/v1.0.0-rc.2/PRIVACY.md).

## Platform status

- **Linux:** the `.deb` and AppImage are the tested path, as in rc.1.
- **Android:** the APK is published for testing. It builds, its unit tests
  pass, and in-app updates follow the code path described above, but it has
  been run on very few devices.
- **Windows:** still cross-compiled and checked only; no installer is
  published, so the Windows update check finds no package for Windows.
- **VPS:** Debian 13 and Ubuntu 24.04 LTS, x86_64 and ARM64. ARM64 servers are
  cross-built and not yet verified on real ARM64 hardware.

## Known limitations

Everything listed for
[1.0.0-rc.1](https://github.com/RamazanBerk20/SirinVPN/blob/v1.0.0-rc.1/docs/release-notes-1.0.0-rc.1.md#known-limitations)
still applies, except that the GitHub release is now an in-app update source.
In addition:

- Automatic VPS security updates check the stable channel only, so while all
  releases are pre-releases they find nothing.
- The machine translations of the new update text are, like the rest, awaiting
  review by native speakers.
