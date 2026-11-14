# SirinVPN 1.0.0-rc.3

The third release candidate of SirinVPN 1.0. Like rc.1 and rc.2 it is a
**pre-release on the preview channel**: test it before relying on it.

## What's new

- **Diagnostics speak your language.** Every check in Diagnostics and the
  "Can't connect?" guide, on the device and from the VPS, now shows its result
  in the app's language instead of English. Outside English, the original
  technical text is still there under **Technical details**, for bug reports.
- **Clearer setup errors.** When the setup refuses an entered value or a file
  before touching the VPS, it now says exactly that, and that nothing on the
  server was changed, instead of a generic failure.
- **Tidier screens.** Spacing and keyboard focus outlines were corrected across
  the app, so focused buttons and fields are clearly marked and content no
  longer sits against edges.
- 122 new interface strings in all ten languages.

Nothing changed in how updates are found, verified or installed. A VPS on rc.2
keeps working with this app; until the server is updated, its checks show a
shorter general sentence in your language, with the server's English text
under **Technical details**.

## Updating from 1.0.0-rc.2

- **Debian package, AppImage, Android:** Settings › General › App updates ›
  **Check release** finds 1.0.0-rc.3, verifies it and installs it in the app.
  On Android the update goes through Android's installer and keeps your data.
- **AUR (`sirinvpn`, `sirinvpn-bin`, `sirinvpn-git`):** update with your AUR
  helper or `makepkg` as usual.
- **VPS:** VPS maintenance › Update VPS.
- **From 1.0.0-rc.1:** rc.1 cannot update itself. Install rc.3 by hand as
  described in the [rc.2 notes](https://github.com/RamazanBerk20/SirinVPN/blob/v1.0.0-rc.2/docs/release-notes-1.0.0-rc.2.md#updating-from-100-rc1).

## What this release contains

| File | What it is |
| --- | --- |
| `SirinVPN_1.0.0-rc.3_amd64.deb` | Linux desktop app, CLI, privileged helper, Polkit policy and systemd units for Debian and Ubuntu (x86_64). Debian version `1.0.0~rc.3`. |
| `SirinVPN_1.0.0-rc.3_amd64.AppImage` | The same app as a portable AppImage (x86_64). |
| `SirinVPN_1.0.0-rc.3_android.apk` | The Android app (Android 12 or later, ARM64 and x86_64 in one APK). |
| `SirinVPN_1.0.0-rc.3_android_x86_64.apk` | The same APK under the name the manifest gives the x86_64 slot. Download the other one. |
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
`bcf4ee209e88153b7ac8dd0c26b4f4e929f9b44eef4a767ac8984c645937ead5`. The APK's
signing certificate SHA-256 is
`73d956a5b45be05698b59daf7c104023af9cf8ad3f8028ea88e7e528ce8b20da`, the same
as rc.2.

## What was tested, and what was not

- **Linux:** the automated tests pass. The spacing fixes were checked in
  Chromium and, on three screens, in the WebKitGTK engine the Linux app uses.
- **Android:** the APK builds and its unit tests pass, but neither the APK nor
  the in-app Android update was tried on a device since rc.2. Updating from
  rc.2 to rc.3 inside the Android app is the first in-app APK update; please
  report how it goes.
- **Windows:** not compiled and not run for this release. There is still no
  Windows package.
- **Translations:** Turkish was written by a person; the other eight
  non-English languages are machine translations awaiting review by native
  speakers.

## Known limitations

Everything listed for
[1.0.0-rc.2](https://github.com/RamazanBerk20/SirinVPN/blob/v1.0.0-rc.2/docs/release-notes-1.0.0-rc.2.md#known-limitations)
still applies. In addition:

- In German, some dialogs scroll sideways on a phone when the system text size
  is 150%.
- In Arabic, the weekday headers of the weekly hours grid (a person's limits
  and permissions in Devices) are clipped at phone width.
