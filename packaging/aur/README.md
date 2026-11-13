# SirinVPN AUR packages

Each directory mirrors one AUR package base:

- `sirinvpn`: a tagged release built from source.
- `sirinvpn-bin`: the tagged release's signed `.deb`, repackaged (x86_64).
- `sirinvpn-git`: the latest `main` built from source.

All three install the layout from `scripts/install-linux.sh` (the same files as
the Debian package, plus licences and `/usr/lib/sirinvpn/install-method`, which
makes the app leave updates to pacman), share the scriptlets in
`sirinvpn.install` (each directory links to it; copy it with `cp -L`), and
conflict with each other. The VPS server payloads always come from the signed
release, because they must be built against Debian Bookworm's glibc.

After publishing a release, run `scripts/update-aur-checksums.sh`: it fills the
`FILL_FROM_RELEASE` checksums and regenerates every `.SRCINFO` with
`makepkg --printsrcinfo`. Build-test each package, then push `PKGBUILD`,
`.SRCINFO` and `sirinvpn.install` to its AUR repository. Never publish a
placeholder checksum. The full sequence is in
[the release checklist](../../docs/release-checklist-1.0.0-rc.1.md).
