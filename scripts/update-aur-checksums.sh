#!/usr/bin/env bash
# After a release is published: fill the AUR packages' checksums from it, so
# nobody builds them with a placeholder, then regenerate each .SRCINFO.
#
# Release assets (the .deb and the two VPS payloads) are taken from the
# release's SHA256SUMS and must equal the sha256 the release's signed manifest
# declares. The source archive and LICENSE are GitHub-generated, so they are
# downloaded and hashed here. Verify the manifest's signature separately
# (docs/release-checklist-1.0.0-rc.1.md); this script only binds the AUR sums
# to its contents.
set -euo pipefail

project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
aur=packaging/aur
repo=RamazanBerk20/SirinVPN
pkgver="$(sed -n 's/^pkgver=//p' "$aur/sirinvpn/PKGBUILD")"
tag="v${pkgver/rc/-rc.}"
payload_tag="$(sed -n 's/^_payload_tag=//p' "$aur/sirinvpn-git/PKGBUILD")"
[[ "$payload_tag" == "$tag" ]] || {
  printf 'sirinvpn-git takes its payloads from %s; set _payload_tag=%s first\n' "$payload_tag" "$tag" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
gh release download "$tag" --repo "$repo" --dir "$work" \
  --pattern SHA256SUMS --pattern sirinvpn-release.json

asset_sum() {
  local name="$1" sum declared
  sum="$(awk -v name="$name" '$2 == name || $2 == "*" name { print $1 }' "$work/SHA256SUMS")"
  declared="$(python3 -I -c '
import json, sys
manifest = json.load(open(sys.argv[1]))
print("".join(a["sha256"] for a in manifest["artifacts"] if a["file_name"] == sys.argv[2]))
' "$work/sirinvpn-release.json" "$name")"
  if ! [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || [[ "$sum" != "$declared" ]]; then
    printf 'no checksum for %s in %s SHA256SUMS that matches its signed manifest\n' "$name" "$tag" >&2
    exit 1
  fi
  printf '%s\n' "$sum"
}

download_sum() {
  curl --fail --silent --show-error --location --proto '=https' "$1" | sha256sum | cut -d' ' -f1
}

# Replace the checksum array that starts with "$2=(" in PKGBUILD "$1".
set_sums() {
  local pkgbuild="$aur/$1/PKGBUILD" variable="$2"
  shift 2
  python3 -I - "$pkgbuild" "$variable" "$@" <<'EOF'
import re, sys
path, variable, sums = sys.argv[1], sys.argv[2], sys.argv[3:]
text = open(path).read()
pattern = re.compile(rf"^{variable}=\([^)]*\)", re.MULTILINE)
indent = " " * (len(variable) + 2)
block = f"{variable}=(" + f"\n{indent}".join(f"'{s}'" for s in sums) + ")"
text, count = pattern.subn(block, text)
if count != 1:
    sys.exit(f"{path}: expected one {variable} array")
open(path, "w").write(text)
EOF
}

deb="SirinVPN_${tag#v}_amd64.deb"
deb_sum="$(asset_sum "$deb")"
x86_64_sum="$(asset_sum sirinvpn-server-x86_64)"
aarch64_sum="$(asset_sum sirinvpn-server-aarch64)"
source_sum="$(download_sum "https://github.com/$repo/archive/refs/tags/$tag.tar.gz")"
license_sum="$(download_sum "https://raw.githubusercontent.com/$repo/$tag/LICENSE")"

set_sums sirinvpn sha256sums "$source_sum" "$x86_64_sum" "$aarch64_sum"
set_sums sirinvpn-git sha256sums SKIP "$x86_64_sum" "$aarch64_sum"
set_sums sirinvpn-bin sha256sums_x86_64 "$deb_sum" "$license_sum"
for package in sirinvpn sirinvpn-git sirinvpn-bin; do
  (cd "$aur/$package" && makepkg --printsrcinfo >.SRCINFO)
done
if grep -rn FILL_FROM_RELEASE "$aur"; then
  echo 'a placeholder checksum remains' >&2
  exit 1
fi
printf 'AUR checksums updated for %s\n' "$tag"
