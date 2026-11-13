#!/bin/sh
# The Linux install layout, in one place.
#
#   install-linux.sh tauri-deb-files
#       Print the Tauri config patch that lists these files for the Debian
#       package (package-linux.sh). Tauri adds the desktop binary, the desktop
#       entry and the icons itself, and the maintainer scripts do the rest.
#   DESTDIR=/path PREFIX=/usr install-linux.sh install BINARY_DIR DESKTOP_BINARY METHOD
#       Install everything into DESTDIR for packagers that do not use Tauri's
#       bundler (the AUR packages). BINARY_DIR holds the files named under
#       "binaries" below; METHOD is written to lib/sirinvpn/install-method so
#       the app offers package-manager updates instead of the Debian installer.
#
# The paths are not relocatable: the Polkit policy, the systemd units and the
# binaries themselves name /usr/lib/sirinvpn, so PREFIX must stay /usr.
set -eu

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

# destination (below PREFIX), mode, source (binaries/NAME or a project path)
files() {
  cat <<'EOF'
bin/sirinvpn 0755 binaries/sirinvpn
lib/sirinvpn/sirinvpn-helper 0755 binaries/sirinvpn-helper
lib/sirinvpn/sirinvpn-release 0755 binaries/sirinvpn-release
lib/sirinvpn/sirinvpn-release-fetch 0755 binaries/sirinvpn-release-fetch
lib/sirinvpn/sirinvpn-server 0755 binaries/sirinvpn-server
lib/sirinvpn/sirinvpn-server-x86_64 0755 binaries/sirinvpn-server-x86_64
lib/sirinvpn/sirinvpn-server-aarch64 0755 binaries/sirinvpn-server-aarch64
share/polkit-1/actions/org.sirinvpn.network.policy 0644 packaging/polkit/org.sirinvpn.network.policy
lib/NetworkManager/conf.d/90-sirinvpn-probe.conf 0644 packaging/networkmanager/90-sirinvpn-probe.conf
lib/systemd/system/sirinvpn-killswitch.service 0644 packaging/systemd/sirinvpn-killswitch.service
lib/systemd/system/sirinvpn-reconnect.service 0644 packaging/systemd/sirinvpn-reconnect.service
lib/systemd/system/sirinvpn-transport.service 0644 packaging/systemd/sirinvpn-transport.service
lib/systemd/system/sirinvpn-transport@.service 0644 packaging/systemd/sirinvpn-transport@.service
EOF
}

# Debian's licence location, as destination (below /usr) and project source: the licence is the
# package's copyright file. The AUR layout uses share/licenses/sirinvpn in install_tree instead.
deb_doc_files() {
  echo "share/doc/sirin-vpn/copyright LICENSE"
  for notice in "$PROJECT_ROOT"/packaging/third-party/*; do
    echo "share/doc/sirin-vpn/third-party/${notice##*/} packaging/third-party/${notice##*/}"
  done
}

tauri_deb_files() {
  # Tauri resolves file sources against apps/desktop/src-tauri.
  printf '{"bundle":{"linux":{"deb":{"files":{'
  separator=
  { files | while read -r destination _mode source; do echo "$destination $source"; done; deb_doc_files; } |
  while read -r destination source; do
    case "$source" in
      binaries/*) ;;
      *) source="../../../$source" ;;
    esac
    printf '%s"/usr/%s":"%s"' "$separator" "$destination" "$source"
    separator=,
  done
  printf '}}}}}\n'
}

install_tree() {
  binary_dir=$1
  desktop_binary=$2
  method=$3
  prefix=${PREFIX:-/usr}
  root=${DESTDIR:-}
  [ "$prefix" = /usr ] || { echo "PREFIX must be /usr: the Polkit policy and units name /usr/lib/sirinvpn" >&2; exit 2; }
  case "$method" in
    ''|*[!a-z]*) echo "install method must be a lowercase word, such as aur" >&2; exit 2 ;;
  esac
  [ -f "$desktop_binary" ] || { echo "desktop binary is missing: $desktop_binary" >&2; exit 1; }

  files | while read -r destination mode source; do
    case "$source" in
      binaries/*) source="$binary_dir/${source#binaries/}" ;;
      *) source="$PROJECT_ROOT/$source" ;;
    esac
    [ -f "$source" ] || { echo "missing install source: $source" >&2; exit 1; }
    install -D -m "$mode" "$source" "$root$prefix/$destination"
  done

  install -D -m 0755 "$desktop_binary" "$root$prefix/bin/sirinvpn-desktop"
  printf '%s\n' "$method" >"$root$prefix/lib/sirinvpn/install-method"
  chmod 0644 "$root$prefix/lib/sirinvpn/install-method"

  # Same entry and icon name as the Debian package, which Tauri generates.
  mkdir -p "$root$prefix/share/applications"
  cat >"$root$prefix/share/applications/SirinVPN.desktop" <<'EOF'
[Desktop Entry]
Categories=Utility;
Comment=Private self-hosted VPN client
Exec=sirinvpn-desktop
StartupWMClass=sirinvpn-desktop
Icon=sirinvpn-desktop
Name=SirinVPN
Terminal=false
Type=Application
EOF
  chmod 0644 "$root$prefix/share/applications/SirinVPN.desktop"
  icons="$PROJECT_ROOT/apps/desktop/src-tauri/icons"
  for icon in 32x32:32x32 128x128:128x128 256x256:128x128@2x 512x512:icon; do
    install -D -m 0644 "$icons/${icon#*:}.png" \
      "$root$prefix/share/icons/hicolor/${icon%%:*}/apps/sirinvpn-desktop.png"
  done
  install -D -m 0644 "$icons/sirinvpn-icon.svg" \
    "$root$prefix/share/icons/hicolor/scalable/apps/sirinvpn-desktop.svg"

  licenses="$root$prefix/share/licenses/sirinvpn"
  install -D -m 0644 "$PROJECT_ROOT/LICENSE" "$licenses/LICENSE"
  install -d -m 0755 "$licenses/third-party"
  install -m 0644 "$PROJECT_ROOT"/packaging/third-party/* "$licenses/third-party/"
  install -D -m 0644 -t "$root$prefix/share/doc/sirinvpn" \
    "$PROJECT_ROOT/README.md" "$PROJECT_ROOT/SECURITY.md" "$PROJECT_ROOT/PRIVACY.md"
}

case "${1:-}" in
  tauri-deb-files)
    [ "$#" -eq 1 ] || { echo "usage: $0 tauri-deb-files" >&2; exit 2; }
    tauri_deb_files
    ;;
  install)
    [ "$#" -eq 4 ] || { echo "usage: DESTDIR=... PREFIX=/usr $0 install BINARY_DIR DESKTOP_BINARY METHOD" >&2; exit 2; }
    install_tree "$2" "$3" "$4"
    ;;
  *)
    echo "usage: $0 tauri-deb-files | install BINARY_DIR DESKTOP_BINARY METHOD" >&2
    exit 2
    ;;
esac
