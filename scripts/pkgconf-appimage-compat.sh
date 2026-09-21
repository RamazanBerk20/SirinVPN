#!/bin/sh
set -eu

: "${SIRINVPN_REAL_PKGCONF:?missing real pkgconf path}"
: "${SIRINVPN_GDK_PIXBUF_COMPAT_ROOT:?missing GdkPixbuf compatibility root}"

if [ "$#" -eq 2 ] && [ "$2" = "gdk-pixbuf-2.0" ]; then
  case "$1" in
    --variable=gdk_pixbuf_binarydir)
      printf '%s\n' "$SIRINVPN_GDK_PIXBUF_COMPAT_ROOT"
      exit 0
      ;;
    --variable=gdk_pixbuf_cache_file)
      printf '%s/loaders.cache\n' "$SIRINVPN_GDK_PIXBUF_COMPAT_ROOT"
      exit 0
      ;;
    --variable=gdk_pixbuf_moduledir)
      printf '%s/loaders\n' "$SIRINVPN_GDK_PIXBUF_COMPAT_ROOT"
      exit 0
      ;;
  esac
fi

exec "$SIRINVPN_REAL_PKGCONF" "$@"
