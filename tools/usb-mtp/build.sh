#!/bin/sh
# build.sh — compile the libptp2 subset (from libmtp's vendored source)
# + mtp_probe_libpt2.c against Homebrew libusb-1.0. Static objects live in
# libptp2-build/ (gitignored); the binary is tools/usb-mtp/mtp_probe_libpt2.
#
# LGPL-2.1 note: ptp.c / ptp-pack.c / libusb1-glue.c are compiled verbatim
# from libmtp 1.1.23 — a static subset is a derivative work; see
# PROVENANCE.md (source path + version recorded there; ship the libmtp
# source alongside any binary you distribute).
#
# Usage: sh tools/usb-mtp/build.sh [path-to-libmtp-src]
#   default source: /tmp/libmtp-src/libmtp-1.1.23/src
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-/tmp/libmtp-src/libmtp-1.1.23/src}"
[ -f "$SRC/ptp.c" ] || { echo "error: $SRC/ptp.c missing (pass the libmtp src dir)"; exit 2; }

LIBUSB="$(brew --prefix libusb 2>/dev/null || echo /opt/homebrew/opt/libusb)"
BUILD="$HERE/libptp2-build"
mkdir -p "$BUILD"

# minimal config.h (mirrors the Homebrew libmtp build's relevant defines)
cat > "$BUILD/config.h" <<'EOF'
/* stub config.h for the libptp2 subset build (see build.sh) */
#define HAVE_LIMITS_H 1
#define HAVE_UNISTD_H 1
#define HAVE_ICONV 1
#define HAVE_LANGINFO_H 1
#define HAVE_LIBUSB1 1
EOF

# macOS has no byteswap.h; gphoto2-endian.h includes it unconditionally
cat > "$BUILD/byteswap.h" <<'EOF'
/* byteswap.h shim for macOS (clang builtins) */
#ifndef _LIBPTP2_BYTESWAP_SHIM
#define _LIBPTP2_BYTESWAP_SHIM
#define bswap_16(x) __builtin_bswap16(x)
#define bswap_32(x) __builtin_bswap32(x)
#define bswap_64(x) __builtin_bswap64(x)
#endif
EOF

echo "== libptp2 subset: ptp.c + libusb1-glue.c (which embeds ptp-pack.c)"
clang -O2 -Wall -I"$BUILD" -I"$SRC" -I"$LIBUSB/include/libusb-1.0" \
    -c "$SRC/ptp.c" -o "$BUILD/ptp.o"
clang -O2 -Wall -I"$BUILD" -I"$SRC" -I"$LIBUSB/include/libusb-1.0" \
    -c "$SRC/libusb1-glue.c" -o "$BUILD/glue.o"

echo "== prober"
clang -O2 -Wall -I"$BUILD" -I"$SRC" -I"$LIBUSB/include/libusb-1.0" \
    -c "$HERE/libmtp_shims.c" -o "$BUILD/shims.o"
clang -O2 -Wall -I"$BUILD" -I"$SRC" -I"$LIBUSB/include/libusb-1.0" \
    -o "$HERE/mtp_probe_libpt2" "$HERE/mtp_probe_libpt2.c" \
    "$BUILD/ptp.o" "$BUILD/glue.o" "$BUILD/shims.o" \
    -L"$LIBUSB/lib" -lusb-1.0 -liconv

echo "== self-test"
"$HERE/mtp_probe_libpt2" --self-test
echo "built: $HERE/mtp_probe_libpt2"
