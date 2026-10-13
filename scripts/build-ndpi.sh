#!/usr/bin/env bash
# Builds a static libndpi.a for a gokrazy target with zig as the C cross
# compiler and installs it to third_party/ndpi/<goarch>/{include,lib}, where
# the cgo directives in internal/ndpi pick it up.
#
# usage: scripts/build-ndpi.sh [amd64|arm64]...   (default: amd64 arm64)
#
# Requires: zig, curl, tar, make, autoconf, automake, libtool, pkg-config.
set -euo pipefail

NDPI_VERSION="${NDPI_VERSION:-6.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/third_party/ndpi"
SRC="$OUT/src/nDPI-$NDPI_VERSION"

command -v zig >/dev/null || { echo "zig not found in PATH (https://ziglang.org/download/)" >&2; exit 1; }

if [ ! -d "$SRC" ]; then
  mkdir -p "$OUT/src"
  curl -fsSL "https://github.com/ntop/nDPI/archive/refs/tags/$NDPI_VERSION.tar.gz" | tar -xz -C "$OUT/src"
fi
if [ ! -x "$SRC/configure" ]; then
  (cd "$SRC" && ./autogen.sh)
fi

archs=("$@")
[ ${#archs[@]} -eq 0 ] && archs=(amd64 arm64)

for goarch in "${archs[@]}"; do
  case "$goarch" in
    amd64) target=x86_64-linux-musl  host=x86_64-linux-musl ;;
    arm64) target=aarch64-linux-musl host=aarch64-linux-musl ;;
    *) echo "unsupported GOARCH: $goarch" >&2; exit 1 ;;
  esac

  build="$OUT/build/$goarch"
  rm -rf "$build" "$OUT/$goarch"
  mkdir -p "$build" "$OUT/$goarch/lib" "$OUT/$goarch/include/ndpi"

  (
    cd "$build"
    CC="zig cc -target $target" AR="zig ar" RANLIB="zig ranlib" \
    CFLAGS="-O2 -fno-sanitize=undefined -DCROARING_COMPILER_SUPPORTS_AVX512=0" \
      "$SRC/configure" --host="$host" \
        --with-only-libndpi \
        --disable-plugin-support \
        --disable-global-context-support \
        --without-pcre --without-maxminddb
    make -C src/lib -j"$(nproc)" libndpi.a
  )

  cp "$build/src/lib/libndpi.a" "$OUT/$goarch/lib/"
  cp "$SRC"/src/include/*.h "$build"/src/include/*.h "$OUT/$goarch/include/ndpi/" 2>/dev/null || true
  echo "==> $OUT/$goarch/lib/libndpi.a"
done
