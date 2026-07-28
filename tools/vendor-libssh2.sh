#!/usr/bin/env bash
# Build a self-contained libssh2 (openssl backend) + OpenSSL, statically, with
# zig cc, into vendor/<name>/. The libssh2 zioscp backend links these so the
# resulting binary needs no libssh2/openssl dylib (only system frameworks/libc,
# and libz unless libssh2 is built without it).
#
# Idempotent: skips any library already built. Re-running is a fast no-op.
#
# Usage: tools/vendor-libssh2.sh <name> <openssl-target> [zig-target-triple]
#   <name>            subdir under vendor/ (e.g. macos-aarch64, linux-x86_64)
#   <openssl-target>  OpenSSL Configure target (e.g. darwin64-arm64-cc, linux-x86_64)
#   [zig-target-triple] optional -target passed to zig cc (empty = native)
#
# Requires: zig, autoconf, automake, libtool, perl, make, curl, tar.
set -euo pipefail

NAME="${1:?usage: vendor-libssh2.sh <name> <openssl-target> [zig-triple]}"
OSSL_TARGET="${2:?usage: vendor-libssh2.sh <name> <openssl-target> [zig-triple]}"
ZIG_TARGET="${3:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$ROOT/vendor/$NAME"
WORK="$ROOT/.vendor-build"   # gitignored scratch space for the C builds
mkdir -p "$WORK" "$V/lib" "$V/include"

OSSL_TAG="openssl-3.6.3"          # Apache-2.0
LIBSSH2_TAG="libssh2-1.11.1"      # BSD-3-Clause
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)"

if [ -n "$ZIG_TARGET" ]; then CC="zig cc -target $ZIG_TARGET"; else CC="zig cc"; fi

echo "==> vendoring libssh2+openssl into $V (openssl-target=$OSSL_TARGET zig-target='$ZIG_TARGET')"

# --- OpenSSL 3.6.3 (static; no-module bakes the providers into libcrypto) ---
if [ ! -f "$V/lib/libcrypto.a" ]; then
  echo "==> building OpenSSL $OSSL_TAG"
  cd "$WORK"
  if [ ! -d openssl-src ]; then
    [ -f openssl.tgz ] || curl -fsSL "https://github.com/openssl/openssl/archive/refs/tags/$OSSL_TAG.tar.gz" -o openssl.tgz
    tar xzf openssl.tgz
    mv "$(tar tzf openssl.tgz | head -1 | cut -d/ -f1)" openssl-src
  fi
  cd openssl-src
  CC="$CC" ./Configure "$OSSL_TARGET" no-shared no-module no-tests no-comp \
    --prefix="$V" > "$WORK/ossl_configure.log" 2>&1
  make -j"$JOBS" > "$WORK/ossl_make.log" 2>&1
  make install_sw > "$WORK/ossl_install.log" 2>&1
else
  echo "==> OpenSSL already built, skipping"
fi

# --- libssh2 1.11.1 (openssl backend, against the vendored OpenSSL above) ---
if [ ! -f "$V/lib/libssh2.a" ]; then
  echo "==> building libssh2 $LIBSSH2_TAG (openssl backend)"
  cd "$WORK"
  if [ ! -d libssh2-src ]; then
    [ -f libssh2.tgz ] || curl -fsSL "https://github.com/libssh2/libssh2/archive/refs/tags/$LIBSSH2_TAG.tar.gz" -o libssh2.tgz
    tar xzf libssh2.tgz
    mv "$(tar tzf libssh2.tgz | head -1 | cut -d/ -f1)" libssh2-src
  fi
  cd libssh2-src
  [ -f configure ] || autoreconf -ivf > "$WORK/libssh2_autoreconf.log" 2>&1
  # --without-libz-prefix keeps libssh2 from pulling in zlib when none is requested;
  # if zlib is found anyway, build.zig still links -lz (libz is ubiquitous).
  CC="$CC" CFLAGS="-O2 -I$V/include" LDFLAGS="-L$V/lib" LIBS="-lssl -lcrypto -lm" \
    ./configure --with-crypto=openssl --without-libz-prefix \
      --disable-shared --enable-static --disable-examples --prefix="$V" \
      > "$WORK/libssh2_configure.log" 2>&1
  make -j"$JOBS" > "$WORK/libssh2_make.log" 2>&1
  make install > "$WORK/libssh2_install.log" 2>&1
else
  echo "==> libssh2 already built, skipping"
fi

echo "==> done. vendored libraries:"
ls -la "$V/lib"/libssh2.a "$V/lib"/libcrypto.a "$V/lib"/libssl.a

# Carry the upstream license notices into the vendor dir (Apache-2.0 / BSD-3).
cp -f "$WORK/openssl-src/LICENSE.txt" "$V/OPENSSL-LICENSE.txt" 2>/dev/null || true
cp -f "$WORK/openssl-src/NOTICE.txt"  "$V/OPENSSL-NOTICE.txt"  2>/dev/null || true
cp -f "$WORK/libssh2-src/COPYING"     "$V/LIBSSH2-LICENSE"     2>/dev/null || true

# Report whether libssh2 still references zlib (so build.zig knows to link -lz).
if nm "$V/lib/libssh2.a" 2>/dev/null | grep -q "T _deflate\|U _deflate"; then
  echo "==> note: libssh2 references zlib; build links -lz"
else
  echo "==> libssh2 has no zlib reference"
fi
