#!/usr/bin/env bash
# Build a self-contained libssh2 (openssl backend) + OpenSSL, statically, with
# zig cc, into vendor/<name>/. The libssh2 zioscp backend links these so the
# resulting binary needs no libssh2/openssl dylib (only system frameworks/libc).
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
WORK="$ROOT/.vendor-build/$NAME"   # per-target scratch space (so targets don't clobber each other)
mkdir -p "$WORK" "$V/lib" "$V/include"

OSSL_TAG="openssl-3.6.3"          # Apache-2.0
LIBSSH2_TAG="libssh2-1.11.1"      # BSD-3-Clause
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)"

if [ -n "$ZIG_TARGET" ]; then CC="zig cc -target $ZIG_TARGET"; else CC="zig cc"; fi

# Cross-compile? Compare the target arch+os (from the OpenSSL target name) to the
# build host's. When cross, libssh2's autotools needs --host (else it tries to RUN
# its test binaries) and the static archives need re-indexing to GNU format (mac's
# ar emits __.SYMDEF, which zig's ELF archive reader rejects).
case "$(uname -s)" in Darwin) bos=darwin ;; Linux) bos=linux ;; *) bos="$(uname -s)" ;; esac
case "$(uname -m)" in arm64|aarch64) barch=arm64 ;; *) barch="$(uname -m)" ;; esac
case "$OSSL_TARGET" in
  darwin64-arm64-cc)  tarch=arm64 ; tos=darwin ;;
  darwin64-x86_64-cc) tarch=x86_64; tos=darwin ;;
  linux-x86_64)       tarch=x86_64; tos=linux ;;
  linux-aarch64)      tarch=arm64 ; tos=linux ;;
  mingw64)            tarch=x86_64; tos=windows ;;
  *) tarch= ; tos= ;;
esac
CROSS=false
GNU_HOST=""
if [ -n "$tarch" ] && { [ "$tarch" != "$barch" ] || [ "$tos" != "$bos" ]; }; then
  CROSS=true
  case "$tarch-$tos" in
    x86_64-linux)   GNU_HOST="x86_64-pc-linux-gnu" ;;
    arm64-linux)    GNU_HOST="aarch64-unknown-linux-gnu" ;;
    x86_64-darwin)  GNU_HOST="x86_64-apple-darwin" ;;
    arm64-darwin)   GNU_HOST="aarch64-apple-darwin" ;;
    x86_64-windows) GNU_HOST="x86_64-w64-mingw32" ;;
  esac
fi

echo "==> vendoring libssh2+openssl into $V (openssl-target=$OSSL_TARGET zig-target='$ZIG_TARGET' cross=$CROSS)"

# --- OpenSSL 3.6.3 (static; no-module bakes the providers into libcrypto) ---
if [ ! -f "$V/lib/libcrypto.a" ] || [ ! -f "$V/lib/libssl.a" ]; then
  echo "==> building OpenSSL $OSSL_TAG"
  cd "$WORK"
  if [ ! -d openssl-src ]; then
    [ -f openssl.tgz ] || curl -fsSL "https://github.com/openssl/openssl/archive/refs/tags/$OSSL_TAG.tar.gz" -o openssl.tgz
    tar xzf openssl.tgz
    mv "$(tar tzf openssl.tgz | head -1 | cut -d/ -f1)" openssl-src
  fi
  cd openssl-src
  # --libdir=lib forces lib/ on linux (default lib64) so build.zig finds them.
  CC="$CC" ./Configure "$OSSL_TARGET" no-shared no-module no-tests no-comp \
    --libdir=lib --prefix="$V" > "$WORK/ossl_configure.log" 2>&1
  # Build only the libraries, not the openssl CLI app: the app's Windows resource
  # file needs windres (which zig cc can't provide on mingw), and we only need
  # libcrypto/libssl + headers anyway. build_libs + install_dev cover all targets.
  make -j"$JOBS" build_libs > "$WORK/ossl_make.log" 2>&1
  make install_dev > "$WORK/ossl_install.log" 2>&1
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
  HOST_ARG=()
  [ "$CROSS" = true ] && [ -n "$GNU_HOST" ] && HOST_ARG=(--host="$GNU_HOST")
  # AR/RANLIB = zig ar so libtool doesn't default to the MSVC 'lib' librarian on
  # mingw, and produces GNU-format archives directly (everywhere).
  # --without-libz-prefix keeps libssh2 from pulling in zlib when none is requested.
  CC="$CC" AR="zig ar" RANLIB="zig ar s" \
    CFLAGS="-O2 -I$V/include" LDFLAGS="-L$V/lib" LIBS="-lssl -lcrypto -lm" \
    ./configure ${HOST_ARG[@]+"${HOST_ARG[@]}"} --with-crypto=openssl --without-libz-prefix \
      --disable-shared --enable-static --prefix="$V" \
      > "$WORK/libssh2_configure.log" 2>&1
  # libtool guesses MSVC for mingw + a non-gcc CC, baking 'lib -OUT:' (the MSVC
  # librarian) as the static-archive command. Force the GNU '$AR $AR_FLAGS' form
  # (AR=zig ar above). No-op on mac/linux where libtool already uses $AR.
  # -i.bak (not -i): BSD sed (macOS) requires an extension arg for -i.
  sed -i.bak 's|old_archive_cmds="lib -OUT:[^"]*"|old_archive_cmds="\\$AR \\$AR_FLAGS \\$oldlib\\$oldobjs"|g' libtool
  rm -f libtool.bak
  # Build only the library (src/): the example/ programs link OpenSSL legacy
  # ciphers (RC4/CAST5/DES) we don't build, and aren't needed.
  make -C src -j"$JOBS" > "$WORK/libssh2_make.log" 2>&1
  make -C src install > "$WORK/libssh2_install.log" 2>&1
  cp include/libssh2.h include/libssh2_publickey.h include/libssh2_sftp.h "$V/include/" 2>/dev/null || true
  # mingw libtool names the static lib libssh2.lib; rename to .a (same archive).
  if [ -f "$V/lib/libssh2.lib" ] && [ ! -f "$V/lib/libssh2.a" ]; then
    mv "$V/lib/libssh2.lib" "$V/lib/libssh2.a"
  fi
else
  echo "==> libssh2 already built, skipping"
fi

# On linux targets, mac's ar produces BSD archives (__.SYMDEF) that zig's ELF
# archive reader rejects ("not an ELF file"); rebuild them as GNU archives.
# Idempotent: only touches archives still in BSD form (mac's `ar x` can't extract
# GNU long-name members, so re-running on an already-GNU archive would corrupt it).
if [ "$CROSS" = true ]; then
  for a in "$V/lib/libssh2.a" "$V/lib/libssl.a" "$V/lib/libcrypto.a"; do
    [ -f "$a" ] || continue
    # First member name. NB: avoid `ar t | head -1` -- under `set -o pipefail` the
    # large libcrypto archive keeps `ar t` writing after head closes -> SIGPIPE ->
    # set -e aborts the whole script mid-loop. Read the full output instead.
    all="$(ar t "$a" 2>/dev/null || true)"
    first="${all%%$'\n'*}"
    case "$first" in __.SYMDEF*) ;; *) continue ;; esac   # already GNU/non-BSD
    echo "==> re-indexing $a to GNU format (zig ar)"
    tmp="$(mktemp -d)"
    # Re-archive every extracted member: *.o on Unix, *.obj on Windows (mingw).
    # nullglob drops a pattern that matches nothing so the bare glob can't fail.
    ( cd "$tmp" && ar x "$a" && rm -f __.SYMDEF* "$a" && shopt -s nullglob && zig ar --format=gnu rcs "$a" *.o *.obj )
    rm -rf "$tmp"
  done
fi

echo "==> done. vendored libraries:"
ls -la "$V/lib"/libssh2.a "$V/lib"/libcrypto.a "$V/lib"/libssl.a

# Carry the upstream license notices into the vendor dir (Apache-2.0 / BSD-3).
cp -f "$WORK/openssl-src/LICENSE.txt" "$V/OPENSSL-LICENSE.txt" 2>/dev/null || true
cp -f "$WORK/openssl-src/NOTICE.txt"  "$V/OPENSSL-NOTICE.txt"  2>/dev/null || true
cp -f "$WORK/libssh2-src/COPYING"     "$V/LIBSSH2-LICENSE"     2>/dev/null || true

# Report whether libssh2 still references zlib.
if nm "$V/lib/libssh2.a" 2>/dev/null | grep -q "T _deflate\|U _deflate"; then
  echo "==> note: libssh2 references zlib"
else
  echo "==> libssh2 has no zlib reference"
fi
