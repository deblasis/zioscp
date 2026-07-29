#!/bin/sh
# zioscp installer: detects your OS/arch, downloads the matching prebuilt binary
# from the latest GitHub release, and installs it to ~/.local/bin.
#
#   curl -fsSL https://raw.githubusercontent.com/deblasis/zioscp/master/install.sh | sh
#
# Install elsewhere (either form works):
#   curl -fsSL https://raw.githubusercontent.com/deblasis/zioscp/master/install.sh | sh -s -- --prefix /opt/bin
#   curl -fsSL https://raw.githubusercontent.com/deblasis/zioscp/master/install.sh | PREFIX=/opt/bin sh
# (Note: `PREFIX=/x curl ... | sh` does NOT work; pipe scoping puts PREFIX in
#  curl's env, not sh's. Put PREFIX after the pipe, or use --prefix.)
set -eu

REPO=deblasis/zioscp
PREFIX=${PREFIX:-$HOME/.local/bin}
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX=$2; shift 2 ;;
    --prefix=*) PREFIX=${1#--prefix=}; shift ;;
    *) shift ;;
  esac
done

# --- detect target -----------------------------------------------------------
OS=$(uname -s)
ARCH=$(uname -m)
EXT=tar.gz
case "$OS:$ARCH" in
  Darwin:arm64)    TARGET=aarch64-macos ;;
  Darwin:x86_64)   TARGET=x86_64-macos ;;
  Linux:aarch64|Linux:arm64) TARGET=aarch64-linux-gnu ;;
  Linux:x86_64)    TARGET=x86_64-linux-gnu ;;
  MINGW*:*|MSYS*:*|CYGWIN*:*) TARGET=x86_64-windows-gnu; EXT=zip ;;
  *) echo "zioscp: unsupported platform ($OS $ARCH). Use a release binary: https://github.com/$REPO/releases" >&2; exit 1 ;;
esac

# --- latest release tag ------------------------------------------------------
TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$TAG" ] || { echo "zioscp: could not determine the latest release" >&2; exit 1; }

ASSET="zioscp-$TAG-$TARGET.$EXT"
URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"
echo "zioscp: downloading $ASSET"

# --- fetch + extract ---------------------------------------------------------
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/$ASSET" "$URL"
if [ "$EXT" = "zip" ]; then
  (command -v unzip >/dev/null || { echo "zioscp: unzip is required" >&2; exit 1; })
  unzip -oq "$TMP/$ASSET" -d "$TMP"
else
  tar -xzf "$TMP/$ASSET" -C "$TMP"
fi
# Binary is at the archive root (newer releases) or in a versioned subdir (older).
BIN=$(find "$TMP" -type f \( -name zioscp -o -name zioscp.exe \) | head -1)
[ -n "$BIN" ] || { echo "zioscp: download did not contain the binary" >&2; exit 1; }

# --- install -----------------------------------------------------------------
mkdir -p "$PREFIX"
mv "$BIN" "$PREFIX/zioscp"
chmod +x "$PREFIX/zioscp"

echo "zioscp: installed $TAG to $PREFIX/zioscp"
case ":$PATH:" in
  *":$PREFIX:"*) ;;  # already on PATH
  *) cat <<EOF

Add zioscp to your PATH (then restart your shell):
  echo 'export PATH="$PREFIX:\$PATH"' >> ~/.profile && source ~/.profile

EOF
esac
"$PREFIX/zioscp" --version 2>/dev/null || true
