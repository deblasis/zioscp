#!/usr/bin/env bash
# Latency-injected benchmark: zioscp vs stock scp under injected RTT.
#
# Runs ON ubuntinovm (x86_64 Linux, root, tc+netem available) over localhost,
# with tc netem adding delay to the loopback so the only latency is the
# injected RTT (the mac<->vm control session rides a different interface and is
# unaffected). A timed run is accepted only if the transfer exits 0 (which is
# what catches connection/auth failures); a final sha256 spot-check confirms
# correctness once per direction.
#
# Setup from the mac:
#   zig build -Dtarget=x86_64-linux-gnu
#   scp zig-out/bin/zioscp root@ubuntinovm:/root/zioscp
#   scp tests/bench-latency.sh root@ubuntinovm:/root/bench-latency.sh
#   ssh root@ubuntinovm 'RUNS=3 bash /root/bench-latency.sh'
set -euo pipefail

Z=${Z:-/root/zioscp}
KEY=/root/.ssh/zioscp_bench_key
RTT_MS_LIST="${RTT_MS_LIST:-0 100}"
RUNS=${RUNS:-3}
BIG=/tmp/bench_lat_big.bin
BIG_SIZE=${BIG_SIZE:-20971520}        # 20 MiB
TREE_SRC=/tmp/bench_lat_tree
TREE_FILES=${TREE_FILES:-100}
TREE_FILE_SIZE=${TREE_FILE_SIZE:-262144}  # 256 KiB -> 100 files ~= 25 MiB
REMOTE_BIG=/root/bench_lat_big.remote
REMOTE_TREE=/root/bench_lat_tree.remote
DST=/tmp/bench_lat_dst

# --- sftp key auth for root@localhost ---
mkdir -p /root/.ssh && chmod 700 /root/.ssh
[ -f "$KEY" ] || ssh-keygen -t ed25519 -N "" -f "$KEY" -q
PUB=$(cat "$KEY.pub")
touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
grep -qF "$PUB" /root/.ssh/authorized_keys || echo "$PUB" >> /root/.ssh/authorized_keys
ssh-keygen -R localhost >/dev/null 2>&1 || true
ssh-keyscan -t ed25519 localhost 2>/dev/null >> /root/.ssh/known_hosts || true

# -n so nested ssh never eats the script's stdin.
SSH="ssh -n -i $KEY -o BatchMode=yes localhost"
SCP="scp -i $KEY -o BatchMode=yes"
Z1="$Z -i $KEY"
Z4="$Z -i $KEY -j4"

# --- fixtures ---
[ -f "$BIG" ] || head -c "$BIG_SIZE" /dev/urandom > "$BIG"
BIG_SHA=$(sha256sum "$BIG" | cut -d' ' -f1)
if [ ! -d "$TREE_SRC" ]; then
  mkdir -p "$TREE_SRC"
  for i in $(seq 1 "$TREE_FILES"); do head -c "$TREE_FILE_SIZE" /dev/urandom > "$TREE_SRC/f$i.bin"; done
fi
N_FILES=$(find "$TREE_SRC" -type f | wc -l | tr -d ' ')
if [ "$N_FILES" != "$TREE_FILES" ]; then
  rm -rf "$TREE_SRC"; mkdir -p "$TREE_SRC"
  for i in $(seq 1 "$TREE_FILES"); do head -c "$TREE_FILE_SIZE" /dev/urandom > "$TREE_SRC/f$i.bin"; done
  N_FILES=$TREE_FILES
fi

cleanup() { tc qdisc del dev lo root 2>/dev/null || true; rm -rf "$REMOTE_BIG" "$REMOTE_TREE" "$DST"; }
trap cleanup EXIT

# tmin: min seconds over RUNS among runs whose transfer exits 0.
tmin() {
  local transfer="$1" best=""
  for _ in $(seq 1 "$RUNS"); do
    local t0 t1 rc e
    t0=$(date +%s.%N); eval "$transfer" >/dev/null 2>&1; rc=$?; t1=$(date +%s.%N)
    if [ "$rc" -eq 0 ]; then
      e=$(echo "$t1 - $t0" | bc)
      if [ -z "$best" ] || (( $(echo "$e < $best" | bc) )); then best=$e; fi
    fi
  done
  [ -z "$best" ] && echo "FAIL" || printf '%.3f' "$best"
}

row() { printf '%-16s' "$1"; shift; for t in "$@"; do printf ' %9s' "$t"; done; printf '\n'; }

set_lat() { # $1 = RTT ms (0 = remove)
  if [ "$1" -eq 0 ]; then
    tc qdisc del dev lo root 2>/dev/null || true
  else
    tc qdisc replace dev lo root netem delay "$(( $1 / 2 ))ms"
  fi
}

check() { echo "spot-check: $*"; }

for RTT in $RTT_MS_LIST; do
  set_lat "$RTT"
  echo "========================= ${RTT}ms RTT ========================="

  echo "--- single large file ($(( BIG_SIZE / 1048576 )) MiB), min of $RUNS exit-0 runs (s) ---"
  row "variant" "scp" "zioscp-j1" "zioscp-j4"
  rm -f "$REMOTE_BIG"; A=$(tmin "$SCP $BIG localhost:$REMOTE_BIG")
  rm -f "$REMOTE_BIG"; B=$(tmin "$Z1 $BIG localhost:$REMOTE_BIG")
  rm -f "$REMOTE_BIG"; C=$(tmin "$Z4 $BIG localhost:$REMOTE_BIG")
  # leave REMOTE_BIG populated for the download comparison
  $SCP "$BIG" localhost:"$REMOTE_BIG" >/dev/null 2>&1 || true
  row "upload" "$A" "$B" "$C"

  rm -rf "$DST"; A=$(tmin "$SCP localhost:$REMOTE_BIG $DST")
  rm -rf "$DST"; B=$(tmin "$Z1 localhost:$REMOTE_BIG $DST")
  rm -rf "$DST"; C=$(tmin "$Z4 localhost:$REMOTE_BIG $DST")
  rm -rf "$DST"
  row "download" "$A" "$B" "$C"

  echo "--- many small files ($N_FILES x $(( TREE_FILE_SIZE / 1024 )) KiB ~= $(( N_FILES * TREE_FILE_SIZE / 1048576 )) MiB), min of $RUNS exit-0 runs (s) ---"
  row "variant" "scp -r" "zioscp -r" "zioscp -r -j4"
  $SSH "rm -rf $REMOTE_TREE" >/dev/null 2>&1 || true
  A=$(tmin "$SCP -r $TREE_SRC localhost:$REMOTE_TREE")
  $SSH "rm -rf $REMOTE_TREE" >/dev/null 2>&1 || true
  B=$(tmin "$Z1 -r $TREE_SRC localhost:$REMOTE_TREE")
  $SSH "rm -rf $REMOTE_TREE" >/dev/null 2>&1 || true
  C=$(tmin "$Z4 -r $TREE_SRC localhost:$REMOTE_TREE")
  $SSH "rm -rf $REMOTE_TREE" >/dev/null 2>&1 || true
  row "upload" "$A" "$B" "$C"
done

# --- one correctness spot-check at 100ms RTT (upload then download, sha both) ---
set_lat 100
echo "========================= correctness spot-check (100ms RTT) ========================="
rm -f "$REMOTE_BIG"
$Z1 "$BIG" localhost:"$REMOTE_BIG"
R=$($SSH sha256sum "$REMOTE_BIG" | cut -d' ' -f1)
check "upload zioscp-j1: src=$BIG_SHA remote=$R $([ "$R" = "$BIG_SHA" ] && echo OK || echo MISMATCH)"
rm -rf "$DST"
$Z1 localhost:"$REMOTE_BIG" "$DST"
D=$(sha256sum "$DST" | cut -d' ' -f1)
check "download zioscp-j1: remote=$BIG_SHA local=$D $([ "$D" = "$BIG_SHA" ] && echo OK || echo MISMATCH)"

echo "done."
