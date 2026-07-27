#!/usr/bin/env bash
# Benchmark stock scp vs zioscp. Every timed run is VERIFIED (sha or file
# count) before its time is accepted, so a failed transfer can never report a
# bogus fast time. The test container's host key is trusted via ssh-keyscan.
#
# CAVEAT: localhost has ~0 RTT and the Docker volume IS the mac filesystem,
# so single-large-file throughput is fs/protocol-overhead bound and -j speedup
# is minimal. The MEANINGFUL comparison here is many-small-files (per-file
# overhead), where zioscp's lean collect-then-transfer beats scp's chattier
# recursive protocol. The -j WAN win needs a latency-injected link (tc netem
# behind a Linux router) -- a follow-up.
set -euo pipefail
cd "$(dirname "$0")/.."
KEY=tests/keys/ed25519
Z="./zig-out/bin/zioscp -P 2222 -i $KEY"
SCP="scp -P 2222 -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
RUNS=${RUNS:-3}

ssh-keygen -R "[localhost]:2222" 2>/dev/null || true
ssh-keyscan -p 2222 -t ed25519 localhost 2>/dev/null >> ~/.ssh/known_hosts || true

# tmin <verify_str> <transfer_str>: min elapsed (s) over RUNS among runs whose
# verify passes; FAIL if none passed.
tmin() {
  local verify="$1" transfer="$2" best=""
  for _ in $(seq 1 "$RUNS"); do
    local t0 t1
    t0=$(date +%s.%N); eval "$transfer" >/dev/null 2>&1; t1=$(date +%s.%N)
    if eval "$verify" >/dev/null 2>&1; then
      local e; e=$(echo "$t1 - $t0" | bc)
      if [ -z "$best" ] || (( $(echo "$e < $best" | bc) )); then best=$e; fi
    fi
  done
  [ -z "$best" ] && echo "FAIL" || echo "$best"
}
sha_local()   { [ -f "$1" ] && [ "$(shasum -a 256 "$1" | cut -d' ' -f1)" = "$2" ]; }
sha_remote()  { [ "$(docker exec zioscp-sftp sha256sum "$1" 2>/dev/null | cut -d' ' -f1)" = "$2" ]; }
count_remote(){ [ "$(docker exec zioscp-sftp find "$1" -type f 2>/dev/null | wc -l | tr -d ' ')" = "$2" ]; }
count_local() { [ -d "$1" ] && [ "$(find "$1" -type f | wc -l | tr -d ' ')" = "$2" ]; }

row() { # label dir variant-times...
  printf '%-16s' "$1"; shift
  for t in "$@"; do printf ' %7s' "$t"; done
  printf '\n'
}

echo "=== single file upload (min of $RUNS verified runs, seconds) ==="
SS=$(shasum -a 256 /tmp/bench_small.bin | cut -d' ' -f1)
SM=$(shasum -a 256 /tmp/bench_medium.bin | cut -d' ' -f1)
SL=$(shasum -a 256 /tmp/bench_large.bin | cut -d' ' -f1)
row "size:" "" "scp" "zioscp-j1" "zioscp-j4"
for spec in "small /tmp/bench_small.bin /config/b_s.bin $SS" \
            "medium /tmp/bench_medium.bin /config/b_m.bin $SM" \
            "large /tmp/bench_large.bin /config/b_l.bin $SL"; do
  set -- $spec; label=$1 lf=$2 rf=$3 sha=$4
  docker exec zioscp-sftp rm -f "$rf"; A=$(tmin "sha_remote $rf $sha" "$SCP $lf testuser@localhost:$rf")
  docker exec zioscp-sftp rm -f "$rf"; B=$(tmin "sha_remote $rf $sha" "$Z $lf testuser@localhost:$rf")
  docker exec zioscp-sftp rm -f "$rf"; C=$(tmin "sha_remote $rf $sha" "$Z -j4 $lf testuser@localhost:$rf")
  docker exec zioscp-sftp rm -f "$rf"
  row "$label" "" "$A" "$B" "$C"
done

echo "=== many small files (min of $RUNS verified runs, seconds) ==="
N=$(find /tmp/bench_many -type f | wc -l | tr -d ' ')
row "tree ($N files):" "" "scp -r" "zioscp -r -j1" "zioscp -r -j4"
docker exec zioscp-sftp rm -rf /config/bt_up; A=$(tmin "count_remote /config/bt_up $N" "$SCP -r /tmp/bench_many testuser@localhost:/config/bt_up")
docker exec zioscp-sftp rm -rf /config/bt_up; B=$(tmin "count_remote /config/bt_up $N" "$Z -r /tmp/bench_many testuser@localhost:/config/bt_up")
docker exec zioscp-sftp rm -rf /config/bt_up; C=$(tmin "count_remote /config/bt_up $N" "$Z -r -j4 /tmp/bench_many testuser@localhost:/config/bt_up")
docker exec zioscp-sftp rm -rf /config/bt_up
row "upload" "" "$A" "$B" "$C"
# Ensure a clean populated remote tree exists for the download comparison.
$Z -r /tmp/bench_many testuser@localhost:/config/bt_up >/dev/null 2>&1
rm -rf /tmp/dl_many; A=$(tmin "count_local /tmp/dl_many $N" "$SCP -r testuser@localhost:/config/bt_up /tmp/dl_many")
rm -rf /tmp/dl_many; B=$(tmin "count_local /tmp/dl_many $N" "$Z -r testuser@localhost:/config/bt_up /tmp/dl_many")
rm -rf /tmp/dl_many; C=$(tmin "count_local /tmp/dl_many $N" "$Z -r -j4 testuser@localhost:/config/bt_up /tmp/dl_many")
rm -rf /tmp/dl_many
row "download" "" "$A" "$B" "$C"
docker exec zioscp-sftp rm -rf /config/bt_up
