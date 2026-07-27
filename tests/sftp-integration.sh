#!/usr/bin/env bash
# Reproducible harness for the SFTP integration test (src/integration.zig).
# Starts a linuxserver/openssh-server container with key auth on :2222,
# runs `zig build integration`, and tears down. Docker must be running.
set -euo pipefail

cd "$(dirname "$0")/.."  # repo root

KEY=tests/keys/ed25519
mkdir -p tests/keys
[ -f "$KEY" ] || ssh-keygen -t ed25519 -N "" -C zioscp-test -f "$KEY" -q
PUB="$(cat "$KEY.pub")"

docker rm -f zioscp-sftp >/dev/null 2>&1 || true
docker run -d --name zioscp-sftp -p 2222:2222 \
  -e PUID=1000 -e PGID=1000 -e USER_NAME=testuser \
  -e PUBLIC_KEY="$PUB" \
  --tmpfs /diskfull:size=131072,uid=1000,gid=1000,mode=1777 \
  linuxserver/openssh-server:latest >/dev/null

cleanup() { docker rm -f zioscp-sftp >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Wait for sshd.
for _ in $(seq 1 30); do
  if ssh -i "$KEY" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=2 testuser@localhost true 2>/dev/null; then
    break
  fi
  sleep 1
done

zig build integration --summary all
