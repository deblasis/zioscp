# zioscp

A drop-in `scp` replacement written in Zig. Same flags and syntax as `scp`, but
it speaks SFTP under the hood over a system `ssh` subprocess, so it can **resume
interrupted transfers** and run **parallel transfers** (file-level and
single-file chunked). Works against any unmodified `sshd`.

## Features

- **scp-compatible syntax**: `[user@]host:path` paths, `-r`, `-p`, `-P`, `-i`.
- **Resume**: a `.zioscppart` sidecar records progress; a re-run continues where
  it left off instead of restarting. Download resume is **integrity-checked**:
  each completed chunk gets a SHA-256 MAC in a `.zioscpmac` file, so a partial
  that was corrupted on disk between runs is detected and re-fetched rather
  than trusted (offset-only resume cannot detect this).
- **Parallel transfers**:
  - `-r -j N` fans a directory tree across N ssh connections (file-level).
  - `-j N` on a single large file shards it at offset ranges across N
    connections (chunked concurrent writes/reads).
- **Pipelined single stream**: the upload path keeps a window of SFTP WRITEs in
  flight, so `zioscp -j1` saturates the server and beats stock `scp` on large
  uploads even at zero added latency.
- **Bandwidth limiting** (`--bwlimit`, paced at chunk granularity), **progress
  bar** (TTY-gated), **`-v`** per-file logging, and **permission + mtime
  preservation** (`-p`).

## Build and test

```
zig build          # build the binary -> zig-out/bin/zioscp
zig build test     # unit tests
just ci            # fmt-check + build + test (what CI runs)
```

### Transport backend

The default (`-Dbackend=ssh`, the default) drives a system `ssh` subprocess, so
it works anywhere `ssh` is installed. A **self-contained** backend that links
libssh2 directly (no `ssh` dependency at all) is also available:

```
zig build -Dbackend=libssh2     # self-contained: no ssh, no libssh2/openssl dylib
```

This backend vendors **libssh2 1.11.1 (OpenSSL backend) + OpenSSL 3.6.3** and
builds both statically with `zig cc`, so the resulting binary has no `ssh`,
`libssh2`, `libssl`, or `libcrypto` dependency (only the OS runtime). All common
key types work: **Ed25519, ECDSA, and RSA** public-key auth, plus the
curve25519 key exchange. `tools/vendor-libssh2.sh` fetches the pinned sources
and builds them into a gitignored `vendor/<os>-<arch>/`; the build invokes it
automatically (an idempotent no-op once built). The first `-Dbackend=libssh2`
build therefore needs `autoconf automake libtool perl make curl` and an internet
fetch (~a few minutes); later builds are fast.

libssh2 provides only the SSH transport: zioscp opens a channel to the `sftp`
subsystem and runs its existing SFTP codec over the channel bytes, so all the
SFTP/resume/pipeline logic is shared between the two backends. Single-file and
recursive (`-r`) transfers work; parallel (`-j`) is not yet wired through this
backend (single connection). Licensing: OpenSSL is Apache-2.0 and libssh2 is
BSD-3-Clause, both compatible with zioscp's dual MIT OR Apache-2.0; the upstream
notices are copied into `vendor/<name>/` when built.

Both backends verify the server host key by default, like scp/ssh under
BatchMode: an unknown or changed key is refused. `--host-key-check` mirrors
ssh's `StrictHostKeyChecking` (`strict` default | `accept-new` | `no`) -- the ssh
backend passes it through as `-o StrictHostKeyChecking=...`; the libssh2 backend
checks `~/.ssh/known_hosts` via libssh2 (plain + hashed entries and the common
key types; ssh's `@cert-authority`/revocation/`CheckHostIP`/canonicalization are
an acknowledged gap).

## Benchmark

`tests/bench.sh` compares stock `scp` against `zioscp` across single-file and
many-small-file transfers. Every timed run is **verified** (sha256 or file
count) before its time is accepted, so a failed transfer can never report a
bogus fast time. Run it after the integration container is up.

On loopback, single-large-file throughput is filesystem/protocol-overhead bound,
so the meaningful comparison is many-small-files (per-file overhead), where
zioscp's lean collect-then-transfer beats scp's chattier recursive protocol.

The wide-area-network speedup is measured by `tests/bench-latency.sh`, which
runs on a Linux host with `tc netem` (it injects RTT on the loopback; the
control session rides a different interface). Representative result at 100 ms
RTT, 50 files: `scp -r` 28 s vs `zioscp -r -j4` 7.7 s (**3.7x faster**).
Single-file upload and download both beat scp under latency too, because both
keep a large window of SFTP requests in flight (the download pipeline relies on
ssh's internal buffering to absorb large DATA responses without a deadlock).

## Design

Built on the deblasis zio fleet: **zioarg** (CLI parsing), **ziojson** (resume
sidecar), **ziocrypt** (per-chunk SHA-256 MACs via `chunker`), **ziorate**
(bandwidth pacing), **zioprogress** (progress bar). The `ssh ... sftp-server`
subprocess duplex is hand-written in `transport.zig` (stderr drain, no
deadlocks, child reap on every path). See the internal repo for the design doc.

## License

Dual-licensed under either of

- the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- the MIT License ([LICENSE-MIT](LICENSE-MIT)),

at your option. Contributions intentionally submitted for inclusion are
dual-licensed the same way unless you state otherwise.
