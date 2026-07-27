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

The SFTP integration tests need a Docker `openssh-server` harness:

```
tests/sftp-integration.sh   # starts the container, runs zig build integration
```

## Benchmark

`tests/bench.sh` compares stock `scp` against `zioscp` across single-file and
many-small-file transfers. Every timed run is **verified** (sha256 or file
count) before its time is accepted, so a failed transfer can never report a
bogus fast time. Run it after the integration container is up.

On loopback, single-large-file throughput is filesystem/protocol-overhead bound,
so the meaningful comparison is many-small-files (per-file overhead), where
zioscp's lean collect-then-transfer beats scp's chattier recursive protocol.
The `-j` wide-area-network speedup needs a latency-injected link (tc netem
behind a Linux router), which the localhost harness cannot simulate.

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
