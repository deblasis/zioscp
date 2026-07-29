# zioscp

A drop-in `scp` replacement written in Zig. Same flags and syntax as `scp`, but
it speaks SFTP under the hood, so it can **resume interrupted transfers** and run
**parallel transfers** (file-level and single-file chunked). Works against any
unmodified `sshd`.

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
- **Pipelined single stream**: the upload/download paths keep an **adaptive,
  BDP-sized** window of SFTP requests in flight (sized from how long each ack
  recv blocks, not a fixed constant), so `zioscp -j1` saturates the server and
  beats stock `scp` on large transfers even at zero added latency.
- **Bandwidth limiting** (`--bwlimit`, paced at chunk granularity), **progress
  bar** (TTY-gated), **`-v`** per-file logging, and **permission + mtime
  preservation** (`-p`).

## Build and test

```
zig build          # build the binary -> zig-out/bin/zioscp
zig build test     # unit tests
just ci            # fmt-check + build + tests + cross matrix (what CI runs)
just integration   # SFTP round-trip tests vs a Docker sshd (heavier)
```

`zioscp` cross-compiles to Linux and Windows from any host
(`zig build -Dtarget=x86_64-linux-gnu`, `... x86_64-windows-gnu`). On Windows the
default build is the self-contained libssh2 backend, which runs natively with no
system `ssh` required; on mac/Linux the default drives the system `ssh`. `just
ci` runs that cross matrix.

### Transport backend

There are two interchangeable backends, selected with `-Dbackend`:

- **`ssh`** (default on mac/Linux) drives the system `ssh` subprocess, so it
  works anywhere OpenSSH is installed, with no bundled crypto.
- **`libssh2`** (default on Windows) links libssh2 directly for a fully
  self-contained binary with no `ssh`, `libssh2`, or `openssl` dependency.

```
zig build -Dbackend=libssh2     # self-contained: no ssh, no libssh2/openssl dylib
```

On Windows the default is libssh2 because the ssh-subprocess backend is not
usable there: `ssh.exe` does not serve a workable SFTP stream over `-s sftp`
pipes, and the subprocess's overlapped stdio pipes surface EOF before data
arrives. The libssh2 backend sidesteps both by dialing its own blocking winsock
socket (it cannot reuse std.Io.net's socket on Windows, which is a raw AFD
endpoint handle rather than a winsock SOCKET).

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
SFTP/resume/pipeline logic is shared between the two backends, including
parallel transfers: both file-level (`-r -j N`) and single-file chunked (`-j N`)
work on either backend. It cross-compiles to a self-contained binary on all
three targets -- `zig build -Dbackend=libssh2 -Dtarget=x86_64-linux-gnu` (Linux)
or `... x86_64-windows-gnu` (Windows, via mingw) -- statically linking libssh2 +
OpenSSL with no system ssh/libssh2/openssl dependency. The vendor script
handles each target's quirks: OpenSSL's Configure target, libssh2's autotools
`--host` (and an MSVC-guess libtool patch on mingw), and re-indexing the static
archives to GNU format for zig's archive readers. Licensing: OpenSSL is
Apache-2.0 and libssh2 is BSD-3-Clause, both compatible with zioscp's dual MIT
OR Apache-2.0; the upstream notices are copied into `vendor/<name>/` when built.

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
RTT, 100 files: `scp -r` ~53 s vs `zioscp -r -j4` ~11 s (**~4.7x faster**);
single-file upload and download both match or beat scp under latency. Both
pipelines grow an adaptive window of SFTP requests to the bandwidth-delay
product (the download pipeline relies on ssh's internal buffering to absorb
large DATA responses without a deadlock). Absolute times vary by host; the
ratios are the stable signal.

## Design

Built on the deblasis zio fleet: [zioarg](https://github.com/deblasis/zioarg)
(CLI parsing), [ziojson](https://github.com/deblasis/ziojson) (resume sidecar),
[ziocrypt](https://github.com/deblasis/ziocrypt) (per-chunk SHA-256 MACs via
`chunker`), [ziorate](https://github.com/deblasis/ziorate) (bandwidth pacing),
[zioprogress](https://github.com/deblasis/zioprogress) (progress bars),
[zioansi](https://github.com/deblasis/zioansi) (ANSI styling), and
[zioconsole](https://github.com/deblasis/zioconsole) (inline live terminal
display — the scrolling per-file log + pinned status bar). The
`ssh ... sftp-server` subprocess duplex is hand-written in `transport.zig`
(stderr drain, no deadlocks, child reap on every path). See the internal repo
for the design doc.

## Trust and antivirus on Windows

zioscp's Windows binary is self-contained (static libssh2 + OpenSSL) and does
raw networking, SSH/crypto, and bulk file I/O. Because it is also **unsigned**
(Authenticode code-signing certificates are not free), some antivirus products
flag it on first download as a false positive. It is not malware: every binary
is built from public source by GitHub Actions, and each release ships a
`SHA256SUMS.txt` you can verify against.

**The plan:** once zioscp has enough traction or sponsorship to justify it,
releases will be Authenticode-signed (a personal code-signing certificate),
which removes the AV and SmartScreen warnings for the vast majority of users.

**How you can help:**

- Sponsor the project at https://github.com/sponsors/deblasis (this is what
  would fund signing).
- If you trust the source, add an antivirus exclusion for zioscp.
- Report the file as a false positive to your antivirus vendor.

## Sponsor

If zioscp saves you time, consider backing its development:

- GitHub Sponsors: https://github.com/sponsors/deblasis
- Ko-fi: https://ko-fi.com/deblasis
- ETH: `deblasis.eth`

## License

Dual-licensed under either of

- the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- the MIT License ([LICENSE-MIT](LICENSE-MIT)),

at your option. Contributions intentionally submitted for inclusion are
dual-licensed the same way unless you state otherwise.
