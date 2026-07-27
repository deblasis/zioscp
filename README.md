# zioscp

A drop-in `scp` replacement written in Zig: same flags and syntax, but it
speaks SFTP under the hood so it can resume interrupted transfers and run
parallel transfers (file-level and single-file chunked). Works against any
unmodified `sshd`.

Status: P1 in progress (scp-compatible SFTP copy + resume). P2 (file-level
parallel) and P3 (single-file chunked parallel) follow.

## Build and test

```
zig build test      # unit tests
zig build run       # build and run the binary
just ci             # fmt-check + build + test (what CI runs)
```

## Design

See the internal repo for the design doc and plan. Built on the deblasis zio
fleet: zioarg (CLI), ziosh (subprocesses), ziocrypt (per-chunk MACs), ziojson
(resume sidecars), ziorate (bandwidth pacing), zioprogress (progress), and
ziometrics/ziotrace (telemetry).
