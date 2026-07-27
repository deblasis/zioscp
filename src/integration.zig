//! Integration test: round-trips a file against a REAL sshd sftp-server.
//!
//! Not part of `zig build test` (network + Docker). Run via the
//! `integration` build step with the Docker harness in
//! tests/sftp-integration.sh providing localhost:2222.
//!
//! If the server is unreachable the test skips; on handshake failure it
//! prints the captured ssh stderr so the argv/connection can be diagnosed.

const std = @import("std");
const client = @import("sftp/client.zig");
const packets = @import("sftp/packets.zig");
const transport = @import("transport.zig");

const testing = std.testing;

fn sshArgv() [18][]const u8 {
    return .{
        "ssh",                "-T",
        "-p",                 "2222",
        "-i",                 "tests/keys/ed25519",
        "-o",                 "StrictHostKeyChecking=no",
        "-o",                 "UserKnownHostsFile=/dev/null",
        "-o",                 "BatchMode=yes",
        "-o",                 "ConnectTimeout=3",
        "-s",                 "--",
        "testuser@localhost", "sftp",
    };
}

test "integration: write then read-back a file against a real sftp-server" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const argv = sshArgv();
    var proc = transport.DuplexProcess.spawn(testing.allocator, io, &argv) catch
        return error.SkipZigTest; // no Docker / sshd reachable
    try proc.startDrain();
    defer proc.deinit();

    var sess = client.Session(transport.DuplexProcess).init(testing.allocator, &proc);
    _ = sess.handshake() catch |err| {
        std.debug.print("\n[integration] handshake failed: {s}\n", .{@errorName(err)});
        std.debug.print("[integration] ssh stderr:\n{s}\n", .{proc.stderr_buf.items});
        return err;
    };

    const remote = "/config/zioscp_probe.bin";

    // Build a patterned payload and write it in chunks.
    const total: usize = 50_000;
    const payload = testing.allocator.alloc(u8, total) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast(i % 251);

    const wh = try sess.open(remote, packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC, packets.Attrs.empty);
    defer testing.allocator.free(wh);
    var off: u64 = 0;
    const chunk: u32 = 8192;
    while (off < total) {
        const end = @min(off + chunk, total);
        try sess.write(wh, off, payload[off..end]);
        off = end;
    }
    try sess.close(wh);

    // Stat confirms the size.
    const st = try sess.stat(remote);
    try testing.expectEqual(@as(u64, total), st.size);

    // Read it all back and compare.
    const rh = try sess.open(remote, packets.FXF_READ, packets.Attrs.empty);
    defer testing.allocator.free(rh);
    const got = testing.allocator.alloc(u8, total) catch return error.OutOfMemory;
    defer testing.allocator.free(got);
    var filled: usize = 0;
    while (filled < total) {
        const want: u32 = @intCast(@min(chunk, total - filled));
        const piece = sess.read(rh, filled, want) catch |err| switch (err) {
            error.Eof => break,
            else => return err,
        };
        if (piece.len == 0) break;
        @memcpy(got[filled .. filled + piece.len], piece);
        filled += piece.len;
        testing.allocator.free(piece);
    }
    try sess.close(rh);
    try testing.expectEqual(total, filled);
    try testing.expectEqualSlices(u8, payload, got[0..filled]);

    // Cleanup.
    try sess.remove(remote);
}
