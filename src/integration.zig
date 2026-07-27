//! Integration tests against a REAL sshd sftp-server.
//!
//! Not part of `zig build test` (network + Docker). Run via the `integration`
//! build step with tests/sftp-integration.sh providing localhost:2222. If the
//! server is unreachable, every test skips.

const std = @import("std");
const client = @import("sftp/client.zig");
const packets = @import("sftp/packets.zig");
const transport = @import("transport.zig");
const engine = @import("engine.zig");
const resume_mod = @import("resume.zig");

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

/// Connect + handshake; null if the container is unreachable (skip).
fn connect(io: std.Io, gpa: std.mem.Allocator) ?transport.Connection {
    const argv = sshArgv();
    return transport.Connection.open(gpa, io, &argv) catch null;
}

test "integration: raw session write/read/stat against a real sftp-server" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const argv = sshArgv();
    var proc = transport.DuplexProcess.spawn(testing.allocator, io, &argv) catch
        return error.SkipZigTest;
    try proc.startDrain();
    defer proc.deinit();

    var sess = client.Session(transport.DuplexProcess).init(testing.allocator, &proc);
    _ = sess.handshake() catch |err| {
        std.debug.print("\n[integration] handshake failed: {s}\nssh stderr:\n{s}\n", .{ @errorName(err), proc.stderr_buf.items });
        return err;
    };

    const remote = "/config/zioscp_probe.bin";
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

    const st = try sess.stat(remote);
    try testing.expectEqual(@as(u64, total), st.size);

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

    try sess.remove(remote);
}

test "integration: engine upload+download round-trip is byte-identical" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const local = "zioscp_engine_src.bin";
    const remote = "/config/zioscp_engine.bin";
    const pulled = "zioscp_engine_dst.bin";
    const sidecar = "zioscp_engine_src.bin.zioscppart";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, pulled) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer conn.sess.remove(remote) catch {};

    const n: usize = 100_000;
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 7) % 251);
    try cwd.writeFile(io, .{ .sub_path = local, .data = payload });

    try engine.uploadFile(testing.allocator, io, &conn.sess, local, remote, .{ .chunk_size = 8192 });
    try testing.expect((cwd.statFile(io, sidecar, .{}) catch null) == null); // sidecar removed
    try engine.downloadFile(testing.allocator, io, &conn.sess, remote, pulled, .{ .chunk_size = 8192 });

    const got = cwd.readFileAlloc(io, pulled, testing.allocator, .limited(1 << 24)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(got);
    try testing.expectEqual(n, got.len);
    try testing.expectEqualSlices(u8, payload, got);
}

test "integration: engine upload resumes after a partial transfer" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const local = "zioscp_resume_src.bin";
    const remote = "/config/zioscp_resume.bin";
    const pulled = "zioscp_resume_dst.bin";
    const sidecar = "zioscp_resume_src.bin.zioscppart";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, pulled) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer conn.sess.remove(remote) catch {};

    const n: usize = 50_000;
    const cut: usize = 20_000;
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 13) % 251);
    try cwd.writeFile(io, .{ .sub_path = local, .data = payload });

    // Simulate an upload killed `cut` bytes in: write the prefix remotely and
    // leave a sidecar pointing at `cut`.
    const wh = try conn.sess.open(remote, packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC, packets.Attrs.empty);
    defer testing.allocator.free(wh);
    try conn.sess.write(wh, 0, payload[0..cut]);
    try conn.sess.close(wh);
    try resume_mod.writeFile(io, testing.allocator, sidecar, .{
        .direction = .upload,
        .total_size = n,
        .chunk_size = 8192,
        .next_offset = cut,
        .source_name = local,
        .source_size = n,
        .source_mtime = 0,
    });

    // Remote is only the partial prefix right now.
    const rst = try conn.sess.stat(remote);
    try testing.expectEqual(@as(u64, cut), rst.size);

    // Resume: uploadFile must continue from `cut`, not restart.
    try engine.uploadFile(testing.allocator, io, &conn.sess, local, remote, .{ .chunk_size = 8192, .resume_enabled = true });
    const rst2 = try conn.sess.stat(remote);
    try testing.expectEqual(@as(u64, n), rst2.size);

    // Pull it back and confirm the whole file is correct.
    try engine.downloadFile(testing.allocator, io, &conn.sess, remote, pulled, .{ .chunk_size = 8192 });
    const got = cwd.readFileAlloc(io, pulled, testing.allocator, .limited(1 << 24)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(got);
    try testing.expectEqual(n, got.len);
    try testing.expectEqualSlices(u8, payload, got);
}

test "integration: engine recursive upload/download preserves a tree" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const src_dir = "zioscp_tree_src";
    const dst_dir = "zioscp_tree_dst";
    const remote_dir = "/config/zioscp_tree";
    defer cwd.deleteTree(io, src_dir) catch {};
    defer cwd.deleteTree(io, dst_dir) catch {};

    // Build a known tree: src/a.txt and src/sub/b.bin.
    try cwd.createDirPath(io, "zioscp_tree_src/sub");
    const a = [_]u8{ 'a', 'a', 'a', 'x' };
    const b = [_]u8{ 'b', '_', '0', '1', '2', '3' };
    try cwd.writeFile(io, .{ .sub_path = "zioscp_tree_src/a.txt", .data = &a });
    try cwd.writeFile(io, .{ .sub_path = "zioscp_tree_src/sub/b.bin", .data = &b });

    try engine.uploadDir(testing.allocator, io, &conn.sess, src_dir, remote_dir, .{ .chunk_size = 8192 });
    try testing.expect(remoteIsDir(&conn.sess, remote_dir));

    try engine.downloadDir(testing.allocator, io, &conn.sess, remote_dir, dst_dir, .{ .chunk_size = 8192 });

    const ga = cwd.readFileAlloc(io, "zioscp_tree_dst/a.txt", testing.allocator, .limited(1 << 20)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(ga);
    try testing.expectEqualSlices(u8, &a, ga);

    const gb = cwd.readFileAlloc(io, "zioscp_tree_dst/sub/b.bin", testing.allocator, .limited(1 << 20)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(gb);
    try testing.expectEqualSlices(u8, &b, gb);
}

fn remoteIsDir(sess: anytype, path: []const u8) bool {
    const x = sess.stat(path) catch return false;
    return (x.flags & packets.ATTR_PERMISSIONS != 0) and ((x.permissions & 0o170000) == 0o040000);
}
