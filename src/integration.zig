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
const chunker = @import("chunker.zig");

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

test "integration: parallel (-j) upload then download round-trips a tree" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cwd = std.Io.Dir.cwd();
    const src = "zioscp_par_src";
    const dst = "zioscp_par_dst";
    const remote = "/config/zioscp_par";
    defer cwd.deleteTree(io, src) catch {};
    defer cwd.deleteTree(io, dst) catch {};

    const a = [_]u8{ 'p', 'a', 'r', 'a', 'l', 'l', 'e', 'l' };
    const b = [_]u8{ 's', 'u', 'b', '_', 'f', 'i', 'l', 'e', '!', '!' };
    try cwd.createDirPath(io, "zioscp_par_src/sub");
    try cwd.writeFile(io, .{ .sub_path = "zioscp_par_src/a.bin", .data = &a });
    try cwd.writeFile(io, .{ .sub_path = "zioscp_par_src/sub/b.bin", .data = &b });

    const argv = sshArgv();

    // Collect + parallel upload.
    var coll = connect(io, testing.allocator) orelse return error.SkipZigTest;
    var up: std.ArrayList(engine.Task) = .empty;
    defer engine.freeTasks(testing.allocator, &up);
    try engine.collectUploadTasks(testing.allocator, io, &coll.sess, src, remote, &up);
    coll.deinit();
    try testing.expectEqual(@as(usize, 2), up.items.len);
    try engine.runParallel(testing.allocator, &argv, up.items, .{ .chunk_size = 8192 }, 4);

    // Collect + parallel download.
    var coll2 = connect(io, testing.allocator) orelse return error.SkipZigTest;
    var dn: std.ArrayList(engine.Task) = .empty;
    defer engine.freeTasks(testing.allocator, &dn);
    try engine.collectDownloadTasks(testing.allocator, io, &coll2.sess, remote, dst, &dn);
    coll2.deinit();
    try engine.runParallel(testing.allocator, &argv, dn.items, .{ .chunk_size = 8192 }, 4);

    const ga = cwd.readFileAlloc(io, "zioscp_par_dst/a.bin", testing.allocator, .limited(1 << 20)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(ga);
    try testing.expectEqualSlices(u8, &a, ga);
    const gb = cwd.readFileAlloc(io, "zioscp_par_dst/sub/b.bin", testing.allocator, .limited(1 << 20)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(gb);
    try testing.expectEqualSlices(u8, &b, gb);
}

test "integration: P3 single-file chunked parallel is byte-identical" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cwd = std.Io.Dir.cwd();
    const local = "zioscp_p3_src.bin";
    const remote = "/config/zioscp_p3.bin";
    const pulled = "zioscp_p3_dst.bin";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, pulled) catch {};
    defer conn_sess_remove(remote);

    const n: usize = 200_000; // ~25 chunks at 8 KiB, so -j 4 actually fans out
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 11) % 251);
    try cwd.writeFile(io, .{ .sub_path = local, .data = payload });

    const argv = sshArgv();
    try engine.uploadFileParallel(testing.allocator, &argv, local, remote, .{ .chunk_size = 8192 }, 4);
    try engine.downloadFileParallel(testing.allocator, &argv, remote, pulled, .{ .chunk_size = 8192 }, 4);

    const got = cwd.readFileAlloc(io, pulled, testing.allocator, .limited(1 << 24)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(got);
    try testing.expectEqual(n, got.len);
    try testing.expectEqualSlices(u8, payload, got);
}

fn conn_sess_remove(path: []const u8) void {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const argv = sshArgv();
    var conn = transport.Connection.open(testing.allocator, io, &argv) catch return;
    defer conn.deinit();
    conn.sess.remove(path) catch {};
}

// ---- Battle tests: resume robustness under failure -----------------------

test "battle: resume a download after a partial transfer" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const remote = "/config/zioscp_battle_dl.bin";
    const local = "zioscp_battle_dl.bin";
    const sidecar = "zioscp_battle_dl.bin.zioscppart";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer conn.sess.remove(remote) catch {};

    // Full file on the remote.
    const n: usize = 50_000;
    const cut: usize = 20_000;
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 17) % 251);
    const wh = try conn.sess.open(remote, packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC, packets.Attrs.empty);
    defer testing.allocator.free(wh);
    var off: u64 = 0;
    while (off < n) : (off += 8192) {
        const end = @min(off + 8192, n);
        try conn.sess.write(wh, off, payload[off..end]);
    }
    try conn.sess.close(wh);

    // Simulate a download killed `cut` bytes in: a local partial + sidecar.
    try cwd.writeFile(io, .{ .sub_path = local, .data = payload[0..cut] });
    try resume_mod.writeFile(io, testing.allocator, sidecar, .{
        .direction = .download,
        .total_size = n,
        .chunk_size = 8192,
        .next_offset = cut,
        .source_name = remote,
        .source_size = n,
        .source_mtime = 0,
    });

    // Resume: downloadFile continues from `cut`, not from 0.
    try engine.downloadFile(testing.allocator, io, &conn.sess, remote, local, .{ .chunk_size = 8192, .resume_enabled = true });
    const got = cwd.readFileAlloc(io, local, testing.allocator, .limited(1 << 24)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(got);
    try testing.expectEqual(n, got.len);
    try testing.expectEqualSlices(u8, payload, got);
    try testing.expect((cwd.statFile(io, sidecar, .{}) catch null) == null); // sidecar removed
}

test "battle: truncated partial (smaller than sidecar) forces a restart" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const remote = "/config/zioscp_battle_trunc.bin";
    const local = "zioscp_battle_trunc.bin";
    const sidecar = "zioscp_battle_trunc.bin.zioscppart";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer conn.sess.remove(remote) catch {};

    const n: usize = 40_000;
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 5) % 251);
    const wh = try conn.sess.open(remote, packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC, packets.Attrs.empty);
    defer testing.allocator.free(wh);
    try conn.sess.write(wh, 0, payload);
    try conn.sess.close(wh);

    // Sidecar claims 30_000 done, but the local partial is only 10_000 bytes
    // (e.g. a crash truncated it). Resume must detect size < next_offset and
    // restart cleanly from 0, not trust the stale sidecar.
    try cwd.writeFile(io, .{ .sub_path = local, .data = payload[0..10_000] });
    try resume_mod.writeFile(io, testing.allocator, sidecar, .{
        .direction = .download,
        .total_size = n,
        .chunk_size = 8192,
        .next_offset = 30_000,
        .source_name = remote,
        .source_size = n,
        .source_mtime = 0,
    });

    try engine.downloadFile(testing.allocator, io, &conn.sess, remote, local, .{ .chunk_size = 8192, .resume_enabled = true });
    const got = cwd.readFileAlloc(io, local, testing.allocator, .limited(1 << 24)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(got);
    try testing.expectEqual(n, got.len);
    try testing.expectEqualSlices(u8, payload, got);
}

test "battle: source changed (size mismatch) forces a restart" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const remote = "/config/zioscp_battle_chg.bin";
    const local = "zioscp_battle_chg.bin";
    const sidecar = "zioscp_battle_chg.bin.zioscppart";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer conn.sess.remove(remote) catch {};

    // Remote file is now 30_000 bytes (changed since a prior 50_000-byte run).
    const n: usize = 30_000;
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 23) % 251);
    const wh = try conn.sess.open(remote, packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC, packets.Attrs.empty);
    defer testing.allocator.free(wh);
    try conn.sess.write(wh, 0, payload);
    try conn.sess.close(wh);

    // Stale sidecar from the old 50_000-byte source.
    try resume_mod.writeFile(io, testing.allocator, sidecar, .{
        .direction = .download,
        .total_size = 50_000,
        .chunk_size = 8192,
        .next_offset = 25_000,
        .source_name = remote,
        .source_size = 50_000,
        .source_mtime = 0,
    });

    try engine.downloadFile(testing.allocator, io, &conn.sess, remote, local, .{ .chunk_size = 8192, .resume_enabled = true });
    const got = cwd.readFileAlloc(io, local, testing.allocator, .limited(1 << 24)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(got);
    try testing.expectEqual(n, got.len);
    try testing.expectEqualSlices(u8, payload, got);
}

test "battle: corrupted local partial is NOT detected (KNOWN GAP)" {
    // Characterization test: offset-based resume trusts a partial whose SIZE
    // matches the sidecar, so a byte flipped on disk between runs survives.
    // This proves the gap; MAC-verified download resume (chunker.hashChunk is
    // wired) is the fix. Flip this test's expectation when that lands.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const remote = "/config/zioscp_battle_corr.bin";
    const local = "zioscp_battle_corr.bin";
    const sidecar = "zioscp_battle_corr.bin.zioscppart";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer conn.sess.remove(remote) catch {};

    const n: usize = 32_769; // just over one 32 KiB chunk
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 29) % 251);
    const wh = try conn.sess.open(remote, packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC, packets.Attrs.empty);
    defer testing.allocator.free(wh);
    try conn.sess.write(wh, 0, payload);
    try conn.sess.close(wh);

    // "Completed" local partial that has been corrupted at one byte.
    var corrupted = testing.allocator.dupe(u8, payload) catch return error.OutOfMemory;
    defer testing.allocator.free(corrupted);
    corrupted[100] ^= 0xff;
    try cwd.writeFile(io, .{ .sub_path = local, .data = corrupted });
    try resume_mod.writeFile(io, testing.allocator, sidecar, .{
        .direction = .download,
        .total_size = n,
        .chunk_size = 32768,
        .next_offset = n, // claims fully done
        .source_name = remote,
        .source_size = n,
        .source_mtime = 0,
    });

    // Resume sees size >= next_offset, re-downloads nothing, "succeeds" -- but
    // the corruption is still there.
    try engine.downloadFile(testing.allocator, io, &conn.sess, remote, local, .{ .chunk_size = 32768, .resume_enabled = true });
    const got = cwd.readFileAlloc(io, local, testing.allocator, .limited(1 << 24)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(got);
    try testing.expectEqual(n, got.len);
    // PROVES THE GAP: the flipped byte survived "resume".
    try testing.expect(got[100] != payload[100]);
}

test "battle: corrupted local partial IS detected (MAC-verified resume)" {
    // The flip-side of the offset-resume gap: with a MAC file present (as a
    // real interrupted download records), a byte flipped on disk between runs
    // is detected on resume and the corrupted chunk is re-fetched, so the
    // final file is correct.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const remote = "/config/zioscp_battle_mac.bin";
    const local = "zioscp_battle_mac.bin";
    const sidecar = "zioscp_battle_mac.bin.zioscppart";
    const mac_path = "zioscp_battle_mac.bin.zioscpmac";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer cwd.deleteFile(io, mac_path) catch {};
    defer conn.sess.remove(remote) catch {};

    const n: usize = 32_769; // 2 chunks at 32 KiB
    const chunk: usize = 32_768;
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 29) % 251);
    const wh = try conn.sess.open(remote, packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC, packets.Attrs.empty);
    defer testing.allocator.free(wh);
    try conn.sess.write(wh, 0, payload);
    try conn.sess.close(wh);

    // Local partial: payload with byte 100 corrupted.
    var corrupted = testing.allocator.dupe(u8, payload) catch return error.OutOfMemory;
    defer testing.allocator.free(corrupted);
    corrupted[100] ^= 0xff;
    try cwd.writeFile(io, .{ .sub_path = local, .data = corrupted });

    // Sidecar claims the download is complete.
    try resume_mod.writeFile(io, testing.allocator, sidecar, .{
        .direction = .download,
        .total_size = n,
        .chunk_size = @intCast(chunk),
        .next_offset = n,
        .source_name = remote,
        .source_size = n,
        .source_mtime = 0,
    });
    // MAC file: the CORRECT MACs of the payload's chunks (what a clean run
    // would have recorded). Verify re-MACs the corrupted local -> mismatch.
    var ci: usize = 0;
    while (ci * chunk < n) : (ci += 1) {
        const s = ci * chunk;
        const e = @min(s + chunk, n);
        const mac = chunker.hashChunk(testing.allocator, payload[s..e]) catch return error.OutOfMemory;
        defer testing.allocator.free(mac);
        try resume_mod.appendMac(io, mac_path, mac, ci);
    }

    // Resume: detects the corruption, re-fetches, lands correct.
    try engine.downloadFile(testing.allocator, io, &conn.sess, remote, local, .{ .chunk_size = @intCast(chunk), .resume_enabled = true });
    const got = cwd.readFileAlloc(io, local, testing.allocator, .limited(1 << 24)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, payload, got); // corruption fixed
    try testing.expect((cwd.statFile(io, mac_path, .{}) catch null) == null); // mac file removed on success
}

test "battle: disk-full fails cleanly mid-transfer (no hang, no silent success)" {
    // /diskfull is a 128 KiB tmpfs the harness mounts in the container. A
    // payload far larger than that forces the server into ENOSPC partway
    // through: the transfer must FAIL (SSH_FX_FAILURE), not hang or report a
    // bogus success, and it must have written a partial before stopping.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const local = "zioscp_diskfull_src.bin";
    const remote = "/diskfull/zioscp_diskfull.bin";
    const sidecar = "zioscp_diskfull_src.bin.zioscppart";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer conn.sess.remove(remote) catch {};

    const n: usize = 512 * 1024; // 4x the 128 KiB tmpfs -> guaranteed ENOSPC
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast(i % 251);
    try cwd.writeFile(io, .{ .sub_path = local, .data = payload });

    try testing.expectError(error.Failure, engine.uploadFile(
        testing.allocator,
        io,
        &conn.sess,
        local,
        remote,
        .{ .chunk_size = 32768 },
    ));

    // Mid-transfer failure: a partial landed, but the whole file did not. tmpfs
    // counts metadata against the limit so the exact size varies; only assert
    // it is strictly between 0 and the full size.
    const rst = conn.sess.stat(remote) catch return error.UnexpectedTestFailure;
    try testing.expect(rst.size > 0 and rst.size < n);
}

test "battle: permission-denied surfaces as a typed error" {
    // `/` in the container is root-owned and not writable by testuser, so
    // creating a file directly under it is denied. The engine must surface a
    // typed PermissionDenied error, not hang or write a partial.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();

    const cwd = std.Io.Dir.cwd();
    const local = "zioscp_perm_src.bin";
    const sidecar = "zioscp_perm_src.bin.zioscppart";
    const remote = "/zioscp_perm.bin";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer conn.sess.remove(remote) catch {};

    const payload = [_]u8{ 'P', 'E', 'R', 'M' };
    try cwd.writeFile(io, .{ .sub_path = local, .data = &payload });

    try testing.expectError(error.PermissionDenied, engine.uploadFile(
        testing.allocator,
        io,
        &conn.sess,
        local,
        remote,
        .{},
    ));
}

test "battle: parallel worker failure skips one file but completes the rest" {
    // A batch where one target is unwritable (root-owned parent /). runParallel
    // must skip that file, still transfer the other two, and surface
    // error.Failure rather than silently exit 0.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cwd = std.Io.Dir.cwd();
    const local_a = "zioscp_pwf_a.bin";
    const local_b = "zioscp_pwf_b.bin";
    const local_c = "zioscp_pwf_c.bin";
    const remote_a = "/config/zioscp_pwf_a.bin";
    const remote_bad = "/zioscp_pwf_fail.bin"; // parent / is root-owned -> denied
    const remote_c = "/config/zioscp_pwf_c.bin";
    defer cwd.deleteFile(io, local_a) catch {};
    defer cwd.deleteFile(io, local_b) catch {};
    defer cwd.deleteFile(io, local_c) catch {};

    const a = [_]u8{ 'a', 'a', 'a', 'a' };
    const b = [_]u8{ 'b', 'b', 'b', 'b' };
    const c = [_]u8{ 'c', 'c', 'c', 'c' };
    try cwd.writeFile(io, .{ .sub_path = local_a, .data = &a });
    try cwd.writeFile(io, .{ .sub_path = local_b, .data = &b });
    try cwd.writeFile(io, .{ .sub_path = local_c, .data = &c });

    // Build the task list manually with owned strings (freed via freeTasks).
    var list: std.ArrayList(engine.Task) = .empty;
    defer engine.freeTasks(testing.allocator, &list);
    try list.append(testing.allocator, .{
        .direction = .upload,
        .local = try testing.allocator.dupe(u8, local_a),
        .remote = try testing.allocator.dupe(u8, remote_a),
    });
    try list.append(testing.allocator, .{
        .direction = .upload,
        .local = try testing.allocator.dupe(u8, local_b),
        .remote = try testing.allocator.dupe(u8, remote_bad),
    });
    try list.append(testing.allocator, .{
        .direction = .upload,
        .local = try testing.allocator.dupe(u8, local_c),
        .remote = try testing.allocator.dupe(u8, remote_c),
    });

    const argv = sshArgv();
    try testing.expectError(error.Failure, engine.runParallel(
        testing.allocator,
        &argv,
        list.items,
        .{ .chunk_size = 8192 },
        3,
    ));

    // The two writable targets landed; the denied one was never created.
    var sc = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer sc.deinit();
    defer sc.sess.remove(remote_a) catch {};
    defer sc.sess.remove(remote_c) catch {};
    try testing.expectEqual(@as(u64, a.len), (try sc.sess.stat(remote_a)).size);
    try testing.expectEqual(@as(u64, c.len), (try sc.sess.stat(remote_c)).size);
    try testing.expectError(error.NoSuchFile, sc.sess.stat(remote_bad));
}

// ---- Battle tests: connection drop ----------------------------------------

const DropCtx = struct {
    gpa: std.mem.Allocator,
    argv: []const []const u8,
    local: []const u8,
    remote: []const u8,
    opts: engine.Options,
    result: ?anyerror = null,
    // Child pid once the worker has connected; -1 until then. Read from the
    // killer thread to drop the connection without sharing the worker's io.
    pid: std.atomic.Value(std.posix.pid_t),
};

fn dropUpload(ctx: *DropCtx) void {
    // Own io + Connection on this thread; the main thread kills via posix.kill
    // so the two threads never share an io (no deadlock risk).
    var threaded = std.Io.Threaded.init(ctx.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = transport.Connection.open(ctx.gpa, io, ctx.argv) catch {
        ctx.result = error.IoClosed;
        return;
    };
    defer conn.deinit();
    if (conn.proc.child.id) |pid| ctx.pid.store(pid, .release);
    ctx.result = if (engine.uploadFile(ctx.gpa, io, &conn.sess, ctx.local, ctx.remote, ctx.opts)) |_| null else |err| err;
}

test "battle: connection drop mid-upload surfaces an error and leaves a resumable partial" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cwd = std.Io.Dir.cwd();
    const local = "zioscp_drop_src.bin";
    const remote = "/config/zioscp_drop.bin";
    const sidecar = "zioscp_drop_src.bin.zioscppart";
    const pulled = "zioscp_drop_dst.bin";
    defer cwd.deleteFile(io, local) catch {};
    defer cwd.deleteFile(io, sidecar) catch {};
    defer cwd.deleteFile(io, pulled) catch {};

    // 2 MiB paced at 512 KiB/s ~= 4 s total. The pipelined uploader does not
    // ACK its first chunk until the 16-deep window fills (~window * interval),
    // so the kill must land comfortably past that and well before completion:
    // ~0.25 s to first ACK, kill at ~1.5 s, ~4 s to finish.
    const n: usize = 2 * 1024 * 1024;
    const payload = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast(i % 251);
    try cwd.writeFile(io, .{ .sub_path = local, .data = payload });

    const argv = sshArgv();
    var ctx: DropCtx = .{
        .gpa = testing.allocator,
        .argv = &argv,
        .local = local,
        .remote = remote,
        .opts = .{ .chunk_size = 8192, .bwlimit_bps = 512 * 1024 },
        .pid = std.atomic.Value(std.posix.pid_t).init(-1),
    };
    const thread = std.Thread.spawn(.{}, dropUpload, .{&ctx}) catch return error.OutOfMemory;

    // Wait for the worker to connect (pid published), then let it transfer.
    var spin: usize = 0;
    while (ctx.pid.load(.acquire) < 0 and spin < 3000) : (spin += 1) {
        std.Io.sleep(io, .{ .nanoseconds = 1_000_000 }, .awake) catch {};
    }
    std.Io.sleep(io, .{ .nanoseconds = 1_500_000_000 }, .awake) catch {};
    // Drop the connection hard.
    const pid = ctx.pid.load(.acquire);
    if (pid > 0) std.posix.kill(pid, std.posix.SIG.KILL) catch {};
    thread.join();

    // The upload must have failed (connection lost), not hung or succeeded.
    try testing.expect(ctx.result != null);
    try testing.expectEqual(error.IoClosed, ctx.result.?);
    // A resumable partial was recorded before the drop.
    try testing.expect((cwd.statFile(io, sidecar, .{}) catch null) != null);

    // Resume on a fresh connection and confirm the whole file is correct.
    var conn = connect(io, testing.allocator) orelse return error.SkipZigTest;
    defer conn.deinit();
    defer conn.sess.remove(remote) catch {};
    try engine.uploadFile(testing.allocator, io, &conn.sess, local, remote, .{ .chunk_size = 8192, .resume_enabled = true });
    try engine.downloadFile(testing.allocator, io, &conn.sess, remote, pulled, .{ .chunk_size = 8192 });
    const got = cwd.readFileAlloc(io, pulled, testing.allocator, .limited(1 << 24)) catch return error.UnexpectedTestFailure;
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, payload, got);
}
