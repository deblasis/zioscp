//! Transfer engine: single-file upload/download with offset-based resume.
//!
//! P1 is single-stream. Upload reads the local file at chunk offsets
//! (positional reads) and writes them to the remote handle; download reads
//! remote chunks and writes them to the local file positionally. A resume
//! sidecar (resume.zig) records next-offset after each chunk so an
//! interrupted transfer continues. Recursive directory transfer and
//! permission preservation land in the follow-on pass.

const std = @import("std");
const client = @import("sftp/client.zig");
const packets = @import("sftp/packets.zig");
const resume_mod = @import("resume.zig");

const Dir = std.Io.Dir;
const Session = client.Session;

pub const Options = struct {
    chunk_size: u32 = 8 * 1024 * 1024,
    resume_enabled: bool = true,
    /// Apply source permissions/mtime to the destination. Not yet wired.
    preserve: bool = false,
};

/// SFTP v3 guarantees servers can process packets with at least ~34000 bytes
/// of payload; OpenSSH caps near 256 KB. Keep each WRITE/READ payload well
/// under that so a single packet never exceeds the server's max. The user's
/// chunk_size still sets resume granularity, but each SFTP op is capped here.
const max_sftp_payload: u32 = 32 * 1024;

inline fn effectiveChunk(opts: Options) u32 {
    return @min(opts.chunk_size, max_sftp_payload);
}

/// If a sidecar + valid partial exist, the offset to resume from; else 0.
fn resumeOffsetUpload(
    io: std.Io,
    gpa: std.mem.Allocator,
    sess: anytype,
    remote_path: []const u8,
    sidecar: []const u8,
    total: u64,
) !u64 {
    const part = (try resume_mod.readFile(io, gpa, sidecar)) orelse return 0;
    defer gpa.free(part.source_name);
    if (part.direction != .upload or part.total_size != total) return 0;
    // Trust the sidecar only if the remote partial is at least as far along.
    const rst = sess.stat(remote_path) catch return 0;
    if (rst.size >= part.next_offset) return part.next_offset;
    return 0;
}

fn resumeOffsetDownload(
    io: std.Io,
    gpa: std.mem.Allocator,
    local_path: []const u8,
    sidecar: []const u8,
    total: u64,
) !u64 {
    const part = (try resume_mod.readFile(io, gpa, sidecar)) orelse return 0;
    defer gpa.free(part.source_name);
    if (part.direction != .download or part.total_size != total) return 0;
    const lst = Dir.cwd().statFile(io, local_path, .{}) catch return 0;
    if (lst.size >= part.next_offset) return part.next_offset;
    return 0;
}

fn record(io: std.Io, gpa: std.mem.Allocator, sidecar: []const u8, dir: resume_mod.Direction, total: u64, chunk: u32, next: u64, name: []const u8) void {
    resume_mod.writeFile(io, gpa, sidecar, .{
        .direction = dir,
        .total_size = total,
        .chunk_size = chunk,
        .next_offset = next,
        .source_name = name,
        .source_size = total,
        .source_mtime = 0,
    }) catch {};
}

pub fn uploadFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    sess: anytype,
    local_path: []const u8,
    remote_path: []const u8,
    opts: Options,
) !void {
    const cwd = Dir.cwd();
    const st = try cwd.statFile(io, local_path, .{});
    const total: u64 = st.size;

    const sidecar = try resume_mod.sidecarPath(gpa, local_path);
    defer gpa.free(sidecar);

    var next_off: u64 = 0;
    if (opts.resume_enabled) next_off = try resumeOffsetUpload(io, gpa, sess, remote_path, sidecar, total);

    var local = try cwd.openFile(io, local_path, .{});
    defer local.close(io);

    const pflags: u32 = if (next_off == 0)
        packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC
    else
        packets.FXF_WRITE | packets.FXF_CREATE; // resume: keep the partial
    const handle = try sess.open(remote_path, pflags, packets.Attrs.empty);
    defer gpa.free(handle);
    errdefer sess.close(handle) catch {};

    const buf = try gpa.alloc(u8, effectiveChunk(opts));
    defer gpa.free(buf);
    var off = next_off;
    while (off < total) {
        const len: usize = @intCast(@min(@as(u64, effectiveChunk(opts)), total - off));
        _ = try local.readPositionalAll(io, buf[0..len], off);
        try sess.write(handle, off, buf[0..len]);
        off += len;
        record(io, gpa, sidecar, .upload, total, effectiveChunk(opts), off, local_path);
    }
    try sess.close(handle);
    resume_mod.removeFile(io, sidecar);
}

pub fn downloadFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    sess: anytype,
    remote_path: []const u8,
    local_path: []const u8,
    opts: Options,
) !void {
    const rst = try sess.stat(remote_path);
    const total: u64 = rst.size;

    const sidecar = try resume_mod.sidecarPath(gpa, local_path);
    defer gpa.free(sidecar);

    var next_off: u64 = 0;
    if (opts.resume_enabled) next_off = try resumeOffsetDownload(io, gpa, local_path, sidecar, total);

    const rh = try sess.open(remote_path, packets.FXF_READ, packets.Attrs.empty);
    defer gpa.free(rh);
    errdefer sess.close(rh) catch {};

    var local = if (next_off == 0)
        try Dir.cwd().createFile(io, local_path, .{ .truncate = true })
    else
        try Dir.cwd().createFile(io, local_path, .{ .truncate = false });
    defer local.close(io);

    const buf = try gpa.alloc(u8, effectiveChunk(opts));
    defer gpa.free(buf);
    var off = next_off;
    while (off < total) {
        const want: u32 = @intCast(@min(@as(u64, effectiveChunk(opts)), total - off));
        const piece = sess.read(rh, off, want) catch |err| switch (err) {
            error.Eof => break,
            else => return err,
        };
        defer gpa.free(piece); // frees this iteration's slice
        if (piece.len == 0) break;
        try local.writePositionalAll(io, piece, off);
        off += piece.len;
        record(io, gpa, sidecar, .download, total, effectiveChunk(opts), off, remote_path);
    }
    try sess.close(rh);
    resume_mod.removeFile(io, sidecar);
}
