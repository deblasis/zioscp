//! zioscp CLI: drop-in scp over SFTP, with resume.
//!
//! Usage: zioscp [options] src dest  (exactly one of src/dest is remote).
//! A remote path is written `[user@]host:path`, scp-style.

const std = @import("std");
const transport = @import("transport.zig");
const engine = @import("engine.zig");
const packets = @import("sftp/packets.zig");

fn isLocalDir(io: std.Io, path: []const u8) bool {
    const st = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return st.kind == .directory;
}

const usage =
    \\zioscp - drop-in scp over SFTP, with resume
    \\
    \\Usage:
    \\  zioscp [options] src dest
    \\
    \\One of src/dest must be remote ([user@]host:path), the other local.
    \\
    \\Options:
    \\  -P PORT          ssh port (default 22)
    \\  -i KEY           identity file
    \\  -r               copy directories recursively
    \\  -p               preserve file permissions
    \\  --chunk-size N   transfer chunk size in bytes (default 8 MiB)
    \\  --no-resume      overwrite from the start instead of resuming
    \\  -h, --help       show this help
    \\
;

const RemoteSpec = struct { user_host: []const u8, path: []const u8 };

/// A `host:path` style remote (colon present, no '/' before the colon).
fn remoteSpec(s: []const u8) ?RemoteSpec {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    const lhs = s[0..colon];
    if (lhs.len == 0) return null;
    if (std.mem.indexOfScalar(u8, lhs, '/') != null) return null;
    return .{ .user_host = lhs, .path = s[colon + 1 ..] };
}

fn bail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("zioscp: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const args = init.minimal.args.toSlice(gpa) catch bail("failed to read args", .{});
    defer gpa.free(args);

    var port: []const u8 = "22";
    var identity: ?[]const u8 = null;
    var chunk_size: u32 = 8 * 1024 * 1024;
    var resume_enabled = true;
    var recursive = false;
    var preserve = false;
    var positionals: [2][]const u8 = .{ "", "" };
    var npos: usize = 0;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            std.debug.print("{s}\n", .{usage});
            return;
        } else if (std.mem.eql(u8, a, "-P")) {
            i += 1;
            if (i >= args.len) bail("{s}", .{usage});
            port = args[i];
        } else if (std.mem.eql(u8, a, "-i")) {
            i += 1;
            if (i >= args.len) bail("{s}", .{usage});
            identity = args[i];
        } else if (std.mem.eql(u8, a, "--no-resume")) {
            resume_enabled = false;
        } else if (std.mem.eql(u8, a, "-r")) {
            recursive = true;
        } else if (std.mem.eql(u8, a, "-p")) {
            preserve = true;
        } else if (std.mem.eql(u8, a, "--chunk-size")) {
            i += 1;
            if (i >= args.len) bail("{s}", .{usage});
            chunk_size = std.fmt.parseInt(u32, args[i], 10) catch bail("bad --chunk-size", .{});
        } else if (a.len > 0 and a[0] == '-') {
            bail("unknown option: {s}", .{a});
        } else {
            if (npos >= 2) bail("{s}", .{usage});
            positionals[npos] = a;
            npos += 1;
        }
    }
    if (npos != 2) bail("{s}", .{usage});

    const src = positionals[0];
    const dest = positionals[1];
    const src_remote = remoteSpec(src);
    const dest_remote = remoteSpec(dest);
    if (src_remote == null and dest_remote == null) bail("one of src/dest must be remote (host:path)", .{});
    if (src_remote != null and dest_remote != null) bail("remote-to-remote copy is not supported", .{});

    const download = src_remote != null;
    const spec = if (src_remote) |s| s else dest_remote.?;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();
    var ssh_argv: std.ArrayList([]const u8) = .empty;
    ssh_argv.append(aa, "ssh") catch bail("oom", .{});
    ssh_argv.append(aa, "-T") catch bail("oom", .{});
    if (!std.mem.eql(u8, port, "22")) {
        ssh_argv.append(aa, "-p") catch bail("oom", .{});
        ssh_argv.append(aa, port) catch bail("oom", .{});
    }
    if (identity) |k| {
        ssh_argv.append(aa, "-i") catch bail("oom", .{});
        ssh_argv.append(aa, k) catch bail("oom", .{});
    }
    ssh_argv.append(aa, "-o") catch bail("oom", .{});
    ssh_argv.append(aa, "BatchMode=yes") catch bail("oom", .{});
    ssh_argv.append(aa, "-s") catch bail("oom", .{});
    ssh_argv.append(aa, "--") catch bail("oom", .{});
    ssh_argv.append(aa, spec.user_host) catch bail("oom", .{});
    ssh_argv.append(aa, "sftp") catch bail("oom", .{});

    const opts: engine.Options = .{ .chunk_size = chunk_size, .resume_enabled = resume_enabled, .preserve = preserve };

    var conn = transport.Connection.open(gpa, io, ssh_argv.items) catch |err|
        bail("connection failed: {s}", .{@errorName(err)});
    defer conn.deinit();

    if (download) {
        if (recursive and remoteIsDir(&conn.sess, spec.path)) {
            engine.downloadDir(gpa, io, &conn.sess, spec.path, dest, opts) catch |err|
                bail("download failed: {s}\nssh stderr: {s}", .{ @errorName(err), conn.stderr() });
        } else {
            engine.downloadFile(gpa, io, &conn.sess, spec.path, dest, opts) catch |err|
                bail("download failed: {s}\nssh stderr: {s}", .{ @errorName(err), conn.stderr() });
        }
    } else {
        if (recursive and isLocalDir(io, src)) {
            engine.uploadDir(gpa, io, &conn.sess, src, spec.path, opts) catch |err|
                bail("upload failed: {s}\nssh stderr: {s}", .{ @errorName(err), conn.stderr() });
        } else {
            engine.uploadFile(gpa, io, &conn.sess, src, spec.path, opts) catch |err|
                bail("upload failed: {s}\nssh stderr: {s}", .{ @errorName(err), conn.stderr() });
        }
    }
}

fn remoteIsDir(sess: anytype, path: []const u8) bool {
    const a = sess.stat(path) catch return false;
    return (a.flags & packets.ATTR_PERMISSIONS != 0) and
        ((a.permissions & 0o170000) == 0o040000);
}
