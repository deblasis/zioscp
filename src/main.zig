//! zioscp CLI: drop-in scp over SFTP, with resume.
//!
//! Usage: zioscp [options] src dest  (exactly one of src/dest is remote).
//! A remote path is written `[user@]host:path`, scp-style. Flags are parsed
//! from a typed struct via zioarg, which also generates --help.

const std = @import("std");
const transport = @import("transport.zig");
const engine = @import("engine.zig");
const packets = @import("sftp/packets.zig");
const zioarg = @import("zioarg");

const Args = struct {
    port: []const u8 = "22",
    identity: ?[]const u8 = null,
    recursive: bool = false,
    preserve: bool = false,
    no_resume: bool = false,
    chunk_size: u32 = 8 * 1024 * 1024,
    bwlimit: u64 = 0,
    files: []const []const u8 = &.{},

    pub const short = .{ .port = 'P', .identity = 'i', .recursive = 'r', .preserve = 'p' };
    pub const help = .{
        .port = "ssh port (default 22)",
        .identity = "identity file",
        .recursive = "copy directories recursively",
        .preserve = "preserve file permissions",
        .no_resume = "overwrite from the start instead of resuming",
        .chunk_size = "transfer chunk size in bytes (default 8 MiB)",
        .bwlimit = "limit transfer to N bytes/sec (default unlimited)",
        .files = "src dest (one remote [user@]host:path, one local)",
    };
};

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

fn printHelp(io: std.Io) void {
    var buf: [4096]u8 = undefined;
    var fw = std.Io.File.stderr().writer(io, &buf);
    zioarg.formatHelp(Args, &fw.interface) catch {};
    fw.interface.flush() catch {};
}

fn isLocalDir(io: std.Io, path: []const u8) bool {
    const st = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return st.kind == .directory;
}

fn remoteIsDir(sess: anytype, path: []const u8) bool {
    const a = sess.stat(path) catch return false;
    return (a.flags & packets.ATTR_PERMISSIONS != 0) and
        ((a.permissions & 0o170000) == 0o040000);
}

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var parsed = zioarg.parse(Args, gpa, init.minimal.args) catch |err| switch (err) {
        error.HelpRequested => {
            printHelp(io);
            return;
        },
        else => {
            zioarg.reportError(Args, err);
            printHelp(io);
            std.process.exit(1);
        },
    };
    defer parsed.deinit(gpa);
    const v = parsed.value;

    if (v.files.len != 2) {
        printHelp(io);
        std.process.exit(1);
    }
    const src = v.files[0];
    const dest = v.files[1];
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
    if (!std.mem.eql(u8, v.port, "22")) {
        ssh_argv.append(aa, "-p") catch bail("oom", .{});
        ssh_argv.append(aa, v.port) catch bail("oom", .{});
    }
    if (v.identity) |k| {
        ssh_argv.append(aa, "-i") catch bail("oom", .{});
        ssh_argv.append(aa, k) catch bail("oom", .{});
    }
    ssh_argv.append(aa, "-o") catch bail("oom", .{});
    ssh_argv.append(aa, "BatchMode=yes") catch bail("oom", .{});
    ssh_argv.append(aa, "-s") catch bail("oom", .{});
    ssh_argv.append(aa, "--") catch bail("oom", .{});
    ssh_argv.append(aa, spec.user_host) catch bail("oom", .{});
    ssh_argv.append(aa, "sftp") catch bail("oom", .{});

    const opts: engine.Options = .{
        .chunk_size = v.chunk_size,
        .resume_enabled = !v.no_resume,
        .preserve = v.preserve,
        .bwlimit_bps = v.bwlimit,
    };

    var conn = transport.Connection.open(gpa, io, ssh_argv.items) catch |err|
        bail("connection failed: {s}", .{@errorName(err)});
    defer conn.deinit();

    if (download) {
        if (v.recursive and remoteIsDir(&conn.sess, spec.path)) {
            engine.downloadDir(gpa, io, &conn.sess, spec.path, dest, opts) catch |err|
                bail("download failed: {s}\nssh stderr: {s}", .{ @errorName(err), conn.stderr() });
        } else {
            engine.downloadFile(gpa, io, &conn.sess, spec.path, dest, opts) catch |err|
                bail("download failed: {s}\nssh stderr: {s}", .{ @errorName(err), conn.stderr() });
        }
    } else {
        if (v.recursive and isLocalDir(io, src)) {
            engine.uploadDir(gpa, io, &conn.sess, src, spec.path, opts) catch |err|
                bail("upload failed: {s}\nssh stderr: {s}", .{ @errorName(err), conn.stderr() });
        } else {
            engine.uploadFile(gpa, io, &conn.sess, src, spec.path, opts) catch |err|
                bail("upload failed: {s}\nssh stderr: {s}", .{ @errorName(err), conn.stderr() });
        }
    }
}
