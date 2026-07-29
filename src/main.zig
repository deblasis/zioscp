//! zioscp CLI: drop-in scp over SFTP, with resume.
//!
//! Usage: zioscp [options] src dest  (exactly one of src/dest is remote).
//! A remote path is written `[user@]host:path`, scp-style. Flags are parsed
//! from a typed struct via zioarg, which also generates --help.

const std = @import("std");
const builtin = @import("builtin");
const transport = @import("transport.zig");
const engine = @import("engine.zig");
const packets = @import("sftp/packets.zig");
const zioarg = @import("zioarg");
const config = @import("config");

const Args = struct {
    port: []const u8 = "22",
    identity: ?[]const u8 = null,
    recursive: bool = false,
    preserve: bool = false,
    no_resume: bool = false,
    chunk_size: u32 = 8 * 1024 * 1024,
    bwlimit: u64 = 0,
    jobs: u32 = 1,
    verbose: bool = false,
    version: bool = false,
    host_key_check: engine.HostKeyCheck = .strict,
    files: []const []const u8 = &.{},

    pub const short = .{ .port = 'P', .identity = 'i', .recursive = 'r', .preserve = 'p', .jobs = 'j', .verbose = 'v', .version = 'V' };
    pub const help = .{
        .port = "ssh port (default 22)",
        .identity = "identity file",
        .recursive = "copy directories recursively",
        .preserve = "preserve file permissions",
        .no_resume = "overwrite from the start instead of resuming",
        .chunk_size = "transfer chunk size in bytes (default 8 MiB)",
        .bwlimit = "limit transfer to N bytes/sec (default unlimited)",
        .jobs = "parallel transfer connections for -r (default 1)",
        .verbose = "print one progress line per file to stderr",
        .version = "print version and exit",
        .host_key_check = "host key check: strict | accept-new | no",
        .files = "src dest (one is [user@]host:path)",
    };
};

const RemoteSpec = struct { user_host: []const u8, path: []const u8 };

/// A `host:path` style remote (colon present, no '/' before the colon).
fn remoteSpec(s: []const u8) ?RemoteSpec {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    const lhs = s[0..colon];
    if (lhs.len == 0) return null;
    // A Windows drive-letter path (C:\... or C:/...) is a local path, not a
    // host spec. Gated to the Windows build so mac/linux host parsing is
    // unchanged (a single-letter host before a colon is vanishingly rare there).
    if (builtin.os.tag == .windows and lhs.len == 1 and std.ascii.isAlphabetic(lhs[0])) {
        const after = s[colon + 1];
        if (after == '\\' or after == '/') return null;
    }
    if (std.mem.indexOfScalar(u8, lhs, '/') != null) return null;
    return .{ .user_host = lhs, .path = s[colon + 1 ..] };
}

/// Home directory for the SSH known_hosts lookup: $HOME on unix, falling back to
/// $USERPROFILE on Windows (where HOME is not set by default).
fn homeDir(environ_map: anytype) ?[]const u8 {
    if (environ_map.get("HOME")) |h| return h;
    if (builtin.os.tag == .windows) {
        if (environ_map.get("USERPROFILE")) |u| return u;
    }
    return null;
}

fn bail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("zioscp: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn printHelp(io: std.Io) void {
    var buf: [4096]u8 = undefined;
    var fw = std.Io.File.stderr().writer(io, &buf);
    zioarg.formatHelp(Args, &fw.interface, "zioscp") catch {};
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

/// Single-connection transfer (sequential: file or -r tree). Generic over the
/// session so it works with both the ssh-subprocess and libssh2 backends.
fn transfer(
    gpa: std.mem.Allocator,
    io: std.Io,
    sess: anytype,
    opts: engine.Options,
    download: bool,
    recursive: bool,
    src: []const u8,
    dest: []const u8,
    remote_path: []const u8,
) !void {
    if (download) {
        if (recursive and remoteIsDir(sess, remote_path))
            try engine.downloadDir(gpa, io, sess, remote_path, dest, opts)
        else
            try engine.downloadFile(gpa, io, sess, remote_path, dest, opts);
    } else {
        if (recursive and isLocalDir(io, src))
            try engine.uploadDir(gpa, io, sess, src, remote_path, opts)
        else
            try engine.uploadFile(gpa, io, sess, src, remote_path, opts);
    }
}

/// libssh2-backend single-connection transfer. Only analyzed (and libssh2 only
/// linked) when -Dbackend=libssh2, because this is reached solely through the
/// comptime branch in main.
fn transferLibssh2(
    gpa: std.mem.Allocator,
    io: std.Io,
    opts: engine.Options,
    download: bool,
    recursive: bool,
    src: []const u8,
    dest: []const u8,
    remote_path: []const u8,
    user_host: []const u8,
    port_s: []const u8,
    identity: ?[]const u8,
    mode: engine.HostKeyCheck,
    known_hosts_path: []const u8,
) !void {
    const tl = @import("transport_libssh2.zig");
    const at = std.mem.indexOfScalar(u8, user_host, '@') orelse
        bail("libssh2 backend requires user@host", .{});
    const user = user_host[0..at];
    const host = user_host[at + 1 ..];
    const port = std.fmt.parseInt(u16, port_s, 10) catch 22;
    const key = identity orelse bail("libssh2 backend requires -i <key>", .{});
    var conn = tl.Connection.open(gpa, io, host, port, user, key, mode, known_hosts_path) catch |err|
        bail("libssh2 connection failed: {s}", .{@errorName(err)});
    defer conn.deinit();
    transfer(gpa, io, &conn.sess, opts, download, recursive, src, dest, remote_path) catch |err|
        bail("transfer failed: {s}", .{@errorName(err)});
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
            zioarg.reportError(Args, err, "zioscp");
            printHelp(io);
            std.process.exit(1);
        },
    };
    defer parsed.deinit(gpa);
    const v = parsed.value;

    if (v.version) {
        var vbuf: [128]u8 = undefined;
        var vw = std.Io.File.stdout().writer(io, &vbuf);
        vw.interface.print("zioscp {s}\n", .{config.version}) catch {};
        vw.interface.flush() catch {};
        return;
    }

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
    // Host-key check mirrors scp/ssh's StrictHostKeyChecking (default strict).
    const shk_val: []const u8 = switch (v.host_key_check) {
        .strict => "yes",
        .accept_new => "accept-new",
        .no => "no",
    };
    const shk_opt = std.fmt.allocPrint(aa, "StrictHostKeyChecking={s}", .{shk_val}) catch bail("oom", .{});
    ssh_argv.append(aa, "-o") catch bail("oom", .{});
    ssh_argv.append(aa, shk_opt) catch bail("oom", .{});
    // Bound the connection so an unreachable/stalled server fails fast instead
    // of hanging on the OS TCP default (~75s) or an indefinite wait. Mirrors the
    // libssh2 backend's SESSION_TIMEOUT_MS (transport_libssh2.zig).
    ssh_argv.append(aa, "-o") catch bail("oom", .{});
    ssh_argv.append(aa, "ConnectTimeout=30") catch bail("oom", .{});
    ssh_argv.append(aa, "-o") catch bail("oom", .{});
    ssh_argv.append(aa, "ServerAliveInterval=15") catch bail("oom", .{});
    ssh_argv.append(aa, "-o") catch bail("oom", .{});
    ssh_argv.append(aa, "ServerAliveCountMax=2") catch bail("oom", .{});
    ssh_argv.append(aa, "-s") catch bail("oom", .{});
    ssh_argv.append(aa, "--") catch bail("oom", .{});
    ssh_argv.append(aa, spec.user_host) catch bail("oom", .{});
    ssh_argv.append(aa, "sftp") catch bail("oom", .{});

    const opts: engine.Options = .{
        .chunk_size = v.chunk_size,
        .resume_enabled = !v.no_resume,
        .preserve = v.preserve,
        .bwlimit_bps = v.bwlimit,
        .verbose = v.verbose,
    };

    // Connection spec for the libssh2 backend (dials directly, no subprocess).
    // Computed up front so the parallel paths below can build their opener; the
    // whole block is comptime-eliminated under the ssh backend.
    const Libssh2Spec = struct { host: []const u8, port: u16, user: []const u8, key: []const u8, kh: []const u8 };
    const tl_spec: ?Libssh2Spec = if (config.backend == .libssh2) blk: {
        const at = std.mem.indexOfScalar(u8, spec.user_host, '@') orelse
            bail("libssh2 backend requires user@host", .{});
        const port = std.fmt.parseInt(u16, v.port, 10) catch 22;
        const key = v.identity orelse bail("libssh2 backend requires -i <key>", .{});
        const home = homeDir(init.environ_map) orelse
            bail("libssh2 backend needs HOME (or USERPROFILE on Windows) for ~/.ssh/known_hosts", .{});
        const kh = std.fmt.allocPrint(aa, "{s}/.ssh/known_hosts", .{home}) catch bail("oom", .{});
        break :blk Libssh2Spec{
            .host = spec.user_host[at + 1 ..],
            .port = port,
            .user = spec.user_host[0..at],
            .key = key,
            .kh = kh,
        };
    } else null;

    // Parallel directory transfer: collect the file list on one connection
    // (also pre-creating dirs), then fan out across `jobs` connections. Each
    // backend builds its own opener; the engine is opener-generic.
    if (v.recursive and v.jobs > 1) {
        var list: std.ArrayList(engine.Task) = .empty;
        if (config.backend == .libssh2) {
            const tl = @import("transport_libssh2.zig");
            const s = tl_spec.?;
            var coll = tl.Connection.open(gpa, io, s.host, s.port, s.user, s.key, v.host_key_check, s.kh) catch |err|
                bail("connection failed: {s}", .{@errorName(err)});
            if (download)
                engine.collectDownloadTasks(aa, io, &coll.sess, spec.path, dest, &list) catch |err|
                    bail("collect failed: {s}", .{@errorName(err)})
            else
                engine.collectUploadTasks(aa, io, &coll.sess, src, spec.path, &list) catch |err|
                    bail("collect failed: {s}", .{@errorName(err)});
            coll.deinit();
            const opener = tl.Opener{ .host = s.host, .port = s.port, .user = s.user, .key = s.key, .mode = v.host_key_check, .known_hosts = s.kh };
            engine.runParallel(tl.Opener, gpa, io, opener, list.items, opts, v.jobs) catch |err|
                bail("parallel transfer failed: {s}", .{@errorName(err)});
        } else {
            var coll = transport.Connection.open(gpa, io, ssh_argv.items) catch |err|
                bail("connection failed: {s}", .{@errorName(err)});
            if (download)
                engine.collectDownloadTasks(aa, io, &coll.sess, spec.path, dest, &list) catch |err|
                    bail("collect failed: {s}", .{@errorName(err)})
            else
                engine.collectUploadTasks(aa, io, &coll.sess, src, spec.path, &list) catch |err|
                    bail("collect failed: {s}", .{@errorName(err)});
            coll.deinit();
            const opener = engine.SshOpener{ .ssh_argv = ssh_argv.items };
            engine.runParallel(engine.SshOpener, gpa, io, opener, list.items, opts, v.jobs) catch |err|
                bail("parallel transfer failed: {s}", .{@errorName(err)});
        }
        return;
    }

    // Single-file chunked parallel: shard one file across `jobs` connections.
    if (!v.recursive and v.jobs > 1) {
        if (config.backend == .libssh2) {
            const tl = @import("transport_libssh2.zig");
            const s = tl_spec.?;
            const opener = tl.Opener{ .host = s.host, .port = s.port, .user = s.user, .key = s.key, .mode = v.host_key_check, .known_hosts = s.kh };
            if (download)
                engine.downloadFileParallel(tl.Opener, gpa, opener, spec.path, dest, opts, v.jobs) catch |err|
                    bail("download failed: {s}", .{@errorName(err)})
            else
                engine.uploadFileParallel(tl.Opener, gpa, opener, src, spec.path, opts, v.jobs) catch |err|
                    bail("upload failed: {s}", .{@errorName(err)});
        } else {
            const opener = engine.SshOpener{ .ssh_argv = ssh_argv.items };
            if (download)
                engine.downloadFileParallel(engine.SshOpener, gpa, opener, spec.path, dest, opts, v.jobs) catch |err|
                    bail("download failed: {s}", .{@errorName(err)})
            else
                engine.uploadFileParallel(engine.SshOpener, gpa, opener, src, spec.path, opts, v.jobs) catch |err|
                    bail("upload failed: {s}", .{@errorName(err)});
        }
        return;
    }

    if (config.backend == .libssh2) {
        const home = homeDir(init.environ_map) orelse
            bail("libssh2 backend needs HOME (or USERPROFILE on Windows) for ~/.ssh/known_hosts", .{});
        const kh_path = std.fmt.allocPrint(aa, "{s}/.ssh/known_hosts", .{home}) catch bail("oom", .{});
        transferLibssh2(gpa, io, opts, download, v.recursive, src, dest, spec.path, spec.user_host, v.port, v.identity, v.host_key_check, kh_path) catch |err|
            bail("transfer failed: {s}", .{@errorName(err)});
        return;
    }

    var conn = transport.Connection.open(gpa, io, ssh_argv.items) catch |err|
        bail("connection failed: {s}", .{@errorName(err)});
    defer conn.deinit();
    transfer(gpa, io, &conn.sess, opts, download, v.recursive, src, dest, spec.path) catch |err|
        bail("transfer failed: {s}\nssh stderr: {s}", .{ @errorName(err), conn.stderr() });
}
