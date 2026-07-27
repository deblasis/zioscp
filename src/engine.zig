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
const zioprogress = @import("zioprogress");
const ziorate = @import("ziorate");
const transport = @import("transport.zig");
const chunker = @import("chunker.zig");

const Dir = std.Io.Dir;
const Session = client.Session;

pub const Options = struct {
    chunk_size: u32 = 8 * 1024 * 1024,
    resume_enabled: bool = true,
    /// Render a progress bar to stderr (only when stderr is a TTY).
    progress: bool = true,
    /// Max bytes/sec (0 = unlimited). Paced at chunk granularity via ziorate.
    bwlimit_bps: u64 = 0,
    /// Print transfer progress lines to stderr (one per file).
    verbose: bool = false,
    /// Apply source permissions/mtime to the destination. Permission bits only.
    preserve: bool = false,
};

/// Bandwidth pacer. ziorate's TokenBucket is per-token, so we treat one token
/// as one chunk: a bucket of capacity 1 refilling at (bwlimit / chunk) tokens
/// per second bounds the transfer to bwlimit bytes/sec. Disabled when
/// bwlimit_bps is 0.
const Pacer = struct {
    bucket: ziorate.TokenBucket,
    io: std.Io,
    enabled: bool,
    interval_ns: i96, // ns to sleep when waiting for the next token

    fn init(io: std.Io, opts: Options, chunk: u32) Pacer {
        const enabled = opts.bwlimit_bps > 0;
        const refill: f64 = if (enabled)
            @as(f64, @floatFromInt(opts.bwlimit_bps)) / @as(f64, @floatFromInt(chunk))
        else
            0;
        const interval: i96 = if (enabled)
            @intCast(@divTrunc(@as(u64, chunk) * 1_000_000_000, opts.bwlimit_bps))
        else
            0;
        return .{
            .bucket = ziorate.TokenBucket.init(1, refill),
            .io = io,
            .enabled = enabled,
            .interval_ns = interval,
        };
    }

    /// Block until one chunk's worth of bandwidth is available.
    fn wait(self: *Pacer) void {
        if (!self.enabled) return;
        while (true) {
            const ts = std.Io.Clock.now(.awake, self.io);
            self.bucket.refill(@intCast(ts.nanoseconds));
            if (self.bucket.allow()) return;
            std.Io.sleep(self.io, .{ .nanoseconds = self.interval_ns }, .awake) catch {};
        }
    }
};

fn stderrIsTty(io: std.Io) bool {
    return std.Io.File.stderr().isTty(io) catch false;
}

/// TTY-gated progress bar. Renders only when interactive (opts.progress and
/// stderr is a TTY), so tests and pipes stay quiet. Re-renders only on a
/// percentage change to keep large transfers from flooding stderr.
const Progress = struct {
    bar: zioprogress.ProgressBar,
    last_pct: u8,
    show: bool,

    fn start(io: std.Io, label: []const u8, total: u64, opts: Options, resume_off: u64) Progress {
        var p: Progress = .{
            .bar = zioprogress.ProgressBar.init(.{ .prefix = label, .width = 30 }, total),
            .last_pct = 255,
            .show = opts.progress and stderrIsTty(io),
        };
        p.bar.current = resume_off;
        return p;
    }
    fn step(self: *Progress, inc: u64) void {
        if (!self.show) return;
        self.bar.advance(inc);
        const pct = self.bar.percent();
        if (pct != self.last_pct) {
            self.last_pct = pct;
            self.render();
        }
    }
    fn render(self: *Progress) void {
        var buf: [256]u8 = undefined;
        const s = self.bar.render(&buf);
        std.debug.print("\r{s}", .{s});
    }
    fn finish(self: *Progress) void {
        if (!self.show) return;
        self.bar.current = self.bar.total;
        self.render();
        std.debug.print("\n", .{});
    }
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

fn vlog(opts: Options, comptime fmt: []const u8, args: anytype) void {
    if (opts.verbose) std.debug.print(fmt ++ "\n", args);
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
    vlog(opts, "upload {s} -> {s} ({d} bytes)", .{ local_path, remote_path, total });

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

    const chunk = effectiveChunk(opts);
    const buf = try gpa.alloc(u8, chunk);
    defer gpa.free(buf);
    // Sliding-window pipeline: keep up to `window` WRITEs in flight. SFTP
    // processes FIFO and STATUS replies are tiny, so a single-threaded fill/
    // drain keeps the server's write path saturated with no pipe-buffer
    // deadlock risk (the benchmark showed serialization was zioscp-j1's main
    // overhead vs scp). Sidecar records the byte offset of acknowledged writes.
    const window: usize = 16;
    var off = next_off;
    var in_flight: usize = 0;
    var acked_writes: u64 = if (chunk > 0) next_off / @as(u64, chunk) else 0;
    var prog = Progress.start(io, remote_path, total, opts, next_off);
    var pacer = Pacer.init(io, opts, chunk);
    while (off < total or in_flight > 0) {
        while (in_flight < window and off < total) {
            pacer.wait();
            const len: usize = @intCast(@min(@as(u64, chunk), total - off));
            _ = try local.readPositionalAll(io, buf[0..len], off);
            try sess.sendWriteUnacked(handle, off, buf[0..len]);
            off += len;
            in_flight += 1;
        }
        try sess.awaitAnyOk();
        in_flight -= 1;
        acked_writes += 1;
        const acked_off: u64 = @min(acked_writes * @as(u64, chunk), total);
        record(io, gpa, sidecar, .upload, total, chunk, acked_off, local_path);
        prog.step(chunk);
    }
    prog.finish();
    if (opts.preserve) {
        // Permission bits + atime/mtime (SFTP ACMODTIME is u32 seconds). The
        // local Stat's Timestamps are ns since epoch. Best-effort.
        const mode = st.permissions.toMode();
        const mtime_s: u32 = @intCast(@divTrunc(st.mtime.nanoseconds, std.time.ns_per_s));
        const atime_s: u32 = if (st.atime) |a|
            @intCast(@divTrunc(a.nanoseconds, std.time.ns_per_s))
        else
            mtime_s;
        sess.fsetstat(handle, .{
            .flags = packets.ATTR_PERMISSIONS | packets.ATTR_ACMODTIME,
            .permissions = @intCast(mode & 0o7777),
            .atime = atime_s,
            .mtime = mtime_s,
        }) catch {};
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
    vlog(opts, "download {s} -> {s} ({d} bytes)", .{ remote_path, local_path, total });

    const sidecar = try resume_mod.sidecarPath(gpa, local_path);
    defer gpa.free(sidecar);

    var next_off: u64 = 0;
    if (opts.resume_enabled) next_off = try resumeOffsetDownload(io, gpa, local_path, sidecar, total);
    const mac_path = try resume_mod.macPath(gpa, local_path);
    defer gpa.free(mac_path);
    // MAC-verify completed chunks; a mismatch (corruption / stale partial)
    // wins over the sidecar offset and forces a re-fetch from there.
    if (opts.resume_enabled) {
        if (verifyDownloadMacs(io, gpa, local_path, mac_path, effectiveChunk(opts), total) catch null) |verified| {
            if (verified < next_off) next_off = verified;
        }
    }

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
    var prog = Progress.start(io, local_path, total, opts, next_off);
    var pacer = Pacer.init(io, opts, effectiveChunk(opts));
    while (off < total) {
        pacer.wait();
        const want: u32 = @intCast(@min(@as(u64, effectiveChunk(opts)), total - off));
        const piece = sess.read(rh, off, want) catch |err| switch (err) {
            error.Eof => break,
            else => return err,
        };
        defer gpa.free(piece); // frees this iteration's slice
        if (piece.len == 0) break;
        try local.writePositionalAll(io, piece, off);
        // Record this chunk's MAC for integrity-checked resume.
        if (chunker.hashChunk(gpa, piece)) |mac| {
            resume_mod.appendMac(io, mac_path, mac, off / @as(u64, effectiveChunk(opts))) catch {};
            gpa.free(mac);
        } else |_| {}
        off += piece.len;
        record(io, gpa, sidecar, .download, total, effectiveChunk(opts), off, remote_path);
        prog.step(@intCast(piece.len));
    }
    prog.finish();
    try sess.close(rh);
    resume_mod.removeFile(io, sidecar);
    resume_mod.removeFile(io, mac_path);
}

/// Re-MAC each completed local chunk and compare to the stored MAC file.
/// Returns null if there is no MAC file (keep the offset-based resume); else
/// the byte offset to resume from: the first mismatch's chunk start, or
/// (mac count * chunk) if all verified.
fn verifyDownloadMacs(
    io: std.Io,
    gpa: std.mem.Allocator,
    local_path: []const u8,
    mac_path: []const u8,
    chunk: u32,
    total: u64,
) !?u64 {
    const bytes = (try resume_mod.readMacFile(io, gpa, mac_path)) orelse return null;
    defer gpa.free(bytes);
    const count = bytes.len / 65;
    if (count == 0) return null;
    var f = std.Io.Dir.cwd().openFile(io, local_path, .{}) catch return 0;
    defer f.close(io);
    const buf = try gpa.alloc(u8, @intCast(chunk));
    defer gpa.free(buf);
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const off = i * chunk;
        if (off >= total) return total;
        const len = @min(@as(u64, chunk), total - off);
        _ = f.readPositionalAll(io, buf[0..@intCast(len)], off) catch return off;
        const h = chunker.hashChunk(gpa, buf[0..@intCast(len)]) catch return off;
        defer gpa.free(h);
        if (!std.mem.eql(u8, h, bytes[i * 65 ..][0..64])) return off; // mismatch
    }
    return count * @as(u64, chunk);
}

fn remoteMkdir(sess: anytype, path: []const u8) void {
    // Ignore "already exists" so resuming a tree transfer is idempotent.
    sess.mkdir(path, packets.Attrs.empty) catch {};
}

/// A single file transfer to perform. Owns its path strings, freed via the
/// task list. Drives both sequential and parallel directory transfer.
pub const Task = struct {
    direction: resume_mod.Direction,
    local: []const u8,
    remote: []const u8,
};

pub fn freeTasks(gpa: std.mem.Allocator, list: *std.ArrayList(Task)) void {
    for (list.items) |t| {
        gpa.free(t.local);
        gpa.free(t.remote);
    }
    list.deinit(gpa);
}

/// Walk a local tree (mkdir-ing remote dirs as it goes) and collect one Task
/// per file into `out`. Skips symlinks and special files. Tasks own their
/// path strings; the caller owns and frees `out`.
pub fn collectUploadTasks(
    gpa: std.mem.Allocator,
    io: std.Io,
    sess: anytype,
    local_dir: []const u8,
    remote_dir: []const u8,
    out: *std.ArrayList(Task),
) !void {
    remoteMkdir(sess, remote_dir);
    var dir = Dir.cwd().openDir(io, local_dir, .{}) catch |err| {
        std.debug.print("zioscp: cannot open dir {s}: {s}\n", .{ local_dir, @errorName(err) });
        return err;
    };
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        switch (entry.kind) {
            .file => {
                const cl = try std.fs.path.join(gpa, &.{ local_dir, entry.name });
                const cr = try std.fs.path.join(gpa, &.{ remote_dir, entry.name });
                errdefer gpa.free(cl);
                errdefer gpa.free(cr);
                try out.append(gpa, .{ .direction = .upload, .local = cl, .remote = cr });
            },
            .directory => {
                const cl = try std.fs.path.join(gpa, &.{ local_dir, entry.name });
                defer gpa.free(cl);
                const cr = try std.fs.path.join(gpa, &.{ remote_dir, entry.name });
                defer gpa.free(cr);
                try collectUploadTasks(gpa, io, sess, cl, cr, out);
            },
            else => {}, // skip symlinks and special files
        }
    }
}

/// Walk a remote tree (mkdir-ing local dirs as it goes) and collect one Task
/// per file into `out`. Skips symlinks and special files.
pub fn collectDownloadTasks(
    gpa: std.mem.Allocator,
    io: std.Io,
    sess: anytype,
    remote_dir: []const u8,
    local_dir: []const u8,
    out: *std.ArrayList(Task),
) !void {
    Dir.cwd().createDirPath(io, local_dir) catch {};
    const dh = try sess.opendir(remote_dir);
    defer gpa.free(dh);
    while (true) {
        const entries = sess.readdir(dh) catch |err| switch (err) {
            error.Eof => break,
            else => return err,
        };
        defer {
            for (entries) |e| {
                gpa.free(e.filename);
                gpa.free(e.longname);
            }
            gpa.free(entries);
        }
        for (entries) |e| {
            if (std.mem.eql(u8, e.filename, ".") or std.mem.eql(u8, e.filename, "..")) continue;
            const is_dir = (e.attrs.flags & packets.ATTR_PERMISSIONS != 0) and
                ((e.attrs.permissions & 0o170000) == 0o040000);
            const cr = try std.fs.path.join(gpa, &.{ remote_dir, e.filename });
            const cl = try std.fs.path.join(gpa, &.{ local_dir, e.filename });
            if (is_dir) {
                defer gpa.free(cr);
                defer gpa.free(cl);
                try collectDownloadTasks(gpa, io, sess, cr, cl, out);
            } else {
                errdefer gpa.free(cr);
                errdefer gpa.free(cl);
                try out.append(gpa, .{ .direction = .download, .local = cl, .remote = cr });
            }
        }
    }
    try sess.close(dh);
}

/// Upload a local directory tree to a remote directory (created if missing).
/// Symlinks and special files are skipped. `-r`. Sequential (single stream);
/// use the parallel runner for `-j N > 1`.
pub fn uploadDir(
    gpa: std.mem.Allocator,
    io: std.Io,
    sess: anytype,
    local_dir: []const u8,
    remote_dir: []const u8,
    opts: Options,
) !void {
    var list: std.ArrayList(Task) = .empty;
    defer freeTasks(gpa, &list);
    try collectUploadTasks(gpa, io, sess, local_dir, remote_dir, &list);
    for (list.items) |t| {
        uploadFile(gpa, io, sess, t.local, t.remote, opts) catch |err| {
            std.debug.print("zioscp: skipping {s}: {s}\n", .{ t.local, @errorName(err) });
        };
    }
}

/// Download a remote directory tree to a local directory (created if missing).
/// Symlinks and special files are skipped. `-r`. Sequential; use the parallel
/// runner for `-j N > 1`.
pub fn downloadDir(
    gpa: std.mem.Allocator,
    io: std.Io,
    sess: anytype,
    remote_dir: []const u8,
    local_dir: []const u8,
    opts: Options,
) !void {
    var list: std.ArrayList(Task) = .empty;
    defer freeTasks(gpa, &list);
    try collectDownloadTasks(gpa, io, sess, remote_dir, local_dir, &list);
    for (list.items) |t| {
        downloadFile(gpa, io, sess, t.remote, t.local, opts) catch |err| {
            std.debug.print("zioscp: skipping {s}: {s}\n", .{ t.remote, @errorName(err) });
        };
    }
}

const ParallelCtx = struct {
    gpa: std.mem.Allocator,
    ssh_argv: []const []const u8,
    opts: Options,
    tasks: []const Task,
    next: std.atomic.Value(usize),
    errors: std.atomic.Value(u32),
};

/// Worker thread body: its own Threaded io + ssh Connection, pulls tasks by
/// atomic index until none remain. A per-file error is logged + counted, not
/// fatal (the remaining tasks still run on other workers).
fn parallelWorker(ctx: *ParallelCtx) void {
    var threaded = std.Io.Threaded.init(ctx.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = transport.Connection.open(ctx.gpa, io, ctx.ssh_argv) catch return;
    defer conn.deinit();
    while (true) {
        const idx = ctx.next.fetchAdd(1, .monotonic);
        if (idx >= ctx.tasks.len) break;
        const t = ctx.tasks[idx];
        switch (t.direction) {
            .upload => uploadFile(ctx.gpa, io, &conn.sess, t.local, t.remote, ctx.opts) catch |err| {
                std.debug.print("zioscp: skipping {s}: {s}\n", .{ t.local, @errorName(err) });
                _ = ctx.errors.fetchAdd(1, .monotonic);
            },
            .download => downloadFile(ctx.gpa, io, &conn.sess, t.remote, t.local, ctx.opts) catch |err| {
                std.debug.print("zioscp: skipping {s}: {s}\n", .{ t.remote, @errorName(err) });
                _ = ctx.errors.fetchAdd(1, .monotonic);
            },
        }
    }
}

/// Run a batch of file tasks across `jobs` worker threads, each with its own
/// ssh subprocess + session (so up to `jobs` files transfer concurrently).
/// Tasks are distributed lock-free via an atomic index. Progress bars are
/// disabled (K interleaving bars would be garbage); parallel mode is quiet.
pub fn runParallel(
    gpa: std.mem.Allocator,
    ssh_argv: []const []const u8,
    tasks: []const Task,
    opts: Options,
    jobs: u32,
) !void {
    if (tasks.len == 0) return;
    var quiet_opts = opts;
    quiet_opts.progress = false;
    var ctx: ParallelCtx = .{
        .gpa = gpa,
        .ssh_argv = ssh_argv,
        .opts = quiet_opts,
        .tasks = tasks,
        .next = std.atomic.Value(usize).init(0),
        .errors = std.atomic.Value(u32).init(0),
    };
    const j: usize = @min(@as(usize, @intCast(jobs)), tasks.len);
    const threads = try gpa.alloc(std.Thread, j);
    defer gpa.free(threads);
    for (0..j) |i| {
        threads[i] = std.Thread.spawn(.{}, parallelWorker, .{&ctx}) catch |err| {
            for (threads[0..i]) |t| t.join();
            return err;
        };
    }
    for (threads) |t| t.join();
}

// ---------------------------------------------------------------------------
// P3: single-file chunked parallel. One large file sharded across N ssh
// sessions at disjoint offsets.
//
// The hard part is concurrent writes to ONE remote file. Protocol:
//   1. One connection pre-truncates the remote fresh (WRITE|CREATE|TRUNC),
//      then closes. This is the ONLY truncation.
//   2. N workers each open the file WRITE|CREATE (NO TRUNC) and write the
//      offset ranges they pull from a shared atomic chunk index.
// Every chunk [0,total) is written by exactly one worker, so no holes remain;
// sparse intermediate state is overwritten as ranges fill in. Download mirrors
// this with concurrent remote reads + positional local writes.
//
// Resume is NOT coordinated in P3 v1 (a re-run re-truncates and restarts);
// per-chunk resume is a follow-on. Small files (<=1 chunk) fall back to the
// single-stream path.

const ChunkCtx = struct {
    gpa: std.mem.Allocator,
    ssh_argv: []const []const u8,
    opts: Options,
    local_path: []const u8,
    remote_path: []const u8,
    total: u64,
    chunk: u32,
    count: u64,
    next: std.atomic.Value(usize),
    errors: std.atomic.Value(u32),
};

fn uploadChunkWorker(ctx: *ChunkCtx) void {
    var threaded = std.Io.Threaded.init(ctx.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = transport.Connection.open(ctx.gpa, io, ctx.ssh_argv) catch return;
    defer conn.deinit();
    const handle = conn.sess.open(ctx.remote_path, packets.FXF_WRITE | packets.FXF_CREATE, packets.Attrs.empty) catch return;
    defer {
        conn.sess.close(handle) catch {};
        ctx.gpa.free(handle);
    }
    var local = std.Io.Dir.cwd().openFile(io, ctx.local_path, .{}) catch return;
    defer local.close(io);
    const buf = ctx.gpa.alloc(u8, ctx.chunk) catch return;
    defer ctx.gpa.free(buf);
    while (true) {
        const idx = ctx.next.fetchAdd(1, .monotonic);
        if (idx >= ctx.count) break;
        const r = chunker.chunkRange(idx, ctx.total, ctx.chunk);
        if (r.len == 0) continue;
        _ = local.readPositionalAll(io, buf[0..@intCast(r.len)], r.offset) catch {
            _ = ctx.errors.fetchAdd(1, .monotonic);
            continue;
        };
        conn.sess.write(handle, r.offset, buf[0..@intCast(r.len)]) catch {
            _ = ctx.errors.fetchAdd(1, .monotonic);
        };
    }
}

fn downloadChunkWorker(ctx: *ChunkCtx) void {
    var threaded = std.Io.Threaded.init(ctx.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = transport.Connection.open(ctx.gpa, io, ctx.ssh_argv) catch return;
    defer conn.deinit();
    const rh = conn.sess.open(ctx.remote_path, packets.FXF_READ, packets.Attrs.empty) catch return;
    defer {
        conn.sess.close(rh) catch {};
        ctx.gpa.free(rh);
    }
    var local = std.Io.Dir.cwd().createFile(io, ctx.local_path, .{ .truncate = false }) catch return;
    defer local.close(io);
    while (true) {
        const idx = ctx.next.fetchAdd(1, .monotonic);
        if (idx >= ctx.count) break;
        const r = chunker.chunkRange(idx, ctx.total, ctx.chunk);
        if (r.len == 0) continue;
        const want: u32 = @intCast(r.len);
        const piece = conn.sess.read(rh, r.offset, want) catch |err| switch (err) {
            error.Eof => break,
            else => {
                _ = ctx.errors.fetchAdd(1, .monotonic);
                continue;
            },
        };
        defer ctx.gpa.free(piece);
        if (piece.len == 0) break;
        local.writePositionalAll(io, piece, r.offset) catch {
            _ = ctx.errors.fetchAdd(1, .monotonic);
        };
    }
}

/// Upload a single file in parallel across `jobs` ssh connections, sharding it
/// at offset ranges. Falls back to single-stream for files that fit in one
/// chunk. See the P3 note above on the concurrent-write protocol.
pub fn uploadFileParallel(
    gpa: std.mem.Allocator,
    ssh_argv: []const []const u8,
    local_path: []const u8,
    remote_path: []const u8,
    opts: Options,
    jobs: u32,
) !void {
    // Use a short-lived io just to stat (the workers make their own).
    var t0 = std.Io.Threaded.init(gpa, .{});
    defer t0.deinit();
    const io0 = t0.io();
    const total: u64 = (try std.Io.Dir.cwd().statFile(io0, local_path, .{})).size;
    const chunk = effectiveChunk(opts);
    const count = chunker.chunkCount(total, chunk);
    if (count <= 1) {
        var conn = try transport.Connection.open(gpa, io0, ssh_argv);
        defer conn.deinit();
        try uploadFile(gpa, io0, &conn.sess, local_path, remote_path, opts);
        return;
    }

    // Pre-truncate the remote fresh (the only truncation).
    {
        var c = try transport.Connection.open(gpa, io0, ssh_argv);
        defer c.deinit();
        const h = try c.sess.open(remote_path, packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC, packets.Attrs.empty);
        defer {
            c.sess.close(h) catch {};
            gpa.free(h);
        }
    }

    var ctx: ChunkCtx = .{
        .gpa = gpa,
        .ssh_argv = ssh_argv,
        .opts = opts,
        .local_path = local_path,
        .remote_path = remote_path,
        .total = total,
        .chunk = chunk,
        .count = count,
        .next = std.atomic.Value(usize).init(0),
        .errors = std.atomic.Value(u32).init(0),
    };
    try spawnChunkWorkers(gpa, uploadChunkWorker, &ctx, jobs, count);
    if (ctx.errors.load(.monotonic) != 0) return error.Failure;
}

/// Download a single file in parallel across `jobs` ssh connections.
pub fn downloadFileParallel(
    gpa: std.mem.Allocator,
    ssh_argv: []const []const u8,
    remote_path: []const u8,
    local_path: []const u8,
    opts: Options,
    jobs: u32,
) !void {
    var t0 = std.Io.Threaded.init(gpa, .{});
    defer t0.deinit();
    const io0 = t0.io();
    var probe = try transport.Connection.open(gpa, io0, ssh_argv);
    const total: u64 = (try probe.sess.stat(remote_path)).size;
    probe.deinit();

    const chunk = effectiveChunk(opts);
    const count = chunker.chunkCount(total, chunk);
    if (count <= 1) {
        var conn = try transport.Connection.open(gpa, io0, ssh_argv);
        defer conn.deinit();
        try downloadFile(gpa, io0, &conn.sess, remote_path, local_path, opts);
        return;
    }

    // Pre-create+truncate the local file fresh.
    {
        var f = try std.Io.Dir.cwd().createFile(io0, local_path, .{ .truncate = true });
        f.close(io0);
    }

    var ctx: ChunkCtx = .{
        .gpa = gpa,
        .ssh_argv = ssh_argv,
        .opts = opts,
        .local_path = local_path,
        .remote_path = remote_path,
        .total = total,
        .chunk = chunk,
        .count = count,
        .next = std.atomic.Value(usize).init(0),
        .errors = std.atomic.Value(u32).init(0),
    };
    try spawnChunkWorkers(gpa, downloadChunkWorker, &ctx, jobs, count);
    if (ctx.errors.load(.monotonic) != 0) return error.Failure;
}

fn spawnChunkWorkers(
    gpa: std.mem.Allocator,
    comptime worker: anytype,
    ctx: *ChunkCtx,
    jobs: u32,
    count: u64,
) !void {
    const j: usize = @min(@as(usize, @intCast(jobs)), @as(usize, @intCast(count)));
    const threads = try gpa.alloc(std.Thread, j);
    defer gpa.free(threads);
    for (0..j) |i| {
        threads[i] = std.Thread.spawn(.{}, worker, .{ctx}) catch |err| {
            for (threads[0..i]) |t| t.join();
            return err;
        };
    }
    for (threads) |t| t.join();
}
