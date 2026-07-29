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
const zioansi = @import("zioansi");
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

/// Server host-key verification policy (mirrors ssh's StrictHostKeyChecking):
/// strict fails on unknown/changed; accept_new fails on changed but proceeds on
/// first-seen; no skips verification. Default strict, like scp under BatchMode.
pub const HostKeyCheck = enum { strict, accept_new, no };

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

/// Human-readable byte count (KiB/MiB/...). Writes into `buf`, returns a slice.
fn humanCount(buf: []u8, bytes: u64) []const u8 {
    const units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB", "PiB" };
    var idx: usize = 0;
    var v: f64 = @floatFromInt(bytes);
    while (v >= 1024.0 and idx < units.len - 1) {
        v /= 1024.0;
        idx += 1;
    }
    if (idx == 0) return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "B";
    return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ v, units[idx] }) catch "?";
}

/// mm:ss or h:mm:ss ETA from seconds. "--:--" while no rate yet.
fn fmtEta(buf: []u8, secs: f64) []const u8 {
    if (!(secs > 0.0) or std.math.isInf(secs) or std.math.isNan(secs)) return "--:--";
    const clamped = @min(secs, 359999.0);
    const s: u64 = @intFromFloat(clamped);
    const h = s / 3600;
    const m = (s % 3600) / 60;
    const sec = s % 60;
    if (h > 0) return std.fmt.bufPrint(buf, "{d}:{d:0>2}:{d:0>2}", .{ h, m, sec }) catch "?";
    return std.fmt.bufPrint(buf, "{d}:{d:0>2}", .{ m, sec }) catch "?";
}

/// TTY-gated progress display: a moving bar plus throughput, bytes done, and an
/// ETA. Renders only when interactive (opts.progress and stderr is a TTY), so
/// tests and pipes stay quiet. Re-renders on a percent change OR at most ~10/s,
/// so the bar moves smoothly without flooding stderr or stalling the transfer.
/// Throughput is the cumulative average of THIS run (bytes since resume / elapsed),
/// which is stable and converges; ETA is remaining / rate. Styled via zioansi,
/// zero allocation in the render path (comptime ANSI codes + stack buffers).
const Progress = struct {
    bar: zioprogress.ProgressBar,
    io: std.Io,
    total: u64,
    start_done: u64, // bytes already present at (re)start; rate counts only new bytes
    last_pct: u8,
    last_render_ns: i96,
    start_ns: i96,
    show: bool,
    label_buf: [28]u8 = undefined,
    label_len: u8 = 0,

    // Comptime format: label + bar in cyan, the stats line dim. The ANSI codes
    // come from zioansi's tables; the {s} slots are filled at runtime.
    const LINE =
        zioansi.Color.cyan.fg() ++ "{s}  {s}" ++ zioansi.reset ++ "  " ++
        zioansi.Style.dim.enable() ++ "{s}/{s}  {s}/s  eta {s}" ++ zioansi.reset;

    fn start(io: std.Io, label: []const u8, total: u64, opts: Options, resume_off: u64) Progress {
        const now = std.Io.Clock.now(.awake, io).nanoseconds;
        var p: Progress = .{
            .bar = zioprogress.ProgressBar.init(.{ .width = 26 }, total),
            .io = io,
            .total = total,
            .start_done = resume_off,
            .last_pct = 255,
            .last_render_ns = now,
            .start_ns = now,
            .show = opts.progress and stderrIsTty(io),
        };
        p.bar.current = resume_off;
        // Keep the tail of long paths (filenames matter more than the prefix).
        const max = p.label_buf.len;
        const lbl = if (label.len > max) label[label.len - max ..] else label;
        @memcpy(p.label_buf[0..lbl.len], lbl);
        p.label_len = @intCast(lbl.len);
        return p;
    }

    fn step(self: *Progress, inc: u64) void {
        if (!self.show) return;
        self.bar.advance(inc);
        const pct = self.bar.percent();
        const now = std.Io.Clock.now(.awake, self.io).nanoseconds;
        if (pct != self.last_pct or now - self.last_render_ns > 100_000_000) {
            self.last_pct = pct;
            self.last_render_ns = now;
            self.render(now);
        }
    }

    /// Build the progress line into `out` (the stats + bar, with ANSI styling).
    /// Pure / side-effect-free so it can be unit-tested without a TTY.
    fn formatLine(self: *Progress, now_ns: i96, out: []u8) []const u8 {
        var bar_buf: [64]u8 = undefined;
        var done_buf: [16]u8 = undefined;
        var tot_buf: [16]u8 = undefined;
        var rate_buf: [16]u8 = undefined;
        var eta_buf: [12]u8 = undefined;

        const done: u64 = self.bar.current;
        const elapsed_s: f64 = @as(f64, @floatFromInt(now_ns - self.start_ns)) / 1_000_000_000.0;
        const delta: u64 = if (done > self.start_done) done - self.start_done else 0;
        const rate: f64 = if (elapsed_s > 0.0) @as(f64, @floatFromInt(delta)) / elapsed_s else 0.0;
        const remaining: u64 = if (self.total > done) self.total - done else 0;
        const eta_s: f64 = if (rate > 0.0) @as(f64, @floatFromInt(remaining)) / rate else 0.0;

        return std.fmt.bufPrint(out, LINE, .{
            self.label_buf[0..self.label_len],
            self.bar.render(&bar_buf),
            humanCount(&done_buf, done),
            humanCount(&tot_buf, self.total),
            humanCount(&rate_buf, @intFromFloat(@max(rate, 0.0))),
            fmtEta(&eta_buf, eta_s),
        }) catch "";
    }

    fn render(self: *Progress, now_ns: i96) void {
        var buf: [256]u8 = undefined;
        const s = self.formatLine(now_ns, &buf);
        if (s.len == 0) return;
        // \r returns to line start; \x1b[K clears to end-of-line so a shorter
        // re-render never leaves stale tail characters.
        std.debug.print("\r{s} \x1b[K", .{s});
    }

    fn finish(self: *Progress) void {
        if (!self.show) return;
        self.bar.current = self.total;
        self.render(std.Io.Clock.now(.awake, self.io).nanoseconds);
        std.debug.print("\n", .{});
    }
};

/// Adaptive sliding-window controller for the SFTP pipeline. Sizes the in-flight
/// window to the bandwidth-delay product without timing per-request RTT: it
/// watches how long each ack RECV blocks. A recv that returns near-instantly had
/// its reply already buffered (the pipe was full -> window already covers the
/// BDP); a recv that blocks waited on the network (the pipe drained -> window is
/// below BDP -> grow). This sidesteps the trap that derails RTT-ratio (Vegas)
/// controllers in this pipeline: the single-threaded recv+process loop inflates
/// a request's measured RTT with the local disk/hash work on EARLIER replies,
/// which reads as queueing and falsely caps the window (a measured regression on
/// downloads). recv-wait is clean -- that work happens AFTER recv returns.
/// Replaces a fixed window (was 256 single-stream / 64 per chunk worker).
const WindowCtl = struct {
    window: usize,
    min_window: usize,
    max_window: usize,
    ss_thresh: usize, // slow-start threshold (chunks)

    const immediate_ns: i96 = 100_000; // <= ~100us => the reply was already buffered

    fn init(min_window: usize, max_window: usize) WindowCtl {
        return .{
            .window = min_window,
            .min_window = min_window,
            .max_window = max_window,
            .ss_thresh = max_window,
        };
    }

    /// Record one ack, given the nanoseconds its RECV spent blocked waiting.
    /// A buffered reply (wait <= immediate_ns) means the pipe was full -> window
    /// already covers the BDP, hold. A blocking recv means the pipe drained ->
    /// window is below BDP, grow. Slow-start (double) below ss_thresh, +1 above.
    /// No shrink: in this single-threaded pipeline there is no clean congestion
    /// signal, and a window above BDP just buffers (harmless, capped at max).
    fn observedWait(self: *WindowCtl, wait_ns: i96) void {
        if (wait_ns >= 0 and wait_ns <= immediate_ns) return; // buffered: hold
        if (self.window >= self.max_window) return;
        if (self.window < self.ss_thresh) {
            self.window = @min(self.window * 2, self.max_window); // slow-start
        } else {
            self.window = @min(self.window + 1, self.max_window); // avoidance
        }
    }
};

test "WindowCtl: grows on blocking recvs, holds once the pipe is full" {
    var w = WindowCtl.init(4, 2048);
    // Blocking recvs (wait well past immediate_ns): pipe draining -> grow.
    var i: usize = 0;
    while (i < 6) : (i += 1) w.observedWait(50_000_000); // 50 ms blocks
    try std.testing.expect(w.window >= 64); // slow-start doubled several times
    try std.testing.expect(w.window < 2048); // not yet at max
    const held = w.window;
    // Buffered recvs (wait <= immediate_ns): pipe full -> stop growing.
    var j: usize = 0;
    while (j < 100) : (j += 1) w.observedWait(5_000); // ~5 us (buffered)
    try std.testing.expectEqual(held, w.window); // held, did not keep climbing
    try std.testing.expect(w.window < 2048);
}

test "WindowCtl: resumes growth if the pipe drains again" {
    var w = WindowCtl.init(8, 2048);
    while (w.window < 64) w.observedWait(50_000_000); // ramp via blocking recvs
    var k: usize = 0;
    while (k < 16) : (k += 1) w.observedWait(1_000); // fill the streak -> hold
    const plateau = w.window;
    w.observedWait(80_000_000); // a blocking recv: pipe drained again
    w.observedWait(80_000_000);
    try std.testing.expect(w.window > plateau); // grew again
}

test "Progress line renders bar, rate, and eta" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var p = Progress.start(io, "backup.tar", 100_000_000, .{ .progress = true }, 0);
    // Simulate 45 MiB transferred over ~5 s of wall clock (rate ~= 9 MiB/s).
    p.bar.current = 45_000_000;
    p.start_ns = std.Io.Clock.now(.awake, io).nanoseconds - 5_000_000_000;

    var buf: [256]u8 = undefined;
    const s = p.formatLine(std.Io.Clock.now(.awake, io).nanoseconds, &buf);

    try std.testing.expect(std.mem.indexOf(u8, s, "backup.tar") != null); // label kept
    try std.testing.expect(std.mem.indexOf(u8, s, "MiB") != null); // human byte count
    try std.testing.expect(std.mem.indexOf(u8, s, "/s") != null); // throughput
    try std.testing.expect(std.mem.indexOf(u8, s, "eta") != null); // ETA slot
    // 45% should be reflected somewhere in the rendered bar.
    try std.testing.expect(std.mem.indexOf(u8, s, "45") != null);
}

test "humanCount and fmtEta format cleanly" {
    var b: [16]u8 = undefined;
    try std.testing.expectEqualStrings("0 B", humanCount(&b, 0));
    try std.testing.expectEqualStrings("1.0 KiB", humanCount(&b, 1024));
    try std.testing.expectEqualStrings("1.5 MiB", humanCount(&b, 1_572_864));

    var e: [12]u8 = undefined;
    try std.testing.expectEqualStrings("--:--", fmtEta(&e, 0));
    try std.testing.expectEqualStrings("1:30", fmtEta(&e, 90));
    try std.testing.expectEqualStrings("1:02:03", fmtEta(&e, 3723));
}

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
    // Sliding-window pipeline: keep up to `win.window` WRITEs in flight. SFTP
    // processes FIFO and STATUS replies are tiny, so a single-threaded fill/drain
    // keeps the server's write path saturated with no pipe-buffer deadlock risk.
    // The window sizes itself to the bandwidth-delay product (WindowCtl, which
    // grows while ack recvs block on the network and holds once the pipe is full);
    // the SSH channel window caps in-flight data anyway.
    // One reused buf, so the window costs no extra client memory. The sidecar
    // records the byte offset of acknowledged writes.
    var win = WindowCtl.init(16, 512);
    var off = next_off;
    var in_flight: usize = 0;
    var acked_writes: u64 = if (chunk > 0) next_off / @as(u64, chunk) else 0;
    var prog = Progress.start(io, remote_path, total, opts, next_off);
    var pacer = Pacer.init(io, opts, chunk);
    while (off < total or in_flight > 0) {
        while (in_flight < win.window and off < total) {
            pacer.wait();
            const len: usize = @intCast(@min(@as(u64, chunk), total - off));
            _ = try local.readPositionalAll(io, buf[0..len], off);
            try sess.sendWriteUnacked(handle, off, buf[0..len]);
            off += len;
            in_flight += 1;
        }
        const wa0 = std.Io.Clock.now(.awake, io).nanoseconds;
        sess.awaitAnyOk() catch |err| {
            // awaitAnyOk consumed one reply (a bad status, e.g. ENOSPC) or the
            // link died. Best-effort drain the remaining outstanding replies so
            // a recoverable status failure does not desynchronize the session
            // for a caller that reuses it: the server still replies to each
            // in-flight WRITE (FIFO), so draining keeps the stream aligned.
            if (in_flight > 0) in_flight -= 1;
            while (in_flight > 0) : (in_flight -= 1) sess.awaitAnyOk() catch {};
            return err;
        };
        win.observedWait(std.Io.Clock.now(.awake, io).nanoseconds - wa0);
        in_flight -= 1;
        acked_writes += 1;
        const acked_off: u64 = @min(acked_writes * @as(u64, chunk), total);
        record(io, gpa, sidecar, .upload, total, chunk, acked_off, local_path);
        prog.step(chunk);
    }
    prog.finish();
    if (opts.preserve) {
        // atime/mtime (SFTP ACMODTIME is u32 seconds) from the local Stat's ns
        // timestamps; plus POSIX mode bits where the platform exposes them. On
        // Windows the permissions enum has no mode mapping, so mtime-only there.
        const has_mode = @hasDecl(@TypeOf(st.permissions), "toMode");
        const mtime_s: u32 = @intCast(@divTrunc(st.mtime.nanoseconds, std.time.ns_per_s));
        const atime_s: u32 = if (st.atime) |a|
            @intCast(@divTrunc(a.nanoseconds, std.time.ns_per_s))
        else
            mtime_s;
        sess.fsetstat(handle, .{
            .flags = (if (has_mode) packets.ATTR_PERMISSIONS else 0) | packets.ATTR_ACMODTIME,
            .permissions = if (has_mode) @intCast(st.permissions.toMode() & 0o7777) else 0,
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

    // Pipelined download: keep up to `win.window` READs in flight to hide RTT,
    // mirroring the upload pipeline. SFTP processes requests FIFO, so the Nth
    // DATA reply corresponds to the Nth READ; `write_off` tracks where the next
    // reply lands. OpenSSH's ssh buffers DATA internally when the stdout pipe
    // is full (flow control, not a deadlock), so a single-threaded fill/drain
    // keeps the server's read path saturated under high RTT. The window sizes
    // itself via ack-recv wait time (WindowCtl).
    const chunk = effectiveChunk(opts);
    var win = WindowCtl.init(16, 512);
    var read_off: u64 = next_off;
    var write_off: u64 = next_off;
    var in_flight: usize = 0;
    var prog = Progress.start(io, local_path, total, opts, next_off);
    var pacer = Pacer.init(io, opts, chunk);
    while (read_off < total or in_flight > 0) {
        while (in_flight < win.window and read_off < total) {
            pacer.wait();
            const want: u32 = @intCast(@min(@as(u64, chunk), total - read_off));
            try sess.sendReadUnacked(rh, read_off, want);
            read_off += want;
            in_flight += 1;
        }
        const wa0 = std.Io.Clock.now(.awake, io).nanoseconds;
        const piece = sess.recvData() catch |err| {
            // recvData consumed one reply (or the link died). Best-effort drain
            // the remaining in-flight replies so a recoverable failure does not
            // desynchronize the session for a caller that reuses it.
            if (in_flight > 0) in_flight -= 1;
            while (in_flight > 0) : (in_flight -= 1) _ = sess.recvData() catch {};
            return err;
        };
        win.observedWait(std.Io.Clock.now(.awake, io).nanoseconds - wa0);
        in_flight -= 1;
        try local.writePositionalAll(io, piece, write_off);
        // Record this chunk's MAC for integrity-checked resume.
        if (chunker.hashChunk(gpa, piece)) |mac| {
            resume_mod.appendMac(io, mac_path, mac, write_off / @as(u64, chunk)) catch {};
            gpa.free(mac);
        } else |_| {}
        write_off += piece.len;
        gpa.free(piece);
        record(io, gpa, sidecar, .download, total, chunk, write_off, remote_path);
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
    // iterate = true is required to read entries (Zig 0.16 opens dirs without
    // it in a mode that cannot be iterated; on Linux .iterate() then panics
    // with EBADF in posixSeekTo/dirReadLinux). Mac tolerates the default, so
    // this only shows up on the linux target.
    var dir = Dir.cwd().openDir(io, local_dir, .{ .iterate = true }) catch |err| {
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

/// Opens a connection for a parallel worker. The parallel engine is generic
/// over an opener: any type with `open(self, gpa, io) !Conn` where Conn has
/// `.sess` (an sftp/client Session) and `.deinit()`. The ssh backend uses
/// SshOpener (a subprocess per worker); the libssh2 backend supplies its own
/// opener that dials directly (no ssh subprocess).
pub const SshOpener = struct {
    ssh_argv: []const []const u8,
    pub fn open(self: SshOpener, gpa: std.mem.Allocator, io: std.Io) !transport.Connection {
        return transport.Connection.open(gpa, io, self.ssh_argv);
    }
};

fn ParallelCtx(comptime Opener: type) type {
    return struct {
        gpa: std.mem.Allocator,
        opts: Options,
        tasks: []const Task,
        opener: Opener,
        next: std.atomic.Value(usize),
        errors: std.atomic.Value(u32),
    };
}

/// Worker thread body: its own Threaded io + connection, pulls tasks by atomic
/// index until none remain. A per-file error is logged + counted, not fatal (the
/// remaining tasks still run on other workers).
fn parallelWorker(comptime Opener: type, ctx: *ParallelCtx(Opener)) void {
    var threaded = std.Io.Threaded.init(ctx.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = ctx.opener.open(ctx.gpa, io) catch return;
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
/// connection + session (so up to `jobs` files transfer concurrently). Tasks are
/// distributed lock-free via an atomic index. Progress bars are disabled (K
/// interleaving bars would be garbage); parallel mode is quiet.
pub fn runParallel(
    comptime Opener: type,
    gpa: std.mem.Allocator,
    opener: Opener,
    tasks: []const Task,
    opts: Options,
    jobs: u32,
) !void {
    if (tasks.len == 0) return;
    var quiet_opts = opts;
    quiet_opts.progress = false;
    var ctx: ParallelCtx(Opener) = .{
        .gpa = gpa,
        .opts = quiet_opts,
        .tasks = tasks,
        .opener = opener,
        .next = std.atomic.Value(usize).init(0),
        .errors = std.atomic.Value(u32).init(0),
    };
    const j: usize = @min(@as(usize, @intCast(jobs)), tasks.len);
    const threads = try gpa.alloc(std.Thread, j);
    defer gpa.free(threads);
    for (0..j) |i| {
        threads[i] = std.Thread.spawn(.{}, parallelWorker, .{ Opener, &ctx }) catch |err| {
            for (threads[0..i]) |t| t.join();
            return err;
        };
    }
    for (threads) |t| t.join();
    // Per-file failures are logged + counted in the workers (the remaining
    // files still transfer, matching scp's "skip and continue"). But a run with
    // any failure must surface a non-zero exit, not silently succeed.
    if (ctx.errors.load(.monotonic) != 0) return error.Failure;
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
// Resume: a `.zioscpchunks` bitmap sidecar (resume.zig) records each completed
// chunk. On a re-run, done chunks are skipped and the dest is NOT re-truncated,
// so an interrupted chunked transfer continues instead of restarting. Small
// files (<=1 chunk) fall back to the single-stream path (which has its own
// offset + MAC resume).

fn ChunkCtx(comptime Opener: type) type {
    return struct {
        gpa: std.mem.Allocator,
        opts: Options,
        local_path: []const u8,
        remote_path: []const u8,
        bitmap_path: []const u8,
        opener: Opener,
        /// Loaded completion bitmap for this transfer (read-only during the run);
        /// empty on a fresh start. Includes the 12-byte header.
        done: []const u8,
        total: u64,
        chunk: u32,
        count: u64,
        next: std.atomic.Value(usize),
        errors: std.atomic.Value(u32),
    };
}

fn uploadChunkWorker(comptime Opener: type, ctx: *ChunkCtx(Opener)) void {
    var threaded = std.Io.Threaded.init(ctx.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = ctx.opener.open(ctx.gpa, io) catch return;
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
    // Pipeline within the worker: keep up to `win.window` WRITEs in flight over
    // this connection, mirroring the single-stream upload pipeline so a chunked
    // -j transfer also hides RTT. `inflight` is the FIFO of chunk indices whose
    // STATUS replies are outstanding (each marked done in the bitmap on ack); the
    // window sizes itself via ack-recv wait time (WindowCtl).
    var win = WindowCtl.init(8, 128);
    var inflight: std.ArrayList(usize) = .empty;
    defer inflight.deinit(ctx.gpa);
    while (true) {
        while (inflight.items.len < win.window) {
            const idx = ctx.next.fetchAdd(1, .monotonic);
            if (idx >= ctx.count) break;
            if (resume_mod.chunkDone(ctx.done, idx)) continue; // already done in a prior run
            const r = chunker.chunkRange(idx, ctx.total, ctx.chunk);
            if (r.len == 0) continue;
            _ = local.readPositionalAll(io, buf[0..@intCast(r.len)], r.offset) catch {
                _ = ctx.errors.fetchAdd(1, .monotonic);
                continue;
            };
            conn.sess.sendWriteUnacked(handle, r.offset, buf[0..@intCast(r.len)]) catch {
                _ = ctx.errors.fetchAdd(1, .monotonic);
                continue;
            };
            inflight.append(ctx.gpa, idx) catch {
                _ = ctx.errors.fetchAdd(1, .monotonic);
                continue;
            };
        }
        if (inflight.items.len == 0) break;
        const wa0 = std.Io.Clock.now(.awake, io).nanoseconds;
        conn.sess.awaitAnyOk() catch {
            // Link in trouble: drain the remaining outstanding replies and stop.
            var n = inflight.items.len;
            if (n > 0) n -= 1; // awaitAnyOk already consumed one
            while (n > 0) : (n -= 1) conn.sess.awaitAnyOk() catch {};
            _ = ctx.errors.fetchAdd(@intCast(inflight.items.len), .monotonic);
            return;
        };
        win.observedWait(std.Io.Clock.now(.awake, io).nanoseconds - wa0);
        const done_idx = inflight.orderedRemove(0);
        resume_mod.markChunkDone(io, ctx.bitmap_path, done_idx) catch {};
    }
}

fn downloadChunkWorker(comptime Opener: type, ctx: *ChunkCtx(Opener)) void {
    var threaded = std.Io.Threaded.init(ctx.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn = ctx.opener.open(ctx.gpa, io) catch return;
    defer conn.deinit();
    const rh = conn.sess.open(ctx.remote_path, packets.FXF_READ, packets.Attrs.empty) catch return;
    defer {
        conn.sess.close(rh) catch {};
        ctx.gpa.free(rh);
    }
    var local = std.Io.Dir.cwd().createFile(io, ctx.local_path, .{ .truncate = false }) catch return;
    defer local.close(io);
    // Pipeline within the worker: keep up to `win.window` READs in flight,
    // mirroring the single-stream download pipeline. `inflight` is the FIFO of
    // chunk indices whose DATA replies are outstanding; each reply lands at its
    // chunkRange offset and is marked done in the bitmap. The window sizes itself
    // via ack-recv wait time (WindowCtl).
    var win = WindowCtl.init(8, 128);
    var inflight: std.ArrayList(usize) = .empty;
    defer inflight.deinit(ctx.gpa);
    while (true) {
        while (inflight.items.len < win.window) {
            const idx = ctx.next.fetchAdd(1, .monotonic);
            if (idx >= ctx.count) break;
            if (resume_mod.chunkDone(ctx.done, idx)) continue; // already done in a prior run
            const r = chunker.chunkRange(idx, ctx.total, ctx.chunk);
            if (r.len == 0) continue;
            conn.sess.sendReadUnacked(rh, r.offset, @intCast(r.len)) catch {
                _ = ctx.errors.fetchAdd(1, .monotonic);
                continue;
            };
            inflight.append(ctx.gpa, idx) catch {
                _ = ctx.errors.fetchAdd(1, .monotonic);
                continue;
            };
        }
        if (inflight.items.len == 0) break;
        const wa0 = std.Io.Clock.now(.awake, io).nanoseconds;
        const piece = conn.sess.recvData() catch {
            var n = inflight.items.len;
            while (n > 0) : (n -= 1) _ = conn.sess.recvData() catch {};
            _ = ctx.errors.fetchAdd(@intCast(inflight.items.len + 1), .monotonic);
            return;
        };
        win.observedWait(std.Io.Clock.now(.awake, io).nanoseconds - wa0);
        const idx = inflight.orderedRemove(0);
        const r = chunker.chunkRange(idx, ctx.total, ctx.chunk);
        if (piece.len == 0) {
            ctx.gpa.free(piece);
            continue;
        }
        local.writePositionalAll(io, piece, r.offset) catch {
            ctx.gpa.free(piece);
            _ = ctx.errors.fetchAdd(1, .monotonic);
            continue;
        };
        ctx.gpa.free(piece);
        resume_mod.markChunkDone(io, ctx.bitmap_path, idx) catch {};
    }
}

/// Upload a single file in parallel across `jobs` connections, sharding it at
/// offset ranges. Falls back to single-stream for files that fit in one chunk.
/// See the P3 note above on the concurrent-write protocol.
pub fn uploadFileParallel(
    comptime Opener: type,
    gpa: std.mem.Allocator,
    opener: Opener,
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
        var conn = try opener.open(gpa, io0);
        defer conn.deinit();
        try uploadFile(gpa, io0, &conn.sess, local_path, remote_path, opts);
        return;
    }

    // Resume: load any completion bitmap for this (total, chunk).
    const bitmap_path = try resume_mod.chunkBitmapPath(gpa, local_path);
    defer gpa.free(bitmap_path);
    var done: []u8 = &.{};
    var is_resume = false;
    if (opts.resume_enabled) {
        if (try resume_mod.loadChunkBitmap(io0, gpa, bitmap_path, total, chunk)) |b| {
            done = b;
            is_resume = true;
        }
    }
    defer if (done.len > 0) gpa.free(done);

    // Fresh run: truncate the remote and start a new bitmap. On resume keep the
    // partial remote and its bitmap (already loaded).
    if (!is_resume) {
        {
            var c = try opener.open(gpa, io0);
            defer c.deinit();
            const h = try c.sess.open(remote_path, packets.FXF_WRITE | packets.FXF_CREATE | packets.FXF_TRUNC, packets.Attrs.empty);
            defer {
                c.sess.close(h) catch {};
                gpa.free(h);
            }
        }
        try resume_mod.initChunkBitmap(io0, bitmap_path, total, chunk);
    }

    var ctx: ChunkCtx(Opener) = .{
        .gpa = gpa,
        .opts = opts,
        .local_path = local_path,
        .remote_path = remote_path,
        .bitmap_path = bitmap_path,
        .opener = opener,
        .done = done,
        .total = total,
        .chunk = chunk,
        .count = count,
        .next = std.atomic.Value(usize).init(0),
        .errors = std.atomic.Value(u32).init(0),
    };
    try spawnChunkWorkers(Opener, uploadChunkWorker, &ctx, jobs, count);
    if (ctx.errors.load(.monotonic) != 0) return error.Failure;
    resume_mod.removeFile(io0, bitmap_path);
}

/// Download a single file in parallel across `jobs` connections.
pub fn downloadFileParallel(
    comptime Opener: type,
    gpa: std.mem.Allocator,
    opener: Opener,
    remote_path: []const u8,
    local_path: []const u8,
    opts: Options,
    jobs: u32,
) !void {
    var t0 = std.Io.Threaded.init(gpa, .{});
    defer t0.deinit();
    const io0 = t0.io();
    var probe = try opener.open(gpa, io0);
    const total: u64 = (try probe.sess.stat(remote_path)).size;
    probe.deinit();

    const chunk = effectiveChunk(opts);
    const count = chunker.chunkCount(total, chunk);
    if (count <= 1) {
        var conn = try opener.open(gpa, io0);
        defer conn.deinit();
        try downloadFile(gpa, io0, &conn.sess, remote_path, local_path, opts);
        return;
    }

    // Resume: load any completion bitmap for this (total, chunk).
    const bitmap_path = try resume_mod.chunkBitmapPath(gpa, local_path);
    defer gpa.free(bitmap_path);
    var done: []u8 = &.{};
    var is_resume = false;
    if (opts.resume_enabled) {
        if (try resume_mod.loadChunkBitmap(io0, gpa, bitmap_path, total, chunk)) |b| {
            done = b;
            is_resume = true;
        }
    }
    defer if (done.len > 0) gpa.free(done);

    // Fresh run: create+truncate the local file and start a new bitmap. On
    // resume keep the partial local file and its bitmap (already loaded).
    if (!is_resume) {
        var f = try std.Io.Dir.cwd().createFile(io0, local_path, .{ .truncate = true });
        f.close(io0);
        try resume_mod.initChunkBitmap(io0, bitmap_path, total, chunk);
    }

    var ctx: ChunkCtx(Opener) = .{
        .gpa = gpa,
        .opts = opts,
        .local_path = local_path,
        .remote_path = remote_path,
        .bitmap_path = bitmap_path,
        .opener = opener,
        .done = done,
        .total = total,
        .chunk = chunk,
        .count = count,
        .next = std.atomic.Value(usize).init(0),
        .errors = std.atomic.Value(u32).init(0),
    };
    try spawnChunkWorkers(Opener, downloadChunkWorker, &ctx, jobs, count);
    if (ctx.errors.load(.monotonic) != 0) return error.Failure;
    resume_mod.removeFile(io0, bitmap_path);
}

fn spawnChunkWorkers(
    comptime Opener: type,
    comptime worker: anytype,
    ctx: *ChunkCtx(Opener),
    jobs: u32,
    count: u64,
) !void {
    const j: usize = @min(@as(usize, @intCast(jobs)), @as(usize, @intCast(count)));
    const threads = try ctx.gpa.alloc(std.Thread, j);
    defer ctx.gpa.free(threads);
    for (0..j) |i| {
        threads[i] = std.Thread.spawn(.{}, worker, .{ Opener, ctx }) catch |err| {
            for (threads[0..i]) |t| t.join();
            return err;
        };
    }
    for (threads) |t| t.join();
}
