//! Subprocess duplex transport: drives a conversational subprocess (the
//! `ssh host sftp-server` pipe) and satisfies the Session `Duplex` contract
//! (writeAll / readExact).
//!
//! Hazard handling (per an adversarial design review):
//!   * STDERR DEADLOCK - ssh writes banners/auth warnings to stderr. An
//!     unpumped stderr pipe fills (~16-64 KB) and ssh blocks while we block
//!     on stdout readExact, deadlocking both sides. A drain task runs
//!     concurrently (Io.Group.concurrent over a Threaded io) for the life of
//!     the connection.
//!   * ZOMBIES - deinit kills and reaps the child on every path (incl. error).
//!   * BROKEN PIPE - writes that hit a dead ssh surface as an Io error and are
//!     mapped to IoClosed; the stdio Io layer converts SIGPIPE to an error
//!     rather than killing the process.
//!   * NO LOST READS - readExact uses File.readStreaming directly (no retained
//!     internal buffer), so a short read never drops bytes between frames.
//!
//! DuplexProcess is self-referential once the drain task starts (it holds a
//! pointer to the process). So it must live at a stable address: heap-allocated
//! via Connection.open (real use), or a local var in tests.

const std = @import("std");
const client = @import("sftp/client.zig");

const Error = client.Error;

pub const DuplexProcess = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    stdin_file: std.Io.File,
    stdout_file: std.Io.File,
    stderr_file: std.Io.File,
    stderr_buf: std.ArrayList(u8),
    group: std.Io.Group,

    /// Spawn `argv` with piped stdin/stdout/stderr. Does NOT start the stderr
    /// drain yet; call startDrain once this value is at its final (stable)
    /// address. Safe to return by value between spawn and startDrain.
    pub fn spawn(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) Error!DuplexProcess {
        var child = std.process.spawn(io, .{
            .argv = argv,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        }) catch return error.IoClosed;

        const stdin_file = child.stdin orelse return error.IoClosed;
        const stdout_file = child.stdout orelse return error.IoClosed;
        const stderr_file = child.stderr orelse return error.IoClosed;
        child.stdin = null;
        child.stdout = null;
        child.stderr = null;

        return .{
            .gpa = gpa,
            .io = io,
            .child = child,
            .stdin_file = stdin_file,
            .stdout_file = stdout_file,
            .stderr_file = stderr_file,
            .stderr_buf = .empty,
            .group = .init,
        };
    }

    /// Start the stderr drain task. Requires a Threaded io (concurrent).
    pub fn startDrain(self: *DuplexProcess) Error!void {
        self.group.concurrent(self.io, drainStderr, .{self}) catch return error.IoClosed;
    }

    pub fn writeAll(self: *DuplexProcess, bytes: []const u8) Error!void {
        var buf: [8192]u8 = undefined;
        var fw = self.stdin_file.writer(self.io, &buf);
        const w = &fw.interface;
        w.writeAll(bytes) catch return error.IoClosed;
        w.flush() catch return error.IoClosed;
    }

    pub fn readExact(self: *DuplexProcess, out: []u8) Error!void {
        var filled: usize = 0;
        while (filled < out.len) {
            const n = self.stdout_file.readStreaming(self.io, &.{out[filled..]}) catch return error.IoClosed;
            if (n == 0) return error.IoClosed; // EOF / nothing more
            filled += n;
        }
    }

    /// Kill and reap the child (kill reaps in 0.16, setting id null), await the
    /// drain task, close pipes, free stderr. Safe on every path incl. error.
    pub fn deinit(self: *DuplexProcess) void {
        self.child.kill(self.io);
        self.group.await(self.io) catch {};
        self.stdin_file.close(self.io);
        self.stdout_file.close(self.io);
        self.stderr_file.close(self.io);
        self.stderr_buf.deinit(self.gpa);
    }
};

/// Background drain of the child's stderr into `stderr_buf`, so a chatty ssh
/// cannot fill the pipe and deadlock stdout. Runs until EOF (child gone).
fn drainStderr(self: *DuplexProcess) void {
    var internal: [4096]u8 = undefined;
    var fr = self.stderr_file.reader(self.io, &internal);
    const r = &fr.interface;
    while (true) {
        var out: [4096]u8 = undefined;
        const n = r.readSliceShort(&out) catch break;
        if (n == 0) break; // EOF
        self.stderr_buf.appendSlice(self.gpa, out[0..n]) catch break;
    }
}

/// Owns a heap-allocated DuplexProcess and the Session over it. The caller
/// stores this by value and deinit()s it; the process lives on the heap so the
/// drain task's pointer stays valid.
pub const Connection = struct {
    gpa: std.mem.Allocator,
    proc: *DuplexProcess,
    sess: client.Session(DuplexProcess),

    pub fn open(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) Error!Connection {
        const proc = gpa.create(DuplexProcess) catch return error.OutOfMemory;
        errdefer gpa.destroy(proc);
        proc.* = try DuplexProcess.spawn(gpa, io, argv);
        errdefer proc.deinit();
        try proc.startDrain();
        var sess = client.Session(DuplexProcess).init(gpa, proc);
        _ = try sess.handshake();
        return .{ .gpa = gpa, .proc = proc, .sess = sess };
    }

    pub fn deinit(self: *Connection) void {
        self.proc.deinit();
        self.gpa.destroy(self.proc);
    }

    /// ssh/stderr output captured by the drain (banners, diagnostics).
    pub fn stderr(self: *Connection) []const u8 {
        return self.proc.stderr_buf.items;
    }
};

// ---------------------------------------------------------------------------
// Tests (real subprocesses; no ssh, no Docker)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "DuplexProcess: writeAll then readExact round-trips through cat" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var proc = try DuplexProcess.spawn(testing.allocator, io, &.{"cat"});
    try proc.startDrain();
    defer proc.deinit();

    // 16 KiB exceeds a typical block buffer, so cat flushes promptly and the
    // streaming read loop is exercised across several short reads.
    const n: usize = 16 * 1024;
    const sent = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(sent);
    for (sent, 0..) |*b, i| b.* = @intCast(i % 251);

    try proc.writeAll(sent);
    const got = testing.allocator.alloc(u8, n) catch return error.OutOfMemory;
    defer testing.allocator.free(got);
    try proc.readExact(got);
    try testing.expectEqualSlices(u8, sent, got);
}

test "DuplexProcess: large stderr does not deadlock stdout (drain works)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Writes ~200 KB to stderr (well past the ~64 KB pipe buffer), THEN a
    // 7-byte marker to stdout. Without the concurrent stderr drain, the
    // subprocess would block filling stderr before it ever reached the echo,
    // and readExact would hang forever.
    var proc = try DuplexProcess.spawn(testing.allocator, io, &.{
        "sh", "-c", "yes ERRORTAG | head -c 200000 >&2; printf OUTOK",
    });
    try proc.startDrain();
    defer proc.deinit();

    var out: [5]u8 = undefined; // "OUTOK"
    try proc.readExact(&out);
    try testing.expectEqualSlices(u8, "OUTOK", &out);
    // The drain captured the bulk of the stderr output.
    try testing.expect(proc.stderr_buf.items.len >= 100_000);
}
