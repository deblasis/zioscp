//! Self-contained transport backed by libssh2 (no ssh subprocess).
//!
//! libssh2 provides the SSH session and a channel to the "sftp" subsystem; the
//! channel's byte stream IS the SFTP protocol, so the existing sftp/packets.zig
//! + sftp/client.zig run over it unchanged via Session(DuplexLibssh2). Only
//! built/linked under -Dbackend=libssh2.
//!
//! The TCP socket is created with std.Io.net (which resolves + connects) and
//! its raw fd handed to libssh2; libssh2 does its own blocking I/O on it. The
//! engine's `io` is otherwise orthogonal (local file ops, not network I/O).

const std = @import("std");
const client = @import("sftp/client.zig");
const libssh2 = @import("c_libssh2.zig");
const engine = @import("engine.zig");

const Error = client.Error;

fn mapLe(err: libssh2.Error) Error {
    return switch (err) {
        error.AuthFailed => error.PermissionDenied,
        else => error.IoClosed,
    };
}

/// Resolve + connect a TCP socket, returning the raw fd for libssh2 and the
/// stream (for closing later). Tries an IP literal first, then DNS.
fn dial(io: std.Io, host: []const u8, port: u16) Error!std.Io.net.Stream {
    if (std.Io.net.IpAddress.resolve(io, host, port)) |addr| {
        var a = addr;
        return a.connect(io, .{ .mode = .stream }) catch return error.IoClosed;
    } else |_| {}
    const hn = std.Io.net.HostName.init(host) catch return error.IoClosed;
    return hn.connect(io, port, .{ .mode = .stream }) catch return error.IoClosed;
}

pub const DuplexLibssh2 = struct {
    io: std.Io,
    session: *libssh2.SESSION,
    channel: *libssh2.CHANNEL,
    stream: std.Io.net.Stream,

    /// Write all bytes (blocking loop). Any libssh2 failure -> IoClosed.
    pub fn writeAll(self: *DuplexLibssh2, bytes: []const u8) Error!void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = libssh2.write(self.channel, bytes[off..]);
            if (n <= 0) return error.IoClosed;
            off += @intCast(n);
        }
    }

    /// Fill `out` exactly (blocking loop). EOF or error -> IoClosed.
    pub fn readExact(self: *DuplexLibssh2, out: []u8) Error!void {
        var filled: usize = 0;
        while (filled < out.len) {
            const n = libssh2.read(self.channel, out[filled..]);
            if (n <= 0) return error.IoClosed;
            filled += @intCast(n);
        }
    }

    pub fn deinit(self: *DuplexLibssh2) void {
        libssh2.close(self.channel);
        libssh2.disconnect(self.session);
        self.stream.close(self.io);
    }
};

/// Owns a heap-allocated DuplexLibssh2 (stable address for the Session) and the
/// Session over it. Mirrors transport.Connection.
pub const Connection = struct {
    gpa: std.mem.Allocator,
    dup: *DuplexLibssh2,
    sess: client.Session(DuplexLibssh2),

    /// `key_path` is the private key; the public key is assumed alongside as
    /// `<key_path>.pub` (matching ssh-keygen / scp -i convention). `mode`
    /// controls server host-key verification against `known_hosts_path` (an
    /// OpenSSH known_hosts file); strict is the scp/BatchMode default.
    pub fn open(
        gpa: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        user: []const u8,
        key_path: []const u8,
        mode: engine.HostKeyCheck,
        known_hosts_path: []const u8,
    ) Error!Connection {
        libssh2.init() catch return error.IoClosed;
        errdefer libssh2.deinit();

        const stream = dial(io, host, port) catch return error.IoClosed;
        errdefer stream.close(io);
        const fd: c_int = @intCast(stream.socket.handle);

        const session = libssh2.newSession() catch return error.IoClosed;
        errdefer libssh2.disconnect(session);
        libssh2.sessionSetBlocking(session, 1);

        libssh2.handshake(session, fd) catch return error.IoClosed;

        // Verify the server host key against the OpenSSH known_hosts file,
        // scp/BatchMode-faithful: strict refuses unknown and changed keys.
        if (mode != .no) {
            const z_host = std.heap.page_allocator.dupeZ(u8, host) catch return error.OutOfMemory;
            defer std.heap.page_allocator.free(z_host);
            const z_kh = std.heap.page_allocator.dupeZ(u8, known_hosts_path) catch return error.OutOfMemory;
            defer std.heap.page_allocator.free(z_kh);
            switch (libssh2.checkHost(session, z_host, port, z_kh)) {
                .match => {},
                .mismatch => return error.HostKeyRefused, // changed key: refuse (MITM protection)
                .notfound => if (mode == .strict) return error.HostKeyRefused,
                .fail => return error.IoClosed,
            }
        }

        // Key auth: z-terminate user, private key, and "<key>.pub".
        const z_user = std.heap.page_allocator.dupeZ(u8, user) catch return error.OutOfMemory;
        defer std.heap.page_allocator.free(z_user);
        const z_priv = std.heap.page_allocator.dupeZ(u8, key_path) catch return error.OutOfMemory;
        defer std.heap.page_allocator.free(z_priv);
        var pub_buf: [4096]u8 = undefined;
        const pub_path = std.fmt.bufPrint(&pub_buf, "{s}.pub", .{key_path}) catch return error.OutOfMemory;
        const z_pub = std.heap.page_allocator.dupeZ(u8, pub_path) catch return error.OutOfMemory;
        defer std.heap.page_allocator.free(z_pub);
        libssh2.authKey(session, z_user, z_pub, z_priv) catch |err| return mapLe(err);

        const channel = libssh2.openSubsystem(session, "sftp") catch |err| return mapLe(err);
        errdefer libssh2.close(channel);

        const dup = gpa.create(DuplexLibssh2) catch return error.OutOfMemory;
        dup.* = .{ .io = io, .session = session, .channel = channel, .stream = stream };
        var sess = client.Session(DuplexLibssh2).init(gpa, dup);
        _ = sess.handshake() catch {
            dup.deinit();
            gpa.destroy(dup);
            return error.IoClosed;
        };
        return .{ .gpa = gpa, .dup = dup, .sess = sess };
    }

    pub fn deinit(self: *Connection) void {
        self.dup.deinit();
        self.gpa.destroy(self.dup);
    }
};
