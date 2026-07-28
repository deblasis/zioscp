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
const builtin = @import("builtin");
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

/// The OS socket libssh2 reads/writes on, plus how to close it. On POSIX this
/// is a std.Io.net.Stream (a real fd); on Windows it is a raw winsock SOCKET —
/// see `winsock` below for why std.Io.net can't be used there.
const Link = if (builtin.os.tag == .windows) usize else std.Io.net.Stream;

/// The raw OS socket value libssh2 wants (SOCKET/usize on Windows, fd on POSIX).
fn linkArg(link: Link) libssh2.SocketArg {
    return if (builtin.os.tag == .windows)
        link
    else
        @intCast(link.socket.handle);
}

fn linkClose(link: Link, io: std.Io) void {
    if (builtin.os.tag == .windows) {
        _ = winsock.closesocket(link);
    } else {
        link.close(io);
    }
}

/// On Windows, std.Io.net opens a raw `\Device\Afd\Endpoint` handle via
/// NtCreateFile and does all I/O through `IOCTL AFD.*` (the libuv/Node model).
/// libssh2 calls winsock `send()`/`recv()`, which only work on a genuine
/// `socket()`-created SOCKET — so we must build one ourselves (blocking, like a
/// normal client) and hand it to libssh2. Resolution uses winsock `getaddrinfo`
/// so DNS + literals both work, scp/ssh-faithful.
const winsock = if (builtin.os.tag == .windows) struct {
    const ws2 = std.os.windows.ws2_32;

    extern "ws2_32" fn WSAStartup(wVersionRequested: u16, lpWSAData: *WSAData) i32;
    extern "ws2_32" fn socket(af: i32, typ: i32, protocol: i32) usize;
    extern "ws2_32" fn connect(s: usize, name: *const ws2.sockaddr, namelen: i32) i32;
    extern "ws2_32" fn closesocket(s: usize) i32;
    extern "ws2_32" fn getaddrinfo(
        node: [*:0]const u8,
        service: [*:0]const u8,
        hints: ?*const AddrInfo,
        result: *?*AddrInfo,
    ) i32;
    extern "ws2_32" fn freeaddrinfo(ai: *AddrInfo) void;

    const INVALID_SOCKET: usize = ~@as(usize, 0);
    const AF_UNSPEC: i32 = 0;
    const SOCK_STREAM: i32 = 1;
    const WSAData = extern struct {
        wVersion: u16,
        wHighVersion: u16,
        iMaxSockets: u16,
        iMaxUdpDg: u16,
        lpVendorInfo: ?[*:0]u8,
        szDescription: [257]u8,
        szSystemStatus: [129]u8,
    };
    const AddrInfo = extern struct {
        flags: i32,
        family: i32,
        socktype: i32,
        protocol: i32,
        addrlen: usize,
        canonname: ?[*:0]u8,
        addr: ?*ws2.sockaddr,
        next: ?*AddrInfo,
    };

    var started = false;
    fn ensureStarted() void {
        if (started) return;
        var data: WSAData = undefined;
        _ = WSAStartup(0x0202, &data); // request WinSock 2.2
        started = true;
    }

    /// Resolve + connect a blocking stream socket (first working addr wins).
    fn dial(host: []const u8, port: u16) !usize {
        ensureStarted();
        var port_buf: [16]u8 = undefined;
        const port_z = std.fmt.bufPrintZ(&port_buf, "{d}", .{port}) catch return error.BadPort;
        var host_buf: [256]u8 = undefined;
        if (host.len >= host_buf.len) return error.NameTooLong;
        @memcpy(host_buf[0..host.len], host);
        host_buf[host.len] = 0;
        const host_z: [*:0]const u8 = @ptrCast(&host_buf);

        var hints: AddrInfo = std.mem.zeroes(AddrInfo);
        hints.family = AF_UNSPEC;
        hints.socktype = SOCK_STREAM;
        var res: ?*AddrInfo = null;
        if (getaddrinfo(host_z, port_z, &hints, &res) != 0) return error.ResolveFailed;
        defer if (res) |r| freeaddrinfo(r);

        var it = res;
        while (it) |ai| : (it = ai.next) {
            const s = socket(ai.family, ai.socktype, ai.protocol);
            if (s == INVALID_SOCKET) continue;
            const addr = ai.addr orelse continue;
            // Fresh winsock sockets are blocking; connect() returns 0 once
            // established (or falls through to try the next addr on failure).
            if (connect(s, addr, @intCast(ai.addrlen)) == 0) return s;
            _ = closesocket(s);
        }
        return error.ConnectFailed;
    }
} else struct {};

/// Resolve + connect a TCP socket for libssh2, returning the OS-native socket.
/// POSIX uses std.Io.net (IP literal first, then DNS); Windows uses raw winsock.
fn dial(io: std.Io, host: []const u8, port: u16) Error!Link {
    if (builtin.os.tag == .windows) {
        return winsock.dial(host, port) catch return error.IoClosed;
    }
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
    link: Link,

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
        linkClose(self.link, self.io);
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

        const link = dial(io, host, port) catch return error.IoClosed;
        errdefer linkClose(link, io);
        // libssh2 takes the raw OS socket: an fd (c_int) on POSIX, a SOCKET
        // (usize) on Windows. POSIX gets it from std.Io.net's stream; Windows
        // gets a genuine winsock SOCKET (dial builds one directly — std.Io.net's
        // AFD handle is unusable by libssh2's winsock send/recv).
        const sock: libssh2.SocketArg = linkArg(link);

        const session = libssh2.newSession() catch return error.IoClosed;
        errdefer libssh2.disconnect(session);
        libssh2.sessionSetBlocking(session, 1);

        libssh2.handshake(session, sock) catch return error.IoClosed;

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
        dup.* = .{ .io = io, .session = session, .channel = channel, .link = link };
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

/// libssh2 connection opener for the parallel engine (mirrors engine.SshOpener):
/// each parallel worker dials its own libssh2 connection directly (no subprocess).
/// The parallel engine is generic over any opener whose `open` returns a type
/// with `.sess` + `.deinit()`; this supplies the libssh2 one.
pub const Opener = struct {
    host: []const u8,
    port: u16,
    user: []const u8,
    key: []const u8,
    mode: engine.HostKeyCheck,
    known_hosts: []const u8,

    pub fn open(self: Opener, gpa: std.mem.Allocator, io: std.Io) Error!Connection {
        return Connection.open(gpa, io, self.host, self.port, self.user, self.key, self.mode, self.known_hosts);
    }
};
