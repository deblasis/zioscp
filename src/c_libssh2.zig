//! Thin FFI to libssh2, used by the (optional) self-contained backend.
//!
//! The backend uses libssh2 only for the SSH transport: it opens an SSH session,
//! authenticates with a key, opens a channel, and requests the "sftp" subsystem.
//! The channel's read/write stream IS the SFTP protocol byte stream, so zioscp's
//! own SFP codec (sftp/packets.zig) and session (sftp/client.zig) run over it
//! unchanged. We do NOT use libssh2's SFTP API.
//!
//! Only built/linked when -Dbackend=libssh2 (build.zig links -lssh2).

const std = @import("std");

pub const SESSION = opaque {};
pub const CHANNEL = opaque {};
pub const KNOWNHOSTS = opaque {};

// libssh2_socket_t: a POSIX fd (c_int) on Unix, a Windows SOCKET (usize) on
// Windows. The handshake FFI takes this; the transport extracts it from the
// std.Io socket handle per platform (see transport_libssh2.zig).
pub const SocketArg = if (@import("builtin").os.tag == .windows) usize else c_int;

// Raw libssh2 entry points. Many "plain" names in libssh2.h are macros that
// map to these `_ex` symbols with extra length/stream-id params, so the extern
// declarations target the real `_ex` symbols. Negative returns are errors.
extern "c" fn libssh2_init(flags: c_int) c_int;
extern "c" fn libssh2_exit() void;
extern "c" fn libssh2_session_init_ex(
    alloc: ?*anyopaque,
    free: ?*anyopaque,
    realloc: ?*anyopaque,
    abstract: ?*anyopaque,
) ?*SESSION;
extern "c" fn libssh2_session_set_blocking(session: *SESSION, blocking: c_int) void;
extern "c" fn libssh2_session_set_timeout(session: *SESSION, timeout: c_long) void;
extern "c" fn libssh2_session_handshake(session: *SESSION, socket: SocketArg) c_int;
extern "c" fn libssh2_userauth_publickey_fromfile_ex(
    session: *SESSION,
    username: [*:0]const u8,
    username_len: c_uint,
    publickeypath: [*:0]const u8,
    privatekeypath: [*:0]const u8,
    passphrase: ?[*:0]const u8,
) c_int;
extern "c" fn libssh2_channel_open_ex(
    session: *SESSION,
    channel_type: [*:0]const u8,
    channel_type_len: c_uint,
    window: c_uint,
    packet: c_uint,
    message: ?[*:0]const u8,
    message_len: c_uint,
) ?*CHANNEL;
extern "c" fn libssh2_channel_process_startup(
    channel: *CHANNEL,
    request: [*:0]const u8,
    request_len: c_uint,
    message: [*:0]const u8,
    message_len: c_uint,
) c_int;
extern "c" fn libssh2_channel_read_ex(channel: *CHANNEL, stream_id: c_int, buf: [*]u8, bufsize: usize) isize;
extern "c" fn libssh2_channel_write_ex(channel: *CHANNEL, stream_id: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn libssh2_channel_close(channel: *CHANNEL) c_int;
extern "c" fn libssh2_channel_free(channel: *CHANNEL) c_int;
extern "c" fn libssh2_session_disconnect_ex(
    session: *SESSION,
    reason: c_int,
    description: [*:0]const u8,
    lang: [*:0]const u8,
) c_int;
extern "c" fn libssh2_session_free(session: *SESSION) c_int;
extern "c" fn libssh2_session_last_error(
    session: *SESSION,
    errmsg: *[*c]const u8,
    errmsg_len: *c_int,
    want_buf: c_int,
) c_int;
extern "c" fn libssh2_session_hostkey(session: *SESSION, len: *usize, key_type: *c_int) ?[*]const u8;
extern "c" fn libssh2_knownhost_init(session: *SESSION) ?*KNOWNHOSTS;
extern "c" fn libssh2_knownhost_readfile(hosts: *KNOWNHOSTS, filename: [*:0]const u8, file_type: c_int) c_int;
extern "c" fn libssh2_knownhost_checkp(
    hosts: *KNOWNHOSTS,
    host: [*:0]const u8,
    port: c_int,
    key: [*]const u8,
    key_len: usize,
    type_mask: c_int,
    out: ?*?*anyopaque,
) c_int;
extern "c" fn libssh2_knownhost_free(hosts: *KNOWNHOSTS) void;

// known_hosts constants (libssh2.h).
const kh_type_plain: c_int = 1;
const kh_keyenc_raw: c_int = 1 << 16;
const kh_file_openssh: c_int = 1;
const kh_check_match: c_int = 0;
const kh_check_mismatch: c_int = 1;
const kh_check_notfound: c_int = 2;

/// Map a LIBSSH2_HOSTKEY_TYPE_* to the LIBSSH2_KNOWNHOST_KEY_* typemask bits.
fn hostKeyFlag(t: c_int) c_int {
    return switch (t) {
        1 => 2 << 18, // RSA -> KEY_SSHRSA
        2 => 3 << 18, // DSS -> KEY_SSHDSS
        3 => 4 << 18, // ECDSA_256
        4 => 5 << 18, // ECDSA_384
        5 => 6 << 18, // ECDSA_521
        6 => 7 << 18, // ED25519
        else => 15 << 18, // KEY_UNKNOWN
    };
}

pub const HostCheck = enum { match, mismatch, notfound, fail };

/// Check the session's server host key against an OpenSSH known_hosts file.
/// FAITHFULNESS NOTE: this covers plain + hashed hostname entries and the
/// common key types. ssh's known_hosts also supports @cert-authority, key
/// revocation, CheckHostIP, and hostname canonicalization, which libssh2's
/// known_hosts API does not -- those edge cases are not verified here.
pub fn checkHost(session: *SESSION, host: [:0]const u8, port: u16, known_hosts_path: [:0]const u8) HostCheck {
    var key_len: usize = 0;
    var key_type: c_int = 0;
    const key = libssh2_session_hostkey(session, &key_len, &key_type) orelse return .fail;
    const kh = libssh2_knownhost_init(session) orelse return .fail;
    defer libssh2_knownhost_free(kh);
    // A missing/unreadable known_hosts file -> treat as no known hosts (notfound).
    _ = libssh2_knownhost_readfile(kh, known_hosts_path.ptr, kh_file_openssh);
    const typemask: c_int = kh_type_plain | kh_keyenc_raw | hostKeyFlag(key_type);
    const r = libssh2_knownhost_checkp(kh, host.ptr, port, key, key_len, typemask, null);
    return switch (r) {
        kh_check_match => .match,
        kh_check_mismatch => .mismatch,
        kh_check_notfound => .notfound,
        else => .fail,
    };
}

/// Last error message recorded on the session (internal pointer; do not free).
pub fn lastError(session: *SESSION) []const u8 {
    var msg: [*c]const u8 = undefined;
    var len: c_int = 0;
    _ = libssh2_session_last_error(session, &msg, &len, 0);
    return std.mem.span(msg);
}

// libssh2.h defaults for channel open (window/packet); mirrored here.
const window_default: c_uint = 2 * 1024 * 1024;
const packet_default: c_uint = 32 * 1024;

pub const Error = error{
    InitFailed,
    SessionInitFailed,
    HandshakeFailed,
    AuthFailed,
    ChannelFailed,
    SubsystemFailed,
};

/// Global libssh2 init. Idempotent to call; safe to invoke per connection.
pub fn init() Error!void {
    if (libssh2_init(0) != 0) return error.InitFailed;
}

pub fn deinit() void {
    libssh2_exit();
}

pub fn newSession() Error!*SESSION {
    return libssh2_session_init_ex(null, null, null, null) orelse error.SessionInitFailed;
}

pub fn handshake(session: *SESSION, fd: SocketArg) Error!void {
    if (libssh2_session_handshake(session, fd) != 0) return error.HandshakeFailed;
}

pub fn sessionSetBlocking(session: *SESSION, blocking: c_int) void {
    libssh2_session_set_blocking(session, blocking);
}

/// Per blocking-call timeout (ms). A blocking libssh2 call (handshake/auth/
/// channel/data) that does not complete within this returns an error, so a
/// stalled or unreachable server fails fast instead of hanging forever.
pub fn sessionSetTimeout(session: *SESSION, ms: c_long) void {
    libssh2_session_set_timeout(session, ms);
}

pub fn authKey(session: *SESSION, user: [:0]const u8, pub_key: [:0]const u8, priv_key: [:0]const u8) Error!void {
    // passphrase = null (unencrypted keys)
    if (libssh2_userauth_publickey_fromfile_ex(session, user.ptr, @intCast(user.len), pub_key.ptr, priv_key.ptr, null) != 0)
        return error.AuthFailed;
}

pub fn openSubsystem(session: *SESSION, name: [:0]const u8) Error!*CHANNEL {
    const ch = libssh2_channel_open_ex(session, "session", 7, window_default, packet_default, null, 0) orelse return error.ChannelFailed;
    if (libssh2_channel_process_startup(ch, "subsystem", 9, name.ptr, @intCast(name.len)) != 0) {
        _ = libssh2_channel_free(ch);
        return error.SubsystemFailed;
    }
    return ch;
}

/// Blocking read into `buf`; returns bytes read (0 = EOF/channel closed).
pub fn read(channel: *CHANNEL, buf: []u8) isize {
    return libssh2_channel_read_ex(channel, 0, buf.ptr, buf.len);
}

/// Blocking write of `buf`; returns bytes written.
pub fn write(channel: *CHANNEL, buf: []const u8) isize {
    return libssh2_channel_write_ex(channel, 0, buf.ptr, buf.len);
}

pub fn close(channel: *CHANNEL) void {
    _ = libssh2_channel_close(channel);
    _ = libssh2_channel_free(channel);
}

pub fn disconnect(session: *SESSION) void {
    // reason 11 = SSH_DISCONNECT_BY_APPLICATION (RFC 4253)
    _ = libssh2_session_disconnect_ex(session, 11, "zioscp done", "");
    _ = libssh2_session_free(session);
}
