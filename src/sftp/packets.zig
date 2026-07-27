//! SFTP v3 packet codec (draft-ietf-secsh-filexfer-02).
//!
//! Frames are length-prefixed:
//!
//!     uint32  length   (counts type + id + payload, never itself)
//!     uint8   type
//!     uint32  id       (omitted only by INIT and VERSION)
//!     bytes   payload
//!
//! All integers are big-endian. The encoder writes to a `std.Io.Writer`
//! using only `writeByte`/`writeAll` (no endianness-API guesswork); the
//! decoder is a cursor over a borrowed frame slice.
//!
//! P1 covers the message types needed for upload, download, recursive
//! directory transfer, stat, and resume: OPEN, CLOSE, READ, WRITE, STAT,
//! FSTAT, FSETSTAT, OPENDIR, READDIR, MKDIR, REMOVE, RENAME, LSTAT,
//! REALPATH, plus the INIT/VERSION handshake and the STATUS/HANDLE/DATA/
//! NAME/ATTRS responses.

const std = @import("std");

// ---------------------------------------------------------------------------
// Message types, status codes, attribute and open-flag bits
// ---------------------------------------------------------------------------

pub const Type = enum(u8) {
    init = 1,
    version = 2,
    open = 3,
    close = 4,
    read = 5,
    write = 6,
    lstat = 7,
    fstat = 8,
    setstat = 9,
    fsetstat = 10,
    opendir = 11,
    readdir = 12,
    remove = 13,
    mkdir = 14,
    rmdir = 15,
    realpath = 16,
    stat = 17,
    rename = 18,
    readlink = 19,
    symlink = 20,
    status = 101,
    handle = 102,
    data = 103,
    name = 104,
    attrs = 105,
    _,
};

/// `true` for INIT and VERSION, the only packets without a request id.
pub fn typeHasId(t: Type) bool {
    return switch (t) {
        .init, .version => false,
        else => true,
    };
}

pub const StatusCode = enum(u32) {
    ok = 0,
    eof = 1,
    no_such_file = 2,
    permission_denied = 3,
    failure = 4,
    bad_message = 5,
    no_connection = 6,
    connection_lost = 7,
    op_unsupported = 8,
    _,
};

// SSH_FILEXFER_ATTR_* bits.
pub const ATTR_SIZE: u32 = 0x00000001;
pub const ATTR_UIDGID: u32 = 0x00000002;
pub const ATTR_PERMISSIONS: u32 = 0x00000004;
pub const ATTR_ACMODTIME: u32 = 0x00000008;

pub const Attrs = struct {
    flags: u32 = 0,
    size: u64 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    permissions: u32 = 0,
    atime: u32 = 0,
    mtime: u32 = 0,

    pub const empty: Attrs = .{ .flags = 0 };
};

fn attrsWireLen(a: Attrs) usize {
    var n: usize = 4; // flags
    if (a.flags & ATTR_SIZE != 0) n += 8;
    if (a.flags & ATTR_UIDGID != 0) n += 8;
    if (a.flags & ATTR_PERMISSIONS != 0) n += 4;
    if (a.flags & ATTR_ACMODTIME != 0) n += 8;
    return n;
}

// SSH_FXF_* open flags, exposed as raw bits so callers compose them.
pub const FXF_READ: u32 = 0x00000001;
pub const FXF_WRITE: u32 = 0x00000002;
pub const FXF_APPEND: u32 = 0x00000004;
pub const FXF_CREATE: u32 = 0x00000008;
pub const FXF_TRUNC: u32 = 0x00000010;
pub const FXF_EXCL: u32 = 0x00000020;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub const Error = error{
    ShortPacket,
    BadString,
    Overflow,
};

// ---------------------------------------------------------------------------
// Encode (big-endian, writeByte-only primitives)
// ---------------------------------------------------------------------------

fn writeU32Be(w: *std.Io.Writer, v: u32) std.Io.Writer.Error!void {
    try w.writeByte(@intCast((v >> 24) & 0xff));
    try w.writeByte(@intCast((v >> 16) & 0xff));
    try w.writeByte(@intCast((v >> 8) & 0xff));
    try w.writeByte(@intCast(v & 0xff));
}

fn writeU64Be(w: *std.Io.Writer, v: u64) std.Io.Writer.Error!void {
    try writeU32Be(w, @intCast((v >> 32) & 0xffffffff));
    try writeU32Be(w, @intCast(v & 0xffffffff));
}

fn writeString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try writeU32Be(w, @intCast(s.len));
    try w.writeAll(s);
}

fn stringLen(s: []const u8) usize {
    return 4 + s.len;
}

fn writeAttrs(w: *std.Io.Writer, a: Attrs) std.Io.Writer.Error!void {
    try writeU32Be(w, a.flags);
    if (a.flags & ATTR_SIZE != 0) try writeU64Be(w, a.size);
    if (a.flags & ATTR_UIDGID != 0) {
        try writeU32Be(w, a.uid);
        try writeU32Be(w, a.gid);
    }
    if (a.flags & ATTR_PERMISSIONS != 0) try writeU32Be(w, a.permissions);
    if (a.flags & ATTR_ACMODTIME != 0) {
        try writeU32Be(w, a.atime);
        try writeU32Be(w, a.mtime);
    }
}

/// Write the length prefix, type, and (if applicable) request id. The
/// caller has already computed `body_len` and writes the body next.
fn writeFrameHeader(
    w: *std.Io.Writer,
    t: Type,
    id: u32,
    body_len: usize,
) std.Io.Writer.Error!void {
    const total: u32 = if (typeHasId(t))
        @intCast(1 + 4 + body_len)
    else
        @intCast(1 + body_len);
    try writeU32Be(w, total);
    try w.writeByte(@intFromEnum(t));
    if (typeHasId(t)) try writeU32Be(w, id);
}

// --- Handshake (no id) ---

pub fn encodeInit(w: *std.Io.Writer, version: u32) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .init, 0, 4);
    try writeU32Be(w, version);
}

pub fn encodeVersion(w: *std.Io.Writer, version: u32) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .version, 0, 4);
    try writeU32Be(w, version);
}

// --- File requests ---

pub fn encodeOpen(
    w: *std.Io.Writer,
    id: u32,
    path: []const u8,
    pflags: u32,
    attrs: Attrs,
) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .open, id, stringLen(path) + 4 + attrsWireLen(attrs));
    try writeString(w, path);
    try writeU32Be(w, pflags);
    try writeAttrs(w, attrs);
}

pub fn encodeClose(w: *std.Io.Writer, id: u32, handle: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .close, id, stringLen(handle));
    try writeString(w, handle);
}

pub fn encodeRead(
    w: *std.Io.Writer,
    id: u32,
    handle: []const u8,
    offset: u64,
    length: u32,
) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .read, id, stringLen(handle) + 8 + 4);
    try writeString(w, handle);
    try writeU64Be(w, offset);
    try writeU32Be(w, length);
}

pub fn encodeWrite(
    w: *std.Io.Writer,
    id: u32,
    handle: []const u8,
    offset: u64,
    data: []const u8,
) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .write, id, stringLen(handle) + 8 + 4 + data.len);
    try writeString(w, handle);
    try writeU64Be(w, offset);
    // length of the data field, then the bytes
    try writeU32Be(w, @intCast(data.len));
    try w.writeAll(data);
}

/// WRITE framing + header ONLY (length, type, id, handle, offset, data_len),
/// without the data bytes. Lets a caller write the header from a small stack
/// buffer and stream `data` directly to the wire, avoiding a per-write
/// allocation/copy of the payload on the hot upload path.
pub fn encodeWriteHeader(
    w: *std.Io.Writer,
    id: u32,
    handle: []const u8,
    offset: u64,
    data_len: usize,
) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .write, id, stringLen(handle) + 8 + 4 + data_len);
    try writeString(w, handle);
    try writeU64Be(w, offset);
    try writeU32Be(w, @intCast(data_len));
}

pub fn encodeStat(w: *std.Io.Writer, id: u32, path: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .stat, id, stringLen(path));
    try writeString(w, path);
}

pub fn encodeLstat(w: *std.Io.Writer, id: u32, path: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .lstat, id, stringLen(path));
    try writeString(w, path);
}

pub fn encodeFstat(w: *std.Io.Writer, id: u32, handle: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .fstat, id, stringLen(handle));
    try writeString(w, handle);
}

pub fn encodeFsetstat(
    w: *std.Io.Writer,
    id: u32,
    handle: []const u8,
    attrs: Attrs,
) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .fsetstat, id, stringLen(handle) + attrsWireLen(attrs));
    try writeString(w, handle);
    try writeAttrs(w, attrs);
}

pub fn encodeOpendir(w: *std.Io.Writer, id: u32, path: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .opendir, id, stringLen(path));
    try writeString(w, path);
}

pub fn encodeReaddir(w: *std.Io.Writer, id: u32, handle: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .readdir, id, stringLen(handle));
    try writeString(w, handle);
}

pub fn encodeMkdir(
    w: *std.Io.Writer,
    id: u32,
    path: []const u8,
    attrs: Attrs,
) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .mkdir, id, stringLen(path) + attrsWireLen(attrs));
    try writeString(w, path);
    try writeAttrs(w, attrs);
}

pub fn encodeRemove(w: *std.Io.Writer, id: u32, path: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .remove, id, stringLen(path));
    try writeString(w, path);
}

pub fn encodeRename(
    w: *std.Io.Writer,
    id: u32,
    old_path: []const u8,
    new_path: []const u8,
) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .rename, id, stringLen(old_path) + stringLen(new_path));
    try writeString(w, old_path);
    try writeString(w, new_path);
}

pub fn encodeRealpath(w: *std.Io.Writer, id: u32, path: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .realpath, id, stringLen(path));
    try writeString(w, path);
}

// --- Responses (used by tests and any future loopback server) ---

pub fn encodeStatus(
    w: *std.Io.Writer,
    id: u32,
    code: StatusCode,
    msg: []const u8,
    lang: []const u8,
) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .status, id, 4 + stringLen(msg) + stringLen(lang));
    try writeU32Be(w, @intFromEnum(code));
    try writeString(w, msg);
    try writeString(w, lang);
}

pub fn encodeHandle(w: *std.Io.Writer, id: u32, handle: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .handle, id, stringLen(handle));
    try writeString(w, handle);
}

pub fn encodeData(w: *std.Io.Writer, id: u32, data: []const u8) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .data, id, 4 + data.len);
    try writeU32Be(w, @intCast(data.len));
    try w.writeAll(data);
}

/// One NAME entry: filename, longname, attrs. `count` entries are written.
pub const NameEntry = struct { filename: []const u8, longname: []const u8, attrs: Attrs };

pub fn encodeName(w: *std.Io.Writer, id: u32, entries: []const NameEntry) std.Io.Writer.Error!void {
    var body: usize = 4;
    for (entries) |e| body += stringLen(e.filename) + stringLen(e.longname) + attrsWireLen(e.attrs);
    try writeFrameHeader(w, .name, id, body);
    try writeU32Be(w, @intCast(entries.len));
    for (entries) |e| {
        try writeString(w, e.filename);
        try writeString(w, e.longname);
        try writeAttrs(w, e.attrs);
    }
}

pub fn encodeAttrs(w: *std.Io.Writer, id: u32, attrs: Attrs) std.Io.Writer.Error!void {
    try writeFrameHeader(w, .attrs, id, attrsWireLen(attrs));
    try writeAttrs(w, attrs);
}

// ---------------------------------------------------------------------------
// Decode (cursor over a borrowed frame payload slice)
// ---------------------------------------------------------------------------

pub const Header = struct {
    type: Type,
    id: ?u32,
    /// Bytes after type (+ id). For decoding the body.
    body: []const u8,
};

/// Decode type and optional id from a full frame payload (the `length`
/// bytes that follow the 4-byte length prefix). Returns the body slice.
pub fn decodeHeader(frame: []const u8) Error!Header {
    if (frame.len < 1) return error.ShortPacket;
    const t: Type = @enumFromInt(frame[0]);
    if (!typeHasId(t)) return .{ .type = t, .id = null, .body = frame[1..] };
    if (frame.len < 5) return error.ShortPacket;
    const id = std.mem.readInt(u32, frame[1..5], .big);
    return .{ .type = t, .id = id, .body = frame[5..] };
}

pub const BodyReader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(body: []const u8) BodyReader {
        return .{ .buf = body };
    }

    pub fn remaining(self: BodyReader) usize {
        return self.buf.len - self.pos;
    }

    pub fn done(self: BodyReader) bool {
        return self.pos == self.buf.len;
    }

    pub fn readU32(self: *BodyReader) Error!u32 {
        if (self.remaining() < 4) return error.ShortPacket;
        const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .big);
        self.pos += 4;
        return v;
    }

    pub fn readU64(self: *BodyReader) Error!u64 {
        if (self.remaining() < 8) return error.ShortPacket;
        const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .big);
        self.pos += 8;
        return v;
    }

    /// Borrowed slice into the frame; valid only while the frame lives.
    pub fn readString(self: *BodyReader) Error![]const u8 {
        const len = try self.readU32();
        if (len > self.remaining()) return error.BadString;
        const s = self.buf[self.pos..][0..len];
        self.pos += len;
        return s;
    }

    /// Read the DATA response payload: a u32 length then that many bytes.
    /// Borrowed slice into the frame.
    pub fn readData(self: *BodyReader) Error![]const u8 {
        return self.readString();
    }

    pub fn readAttrs(self: *BodyReader) Error!Attrs {
        var a: Attrs = .{};
        a.flags = try self.readU32();
        if (a.flags & ATTR_SIZE != 0) a.size = try self.readU64();
        if (a.flags & ATTR_UIDGID != 0) {
            a.uid = try self.readU32();
            a.gid = try self.readU32();
        }
        if (a.flags & ATTR_PERMISSIONS != 0) a.permissions = try self.readU32();
        if (a.flags & ATTR_ACMODTIME != 0) {
            a.atime = try self.readU32();
            a.mtime = try self.readU32();
        }
        return a;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Encode into a fresh fixed buffer and return the written bytes (the
/// meaningful prefix; the rest of the array is left undefined).
fn enc(fn_: anytype, args: anytype) ![4096]u8 {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try @call(.auto, fn_, .{&w} ++ args);
    var out: [4096]u8 = undefined;
    const n = w.end;
    @memcpy(out[0..n], buf[0..n]);
    return out;
}

/// Length of the frame that starts at `bytes[0]` (the 4-byte prefix value).
fn frameLen(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

/// The payload that follows the 4-byte length prefix (type + id + body).
fn framePayload(bytes: []const u8) []const u8 {
    const total = frameLen(bytes);
    return bytes[4 .. 4 + total];
}

test "init and version omit the id" {
    const i = try enc(encodeInit, .{@as(u32, 3)});
    try testing.expectEqual(@as(u32, 1 + 4), frameLen(&i)); // type + u32 version
    try testing.expectEqual(@as(u8, 1), i[4]); // type = init
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, i[5..9], .big));

    const h = try decodeHeader(framePayload(&i));
    try testing.expectEqual(Type.init, h.type);
    try testing.expect(h.id == null);
    var br = BodyReader.init(h.body);
    try testing.expectEqual(@as(u32, 3), try br.readU32());
    try testing.expect(br.done());
}

test "open round-trips path, flags, attrs" {
    const attrs = Attrs{ .flags = ATTR_PERMISSIONS, .permissions = 0o644 };
    const b = try enc(encodeOpen, .{ @as(u32, 7), "/tmp/f.txt", FXF_READ, attrs });
    const total = frameLen(&b);
    try testing.expect(total == 1 + 4 + (4 + 10) + 4 + (4 + 4));
    const h = try decodeHeader(framePayload(&b));
    try testing.expectEqual(Type.open, h.type);
    try testing.expectEqual(@as(?u32, 7), h.id);
    var br = BodyReader.init(h.body);
    try testing.expectEqualSlices(u8, "/tmp/f.txt", try br.readString());
    try testing.expectEqual(FXF_READ, try br.readU32());
    const got = try br.readAttrs();
    try testing.expectEqual(attrs.flags, got.flags);
    try testing.expectEqual(attrs.permissions, got.permissions);
    try testing.expect(br.done());
}

test "read round-trips handle, offset, length" {
    const b = try enc(encodeRead, .{ @as(u32, 11), "h", @as(u64, 0x1020304050607080), @as(u32, 4096) });
    const h = try decodeHeader(framePayload(&b));
    try testing.expectEqual(Type.read, h.type);
    var br = BodyReader.init(h.body);
    try testing.expectEqualSlices(u8, "h", try br.readString());
    try testing.expectEqual(@as(u64, 0x1020304050607080), try br.readU64());
    try testing.expectEqual(@as(u32, 4096), try br.readU32());
    try testing.expect(br.done());
}

test "write round-trips and carries data verbatim" {
    const payload = "hello, sftp";
    const b = try enc(encodeWrite, .{ @as(u32, 5), "h", @as(u64, 0), payload });
    const total = frameLen(&b);
    // body = string("h") + u64 + u32(len) + data
    try testing.expectEqual(@as(u32, 1 + 4 + (4 + 1) + 8 + 4 + payload.len), total);
    const h = try decodeHeader(framePayload(&b));
    try testing.expectEqual(Type.write, h.type);
    var br = BodyReader.init(h.body);
    try testing.expectEqualSlices(u8, "h", try br.readString());
    try testing.expectEqual(@as(u64, 0), try br.readU64());
    try testing.expectEqualSlices(u8, payload, try br.readData());
    try testing.expect(br.done());
}

test "one-string requests round-trip" {
    const cases = .{
        .{ encodeClose, Type.close },
        .{ encodeStat, Type.stat },
        .{ encodeLstat, Type.lstat },
        .{ encodeFstat, Type.fstat },
        .{ encodeOpendir, Type.opendir },
        .{ encodeReaddir, Type.readdir },
        .{ encodeRemove, Type.remove },
        .{ encodeRealpath, Type.realpath },
    };
    inline for (cases, 0..) |c, i| {
        const b = try enc(c[0], .{ @as(u32, @intCast(i)), "p" });
        const h = try decodeHeader(framePayload(&b));
        try testing.expectEqual(c[1], h.type);
        try testing.expectEqual(@as(?u32, @intCast(i)), h.id);
        var br = BodyReader.init(h.body);
        try testing.expectEqualSlices(u8, "p", try br.readString());
        try testing.expect(br.done());
    }
}

test "fsetstat and mkdir carry attrs" {
    const attrs = Attrs{ .flags = ATTR_PERMISSIONS | ATTR_ACMODTIME, .permissions = 0o755, .atime = 100, .mtime = 200 };
    inline for (.{
        .{ encodeFsetstat, Type.fsetstat },
        .{ encodeMkdir, Type.mkdir },
    }) |c| {
        const b = try enc(c[0], .{ @as(u32, 1), "p", attrs });
        const h = try decodeHeader(framePayload(&b));
        try testing.expectEqual(c[1], h.type);
        var br = BodyReader.init(h.body);
        try testing.expectEqualSlices(u8, "p", try br.readString());
        const got = try br.readAttrs();
        try testing.expectEqual(attrs.permissions, got.permissions);
        try testing.expectEqual(attrs.atime, got.atime);
        try testing.expectEqual(attrs.mtime, got.mtime);
        try testing.expect(br.done());
    }
}

test "rename round-trips two paths" {
    const b = try enc(encodeRename, .{ @as(u32, 2), "a", "b" });
    const h = try decodeHeader(framePayload(&b));
    try testing.expectEqual(Type.rename, h.type);
    var br = BodyReader.init(h.body);
    try testing.expectEqualSlices(u8, "a", try br.readString());
    try testing.expectEqualSlices(u8, "b", try br.readString());
    try testing.expect(br.done());
}

test "status, handle, data, attrs responses round-trip" {
    const st = try enc(encodeStatus, .{ @as(u32, 9), StatusCode.ok, "ok", "en" });
    const hd = try enc(encodeHandle, .{ @as(u32, 9), "H" });
    const dt = try enc(encodeData, .{ @as(u32, 9), "DATA" });
    const at = try enc(encodeAttrs, .{ @as(u32, 9), Attrs{ .flags = ATTR_SIZE, .size = 12345 } });

    var br: BodyReader = undefined;
    var h: Header = undefined;

    h = try decodeHeader(framePayload(&st));
    try testing.expectEqual(Type.status, h.type);
    br = BodyReader.init(h.body);
    try testing.expectEqual(@as(u32, 0), try br.readU32());
    try testing.expectEqualSlices(u8, "ok", try br.readString());
    try testing.expectEqualSlices(u8, "en", try br.readString());

    h = try decodeHeader(framePayload(&hd));
    try testing.expectEqual(Type.handle, h.type);
    br = BodyReader.init(h.body);
    try testing.expectEqualSlices(u8, "H", try br.readString());

    h = try decodeHeader(framePayload(&dt));
    try testing.expectEqual(Type.data, h.type);
    br = BodyReader.init(h.body);
    try testing.expectEqualSlices(u8, "DATA", try br.readData());

    h = try decodeHeader(framePayload(&at));
    try testing.expectEqual(Type.attrs, h.type);
    br = BodyReader.init(h.body);
    const ga = try br.readAttrs();
    try testing.expectEqual(@as(u64, 12345), ga.size);
}

test "name response round-trips entries" {
    const entries = [_]NameEntry{
        .{ .filename = "a.txt", .longname = "-rw-r--r-- 1 a a 0 a.txt", .attrs = .{ .flags = ATTR_SIZE, .size = 0 } },
        .{ .filename = "b.bin", .longname = "-rw-r--r-- 1 a a 7 b.bin", .attrs = .{ .flags = ATTR_SIZE, .size = 7 } },
    };
    const b = try enc(encodeName, .{ @as(u32, 1), &entries });
    const h = try decodeHeader(framePayload(&b));
    try testing.expectEqual(Type.name, h.type);
    var br = BodyReader.init(h.body);
    try testing.expectEqual(@as(u32, 2), try br.readU32());
    try testing.expectEqualSlices(u8, "a.txt", try br.readString());
    _ = try br.readString(); // longname
    _ = try br.readAttrs();
    try testing.expectEqualSlices(u8, "b.bin", try br.readString());
    _ = try br.readString();
    _ = try br.readAttrs();
    try testing.expect(br.done());
}

test "decode rejects truncated frames without panicking" {
    try testing.expectError(error.ShortPacket, decodeHeader(&.{}));
    try testing.expectError(error.ShortPacket, decodeHeader(&.{3})); // open type, no id
    var br = BodyReader.init(&[_]u8{ 0, 0, 0, 5 }); // claims 5-byte string, none there
    try testing.expectError(error.BadString, br.readString());
}

test "decodeHeader never panics on arbitrary bytes" {
    // Deterministic LCG: feed 256 pseudorandom short buffers through the
    // decoder; every call must either decode or error, never trap.
    var state: u64 = 0x9e3779b97f4a7c15;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const len: usize = @intCast(state % 16);
        var buf: [16]u8 = undefined;
        var j: usize = 0;
        while (j < len) : (j += 1) {
            state = state *% 6364136223846793005 +% 1442695040888963407;
            buf[j] = @intCast(state & 0xff);
        }
        _ = decodeHeader(buf[0..len]) catch {};
    }
}
