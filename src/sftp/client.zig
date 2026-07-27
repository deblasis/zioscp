//! SFTP session: request/response logic over a byte duplex.
//!
//! Generic over a `Duplex` type that provides:
//!
//!     pub fn writeAll(self: *@This(), bytes: []const u8) Error!void
//!     pub fn readExact(self: *@This(), buf: []u8) Error!void   // fill buf or error
//!
//! The transport layer fills that contract with a live `ssh ... sftp-server`
//! subprocess; tests fill it with a scripted in-memory mock. P1 is strict
//! request/response (send one, await its reply by id); pipelining is a later
//! optimization.

const std = @import("std");
const packets = @import("packets.zig");

const StatusCode = packets.StatusCode;
const Attrs = packets.Attrs;

pub const Error = error{
    UnexpectedResponse,
    Eof,
    NoSuchFile,
    PermissionDenied,
    Failure,
    BadMessage,
    OpUnsupported,
    ProtocolError,
    Truncated,
    IoClosed,
    OutOfMemory,
};

/// Map an SFTP status code to a typed session error. `ok` here means the
/// server replied STATUS OK where the caller expected a different response
/// type, which is itself a protocol error.
fn statusToError(code: StatusCode) Error {
    return switch (code) {
        .ok => error.UnexpectedResponse,
        .eof => error.Eof,
        .no_such_file => error.NoSuchFile,
        .permission_denied => error.PermissionDenied,
        .failure => error.Failure,
        .bad_message => error.BadMessage,
        .op_unsupported => error.OpUnsupported,
        .no_connection, .connection_lost => error.IoClosed,
        _ => error.Failure,
    };
}

fn mapDecodeErr(err: packets.Error) Error {
    return switch (err) {
        error.ShortPacket => error.Truncated,
        error.BadString => error.ProtocolError,
        error.Overflow => error.Failure,
    };
}

pub fn Session(comptime Duplex: type) type {
    return struct {
        gpa: std.mem.Allocator,
        dup: *Duplex,
        next_id: u32 = 1,

        const Self = @This();

        pub fn init(gpa: std.mem.Allocator, dup: *Duplex) Self {
            return .{ .gpa = gpa, .dup = dup, .next_id = 1 };
        }

        fn allocId(self: *Self) u32 {
            const id = self.next_id;
            self.next_id +%= 1;
            return id;
        }

        /// Encode a request (via `encode_fn` with the non-writer `args` tuple)
        /// and write the full frame to the duplex.
        fn send(self: *Self, encode_fn: anytype, args: anytype) Error!void {
            var aw: std.Io.Writer.Allocating = .init(self.gpa);
            defer aw.deinit();
            @call(.auto, encode_fn, .{&aw.writer} ++ args) catch return error.OutOfMemory;
            self.dup.writeAll(aw.writer.buffered()) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.IoClosed,
            };
        }

        /// Read exactly one frame. Caller owns the returned payload
        /// (type + id + body) and must free it.
        fn recv(self: *Self) Error![]u8 {
            var lenbuf: [4]u8 = undefined;
            self.dup.readExact(&lenbuf) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.IoClosed,
            };
            const length = std.mem.readInt(u32, &lenbuf, .big);
            const payload = self.gpa.alloc(u8, length) catch return error.OutOfMemory;
            errdefer self.gpa.free(payload);
            self.dup.readExact(payload) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.IoClosed,
            };
            return payload;
        }

        fn decodeStatus(body: []const u8) Error!StatusCode {
            var br = packets.BodyReader.init(body);
            const code_u = br.readU32() catch return error.Truncated;
            return @enumFromInt(code_u);
        }

        /// Expect a STATUS OK reply for `id`; any other reply is an error.
        fn expectOk(self: *Self, id: u32) Error!void {
            const payload = try self.recv();
            defer self.gpa.free(payload);
            const h = packets.decodeHeader(payload) catch |e| return mapDecodeErr(e);
            if (h.id == null or h.id.? != id) return error.UnexpectedResponse;
            switch (h.type) {
                .status => {
                    const code = try decodeStatus(h.body);
                    if (code != .ok) return statusToError(code);
                },
                else => return error.UnexpectedResponse,
            }
        }

        fn statRoundtrip(self: *Self, id: u32) Error!Attrs {
            const payload = try self.recv();
            defer self.gpa.free(payload);
            const h = packets.decodeHeader(payload) catch |e| return mapDecodeErr(e);
            if (h.id == null or h.id.? != id) return error.UnexpectedResponse;
            switch (h.type) {
                .attrs => {
                    var br = packets.BodyReader.init(h.body);
                    return br.readAttrs() catch error.ProtocolError;
                },
                .status => return statusToError(try decodeStatus(h.body)),
                else => return error.UnexpectedResponse,
            }
        }

        // --- Handshake ---

        pub fn handshake(self: *Self) Error!u32 {
            try self.send(packets.encodeInit, .{@as(u32, 3)});
            const payload = try self.recv();
            defer self.gpa.free(payload);
            const h = packets.decodeHeader(payload) catch |e| return mapDecodeErr(e);
            if (h.type != .version) return error.UnexpectedResponse;
            var br = packets.BodyReader.init(h.body);
            return br.readU32() catch error.Truncated;
        }

        // --- File operations ---

        /// OPEN; returns an owned handle. Caller frees it.
        pub fn open(self: *Self, path: []const u8, pflags: u32, attrs: Attrs) Error![]u8 {
            const id = self.allocId();
            try self.send(packets.encodeOpen, .{ id, path, pflags, attrs });
            const payload = try self.recv();
            defer self.gpa.free(payload);
            const h = packets.decodeHeader(payload) catch |e| return mapDecodeErr(e);
            if (h.id == null or h.id.? != id) return error.UnexpectedResponse;
            switch (h.type) {
                .handle => {
                    var br = packets.BodyReader.init(h.body);
                    const handle = br.readString() catch return error.ProtocolError;
                    return self.gpa.dupe(u8, handle) catch error.OutOfMemory;
                },
                .status => return statusToError(try decodeStatus(h.body)),
                else => return error.UnexpectedResponse,
            }
        }

        pub fn close(self: *Self, handle: []const u8) Error!void {
            const id = self.allocId();
            try self.send(packets.encodeClose, .{ id, handle });
            try self.expectOk(id);
        }

        /// READ up to `len` bytes at `offset`. Returns owned data (may be
        /// shorter than `len` near EOF). Past-end reads report `error.Eof`.
        pub fn read(self: *Self, handle: []const u8, offset: u64, len: u32) Error![]u8 {
            const id = self.allocId();
            try self.send(packets.encodeRead, .{ id, handle, offset, len });
            const payload = try self.recv();
            defer self.gpa.free(payload);
            const h = packets.decodeHeader(payload) catch |e| return mapDecodeErr(e);
            if (h.id == null or h.id.? != id) return error.UnexpectedResponse;
            switch (h.type) {
                .data => {
                    var br = packets.BodyReader.init(h.body);
                    const data = br.readData() catch return error.ProtocolError;
                    return self.gpa.dupe(u8, data) catch error.OutOfMemory;
                },
                .status => {
                    const code = try decodeStatus(h.body);
                    if (code == .eof) return error.Eof;
                    return statusToError(code);
                },
                else => return error.UnexpectedResponse,
            }
        }

        pub fn write(self: *Self, handle: []const u8, offset: u64, data: []const u8) Error!void {
            try self.sendWriteUnacked(handle, offset, data);
            try self.awaitAnyOk();
        }

        /// Send a WRITE without waiting for the STATUS reply (for pipelining).
        /// Header from a stack buffer + payload streamed straight to the wire.
        pub fn sendWriteUnacked(self: *Self, handle: []const u8, offset: u64, data: []const u8) Error!void {
            const id = self.allocId();
            var hdr: [256]u8 = undefined;
            var hw = std.Io.Writer.fixed(&hdr);
            packets.encodeWriteHeader(&hw, id, handle, offset, data.len) catch {
                // Oversized handle: fall back to the allocating encode path.
                try self.send(packets.encodeWrite, .{ id, handle, offset, data });
                return;
            };
            self.dup.writeAll(hdr[0..hw.end]) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.IoClosed,
            };
            if (data.len > 0) {
                self.dup.writeAll(data) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.IoClosed,
                };
            }
        }

        /// Await one STATUS reply and require it OK. For pipelining: SFTP
        /// processes requests FIFO, so draining N replies after N sends acks
        /// them in order without matching ids.
        pub fn awaitAnyOk(self: *Self) Error!void {
            const payload = try self.recv();
            defer self.gpa.free(payload);
            const h = packets.decodeHeader(payload) catch |e| return mapDecodeErr(e);
            switch (h.type) {
                .status => {
                    const code = try decodeStatus(h.body);
                    if (code != .ok) return statusToError(code);
                },
                else => return error.UnexpectedResponse,
            }
        }

        pub fn fsetstat(self: *Self, handle: []const u8, attrs: Attrs) Error!void {
            const id = self.allocId();
            try self.send(packets.encodeFsetstat, .{ id, handle, attrs });
            try self.expectOk(id);
        }

        pub fn stat(self: *Self, path: []const u8) Error!Attrs {
            const id = self.allocId();
            try self.send(packets.encodeStat, .{ id, path });
            return self.statRoundtrip(id);
        }

        pub fn lstat(self: *Self, path: []const u8) Error!Attrs {
            const id = self.allocId();
            try self.send(packets.encodeLstat, .{ id, path });
            return self.statRoundtrip(id);
        }

        pub fn fstat(self: *Self, handle: []const u8) Error!Attrs {
            const id = self.allocId();
            try self.send(packets.encodeFstat, .{ id, handle });
            return self.statRoundtrip(id);
        }

        pub fn opendir(self: *Self, path: []const u8) Error![]u8 {
            const id = self.allocId();
            try self.send(packets.encodeOpendir, .{ id, path });
            const payload = try self.recv();
            defer self.gpa.free(payload);
            const h = packets.decodeHeader(payload) catch |e| return mapDecodeErr(e);
            if (h.id == null or h.id.? != id) return error.UnexpectedResponse;
            switch (h.type) {
                .handle => {
                    var br = packets.BodyReader.init(h.body);
                    const handle = br.readString() catch return error.ProtocolError;
                    return self.gpa.dupe(u8, handle) catch error.OutOfMemory;
                },
                .status => return statusToError(try decodeStatus(h.body)),
                else => return error.UnexpectedResponse,
            }
        }

        pub const Entry = struct { filename: []u8, longname: []u8, attrs: Attrs };

        /// One READDIR. Returns owned entries (caller frees each filename and
        /// longname and the slice). Directory EOF reports `error.Eof`.
        pub fn readdir(self: *Self, handle: []const u8) Error![]Entry {
            const id = self.allocId();
            try self.send(packets.encodeReaddir, .{ id, handle });
            const payload = try self.recv();
            defer self.gpa.free(payload);
            const h = packets.decodeHeader(payload) catch |e| return mapDecodeErr(e);
            if (h.id == null or h.id.? != id) return error.UnexpectedResponse;
            switch (h.type) {
                .name => {
                    var br = packets.BodyReader.init(h.body);
                    const count = br.readU32() catch return error.ProtocolError;
                    const entries = self.gpa.alloc(Entry, count) catch return error.OutOfMemory;
                    var filled: usize = 0;
                    errdefer {
                        for (entries[0..filled]) |e| {
                            self.gpa.free(e.filename);
                            self.gpa.free(e.longname);
                        }
                        self.gpa.free(entries);
                    }
                    while (filled < count) : (filled += 1) {
                        const fn_text = br.readString() catch return error.ProtocolError;
                        const ln_text = br.readString() catch return error.ProtocolError;
                        const a = br.readAttrs() catch return error.ProtocolError;
                        entries[filled] = .{
                            .filename = self.gpa.dupe(u8, fn_text) catch return error.OutOfMemory,
                            .longname = self.gpa.dupe(u8, ln_text) catch return error.OutOfMemory,
                            .attrs = a,
                        };
                    }
                    return entries;
                },
                .status => {
                    const code = try decodeStatus(h.body);
                    if (code == .eof) return error.Eof;
                    return statusToError(code);
                },
                else => return error.UnexpectedResponse,
            }
        }

        pub fn mkdir(self: *Self, path: []const u8, attrs: Attrs) Error!void {
            const id = self.allocId();
            try self.send(packets.encodeMkdir, .{ id, path, attrs });
            try self.expectOk(id);
        }

        pub fn remove(self: *Self, path: []const u8) Error!void {
            const id = self.allocId();
            try self.send(packets.encodeRemove, .{ id, path });
            try self.expectOk(id);
        }

        pub fn rename(self: *Self, old_path: []const u8, new_path: []const u8) Error!void {
            const id = self.allocId();
            try self.send(packets.encodeRename, .{ id, old_path, new_path });
            try self.expectOk(id);
        }

        pub fn realpath(self: *Self, path: []const u8) Error![]u8 {
            const id = self.allocId();
            try self.send(packets.encodeRealpath, .{ id, path });
            const payload = try self.recv();
            defer self.gpa.free(payload);
            const h = packets.decodeHeader(payload) catch |e| return mapDecodeErr(e);
            if (h.id == null or h.id.? != id) return error.UnexpectedResponse;
            switch (h.type) {
                .name => {
                    var br = packets.BodyReader.init(h.body);
                    const count = br.readU32() catch return error.ProtocolError;
                    if (count == 0) return error.ProtocolError;
                    const resolved = br.readString() catch return error.ProtocolError;
                    return self.gpa.dupe(u8, resolved) catch return error.OutOfMemory;
                },
                .status => return statusToError(try decodeStatus(h.body)),
                else => return error.UnexpectedResponse,
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Scripted in-memory duplex for tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const MockDuplex = struct {
    gpa: std.mem.Allocator,
    rx: []const u8,
    rx_pos: usize = 0,
    tx: std.ArrayList(u8) = .empty,

    pub fn writeAll(self: *MockDuplex, bytes: []const u8) Error!void {
        self.tx.appendSlice(self.gpa, bytes) catch return error.OutOfMemory;
    }
    pub fn readExact(self: *MockDuplex, buf: []u8) Error!void {
        if (self.rx_pos + buf.len > self.rx.len) return error.IoClosed;
        @memcpy(buf, self.rx[self.rx_pos..][0..buf.len]);
        self.rx_pos += buf.len;
    }
};

/// Append a fully-framed response to `rx_buf` using `encoder` + args tuple.
fn canned(rx_buf: *std.Io.Writer.Allocating, encoder: anytype, args: anytype) void {
    @call(.auto, encoder, .{&rx_buf.writer} ++ args) catch {};
}

test "handshake sends INIT(3) and returns server version" {
    var rx_aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer rx_aw.deinit();
    canned(&rx_aw, packets.encodeVersion, .{@as(u32, 3)});

    var mock = MockDuplex{ .gpa = testing.allocator, .rx = rx_aw.writer.buffered() };
    defer mock.tx.deinit(testing.allocator);

    var sess = Session(MockDuplex).init(testing.allocator, &mock);
    const v = try sess.handshake();
    try testing.expectEqual(@as(u32, 3), v);

    // The session must have written exactly an INIT(3) frame.
    const sent = mock.tx.items;
    const h = try packets.decodeHeader(sent[4..]);
    try testing.expectEqual(packets.Type.init, h.type);
    var br = packets.BodyReader.init(h.body);
    try testing.expectEqual(@as(u32, 3), try br.readU32());
}

test "open returns the server handle and writes the expected request" {
    var rx_aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer rx_aw.deinit();
    canned(&rx_aw, packets.encodeHandle, .{ @as(u32, 1), "H1" });

    var mock = MockDuplex{ .gpa = testing.allocator, .rx = rx_aw.writer.buffered() };
    defer mock.tx.deinit(testing.allocator);

    var sess = Session(MockDuplex).init(testing.allocator, &mock);
    const handle = try sess.open("/path", packets.FXF_READ, Attrs.empty);
    defer testing.allocator.free(handle);
    try testing.expectEqualSlices(u8, "H1", handle);

    const sent = mock.tx.items;
    const h = try packets.decodeHeader(sent[4..]);
    try testing.expectEqual(packets.Type.open, h.type);
    try testing.expectEqual(@as(?u32, 1), h.id);
    var br = packets.BodyReader.init(h.body);
    try testing.expectEqualSlices(u8, "/path", try br.readString());
    try testing.expectEqual(packets.FXF_READ, try br.readU32());
}

test "open surfaces a STATUS error as a typed error" {
    var rx_aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer rx_aw.deinit();
    canned(&rx_aw, packets.encodeStatus, .{ @as(u32, 1), StatusCode.no_such_file, "nope", "en" });

    var mock = MockDuplex{ .gpa = testing.allocator, .rx = rx_aw.writer.buffered() };
    defer mock.tx.deinit(testing.allocator);
    var sess = Session(MockDuplex).init(testing.allocator, &mock);
    try testing.expectError(error.NoSuchFile, sess.open("/missing", packets.FXF_READ, Attrs.empty));
}

test "read decodes DATA and reports EOF past the end" {
    var rx_aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer rx_aw.deinit();
    canned(&rx_aw, packets.encodeData, .{ @as(u32, 1), "ABCDE" });
    canned(&rx_aw, packets.encodeStatus, .{ @as(u32, 2), StatusCode.eof, "eof", "en" });

    var mock = MockDuplex{ .gpa = testing.allocator, .rx = rx_aw.writer.buffered() };
    defer mock.tx.deinit(testing.allocator);
    var sess = Session(MockDuplex).init(testing.allocator, &mock);

    const data = try sess.read("H", 0, 5);
    defer testing.allocator.free(data);
    try testing.expectEqualSlices(u8, "ABCDE", data);

    try testing.expectError(error.Eof, sess.read("H", 5, 5));
}

test "write expects STATUS ok and carries data verbatim on the wire" {
    var rx_aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer rx_aw.deinit();
    canned(&rx_aw, packets.encodeStatus, .{ @as(u32, 1), StatusCode.ok, "", "en" });

    var mock = MockDuplex{ .gpa = testing.allocator, .rx = rx_aw.writer.buffered() };
    defer mock.tx.deinit(testing.allocator);
    var sess = Session(MockDuplex).init(testing.allocator, &mock);
    try sess.write("H", 0, "payload");

    const sent = mock.tx.items;
    const h = try packets.decodeHeader(sent[4..]);
    try testing.expectEqual(packets.Type.write, h.type);
    var br = packets.BodyReader.init(h.body);
    try testing.expectEqualSlices(u8, "H", try br.readString());
    try testing.expectEqual(@as(u64, 0), try br.readU64());
    try testing.expectEqualSlices(u8, "payload", try br.readData());
}

test "stat returns attrs" {
    var rx_aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer rx_aw.deinit();
    canned(&rx_aw, packets.encodeAttrs, .{ @as(u32, 1), Attrs{ .flags = packets.ATTR_SIZE, .size = 999 } });

    var mock = MockDuplex{ .gpa = testing.allocator, .rx = rx_aw.writer.buffered() };
    defer mock.tx.deinit(testing.allocator);
    var sess = Session(MockDuplex).init(testing.allocator, &mock);
    const a = try sess.stat("/f");
    try testing.expectEqual(@as(u64, 999), a.size);
}

test "readdir returns entries; directory EOF is error.Eof" {
    var rx_aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer rx_aw.deinit();
    const entries = [_]packets.NameEntry{
        .{ .filename = "a", .longname = "a", .attrs = Attrs{ .flags = packets.ATTR_SIZE, .size = 1 } },
        .{ .filename = "b", .longname = "b", .attrs = Attrs{ .flags = packets.ATTR_SIZE, .size = 2 } },
    };
    canned(&rx_aw, packets.encodeName, .{ @as(u32, 1), &entries });
    canned(&rx_aw, packets.encodeStatus, .{ @as(u32, 2), StatusCode.eof, "eof", "en" });

    var mock = MockDuplex{ .gpa = testing.allocator, .rx = rx_aw.writer.buffered() };
    defer mock.tx.deinit(testing.allocator);
    var sess = Session(MockDuplex).init(testing.allocator, &mock);

    const e1 = try sess.readdir("D");
    defer {
        for (e1) |e| {
            testing.allocator.free(e.filename);
            testing.allocator.free(e.longname);
        }
        testing.allocator.free(e1);
    }
    try testing.expectEqual(@as(usize, 2), e1.len);
    try testing.expectEqualSlices(u8, "a", e1[0].filename);
    try testing.expectEqualSlices(u8, "b", e1[1].filename);

    try testing.expectError(error.Eof, sess.readdir("D"));
}
