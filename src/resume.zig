//! Resume sidecar: a tiny JSON file (`.zioscppart`) recording transfer
//! progress so an interrupted transfer continues instead of restarting.
//!
//! P1 resume is offset-based: the sidecar records the next offset to write
//! (upload) or read (download). On restart we skip the completed prefix and
//! continue. Per-chunk MAC verification (chunker.hashChunk) is wired for a
//! future hardening pass; the sidecar shape leaves room for it.
//!
//! Shape (flat, so ziojson.findKey parses each field directly):
//!   {"v":1,"dir":"up","total":N,"chunk":C,"next":K,"name":"...","size":N,"mtime":M}

const std = @import("std");
const ziojson = @import("ziojson");

pub const Error = error{
    BadJson,
    MissingField,
    OutOfMemory,
};

pub const Direction = enum {
    upload,
    download,

    fn toText(self: Direction) []const u8 {
        return switch (self) {
            .upload => "up",
            .download => "down",
        };
    }

    fn fromText(t: []const u8) ?Direction {
        if (std.mem.eql(u8, t, "up")) return .upload;
        if (std.mem.eql(u8, t, "down")) return .download;
        return null;
    }
};

/// `source_name` is borrowed on serialize; on deserialize it is owned (caller
/// frees it with the same allocator).
pub const Part = struct {
    direction: Direction,
    total_size: u64,
    chunk_size: u64,
    next_offset: u64,
    source_name: []const u8,
    source_size: u64,
    source_mtime: i64,
};

pub fn serialize(gpa: std.mem.Allocator, part: Part) error{OutOfMemory}![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var jw = ziojson.Writer.init(&aw.writer);
    jw.beginObject() catch return error.OutOfMemory;
    jw.field("v") catch return error.OutOfMemory;
    jw.writeInt(@as(u32, 1)) catch return error.OutOfMemory;
    jw.field("dir") catch return error.OutOfMemory;
    jw.writeString(part.direction.toText()) catch return error.OutOfMemory;
    jw.field("total") catch return error.OutOfMemory;
    jw.writeInt(part.total_size) catch return error.OutOfMemory;
    jw.field("chunk") catch return error.OutOfMemory;
    jw.writeInt(part.chunk_size) catch return error.OutOfMemory;
    jw.field("next") catch return error.OutOfMemory;
    jw.writeInt(part.next_offset) catch return error.OutOfMemory;
    jw.field("name") catch return error.OutOfMemory;
    jw.writeString(part.source_name) catch return error.OutOfMemory;
    jw.field("size") catch return error.OutOfMemory;
    jw.writeInt(part.source_size) catch return error.OutOfMemory;
    jw.field("mtime") catch return error.OutOfMemory;
    jw.writeInt(part.source_mtime) catch return error.OutOfMemory;
    jw.endObject() catch return error.OutOfMemory;
    return gpa.dupe(u8, aw.writer.buffered()) catch error.OutOfMemory;
}

fn parseU64(text: []const u8) Error!u64 {
    return std.fmt.parseInt(u64, text, 10) catch error.BadJson;
}
fn parseI64(text: []const u8) Error!i64 {
    return std.fmt.parseInt(i64, text, 10) catch error.BadJson;
}

pub fn deserialize(gpa: std.mem.Allocator, bytes: []const u8) Error!Part {
    const dir_t = ziojson.findKey(bytes, "dir") orelse return error.MissingField;
    const direction = Direction.fromText(dir_t) orelse return error.BadJson;
    const total = try parseU64(ziojson.findKey(bytes, "total") orelse return error.MissingField);
    const chunk = try parseU64(ziojson.findKey(bytes, "chunk") orelse return error.MissingField);
    const next = try parseU64(ziojson.findKey(bytes, "next") orelse return error.MissingField);
    const name = ziojson.findKey(bytes, "name") orelse return error.MissingField;
    const size = try parseU64(ziojson.findKey(bytes, "size") orelse return error.MissingField);
    const mtime = try parseI64(ziojson.findKey(bytes, "mtime") orelse return error.MissingField);
    return .{
        .direction = direction,
        .total_size = total,
        .chunk_size = chunk,
        .next_offset = next,
        .source_name = gpa.dupe(u8, name) catch return error.OutOfMemory,
        .source_size = size,
        .source_mtime = mtime,
    };
}

/// Path of the sidecar for a given destination. Caller owns it.
pub fn sidecarPath(gpa: std.mem.Allocator, dest_path: []const u8) error{OutOfMemory}![]u8 {
    return std.fmt.allocPrint(gpa, "{s}.zioscppart", .{dest_path}) catch error.OutOfMemory;
}

pub fn writeFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8, part: Part) !void {
    const bytes = try serialize(gpa, part);
    defer gpa.free(bytes);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
}

/// Read a sidecar; null if it does not exist. `name` in the result is owned.
pub fn readFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !?Part {
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4096)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer gpa.free(bytes);
    return try deserialize(gpa, bytes);
}

pub fn removeFile(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "serialize/deserialize round-trips every field" {
    const original = Part{
        .direction = .upload,
        .total_size = 123456,
        .chunk_size = 8 * 1024 * 1024,
        .next_offset = 32768,
        .source_name = "some/file.bin",
        .source_size = 123456,
        .source_mtime = 1700000000,
    };
    const bytes = try serialize(testing.allocator, original);
    defer testing.allocator.free(bytes);
    const got = try deserialize(testing.allocator, bytes);
    defer testing.allocator.free(got.source_name);
    try testing.expectEqual(original.direction, got.direction);
    try testing.expectEqual(original.total_size, got.total_size);
    try testing.expectEqual(original.chunk_size, got.chunk_size);
    try testing.expectEqual(original.next_offset, got.next_offset);
    try testing.expectEqualStrings(original.source_name, got.source_name);
    try testing.expectEqual(original.source_size, got.source_size);
    try testing.expectEqual(original.source_mtime, got.source_mtime);
}

test "deserialize rejects garbage" {
    try testing.expectError(error.MissingField, deserialize(testing.allocator, "{}"));
    try testing.expectError(error.MissingField, deserialize(testing.allocator, "{\"dir\":\"up\"}"));
}

test "write/read/remove round-trips through the filesystem" {
    // A self-contained io for fs ops in the test.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "zioscp-resume-test.json";
    defer removeFile(io, path);

    const original = Part{
        .direction = .download,
        .total_size = 99,
        .chunk_size = 10,
        .next_offset = 40,
        .source_name = "remote.dat",
        .source_size = 99,
        .source_mtime = 17,
    };
    try writeFile(io, testing.allocator, path, original);

    const read = (try readFile(io, testing.allocator, path)) orelse return error.UnexpectedTestFailure;
    defer testing.allocator.free(read.source_name);
    try testing.expectEqual(original.direction, read.direction);
    try testing.expectEqual(original.next_offset, read.next_offset);
    try testing.expectEqualStrings(original.source_name, read.source_name);

    removeFile(io, path);
    const after = try readFile(io, testing.allocator, path);
    try testing.expect(after == null);
}
