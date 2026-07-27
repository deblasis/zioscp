//! Chunk planner and per-chunk MAC.
//!
//! A file is divided into fixed-size chunks. The chunk is the unified unit
//! of resume (verify a completed chunk, skip it) and of P3 single-file
//! parallelism (hand disjoint ranges to N sessions). Each chunk's MAC
//! (SHA-256 of its bytes, via ziocrypt) is the integrity token recorded in
//! the resume sidecar.
//!
//! P1 uses chunks for resume granularity; transfers are single-stream.

const std = @import("std");
const ziocrypt = @import("ziocrypt");

pub const default_chunk_size: u64 = 8 * 1024 * 1024;

pub const ChunkRange = struct {
    index: u64,
    offset: u64,
    len: u64,
};

pub fn chunkCount(total_size: u64, chunk_size: u64) u64 {
    std.debug.assert(chunk_size > 0);
    return (total_size + chunk_size - 1) / chunk_size;
}

/// The byte range of chunk `index` within a file of `total_size` bytes,
/// chunked at `chunk_size`. The last chunk may be short; a zero-length file
/// has zero chunks.
pub fn chunkRange(index: u64, total_size: u64, chunk_size: u64) ChunkRange {
    std.debug.assert(chunk_size > 0);
    const offset = index * chunk_size;
    if (offset >= total_size) return .{ .index = index, .offset = total_size, .len = 0 };
    const remaining = total_size - offset;
    const len = if (remaining < chunk_size) remaining else chunk_size;
    return .{ .index = index, .offset = offset, .len = len };
}

/// SHA-256 of `bytes` as a lowercase hex string. Caller owns it. This is the
/// per-chunk integrity token for resume verification.
pub fn hashChunk(gpa: std.mem.Allocator, bytes: []const u8) error{OutOfMemory}![]u8 {
    return ziocrypt.sha256Hex(gpa, bytes) catch error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "chunkCount: exact multiples and a remainder" {
    try testing.expectEqual(@as(u64, 0), chunkCount(0, 1024));
    try testing.expectEqual(@as(u64, 1), chunkCount(1024, 1024));
    try testing.expectEqual(@as(u64, 3), chunkCount(3072, 1024));
    try testing.expectEqual(@as(u64, 4), chunkCount(3073, 1024));
}

test "chunkRange: full chunks and a short tail" {
    // 3 full 1024-byte chunks, then a 1-byte tail.
    var i: u64 = 0;
    while (i < 3) : (i += 1) {
        const r = chunkRange(i, 3073, 1024);
        try testing.expectEqual(i, r.index);
        try testing.expectEqual(i * 1024, r.offset);
        try testing.expectEqual(@as(u64, 1024), r.len);
    }
    const tail = chunkRange(3, 3073, 1024);
    try testing.expectEqual(@as(u64, 3072), tail.offset);
    try testing.expectEqual(@as(u64, 1), tail.len);
    // Past the end is empty.
    const after = chunkRange(4, 3073, 1024);
    try testing.expectEqual(@as(u64, 0), after.len);
}

test "chunkRange: zero-length file has empty range at index 0" {
    const r = chunkRange(0, 0, 1024);
    try testing.expectEqual(@as(u64, 0), r.offset);
    try testing.expectEqual(@as(u64, 0), r.len);
}

test "hashChunk: deterministic and content-dependent" {
    const a1 = try hashChunk(testing.allocator, "hello");
    defer testing.allocator.free(a1);
    const a2 = try hashChunk(testing.allocator, "hello");
    defer testing.allocator.free(a2);
    try testing.expectEqualStrings(a1, a2);
    try testing.expectEqual(@as(usize, 64), a1.len); // sha-256 hex

    const b = try hashChunk(testing.allocator, "world");
    defer testing.allocator.free(b);
    try testing.expect(a1.len == b.len);
    try testing.expect(!std.mem.eql(u8, a1, b));
}
