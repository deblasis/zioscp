//! Crypto helpers for Zig.

const std = @import("std");

/// Constant-time comparison of two byte slices.
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var result: u8 = 0;
    for (a, b) |aa, bb| {
        result |= aa ^ bb;
    }
    return result == 0;
}

/// SHA-256 hash of data, returned as hex string.
/// Caller must free.
pub fn sha256Hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return toHex(allocator, &hash);
}

/// HMAC-SHA256, returned as hex string.
/// Caller must free.
pub fn hmacSha256Hex(allocator: std.mem.Allocator, key: []const u8, data: []const u8) ![]u8 {
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, data, key);
    return toHex(allocator, &mac);
}

fn toHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, bytes.len * 2);
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        result[i * 2] = charset[b >> 4];
        result[i * 2 + 1] = charset[b & 0x0f];
    }
    return result;
}

/// Generate a random hex token, using the entropy source behind `io`.
/// Caller must free.
///
/// This used to seed a Xoshiro PRNG with the constant 42, which meant every
/// token it returned was identical on every machine and every run. Tokens now
/// come from the `Io` CSPRNG, which is why an `io` argument is required.
pub fn generateToken(io: std.Io, allocator: std.mem.Allocator, byte_len: usize) ![]u8 {
    const bytes = try allocator.alloc(u8, byte_len);
    defer allocator.free(bytes);
    io.random(bytes);
    const result = try allocator.alloc(u8, byte_len * 2);
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        result[i * 2] = charset[b >> 4];
        result[i * 2 + 1] = charset[b & 0x0f];
    }
    return result;
}

test "constantTimeEqual" {
    try std.testing.expect(constantTimeEqual("hello", "hello"));
    try std.testing.expect(!constantTimeEqual("hello", "world"));
}

test "sha256Hex deterministic" {
    const h1 = try sha256Hex(std.testing.allocator, "test");
    defer std.testing.allocator.free(h1);
    const h2 = try sha256Hex(std.testing.allocator, "test");
    defer std.testing.allocator.free(h2);
    try std.testing.expectEqualStrings(h1, h2);
    try std.testing.expectEqual(@as(usize, 64), h1.len);
}

test "sha256Hex differs for different inputs" {
    const h1 = try sha256Hex(std.testing.allocator, "foo");
    defer std.testing.allocator.free(h1);
    const h2 = try sha256Hex(std.testing.allocator, "bar");
    defer std.testing.allocator.free(h2);
    try std.testing.expect(!std.mem.eql(u8, h1, h2));
}

test "hmacSha256Hex produces output" {
    const mac = try hmacSha256Hex(std.testing.allocator, "key", "message");
    defer std.testing.allocator.free(mac);
    try std.testing.expectEqual(@as(usize, 64), mac.len);
}

test "generateToken produces hex" {
    const token = try generateToken(std.testing.io, std.testing.allocator, 16);
    defer std.testing.allocator.free(token);
    try std.testing.expectEqual(@as(usize, 32), token.len);
    for (token) |ch| {
        try std.testing.expect(std.ascii.isHex(ch));
    }
}

test "constantTimeEqual different lengths" {
    try std.testing.expect(!constantTimeEqual("short", "longer"));
    try std.testing.expect(!constantTimeEqual("", "a"));
}

test "constantTimeEqual empty slices" {
    try std.testing.expect(constantTimeEqual("", ""));
}

test "toHex all zeros" {
    const bytes = [_]u8{0} ** 4;
    const hex = try toHex(std.testing.allocator, &bytes);
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings("00000000", hex);
}

test "toHex all ff" {
    const bytes = [_]u8{0xff} ** 2;
    const hex = try toHex(std.testing.allocator, &bytes);
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings("ffff", hex);
}

test "sha256Hex empty string" {
    const h = try sha256Hex(std.testing.allocator, "");
    defer std.testing.allocator.free(h);
    try std.testing.expectEqual(@as(usize, 64), h.len);
}

test "generateToken different lengths" {
    const t1 = try generateToken(std.testing.io, std.testing.allocator, 8);
    defer std.testing.allocator.free(t1);
    try std.testing.expectEqual(@as(usize, 16), t1.len);
    const t2 = try generateToken(std.testing.io, std.testing.allocator, 32);
    defer std.testing.allocator.free(t2);
    try std.testing.expectEqual(@as(usize, 64), t2.len);
}

test "sha256Hex well known vector" {
    const h = try sha256Hex(std.testing.allocator, "");
    defer std.testing.allocator.free(h);
    try std.testing.expectEqualStrings("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", h);
}

test "hmacSha256Hex deterministic" {
    const h1 = try hmacSha256Hex(std.testing.allocator, "key", "data");
    defer std.testing.allocator.free(h1);
    const h2 = try hmacSha256Hex(std.testing.allocator, "key", "data");
    defer std.testing.allocator.free(h2);
    try std.testing.expectEqualStrings(h1, h2);
}

test "constantTimeEqual self" {
    const data = "test123";
    try std.testing.expect(constantTimeEqual(data, data));
}

test "generateToken is hex" {
    const t = try generateToken(std.testing.io, std.testing.allocator, 4);
    defer std.testing.allocator.free(t);
    for (t) |ch| {
        try std.testing.expect(std.ascii.isHex(ch));
    }
}

test "sha256Hex hello world" {
    const h = try sha256Hex(std.testing.allocator, "hello world");
    defer std.testing.allocator.free(h);
    try std.testing.expectEqualStrings("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", h);
}

test "constantTimeEqual different lengths returns false" {
    try std.testing.expect(!constantTimeEqual("short", "longer string"));
}

test "generateToken zero length" {
    const t = try generateToken(std.testing.io, std.testing.allocator, 0);
    defer std.testing.allocator.free(t);
    try std.testing.expectEqual(@as(usize, 0), t.len);
}

test "sha256Hex abc" {
    const h = try sha256Hex(std.testing.allocator, "abc");
    defer std.testing.allocator.free(h);
    try std.testing.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", h);
}

test "hmacSha256Hex different keys" {
    const h1 = try hmacSha256Hex(std.testing.allocator, "key1", "data");
    defer std.testing.allocator.free(h1);
    const h2 = try hmacSha256Hex(std.testing.allocator, "key2", "data");
    defer std.testing.allocator.free(h2);
    try std.testing.expect(!std.mem.eql(u8, h1, h2));
}

test "generateToken is not deterministic" {
    const a = try generateToken(std.testing.io, std.testing.allocator, 16);
    defer std.testing.allocator.free(a);
    const b = try generateToken(std.testing.io, std.testing.allocator, 16);
    defer std.testing.allocator.free(b);
    try std.testing.expect(!std.mem.eql(u8, a, b));
}
