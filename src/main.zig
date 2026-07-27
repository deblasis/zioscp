const std = @import("std");

const version = "0.1.0";

pub fn main() !void {
    // Slice 0 stub. Real CLI (zioarg, scp grammar) lands in slice 6.
    std.debug.print("zioscp {s} (P1 in progress)\n", .{version});
}
