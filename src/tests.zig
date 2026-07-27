//! Test root. Imports every module so its `test` blocks run under
//! `zig build test`. Add a line per new module.
const std = @import("std");

test {
    _ = @import("sftp/packets.zig");
    _ = @import("sftp/client.zig");
    _ = @import("chunker.zig");
}
