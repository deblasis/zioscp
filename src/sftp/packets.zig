//! SFTP v3 packet codec.
//!
//! Slice 0: build anchor only. Slice 1 fills in message types, encode/decode,
//! and length-prefixed framing. SFTP packets are framed as:
//!
//!     uint32  length      (counts type + id + payload, not itself)
//!     uint8   type
//!     uint32  id          (request id; echoed in the response)
//!     bytes   payload
//!
//! All integers are big-endian (network order), per draft-ietf-secsh-filexfer.
const std = @import("std");

test "packets: build anchor" {
    try std.testing.expect(1 + 1 == 2);
}
