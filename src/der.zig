//! Distinguised Encoding Rules as defined in X.690 and X.691.
//!
//! A version of Basic Encoding Rules (BER) where there is exactly ONE canonical way to
//! represent non-constructed elements. This is useful for cryptographic signatures.
const std = @import("std");
const asn1 = @import("./asn1.zig");

pub const Decoder = @import("./der/Decoder.zig");
pub const Encoder = @import("./der/Encoder.zig");

pub fn decode(comptime T: type, encoded: []const u8) !T {
    var decoder = Decoder{ .bytes = encoded };
    const res = try decoder.expect(T);
    std.debug.assert(decoder.index == encoded.len);
    return res;
}

pub fn encode(value: anytype, writer: anytype) !void {
    var encoder = Encoder.init(writer.any());
    try encoder.any(value);
}

test {
    _ = Decoder;
    _ = Encoder;
}
