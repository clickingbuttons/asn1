//! ASN.1 types for public consumption.
const std = @import("std");
pub const encodings = @import("./encodings.zig");
pub const der = @import("./der.zig");
pub const Oid = @import("./Oid.zig");

pub const BitString = struct {
    /// Number of bits in rightmost byte that are unused.
    right_padding: u3 = 0,
    bytes: []const u8,

    pub fn bitLen(self: BitString) usize {
        return self.bytes.len * 8 - self.right_padding;
    }

    const asn1_tag = encodings.Tag{ .number = .bitstring };

    pub fn decodeDer(decoder: *der.Decoder) !BitString {
        const ele = try decoder.element(asn1_tag.toExpected());
        const bytes = decoder.view(ele);

        return try fromDer(bytes);
    }

    pub fn fromDer(bytes: []const u8) !BitString {
        if (bytes.len < 1) return error.InvalidBitString;
        const padding = bytes[0];
        if (padding >= 8) return error.InvalidBitString;
        const right_padding: u3 = @intCast(padding);

        // DER requires that unused bits be zero.
        if (@ctz(bytes[bytes.len - 1]) < right_padding) return error.InvalidBitString;

        return BitString{ .bytes = bytes[1..], .right_padding = right_padding };
    }

    pub fn encodeDer(self: BitString, encoder: *der.Encoder) !void {
        try encoder.tag(asn1_tag);
        try encoder.length(self.bytes.len + 1);
        try encoder.writer().writeByte(self.right_padding);
        try encoder.writer().writeAll(self.bytes);
    }
};

/// An opaque type to hold the bytes of a tag.
pub fn Opaque(comptime tag: encodings.Tag) type {
    return struct {
        bytes: []const u8,

        pub fn decodeDer(decoder: *der.Decoder) !@This() {
            const ele = try decoder.element(tag.toExpected());
            if (tag.constructed) decoder.index = ele.slice.end;
            return .{ .bytes = decoder.view(ele) };
        }

        pub fn encodeDer(self: @This(), encoder: *der.Encoder) !void {
            try encoder.tag(tag);
            try encoder.length(self.bytes.len);
            try encoder.writer().writeAll(self.bytes);
        }
    };
}

test {
    _ = der;
    _ = Oid;
    _ = encodings;
    _ = @import("./test.zig");
}
