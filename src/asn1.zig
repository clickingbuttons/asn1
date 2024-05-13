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

    /// Buffer must be most significant byte to least significant.
    pub fn init(buffer: []const u8) BitString {
        // Ignore leading zeros
        const start = std.mem.indexOfNone(u8, buffer, &[_]u8{0}) orelse buffer.len;
        return BitString{
            .bytes = buffer[start..],
            .right_padding = if (start == buffer.len) 0 else @intCast(@ctz(buffer[buffer.len - 1])),
        };
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

pub fn Slice(comptime tag: encodings.Tag, comptime T: type, arr_len: comptime_int) type {
    return struct {
        items: [arr_len]T = undefined,
        len: usize = 0,

        pub fn decodeDer(decoder: *der.Decoder) !@This() {
            const ele = try decoder.element(tag.toExpected());
            decoder.index = ele.slice.start;

            var res = @This(){};
            while (decoder.index < ele.slice.end) : (res.len += 1) {
                if (arr_len < res.len) return error.ArrayTooSmall;
                res.items[res.len] = try decoder.expect(T);
            }
            return res;
        }

        pub fn encodeDer(self: @This(), encoder: *der.Encoder) !void {
            try encoder.tag(tag);
            var fake_encoder = der.Encoder.init(std.io.null_writer.any());
            for (self.items[0..self.len]) |i| try fake_encoder.any(i);
            try encoder.length(fake_encoder.underlying.bytes_written);
            for (self.items[0..self.len]) |i| try encoder.any(i);
        }

        pub fn slice(self: @This()) []const T {
            return self.items[0..self.len];
        }
    };
}

pub const Any = struct {
    tag: encodings.Tag,
    bytes: []const u8,

    pub fn decodeDer(decoder: *der.Decoder) !@This() {
        const ele = try decoder.element(encodings.ExpectedTag{});
        return .{ .tag = ele.tag, .bytes = decoder.view(ele) };
    }

    pub fn encodeDer(self: @This(), encoder: *der.Encoder) !void {
        try encoder.tag(self.tag);
        try encoder.length(self.bytes.len);
        try encoder.writer().writeAll(self.bytes);
    }
};

test {
    _ = der;
    _ = Oid;
    _ = encodings;
    _ = @import("./test.zig");
}
