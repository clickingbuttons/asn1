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

        // DER requires that unused bits be zero
        const last_byte_trunc = bytes[bytes.len - 1] >> right_padding << right_padding;
        if (bytes[bytes.len - 1] != last_byte_trunc) return error.InvalidBitString;

        return BitString{ .bytes = bytes[1..], .right_padding = right_padding };
    }

    pub fn encodeDer(self: BitString, encoder: *der.Encoder) !void {
        try encoder.tag(asn1_tag);
        try encoder.length(self.bytes.len + 1);
        try encoder.writer().writeByte(self.right_padding);
        try encoder.writer().writeAll(self.bytes);
    }
};

pub const String = struct {
    tag: String.Tag,
    data: []const u8,

    pub const Tag = enum {
        utf8,
        /// us-ascii ([-][0-9][eE][.])*
        numeric,
        /// us-ascii ([A-Z][a-z][0-9][.?!,][ \t])*
        printable,
        /// iso-8859-1 with escaping into different character sets
        teletex,
        /// iso-8859-1
        videotex,
        /// us-ascii first 128 characters
        ia5,
        /// us-ascii without control characters
        visible,
        /// utf-32-be
        universal,
        /// utf-16-be
        bmp,
        /// character set deferred to runtime
        char,
        /// any standarized character set
        any,
        /// any standarized character set, no control characters
        graphic,
        /// alternative to oids
        object_descriptor,
    };

    pub fn decodeDer(decoder: *der.Decoder) !String {
        const last_index = decoder.index;
        const ele = decoder.element(encodings.ExpectedTag.init(null, false, .universal)) catch |err| {
            decoder.index = last_index;
            return err;
        };
        switch (ele.tag.number) {
            inline .string_utf8,
            .string_numeric,
            .string_printable,
            .string_teletex,
            .string_videotex,
            .string_ia5,
            .string_visible,
            .string_universal,
            .string_bmp,
            .string_char,
            .string_graphic,
            .string_general,
            .object_descriptor,
            => |t| {
                const tagname = @tagName(t)["string_".len..];
                const tag = std.meta.stringToEnum(String.Tag, tagname) orelse unreachable;
                return String{ .tag = tag, .data = decoder.view(ele) };
            },
            else => return error.InvalidString,
        }
    }

    pub fn encodeDer(self: String, encoder: *der.Encoder) !void {
        const number: encodings.Tag.Number = switch (self.tag) {
            inline else => |t| std.meta.stringToEnum(encodings.Tag.Number, "string_" ++ @tagName(t)).?,
        };
        try encoder.tag(encodings.Tag.init(number, false, .universal));
        try encoder.length(self.data.len);
        try encoder.writer().writeAll(self.data);
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
