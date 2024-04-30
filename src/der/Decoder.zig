//! A secure DER parser that:
//! - Does NOT read memory outside `bytes`.
//! - Does NOT return elements with slices outside `bytes`.
//! - Errors on values that do NOT follow DER rules.
//!     - Lengths that could be represented in a shorter form.
//!     - Booleans that are not 0xff or 0x00.
bytes: []const u8,
index: Index = 0,

pub const Error = Element.InitError || error{
    UnexpectedElement,
    InvalidIntegerEncoding,
    InvalidBitString,
    Overflow,
    NonCanonical,
};

pub fn expectBool(self: *Decoder) Error!bool {
    const ele = try self.expect(.boolean, false, .universal);
    if (ele.slice.len() != 1) return error.InvalidBool;

    return switch (self.view(ele)[0]) {
        0x00 => false,
        0xff => true,
        else => error.InvalidBool,
    };
}

pub fn expectBitstring(self: *Decoder) Error!asn1.BitString {
    const ele = try self.expect(.bitstring, false, .universal);
    const bytes = self.view(ele);
    const padding = bytes[0];
    if (padding >= 8) return error.InvalidBitString;

    const right_padding: u3 = @intCast(padding);
    // Padded bits should all be 0.
    const mask = @as(u9, 0xff) >> (8 - @as(u4, right_padding));
    if (bytes[bytes.len - 1] & mask != 0) return error.InvalidBitString;

    return .{ .bytes = bytes[1..], .right_padding = right_padding };
}

/// RFC 5280 disallows ambiguous representations and forces "Z".
pub fn expectDateTimeRfc5280(self: *Decoder) Error!asn1.DateTime {
    const ele = try self.expect(null, false, .universal);
    const bytes = self.view(ele);
    switch (ele.identifier.tag) {
        .utc_time => {
            if (bytes.len != "yymmddHHmmssZ".len)
                return error.InvalidDateTime;
            if (bytes[bytes.len - 1] != 'Z')
                return error.InvalidDateTime;

            var date: asn1.Date = undefined;
            date.year = try parseDigits(bytes[0..2], 0, 99);
            // > Where YY is greater than or equal to 50, the year SHALL be
            // > interpreted as 19YY; and
            // > Where YY is less than 50, the year SHALL be interpreted as 20YY.
            date.year += if (date.year >= 50) 1900 else 2000;
            date.month = try parseDigits(bytes[2..4], 1, 12);
            date.day = try parseDigits(bytes[4..6], 1, 31);

            return .{ .date = date, .time = try parseTime(bytes[6..12])};
        },
        .generalized_time => {
            if (bytes.len != "yyyymmddHHmmssZ".len)
                return error.InvalidDateTime;
            if (bytes[bytes.len - 1] != 'Z')
                return error.InvalidDateTime;

            var date: asn1.Date = undefined;
            date.year = try parseYear4(bytes[0..4]);
            date.month = try parseDigits(bytes[4..6], 1, 12);
            date.day = try parseDigits(bytes[6..8], 1, 31);

            return .{ .date = date, .time = try parseTime(bytes[8..14]) };
        },
        else => return error.InvalidDateTime,
    }
}

pub fn expectOid(self: *Decoder) Error![]const u8 {
    const ele = try self.expect(.object_identifier, false, .universal);
    return self.view(ele);
}

pub fn expectEnum(self: *Decoder, comptime Enum: type) Error!Enum {
    const ele = try self.expectOid();
    return Enum.oids.get(ele.bytes) orelse {
        if (builtin.mode == .Debug) {
            var buf: [256]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buf);
            try ele.toDot(ele, stream.writer());
            log.warn("unknown oid {s} for enum {s}\n", .{ stream.getWritten(), @typeName(Enum) });
        }
        return error.UnknownObjectId;
    };
}

pub fn expectInt(self: *Decoder, comptime T: type) Error!T {
    const ele = try self.expectPrimitive(.integer);
    const bytes = self.view(ele);

    const info = @typeInfo(T);
    if (info != .Int) @compileError(@typeName(T) ++ " is not an int type");
    const Shift = std.math.Log2Int(u8);

    var result: std.meta.Int(.unsigned, info.Int.bits) = 0;
    for (bytes, 0..) |b, index| {
        const shifted = @shlWithOverflow(b, @as(Shift, @intCast(index * 8)));
        if (shifted[1] == 1) return error.Overflow;

        result |= shifted[0];
    }

    return @bitCast(result);
}

test expectInt {
    const one = [_]u8{ 2, 1, 1 };
    var parser = Decoder{ .bytes = &one };
    try std.testing.expectEqual(@as(u8, 1), try parser.expectInt(u8));
}

pub fn expectString(self: *Decoder) Error!asn1.String {
    const ele = try self.expect(.universal, false, null);
    switch (ele.identifier.tag) {
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
            const tag = std.meta.stringToEnum(asn1.String.Tag, tagname) orelse unreachable;
            return asn1.String{ .tag = tag, .data = self.view(ele) };
        },
        else => {},
    }
    return error.UnexpectedElement;
}

pub fn expectPrimitive(self: *Decoder, tag: ?Identifier.Tag) Error!Element {
    var elem = try self.expect(tag, false, .universal);
    if (tag == .integer and elem.slice.len() > 0) {
        if (self.view(elem)[0] == 0) elem.slice.start += 1;
        if (elem.slice.len() > 0 and self.view(elem)[0] == 0) return error.InvalidIntegerEncoding;
    }
    return elem;
}

/// Remember to call `expectEnd`
pub fn expectSequence(self: *Decoder) Error!Element {
    return try self.expect(.sequence, true, .universal);
}

/// Remember to call `expectEnd`
pub fn expectSequenceOf(self: *Decoder) Error!Element {
    return try self.expect(.sequence_of, true, .universal);
}

pub fn expectEnd(self: *Decoder, val: usize) Error!void {
    if (self.index != val) return error.NonCanonical; // either forgot to parse end OR an attacker
}

pub fn expect(
    self: *Decoder,
    tag: ?Identifier.Tag,
    constructed: ?bool,
    class: ?Identifier.Class,
) Error!Element {
    if (self.index >= self.bytes.len) return error.EndOfStream;

    const res = try Element.decode(self.bytes, self.index);
    if (tag) |e| {
        if (res.identifier.tag != e) return error.UnexpectedElement;
    }
    if (constructed) |e| {
        if (res.identifier.constructed != e) return error.UnexpectedElement;
    }
    if (class) |e| {
        if (res.identifier.class != e) return error.UnexpectedElement;
    }
    self.index = if (res.identifier.constructed) res.slice.start else res.slice.end;
    return res;
}

pub fn view(self: Decoder, elem: Element) []const u8 {
    return elem.slice.view(self.bytes);
}

pub fn seek(self: *Decoder, index: usize) void {
    self.index = index;
}

pub fn eof(self: *Decoder) bool {
    return self.index == self.bytes.len;
}

pub const Element = struct {
    identifier: Identifier,
    slice: Slice,

    pub const Slice = struct {
        start: Index,
        end: Index,

        pub fn len(self: Slice) Index {
            return self.end - self.start;
        }

        pub fn view(self: Slice, bytes: []const u8) []const u8 {
            return bytes[self.start..self.end];
        }
    };

    pub const InitError = error{ InvalidLength, EndOfStream };

    /// Safely decode an element at `index`:
    /// - Ensures length uses shortest form
    /// - Ensures length is within `bytes`
    /// - Ensures length is less than `std.math.maxInt(Index)`
    pub fn decode(bytes: []const u8, index: Index) InitError!Element {
        var stream = std.io.fixedBufferStream(bytes[index..]);
        var reader = stream.reader();

        const first = try reader.readByte();
        const identifier: Identifier = if (first & 0x1f == 0x1f) {
        } else {
        };
        const size_or_len_size = try reader.readByte();

        var start = index + 2;
        var end = start + size_or_len_size;
        // short form between 0-127
        if (size_or_len_size < 128) {
            if (end > bytes.len) return error.InvalidLength;
        } else {
            // long form between 0 and std.math.maxInt(u1024)
            const len_size: u7 = @truncate(size_or_len_size);
            start += len_size;
            if (len_size > @sizeOf(Index)) return error.InvalidLength;

            const len = try reader.readVarInt(Index, .big, len_size);
            if (len < 128) return error.InvalidLength; // should have used short form

            end = std.math.add(Index, start, len) catch return error.InvalidLength;
            if (end > bytes.len) return error.InvalidLength;
        }

        return .{ .identifier = identifier, .slice = .{ .start = start, .end = end } };
    }
};

test Element {
    const short_form = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x09 };
    try std.testing.expectEqual(Element{
        .identifier = Identifier{ .tag = .sequence, .constructed = true, .class = .universal },
        .slice = .{ .start = 2, .end = short_form.len },
    }, Element.decode(&short_form, 0));

    const long_form = [_]u8{ 0x30, 129, 129 } ++ [_]u8{0} ** 129;
    try std.testing.expectEqual(Element{
        .identifier = Identifier{ .tag = .sequence, .constructed = true, .class = .universal },
        .slice = .{ .start = 3, .end = long_form.len },
    }, Element.decode(&long_form, 0));
}



fn parseDigits(
    text: *const [2]u8,
    min: comptime_int,
    max: comptime_int,
) !std.math.IntFittingRange(min, max) {
    const result = std.fmt.parseInt(std.math.IntFittingRange(min, max), text, 10) catch
        return error.InvalidTime;
    if (result < min) return error.InvalidTime;
    if (result > max) return error.InvalidTime;
    return result;
}

test parseDigits {
    try expectEqual(@as(u8, 0), try parseDigits("00", 0, 99));
    try expectEqual(@as(u8, 99), try parseDigits("99", 0, 99));
    try expectEqual(@as(u8, 42), try parseDigits("42", 0, 99));
    try expectError(error.InvalidTime, parseDigits("13", 1, 12));
    try expectError(error.InvalidTime, parseDigits("00", 1, 12));
    try expectError(error.InvalidTime, parseDigits("Di", 0, 99));
}

fn parseYear4(text: *const [4]u8) !asn1.Date.Year {
    const result = std.fmt.parseInt(asn1.Date.Year, text, 10) catch return error.InvalidYear;
    if (result > 9999) return error.InvalidYear;
    return result;
}

test parseYear4 {
    try expectEqual(@as(asn1.Date.Year, 0), try parseYear4("0000"));
    try expectEqual(@as(asn1.Date.Year, 9999), try parseYear4("9999"));
    try expectEqual(@as(asn1.Date.Year, 1988), try parseYear4("1988"));
    try expectError(error.InvalidYear, parseYear4("999b"));
    try expectError(error.InvalidYear, parseYear4("crap"));
    try expectError(error.InvalidYear, parseYear4("r:bQ"));
}

fn parseTime(bytes: [6]*const u8) asn1.Time {
    return .{
        .hour = try parseDigits(bytes[0..2], 0, 23),
        .minute = try parseDigits(bytes[2..4], 0, 59),
        .second = try parseDigits(bytes[4..6], 0, 60),
    };
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var res: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&res, hex) catch unreachable;
    return res;
}

test Decoder {
    var parser = Decoder{ .bytes = @embedFile("./testdata/id_ecc.pub.der") };
   const seq = try parser.expectSequence();

   {
       const seq2 = try parser.expectSequence();
       const oid1 = try parser.expectOid();
       const oid2 = try parser.expectOid();

       try std.testing.expectEqualSlices(u8, &comptimeOid("1.2.840.10045.2.1"), oid1);
       try std.testing.expectEqualSlices(u8, &comptimeOid("1.2.840.10045.3.1.7"), oid2);

        try parser.expectEnd(seq2.slice.end);
   }

   const key = try parser.expectBitstring();
   try std.testing.expectEqualSlices(
       u8,
       &hexToBytes("04a01532a3c0900053de60fbefefcca58793301598d308b41e6f4e364e388c2711bef432c599148c94143d4ff46c2cb73e3e6a41d7eef23c047ea11e60667de425"),
       key.bytes,
   );

    try parser.expectEnd(seq.slice.end);
    try parser.expectEnd(parser.bytes.len);
}

const std = @import("std");
const builtin = @import("builtin");
const asn1 = @import("../asn1.zig");
const Oid = @import("../oid.zig");

const log = std.log.scoped(.der);
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const Decoder = @This();
const Index = asn1.Index;
const Identifier = asn1.Identifier;
const comptimeOid = Oid.encodeComptime;
