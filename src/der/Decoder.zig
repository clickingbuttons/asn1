//! A secure DER parser that:
//! - Does NOT read memory outside `bytes`.
//! - Does NOT return elements with slices outside `bytes`.
//! - Errors on values that do NOT follow DER rules:
//!     - Lengths that could be represented in a shorter form.
//!     - Booleans that are not 0xff or 0x00.
bytes: []const u8,
index: Index = 0,

pub fn expect(self: *Decoder, comptime T: type) !T {
    if (std.meta.hasFn(T, "decodeDer")) return try T.decodeDer(self);

    switch (@typeInfo(T)) {
        .Struct => {
            var res: T = undefined;
            const seq = try self.sequence();

            inline for (std.meta.fields(T)) |f| {
                @field(res, f.name) = self.expect(f.type) catch |err| brk: {
                    if (f.default_value) |d| {
                        const v: *const f.type = @alignCast(@ptrCast(d));
                        break :brk v.*;
                    }
                    return err;
                };
            }

            try self.expectEnd(seq.slice.end);
            return res;
        },
        .Bool => return try self.boolean(),
        .Int => return try self.int(T),
        .Enum => |e| {
            if (@hasDecl(T, "oids")) {
                const oid = try self.expect(asn1.Oid);
                return T.oids.get(oid.encoded) orelse return error.UnknownOid;
            }
            return @enumFromInt(try self.int(e.tag_type));
        },
        .Optional => |o| return self.expect(o.child) catch return null,
        else => {},
    }
    @compileError("cannot decode type " ++ @typeName(T));
}

pub fn expectEnum(self: *Decoder, comptime T: type) !T.Enum {
    const oid = try self.expect(asn1.Oid);
    return T.oids.get(oid.encoded) orelse return error.UnknownOid;
}

pub fn view(self: Decoder, elem: Element) []const u8 {
    return elem.slice.view(self.bytes);
}

pub fn eof(self: *Decoder) bool {
    return self.index == self.bytes.len;
}

fn boolean(self: *Decoder) !bool {
    const ele = try self.element(ExpectedTag.init(.boolean, false, .universal));
    if (ele.slice.len() != 1) return error.InvalidBool;

    return switch (self.view(ele)[0]) {
        0x00 => false,
        0xff => true,
        else => error.InvalidBool,
    };
}

fn int(self: *Decoder, comptime T: type) !T {
    if (@typeInfo(T).Int.bits % 8 != 0) @compileError("T must be byte aligned");
    const ele = try self.element(.{ .constructed = false, .class = .universal });
    const last_index = self.index;
    errdefer self.index = last_index;
    if (ele.tag.number != .integer and ele.tag.number != .enumerated) return error.UnexpectedElement;

    var bytes = self.view(ele);
    if (bytes.len >= 2) {
        if (bytes[0] == 0) {
            if (@clz(bytes[1]) > 0) return error.NonCanonical;
            bytes.ptr += 1;
        }
        if (bytes[0] == 0xff and @clz(bytes[1]) == 0) return error.NonCanonical;
    }

    if (bytes.len > @sizeOf(T)) return error.LargeValue;
    if (@sizeOf(T) == 1) return @bitCast(bytes[0]);

    return std.mem.readVarInt(T, bytes, .big);
}

test int {
    const one = [_]u8{ 2, 1, 1 };
    var parser = Decoder{ .bytes = &one };
    try std.testing.expectEqual(@as(u8, 1), try parser.int(u8));

    const one_padded = [_]u8{ 2, 2, 0, 1 };
    parser = Decoder{ .bytes = &one_padded };
    try std.testing.expectError(error.NonCanonical, parser.int(u8));

    const big_padded = [_]u8{ 2, 2, 0xff, 0xff };
    parser = Decoder{ .bytes = &big_padded };
    try std.testing.expectError(error.NonCanonical, parser.int(u8));

    const big = [_]u8{ 2, 2, 0xef, 0xff };
    parser = Decoder{ .bytes = &big };
    try std.testing.expectError(error.LargeValue, parser.int(u8));
    parser.index = 0;
    try std.testing.expectEqual(0xefff, parser.int(u16));
}

/// Remember to call `expectEnd`
pub fn sequence(self: *Decoder) !Element {
    return try self.element(encodings.ExpectedTag.init(.sequence, true, .universal));
}

/// Remember to call `expectEnd`
pub fn sequenceOf(self: *Decoder) !Element {
    return try self.element(encodings.ExpectedTag.init(.sequence_of, true, .universal));
}

pub fn expectEnd(self: *Decoder, val: usize) !void {
    if (self.index != val) return error.NonCanonical; // either forgot to parse OR a length-extension attack
}

pub fn element(self: *Decoder, expected: ExpectedTag) !Element {
    if (self.index >= self.bytes.len) return error.EndOfStream;

    const res = try Element.decode(self.bytes, self.index);
    if (expected.number) |e| {
        if (res.tag.number != e) return error.UnexpectedElement;
    }
    if (expected.constructed) |e| {
        if (res.tag.constructed != e) return error.UnexpectedElement;
    }
    if (expected.class) |e| {
        if (res.tag.class != e) return error.UnexpectedElement;
    }
    self.index = if (res.tag.constructed) res.slice.start else res.slice.end;
    return res;
}

test Decoder {
    var parser = Decoder{ .bytes = @embedFile("./testdata/id_ecc.pub.der") };
    const seq = try parser.sequence();

    {
        const seq2 = try parser.sequence();
        _ = try parser.element(ExpectedTag.init(.oid, false, .universal));
        _ = try parser.element(ExpectedTag.init(.oid, false, .universal));

        try parser.expectEnd(seq2.slice.end);
    }
    _ = try parser.element(ExpectedTag.init(.bitstring, false, .universal));

    try parser.expectEnd(seq.slice.end);
    try parser.expectEnd(parser.bytes.len);
}

const std = @import("std");
const builtin = @import("builtin");
const asn1 = @import("../asn1.zig");
const Oid = @import("../Oid.zig");
const encodings = @import("../encodings.zig");

const log = std.log.scoped(.der);
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const Decoder = @This();
const Index = encodings.Index;
const Tag = encodings.Tag;
const ExpectedTag = encodings.ExpectedTag;
const Element = encodings.Element;
