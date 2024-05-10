//! A secure DER parser that:
//! - Does NOT read memory outside `bytes`.
//! - Does NOT return elements with slices outside `bytes`.
//! - Errors on values that do NOT follow DER rules:
//!     - Lengths that could be represented in a shorter form.
//!     - Booleans that are not 0xff or 0x00.
bytes: []const u8,
index: Index = 0,
/// The field tag of the most recently visited field.
field_tag: ?FieldTag = null,

pub fn expect(self: *Decoder, comptime T: type) !T {
    if (std.meta.hasFn(T, "decodeDer")) return try T.decodeDer(self);

    const tag = Tag.fromZig(T).toExpected();
    switch (@typeInfo(T)) {
        .Struct => {
            const ele = try self.element(tag);
            var res: T = undefined;

            inline for (std.meta.fields(T)) |f| {
                self.field_tag = FieldTag.fromContainer(T, f.name);

                if (self.field_tag) |ft| {
                    if (ft.explicit) {
                        const expected = Tag.init(undefined, true, undefined).toExpected();
                        const seq = try self.element(expected);
                        self.index = seq.slice.start;
                        self.field_tag = null;
                    }
                }

                @field(res, f.name) = self.expect(f.type) catch |err| brk: {
                    if (f.default_value) |d| {
                        break :brk @as(*const f.type, @alignCast(@ptrCast(d))).*;
                    }
                    return err;
                };
                // DER encodes null values by skipping them.
                if (@typeInfo(f.type) == .Optional and @field(res, f.name) == null) {
                    if (f.default_value) |d| {
                        @field(res, f.name) = @as(*const f.type, @alignCast(@ptrCast(d))).*;
                    }
                }
            }

            std.debug.assert(self.index == ele.slice.end);
            return res;
        },
        .Bool => {
            const ele = try self.element(tag);
            const bytes = self.view(ele);
            if (bytes.len != 1) return error.InvalidBool;

            return switch (bytes[0]) {
                0x00 => false,
                0xff => true,
                else => error.InvalidBool,
            };
        },
        .Int => {
            const ele = try self.element(tag);
            const bytes = self.view(ele);
            return try int(T, bytes);
        },
        .Enum => |e| {
            const ele = try self.element(tag);
            const bytes = self.view(ele);
            if (@hasDecl(T, "oids")) {
                return T.oids.get(bytes) orelse return error.UnknownOid;
            }
            return @enumFromInt(try int(e.tag_type, bytes));
        },
        .Optional => |o| return self.expect(o.child) catch return null,
        else => @compileError("cannot decode type " ++ @typeName(T)),
    }
}

pub fn expectEnum(self: *Decoder, comptime T: type) !T {
    const oid = try self.expect(asn1.Oid);
    return T.oids.get(oid.encoded) orelse return error.UnknownOid;
}

pub fn view(self: Decoder, elem: Element) []const u8 {
    return elem.slice.view(self.bytes);
}

pub fn eof(self: *Decoder) bool {
    return self.index == self.bytes.len;
}

fn int(comptime T: type, value: []const u8) !T {
    if (@typeInfo(T).Int.bits % 8 != 0) @compileError("T must be byte aligned");

    var bytes = value;
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
    try expectEqual(@as(u8, 1), try int(u8, &[_]u8{1}));
    try expectError(error.NonCanonical, int(u8, &[_]u8{ 0, 1 }));
    try expectError(error.NonCanonical, int(u8, &[_]u8{ 0xff, 0xff }));

    const big = [_]u8{ 0xef, 0xff };
    try expectError(error.LargeValue, int(u8, &big));
    try expectEqual(0xefff, int(u16, &big));
}

pub fn sequence(self: *Decoder) !Element {
    return try self.element(ExpectedTag.init(.sequence, true, .universal));
}

pub fn element(self: *Decoder, expected: ExpectedTag) !Element {
    if (self.index >= self.bytes.len) return error.EndOfStream;

    const res = try Element.decode(self.bytes, self.index);
    var e = expected;
    if (self.field_tag) |ft| {
        e.number = @enumFromInt(ft.number);
        e.class = ft.class;
    }
    if (!e.equal(res.tag)) {
        std.debug.print("expected {} got {}\n", .{ e, res });
        return error.UnexpectedElement;
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

        try std.testing.expectEqual(parser.index, seq2.slice.end);
    }
    _ = try parser.element(ExpectedTag.init(.bitstring, false, .universal));

    try std.testing.expectEqual(parser.index, seq.slice.end);
    try std.testing.expectEqual(parser.index, parser.bytes.len);
}

const std = @import("std");
const builtin = @import("builtin");
const asn1 = @import("../asn1.zig");
const Oid = @import("../Oid.zig");
const encodings = @import("../encodings.zig");

const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const Decoder = @This();
const Index = encodings.Index;
const Tag = encodings.Tag;
const FieldTag = encodings.FieldTag;
const ExpectedTag = encodings.ExpectedTag;
const Element = encodings.Element;
