underlying: Writer,
/// The field tag of the most recently visited field.
field_tag: ?FieldTag = null,

const Writer = std.io.CountingWriter(std.io.AnyWriter);

pub fn init(underlying: std.io.AnyWriter) Encoder {
    return Encoder{ .underlying = std.io.countingWriter(underlying) };
}

pub fn any(self: *Encoder, val: anytype) !void {
    const T = @TypeOf(val);
    try self.tagLengthValue(encodings.Tag.fromZig(T), val);
}

fn tagLengthValue(self: *Encoder, tag_: encodings.Tag, val: anytype) !void {
    const T = @TypeOf(val);
    if (std.meta.hasFn(T, "encodeDer")) return try val.encodeDer(self);

    switch (@typeInfo(T)) {
        .Struct => {
            var fake_encoder = Encoder.init(std.io.null_writer.any());
            try fake_encoder.@"struct"(val);
            const len = fake_encoder.underlying.bytes_written;

            try self.tag(tag_);
            try self.length(len);
            try self.@"struct"(val);
        },
        .Bool => {
            try self.tag(tag_);
            try self.length(1);
            try self.writer.writeByte(if (val) 0xff else 0);
        },
        .Int => {
            try self.tag(tag_);
            try self.intLengthValue(T, val);
        },
        .Enum => |e| {
            if (@hasDecl(T, "oids")) {
                // TODO: Make static map of enum value -> string for O(1) encoding instead of O(n).
                for (T.oids.values(), 0..) |v, i| {
                    if (v == val) return self.any(asn1.Oid{ .encoded = T.oids.keys()[i] });
                }
                unreachable; // Oid.StaticMap verifies all members are accounted for at comptime.
            } else {
                try self.tag(tag_);
                try self.intLengthValue(e.tag_type, @intFromEnum(val));
            }
        },
        .Optional => if (val) |v| return try self.tagLengthValue(tag_, v),
        .Null => {
            try self.tag(tag_);
            try self.length(0);
        },
        else => @compileError("cannot encode type " ++ @typeName(T)),
    }
}

inline fn @"struct"(self: *Encoder, val: anytype) !void {
    const T = @TypeOf(val);
    inline for (@typeInfo(T).Struct.fields) |f| {
        const field_val = @field(val, f.name);

        // > The encoding of a set value or sequence value shall not include an encoding for any
        // > component value which is equal to its default value.
        const is_default = if (f.default_value) |v| brk: {
            const default_val: *const f.type = @alignCast(@ptrCast(v));
            break :brk std.mem.eql(u8, std.mem.asBytes(default_val), std.mem.asBytes(&field_val));
        } else false;

        if (!is_default) {
            self.field_tag = FieldTag.fromContainer(T, f.name);
            if (self.field_tag) |ft| {
                if (ft.explicit) {
                    var fake_encoder = Encoder.init(std.io.null_writer.any());
                    try fake_encoder.tagLengthValue(Tag.fromZig(f.type), field_val);
                    try self.tag(Tag.init(undefined, true, undefined));
                    try self.length(fake_encoder.underlying.bytes_written);
                    self.field_tag = null;
                }
            }
            try self.tagLengthValue(Tag.fromZig(f.type), field_val);
        }
    }
}

pub fn tag(self: *Encoder, tag_: Tag) !void {
    var t = tag_;
    if (self.field_tag) |ft| {
        t.number = @enumFromInt(ft.number);
        t.class = ft.class;
    }
    try t.encode(self.writer());
}

pub fn length(self: *Encoder, len: usize) !void {
    const writer_ = self.writer();
    if (len < 128) {
        try writer_.writeInt(u8, @intCast(len), .big);
        return;
    }
    inline for ([_]type{ u8, u16, u32 }) |T| {
        if (len < std.math.maxInt(T)) {
            try writer_.writeInt(u8, @sizeOf(T) | 0x80, .big);
            try writer_.writeInt(T, @intCast(len), .big);
            return;
        }
    }
    return error.InvalidLength;
}

pub fn writer(self: *Encoder) Writer.Writer {
    return self.underlying.writer();
}

fn intLengthValue(self: *Encoder, comptime T: type, value: T) !void {
    const big = std.mem.nativeTo(T, value, .big);
    const big_bytes = std.mem.asBytes(&big);

    const bits_needed = @bitSizeOf(T) - @clz(value);
    const needs_padding: u1 = if (value == 0)
        1
    else if (bits_needed > 8) brk: {
        const RightShift = std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(bits_needed)) - 1);
        const right_shift: RightShift = @intCast(bits_needed - 9);
        break :brk if (value >> right_shift == 0x1ff) 1 else 0;
    } else 0;
    const bytes_needed = try std.math.divCeil(usize, bits_needed, 8) + needs_padding;
    try self.length(bytes_needed);

    const writer_ = self.writer();
    if (needs_padding == 1) try writer_.writeByte(0);
    for (0..bytes_needed - needs_padding) |i| {
        try writer_.writeByte(big_bytes[big_bytes.len - i - 1]);
    }
}

test intLengthValue {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var encoder = Encoder.init(stream.writer().any());

    try encoder.intLengthValue(u8, 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0 }, stream.getWritten());

    stream.reset();
    try encoder.intLengthValue(u16, 0x00ff);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0xff }, stream.getWritten());

    stream.reset();
    try encoder.intLengthValue(u32, 0xffff);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 3, 0, 0xff, 0xff }, stream.getWritten());
}

const std = @import("std");
const Oid = @import("../Oid.zig");
const asn1 = @import("../asn1.zig");
const encodings = @import("../encodings.zig");
const Tag = encodings.Tag;
const FieldTag = encodings.FieldTag;
const Encoder = @This();
