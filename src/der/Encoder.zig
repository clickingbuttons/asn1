const std = @import("std");
const Oid = @import("../Oid.zig");
const asn1 = @import("../asn1.zig");
const encodings = @import("../encodings.zig");
const Tag = encodings.Tag;

pub fn encodeAny(value: anytype, writer: anytype) !void {
    const T = @TypeOf(value);
    if (std.meta.hasFn(T, "encodeDer")) return try value.encodeDer(writer);

    switch (@typeInfo(T)) {
        .Struct => {
            var counting_writer = std.io.countingWriter(std.io.null_writer);
            inline for (std.meta.fields(T)) |f| {
                try encodeAny(@field(value, f.name), counting_writer.writer());
            }
            const seq_tag: encodings.Tag = .{ .number = .sequence, .constructed = true };
            try tagLength(writer, seq_tag, counting_writer.bytes_written);

            inline for (std.meta.fields(T)) |f| try encodeAny(@field(value, f.name), writer);
        },
        .Bool => try @"bool"(writer, value),
        .Int => try int(writer, T, value, .integer),
        .Enum => |e| try int(
            writer,
            e.tag_type,
            @intFromEnum(value),
            if (e.is_exhaustive) .integer else .enumerated,
        ),
        .Optional => if (value) |v| try encodeAny(v, writer),
        else => @compileError("cannot encode type " ++ @typeName(T)),
    }
}

fn @"bool"(writer: anytype, val: bool) !void {
    try tagLength(writer, .{ .number = .boolean }, 1);
    try writer.writeByte(if (val) 0xff else 0);
}

fn int(writer: anytype, comptime T: type, value: T, number: Tag.Number) !void {
    if (@typeInfo(T).Int.bits % 8 != 0) @compileError(@typeName(T) ++ " must be byte aligned");
    const bits_needed = if (value <= 1) 1 else std.math.log2_int_ceil(usize, @intCast(value));
    const needs_padding: u1 = if (@clz(~value) > 8) 1 else 0;
    const bytes_needed = try std.math.divCeil(usize, bits_needed, 8) + needs_padding;
    try tagLength(writer, .{ .number = number }, bytes_needed);

    const big = std.mem.nativeTo(T, value, .big);
    const big_bytes = std.mem.asBytes(&big);
    if (needs_padding == 1) try writer.writeByte(0);
    for (0..bytes_needed - needs_padding) |i| {
        try writer.writeByte(big_bytes[big_bytes.len - i - 1]);
    }
}

test int {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    try int(writer, u8, 0, .integer);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 2, 1, 0 }, stream.getWritten());

    stream.reset();
    try int(writer, u16, 0xffff, .integer);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        2,
        3,
        0,
        0xff,
        0xff,
    }, stream.getWritten());
}

pub fn tagLength(writer: anytype, tag: Tag, len: usize) !void {
    try tag.encode(writer);
    if (len < 128) {
        try writer.writeInt(u8, @intCast(len), .big);
        return;
    }
    inline for ([_]type{ u8, u16, u32 }) |T| {
        if (len < std.math.maxInt(T)) {
            try writer.writeInt(T, @sizeOf(T), .big);
            try writer.writeInt(T, @intCast(len), .big);
            return;
        }
    }
    return error.InvalidLength;
}
