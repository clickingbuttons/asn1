//! A DER encoder which encodes elements in reverse order.
//! This allows encoding variable-length element prefixes without extra memcpys.
buf: ArrayListReverse,
indices: std.BoundedArray(asn1.Index, max_indices) = .{},

pub fn init(allocator: std.mem.Allocator) Encoder {
    return .{ .buf = ArrayListReverse.init(allocator) };
}

pub fn deinit(self: *Encoder) void {
    self.buf.deinit();
}

pub fn startLength(self: *Encoder) !void {
    try self.indices.append(@intCast(self.buf.data.len));
}

pub fn length(self: *Encoder, identifer: Identifier) !void {
    const start = self.indices.pop();
    try self.element(identifer, self.buf.data.len - start);
}

pub fn sequence(self: *Encoder) !void {
    try self.length(.{ .tag = .sequence, .constructed = true });
}

pub fn @"bool"(self: *Encoder, val: bool) !void {
    try self.buf.prependByte(if (val) 0xff else 0);
    try self.element(.{ .tag = .boolean }, 1);
}

pub fn bitstring(self: *Encoder, bs: asn1.BitString) !void {
    try self.buf.prependSlice(bs.bytes);
    try self.buf.prependByte(bs.right_padding);
    try self.element(.{ .tag = .bitstring }, bs.bytes.len + 1);
}

pub fn octetstring(self: *Encoder, octets: []const u8) !void {
    try self.buf.prependSlice(octets);
    try self.element(.{ .tag = .octetstring });
}

pub fn integer(self: *Encoder, comptime T: type, value: T) !void {
    try self.buf.writer().writeInt(T, value, .big);
    try self.element(.{ .tag = .integer }, @sizeOf(T));
}

pub fn string(self: *Encoder, s: asn1.String) !void {
    try self.buf.prependSlice(s.data);

    const tag : Identifier.Tag = switch (s.tag) {
        inline else => |t| std.meta.stringToEnum(Identifier.Tag, "string_" ++ @tagName(t)).?,
    };
    try self.element(.{ .tag = tag }, s.data.len);
}

pub fn oid(self: *Encoder, encoded: []const u8) !void {
    try self.buf.prependSlice(encoded);
    try self.element(.{ .tag = .object_identifier }, encoded.len);
}

pub fn comptimeOid(self: *Encoder, comptime dot_notation: []const u8) !void {
    const encoded = comptime oid_mod.encodeComptime(dot_notation);
    try self.oid(&encoded);
}

pub fn anyOid(self: *Encoder, value: anytype) !void {
    const encoded = value.oid();
    try self.oid(&encoded);
}

pub const DateTimeFormat = enum {
    /// Range 1950 to 2050.
    utc,
    /// No fractional seconds, always Zulu
    generalized,
    /// ISO 8601 compliant
    date_time,
};

pub fn dateTime(self: *Encoder, date_time: asn1.DateTime, format: DateTimeFormat) !void {
    var buf: ["yyyy-mm-ddTHH:mm:ssZ".len]u8 = undefined;
    const date = date_time.date;
    const time = date_time.time;
    const args = .{ date.year, date.month.numeric(), date.day, time.hour, time.minute, time.second };
    const bytes = switch (format) {
        .utc => std.fmt.bufPrint(&buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", args),
        .generalized => std.fmt.bufPrint(&buf, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", args),
        .date_time => std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", args),
    } catch unreachable;
    try self.buf.prependSlice(bytes);
    const tag: Identifier.Tag = switch (format) {
        .utc => .utc_time,
        .generalized => .generalized_time,
        .date_time => .date_time,
    };
    try self.element(tag, bytes.len);
}

pub fn element(self: *Encoder, identifier: Identifier, len: usize) !void {
    var writer = self.buf.writer();
    len: {
        if (len < 128) {
            try writer.writeInt(u8, @intCast(len), .big);
            break :len;
        }
        inline for ([_]type{u8, u16, u32}) |T| {
            if (len < std.math.maxInt(T)) {
                try writer.writeInt(T, @sizeOf(T), .big);
                try writer.writeInt(T, @intCast(len), .big);
                break :len;
            }
        }
        return error.InvalidLength;
    }
    try writer.writeByte(@bitCast(identifier));
}

pub fn toOwnedSlice(self: *Encoder) ![]u8 {
    return try self.buf.toOwnedSlice();
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var res: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&res, hex) catch unreachable;
    return res;
}

test Encoder {
    const allocator = std.testing.allocator;
    var  e = Encoder.init(allocator);
    defer e.deinit();

    {
        try e.startLength();
        try e.string(asn1.String{ .tag = .printable, .data = "aaa" });
        {
            try e.startLength();
            try e.startLength();
            try e.integer(u8, 6);
            try e.integer(u8, 5);
            try e.sequence();
            try e.buf.prependByte(0);
            try e.length(.{ .tag = .bitstring });
        }

        {
            try e.startLength();
            try e.startLength();
            try e.integer(u8, 4);
            try e.integer(u8, 3);
            try e.sequence();
            try e.length(.{ .tag = .octetstring });
        }
        try e.sequence();
    }

    try std.testing.expectEqualSlices(u8, @embedFile("./testdata/int_strings.der"), e.buf.data);
}

test "Encoder id_ecc.pub" {
    const allocator = std.testing.allocator;
    var  e = Encoder.init(allocator);
    defer e.deinit();

    {
        try e.startLength();
        try e.bitstring(.{
            .bytes =&hexToBytes("04a01532a3c0900053de60fbefefcca58793301598d308b41e6f4e364e388c2711bef432c599148c94143d4ff46c2cb73e3e6a41d7eef23c047ea11e60667de425"),
        });
        try std.testing.expectEqual(1, e.indices.len);
        {
            try e.startLength();
            try std.testing.expectEqual(2, e.indices.len);
            try e.comptimeOid("1.2.840.10045.3.1.7");
            try e.comptimeOid("1.2.840.10045.2.1");
            try e.sequence();
        }

        try e.sequence();
    }

    try std.testing.expectEqualSlices(u8, @embedFile("./testdata/id_ecc.pub.der"), e.buf.data);
}

test dateTime {
    const allocator = std.testing.allocator;
    var  e = Encoder.init(allocator);
    defer e.deinit();

    {
        try e.startLength();
        try e.dateTime(asn1.DateTime.init(1970, .jan, 1, 0, 0, 0), .utc);
        try e.dateTime(asn1.DateTime.init(1970, .jan, 1, 0, 0, 0), .generalized);
        try e.dateTime(asn1.DateTime.init(1970, .jan, 1, 0, 0, 0), .date_time);
        try e.sequence();
    }

    try std.testing.expectEqualSlices(u8, @embedFile("./testdata/id_ecc.pub.der"), e.buf.data);
}

const std = @import("std");
const oid_mod = @import("../oid.zig");
const asn1 = @import("../asn1.zig");
const ArrayListReverse = @import("./ArrayListReverse.zig");
const Encoder = @This();
const Identifier = asn1.Identifier;
const max_indices = 20;
