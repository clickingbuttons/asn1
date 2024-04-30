//! Globally unique hierarchical identifiers made of a sequence of integers.
//!
//! Commonly used to identify standards, algorithms, certificate extensions,
//! organizations, or policy documents.

pub const InitError = std.fmt.ParseIntError || error{ MissingPrefix } || std.io.FixedBufferStream(u8).WriteError;

pub fn fromDot(dot_notation: []const u8, out: []u8) InitError![]const u8 {
    var split = std.mem.splitScalar(u8, dot_notation, '.');
    const first_str = split.next() orelse return error.MissingPrefix;
    const second_str = split.next() orelse return error.MissingPrefix;

    const first = try std.fmt.parseInt(u8, first_str, 10);
    const second = try std.fmt.parseInt(u8, second_str, 10);

    var stream = std.io.fixedBufferStream(out);
    var writer = stream.writer();

    try writer.writeByte(first * 40 + second);

    var i: usize = 1;
    while (split.next()) |s| {
        var parsed = try std.fmt.parseUnsigned(Arc, s, 10);
        const n_bytes = if (parsed == 0) 0 else std.math.log(Arc, encoding_base, parsed);

        for (0..n_bytes) |j| {
            const place = std.math.pow(Arc, encoding_base, n_bytes - @as(Arc, @intCast(j)));
            const digit: u8 = @intCast(@divFloor(parsed, place));

            try writer.writeByte(digit | 0x80);
            parsed -= digit * place;

            i += 1;
        }
        try writer.writeByte(@intCast(parsed));
        i += 1;
    }

    return stream.getWritten();
}

test fromDot {
    var buf: [256]u8 = undefined;
    for (test_cases) |t| {
        const actual = try fromDot(t.dot_notation, &buf);
        try std.testing.expectEqualSlices(u8, t.encoded, actual);
    }
}

pub fn toDot(encoded: []const u8, writer: anytype) @TypeOf(writer).Error!void {
    const first = @divTrunc(encoded[0], 40);
    const second = encoded[0] - first * 40;
    try writer.print("{d}.{d}", .{ first, second });

    var i: usize = 1;
    while (i != encoded.len) {
        const n_bytes: usize = brk: {
            var res: usize = 1;
            var j: usize = i;
            while (encoded[j] & 0x80 != 0) {
                res += 1;
                j += 1;
            }
            break :brk res;
        };

        var n: usize = 0;
        for (0..n_bytes) |j| {
            const place = std.math.pow(usize, encoding_base, n_bytes - j - 1);
            n += place * (encoded[i] & 0b01111111);
            i += 1;
        }
        try writer.print(".{d}", .{n});
    }
}

test toDot {
    var buf: [256]u8 = undefined;

    for (test_cases) |t| {
        var stream = std.io.fixedBufferStream(&buf);
        try toDot(t.encoded, stream.writer());
        try std.testing.expectEqualStrings(t.dot_notation, stream.getWritten());
    }
}

fn testOid(expected_encoded: []const u8, expected_dot_notation: []const u8) !void {
    const allocator = std.testing.allocator;
    const oid = try fromDot(allocator, expected_dot_notation);
    defer oid.deinit(allocator);
    try std.testing.expectEqualSlices(u8, expected_encoded, oid.bytes);

    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try oid.toDot(stream.writer());
    try std.testing.expectEqualStrings(expected_dot_notation, stream.getWritten());
}

const TestCase = struct {
    encoded: []const u8,
    dot_notation: []const u8,

    pub fn init(comptime hex: []const u8, dot_notation: []const u8) TestCase {
        return .{ .encoded = &hexToBytes(hex), .dot_notation = dot_notation };
    }
};

const test_cases = [_]TestCase{
    // https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
    TestCase.init("2b0601040182371514", "1.3.6.1.4.1.311.21.20"),
    // https://luca.ntop.org/Teaching/Appunti/asn1.html
    TestCase.init("2a864886f70d",  "1.2.840.113549"),
    // https://www.sysadmins.lv/blog-en/how-to-encode-object-identifier-to-an-asn1-der-encoded-string.aspx
    TestCase.init("2a868d20", "1.2.100000"),
    TestCase.init("2a864886f70d01010b", "1.2.840.113549.1.1.11"),
    TestCase.init("2b6570", "1.3.101.112"),
};

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var res: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&res, hex) catch unreachable;
    return res;
}

fn encodedLen(dot_notation: []const u8) usize {
    var buf: [256]u8 = undefined;
    const oid = fromDot(dot_notation, &buf) catch unreachable;
    return oid.len;
}

pub fn encodeComptime(comptime dot_notation: []const u8) [encodedLen(dot_notation)]u8 {
    comptime var buf: [256]u8 = undefined;
    const oid = comptime fromDot(dot_notation, &buf) catch unreachable;
    return oid[0..oid.len].*;
}

test encodeComptime {
    try std.testing.expectEqual(
        hexToBytes("2b0601040182371514"),
        comptime encodeComptime("1.3.6.1.4.1.311.21.20"),
    );
}

const std = @import("std");
const Oid = @This();
const Arc = u32;
const encoding_base = 128;
const Allocator = std.mem.Allocator;
