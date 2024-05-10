//! Globally unique hierarchical identifier made of a sequence of integers.
//!
//! Commonly used to identify standards, algorithms, certificate extensions,
//! organizations, or policy documents.

/// The ASN.1 defined bytes.
encoded: []const u8,

pub const InitError = std.fmt.ParseIntError || error{MissingPrefix} || std.io.FixedBufferStream(u8).WriteError;
pub fn fromDot(dot_notation: []const u8, out: []u8) InitError!Oid {
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

    return .{ .encoded = stream.getWritten() };
}

test fromDot {
    var buf: [256]u8 = undefined;
    for (test_cases) |t| {
        const actual = try fromDot(t.dot_notation, &buf);
        try std.testing.expectEqualSlices(u8, t.encoded, actual.encoded);
    }
}

pub fn toDot(self: Oid, writer: anytype) @TypeOf(writer).Error!void {
    const encoded = self.encoded;
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
        try toDot(Oid{ .encoded = t.encoded }, stream.writer());
        try std.testing.expectEqualStrings(t.dot_notation, stream.getWritten());
    }
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
    TestCase.init("2a864886f70d", "1.2.840.113549"),
    // https://www.sysadmins.lv/blog-en/how-to-encode-object-identifier-to-an-asn1-der-encoded-string.aspx
    TestCase.init("2a868d20", "1.2.100000"),
    TestCase.init("2a864886f70d01010b", "1.2.840.113549.1.1.11"),
    TestCase.init("2b6570", "1.3.101.112"),
};

const asn1_tag = encodings.Tag.init(.oid, false, .universal);

pub fn decodeDer(decoder: *der.Decoder) !Oid {
    const ele = try decoder.element(asn1_tag.toExpected());
    return Oid{ .encoded = decoder.view(ele) };
}

pub fn encodeDer(self: Oid, encoder: *der.Encoder) !void {
    try encoder.tag(asn1_tag);
    try encoder.length(self.encoded.len);
    try encoder.writer().writeAll(self.encoded);
}

fn encodedLen(dot_notation: []const u8) usize {
    var buf: [256]u8 = undefined;
    const oid = fromDot(dot_notation, &buf) catch unreachable;
    return oid.encoded.len;
}

pub fn encodeComptime(comptime dot_notation: []const u8) [encodedLen(dot_notation)]u8 {
    @setEvalBranchQuota(4000);
    comptime var buf: [256]u8 = undefined;
    const oid = comptime fromDot(dot_notation, &buf) catch unreachable;
    return oid.encoded[0..oid.encoded.len].*;
}

test encodeComptime {
    try std.testing.expectEqual(
        hexToBytes("2b0601040182371514"),
        comptime encodeComptime("1.3.6.1.4.1.311.21.20"),
    );
}

pub fn Enum(comptime key_pairs: anytype) type {
    var enum_fields: [key_pairs.len]std.builtin.Type.EnumField = undefined;
    comptime for (key_pairs, 0..) |kp, i| {
        enum_fields[i] = std.builtin.Type.EnumField{ .name = @tagName(kp.@"1"), .value = i };
    };

    const EnumT = @Type(std.builtin.Type{
        .Enum = .{
            .tag_type = u8,
            .fields = &enum_fields,
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_exhaustive = true,
        },
    });

    const KeyPair = struct { []const u8, EnumT };
    comptime var static_key_pairs: [key_pairs.len]KeyPair = undefined;
    comptime for (key_pairs, 0..) |kp, i| {
        static_key_pairs[i] = .{ &encodeComptime(kp.@"0"), kp.@"1" };
    };

    return struct {
        pub const Enum = EnumT;

        pub const oids = std.StaticStringMap(EnumT).initComptime(static_key_pairs);

        pub fn oid(value: EnumT) Oid {
            return switch (value) {
                inline else => |v| {
                    inline for (key_pairs, 0..) |kp, i| {
                        if (kp.@"1" == v) return Oid{ .encoded = static_key_pairs[i].@"0" };
                    }
                    unreachable;
                },
            };
        }
    };
}

test Enum {
    const T = Enum(.{
        .{ "1.2.840.113549.1.1.5", .rsa_pkcs_sha1 },
        .{ "1.2.840.113549.1.1.10", .rsa_pss },
        .{ "1.2.840.113549.1.1.11", .rsa_pkcs_sha256 },
        .{ "1.2.840.113549.1.1.12", .rsa_pkcs_sha384 },
        .{ "1.2.840.113549.1.1.13", .rsa_pkcs_sha512 },
        .{ "1.2.840.113549.1.1.14", .rsa_pkcs_sha224 },
        .{ "1.2.840.10045.4.3.1", .ecdsa_sha224 },
        .{ "1.2.840.10045.4.3.2", .ecdsa_sha256 },
        .{ "1.2.840.10045.4.3.3", .ecdsa_sha384 },
        .{ "1.2.840.10045.4.3.4", .ecdsa_sha512 },
        .{ "1.3.101.112", .ed25519 },
    });
    try std.testing.expectEqual(.ed25519, T.oids.get(&encodeComptime("1.3.101.112")));
    try std.testing.expectEqual(Oid{ .encoded = &[_]u8{ 43, 101, 112 } }, T.oid(.ed25519));
}

const std = @import("std");
const Oid = @This();
const Arc = u32;
const encoding_base = 128;
const Allocator = std.mem.Allocator;
const encodings = @import("./encodings.zig");
const hexToBytes = encodings.hexToBytes;
const der = @import("./der.zig");
