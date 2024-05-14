const std = @import("std");
const asn1 = @import("./asn1.zig");
const hexToBytes = @import("./encodings.zig").hexToBytes;
const Certificate = @import("./Certificate.zig");

const der = asn1.der;
const Tag = asn1.encodings.Tag;
const FieldTag = asn1.encodings.FieldTag;

const AllTypes = struct {
    a: u8 = 0,
    b: asn1.BitString,
    c: C,
    d: asn1.Opaque(.{ .number = .string_utf8 }),
    e: asn1.Opaque(.{ .number = .octetstring }),
    f: ?u16,
    g: ?Nested,
    h: asn1.List(.{ .number = .sequence, .constructed = true }, C, 2),
    i: asn1.Any,

    pub const asn1_tags = .{
        .a = FieldTag.explicit(0, .context_specific),
        .b = FieldTag.explicit(1, .context_specific),
        .c = FieldTag.implicit(2, .context_specific),
        .g = FieldTag.implicit(3, .context_specific),
    };

    const C = enum {
        a,
        b,

        pub const oids = asn1.Oid.StaticMap(@This()).initComptime(.{
            .a = "1.2.3.4",
            .b = "1.2.3.5",
        });
    };

    const Nested = struct {
        inner: Asn1T,
        sum: i16,

        const Asn1T = struct { a: u8, b: i16 };

        pub fn decodeDer(decoder: *der.Decoder) !Nested {
            const inner = try decoder.any(Asn1T);
            return Nested{ .inner = inner, .sum = inner.a + inner.b };
        }

        pub fn encodeDer(self: Nested, encoder: *der.Encoder) !void {
            try encoder.any(self.inner);
        }
    };
};

test AllTypes {
    const expected = AllTypes{
        .a = 2,
        .b = asn1.BitString{ .bytes = &hexToBytes("04a0") },
        .c = .a,
        .d = .{ .bytes = "asdf" },
        .e = .{ .bytes = "fdsa" },
        .f = (1 << 8) + 1,
        .g = .{ .inner = .{ .a = 4, .b = 5 }, .sum = 9 },
        .h = .{ .len = 2, .items = [_]AllTypes.C{ .a, .b } },
        .i = .{ .tag = Tag.init(.string_ia5, false, .universal), .bytes = "asdf" },
    };
    const path = "./der/testdata/all_types.der";
    const encoded = @embedFile(path);
    const actual = try asn1.der.decode(AllTypes, encoded);
    try std.testing.expectEqualDeep(expected, actual);

    const allocator = std.testing.allocator;
    const buf = try asn1.der.encode(allocator, expected);
    defer allocator.free(buf);
    try std.testing.expectEqualSlices(u8, encoded, buf);

    // Use this to update test file.
    // const dir = try std.fs.cwd().openDir("src", .{});
    // var file = try dir.createFile(path, .{});
    // defer file.close();
    // try file.writeAll(buf);
}

fn testCertificate(comptime path: []const u8) !void {
    const encoded = @embedFile(path);
    const cert = try asn1.der.decode(Certificate, encoded);

    const allocator = std.testing.allocator;
    const actual = try asn1.der.encode(allocator, cert);
    defer allocator.free(actual);

    // If the below test fails, use this to create debug files that can be
    // viewed with another DER parser.
    // const dir = try std.fs.cwd().openDir("src", .{});
    // var file = try dir.createFile(path ++ ".debug", .{});
    // defer file.close();
    // try file.writeAll(stream.getWritten());
    try std.testing.expectEqualSlices(u8, encoded, actual);
}

test Certificate {
    try testCertificate("./der/testdata/cert_rsa2048.der");
    // try testCertificate("./der/testdata/cert_ecc256.der");
}
