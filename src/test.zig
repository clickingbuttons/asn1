const std = @import("std");
const asn1 = @import("./asn1.zig");
const hexToBytes = @import("./encodings.zig").hexToBytes;
const Certificate = @import("./Certificate.zig");

const comptimeOid = asn1.Oid.encodeComptime;
const der = asn1.der;
const FieldTag = asn1.encodings.FieldTag;

const AllTypes = struct {
    a: u8 = 0,
    b: asn1.BitString,
    c: asn1.Oid,
    d: asn1.String,
    e: asn1.Opaque(.{ .number = .octetstring }),
    f: ?u16,
    g: ?Nested,

    pub const asn1_tags = .{
        .a = FieldTag.explicit(0, .context_specific),
        .b = FieldTag.explicit(1, .context_specific),
        .c = FieldTag.implicit(2, .context_specific),
        .g = FieldTag.implicit(3, .context_specific),
    };

    const Nested = struct {
        a: u8,
        b: i16,
        sum: i16,

        const Asn1T = struct {
            a: u8,
            b: i16,
        };

        pub fn decodeDer(decoder: *der.Decoder) !Nested {
            const inner = try decoder.expect(Asn1T);
            return Nested{
                .a = inner.a,
                .b = inner.b,
                .sum = inner.a + inner.b,
            };
        }

        pub fn encodeDer(self: Nested, encoder: *der.Encoder) !void {
            const inner = Asn1T{ .a = self.a, .b = self.b };
            try encoder.any(inner);
        }
    };
};

test AllTypes {
    const expected = AllTypes{
        .a = 2,
        .b = asn1.BitString{ .bytes = &hexToBytes("04a0") },
        .c = asn1.Oid{ .encoded = &comptimeOid("1.2.3.4") },
        .d = asn1.String{ .tag = .utf8, .data = "asdf" },
        .e = .{ .bytes = "fdsa" },
        .f = (1 << 8) + 1,
        .g = .{
            .a = 4,
            .b = 5,
            .sum = 9,
        },
    };
    const path = "./der/testdata/all_types.der";
    const encoded = @embedFile(path);
    const actual = try asn1.der.decode(AllTypes, encoded);
    try std.testing.expectEqualDeep(expected, actual);

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try asn1.der.encode(expected, stream.writer());
    try std.testing.expectEqualSlices(u8, encoded, stream.getWritten());

    // Use this to update test file.
    // const dir = try std.fs.cwd().openDir("src", .{});
    // var file = try dir.createFile(path, .{});
    // defer file.close();
    // try file.writeAll(stream.getWritten());
}

// test Certificate {
//     const encoded = @embedFile("./der/testdata/cert_rsa2048.der");
//     const cert = try asn1.der.decode(Certificate, encoded);
//     // std.debug.print("{}\n", .{cert});
//
//     var buf: [4096]u8 = undefined;
//     var stream = std.io.fixedBufferStream(&buf);
//     try asn1.der.encode(cert, stream.writer());
//     try std.testing.expectEqualSlices(u8, encoded, stream.getWritten());
// }
