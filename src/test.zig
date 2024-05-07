const std = @import("std");
const asn1 = @import("./asn1.zig");
const hexToBytes = @import("./encodings.zig").hexToBytes;
const Certificate = @import("./Certificate.zig");

const comptimeOid = asn1.Oid.encodeComptime;
const der = asn1.der;

const AllTypes = struct {
    a: u8,
    b: i16,
    c: i32,
    d: i64,
    bitstring: asn1.BitString,
    oid: asn1.Oid,
    string: asn1.String,
    @"opaque": asn1.Opaque(.{ .number = .octetstring }),
    optional: ?u8 = null,
    nested: Nested,

    const Nested = struct {
        a: u8,
        b: i16,
    };
};

test AllTypes {
    const expected = AllTypes{
        .a = 0,
        .b = 1,
        .c = (1 << 8) + 1,
        .d = (1 << 16) + 1,
        .bitstring = asn1.BitString{ .bytes = &hexToBytes("04a0") },
        .oid = asn1.Oid{ .encoded = &comptimeOid("1.2.3.4") },
        .string = asn1.String{ .tag = .utf8, .data = "asdf" },
        .@"opaque" = .{ .bytes = "fdsa" },
        .optional = null,
        .nested = .{
            .a = 4,
            .b = 5,
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

    // const dir = try std.fs.cwd().openDir("src", .{});
    // var file = try dir.createFile(path, .{});
    // defer file.close();
    // try file.writeAll(stream.getWritten());
}

test Certificate {
    const encoded = @embedFile("./der/testdata/cert_rsa2048.der");
    const cert = try asn1.der.decode(Certificate, encoded);
    // std.debug.print("{}\n", .{cert});

    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try asn1.der.encode(cert, stream.writer());
    try std.testing.expectEqualSlices(u8, encoded, stream.getWritten());
}
