tbs: ToBeSigned,
signature_algo: AlgorithmIdentifier,
signature: asn1.BitString,

pub const ToBeSigned = struct {
    version: Version = .v1,
    serial_number: SerialNumber,
    signature_algo: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_pub_key: PubKey,

    issuer_uid: ?asn1.BitString = null,
    subject_uid: ?asn1.BitString = null,
    extensions: ?Sequence = null,

    pub const asn1_tags = .{
        .version = FieldTag.explicit(0, .context_specific),
        .issuer_uid = FieldTag.implicit(1, .context_specific),
        .subject_uid = FieldTag.implicit(2, .context_specific),
        .extensions = FieldTag.explicit(3, .context_specific),
    };

    const Version = enum(u8) {
        v1 = 0,
        v2 = 1,
        v3 = 2,
        _,
    };

    const OctectString = asn1.Opaque(Asn1Tag.init(.octetstring, false, .universal));
    const sequence_tag = Asn1Tag.init(.sequence, true, .universal);
    const Sequence = asn1.Opaque(sequence_tag);
    const SerialNumber = asn1.Opaque(Asn1Tag.universal(.integer, false));
    const KeyIdentifier = OctectString;

    const Name = asn1.Opaque(Asn1Tag.universal(.sequence, true));

    const Validity = struct {
        not_before: DateTime,
        not_after: DateTime,

        const DateTime = struct {
            date: Date,
            time: Time,
            format: enum { generalized, utc } = .utc,

            fn init(
                year: Date.Year,
                month: Date.Month,
                day: Date.Day,
                hour: Time.Hour,
                minute: Time.Minute,
                second: Time.Second,
            ) DateTime {
                return .{ .date = Date.init(year, month, day), .time = Time.init(hour, minute, second) };
            }

            const Date = struct {
                year: Year,
                month: Month,
                day: Day,

                const Year = u16;
                const Month = std.time.epoch.Month;
                const Day = std.math.IntFittingRange(1, 31);

                pub fn init(year: Year, month: Month, day: Day) Date {
                    return .{ .year = year, .month = month, .day = day };
                }
            };

            const Time = struct {
                hour: Hour,
                minute: Minute,
                second: Second,

                const Hour = std.math.IntFittingRange(0, 23);
                const Minute = std.math.IntFittingRange(0, 59);
                const Second = std.math.IntFittingRange(0, 60);

                const DaySeconds = std.math.IntFittingRange(0, std.time.epoch.secs_per_day + 1);

                pub fn init(hour: Hour, minute: Minute, second: Second) Time {
                    return .{ .hour = hour, .minute = minute, .second = second };
                }
            };

            /// Follows RFC 5280 to disallow ambiguous representations and forces "Z".
            pub fn decodeDer(decoder: *der.Decoder) !DateTime {
                const ele = try decoder.element(ExpectedTag.init(null, false, .universal));
                const bytes = decoder.view(ele);
                switch (ele.tag.number) {
                    .utc_time => {
                        if (bytes.len != "yymmddHHmmssZ".len)
                            return error.InvalidDateTime;
                        if (bytes[bytes.len - 1] != 'Z')
                            return error.InvalidDateTime;

                        var date: Date = undefined;
                        date.year = try parseDigits(bytes[0..2], 0, 99);
                        // > Where YY is greater than or equal to 50, the year SHALL be
                        // > interpreted as 19YY; and
                        // > Where YY is less than 50, the year SHALL be interpreted as 20YY.
                        date.year += if (date.year >= 50) 1900 else 2000;
                        date.month = @enumFromInt(try parseDigits(bytes[2..4], 1, 12));
                        date.day = try parseDigits(bytes[4..6], 1, 31);

                        return .{ .date = date, .time = try parseTime(bytes[6..12]), .format = .generalized };
                    },
                    .generalized_time => {
                        if (bytes.len != "yyyymmddHHmmssZ".len)
                            return error.InvalidDateTime;
                        if (bytes[bytes.len - 1] != 'Z')
                            return error.InvalidDateTime;

                        var date: Date = undefined;
                        date.year = try parseYear4(bytes[0..4]);
                        date.month = @enumFromInt(try parseDigits(bytes[4..6], 1, 12));
                        date.day = try parseDigits(bytes[6..8], 1, 31);

                        return .{ .date = date, .time = try parseTime(bytes[8..14]), .format = .utc };
                    },
                    else => return error.InvalidDateTime,
                }
            }

            pub fn encodeDer(self: DateTime, encoder: *der.Encoder) !void {
                const date = self.date;
                const time = self.time;
                const year: u16 = if (date.year > 2000) date.year - 2000 else date.year - 1900;
                const args = .{ year, date.month.numeric(), date.day, time.hour, time.minute, time.second };
                var buffer: ["yyyymmddHHmmssZ".len]u8 = undefined;

                switch (self.format) {
                    .generalized => {
                        const fmt = "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z";
                        const bytes = try std.fmt.bufPrint(&buffer, fmt, args);
                        try encoder.tagBytes(Asn1Tag.universal(.utc_time, false), bytes);
                    },
                    .utc => {
                        const fmt = "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z";
                        const bytes = try std.fmt.bufPrint(&buffer, fmt, args);
                        try encoder.tagBytes(Asn1Tag.universal(.generalized_time, false), bytes);
                    },
                }
            }

            fn parseTime(bytes: *const [6]u8) !Time {
                return .{
                    .hour = try parseDigits(bytes[0..2], 0, 23),
                    .minute = try parseDigits(bytes[2..4], 0, 59),
                    .second = try parseDigits(bytes[4..6], 0, 60),
                };
            }

            fn parseDigits(
                text: *const [2]u8,
                min: comptime_int,
                max: comptime_int,
            ) !std.math.IntFittingRange(min, max) {
                const result = std.fmt.parseInt(std.math.IntFittingRange(min, max), text, 10) catch
                    return error.InvalidTime;
                if (result < min) return error.InvalidTime;
                if (result > max) return error.InvalidTime;
                return result;
            }

            test parseDigits {
                try expectEqual(@as(u8, 0), try parseDigits("00", 0, 99));
                try expectEqual(@as(u8, 99), try parseDigits("99", 0, 99));
                try expectEqual(@as(u8, 42), try parseDigits("42", 0, 99));
                try expectError(error.InvalidTime, parseDigits("13", 1, 12));
                try expectError(error.InvalidTime, parseDigits("00", 1, 12));
                try expectError(error.InvalidTime, parseDigits("Di", 0, 99));
            }

            fn parseYear4(text: *const [4]u8) !Date.Year {
                const result = std.fmt.parseInt(Date.Year, text, 10) catch return error.InvalidYear;
                if (result > 9999) return error.InvalidYear;
                return result;
            }

            test parseYear4 {
                try expectEqual(@as(Date.Year, 0), try parseYear4("0000"));
                try expectEqual(@as(Date.Year, 9999), try parseYear4("9999"));
                try expectEqual(@as(Date.Year, 1988), try parseYear4("1988"));
                try expectError(error.InvalidYear, parseYear4("999b"));
                try expectError(error.InvalidYear, parseYear4("crap"));
                try expectError(error.InvalidYear, parseYear4("r:bQ"));
            }
        };
    };

    const PubKey = struct {
        algorithm: Algorithm,
        key: asn1.BitString,

        const Algorithm = union(Tag) {
            rsa: void,
            ecdsa: NamedCurve,
            ed25519: void,

            const NamedCurve = AlgorithmIdentifier.Ecdsa.NamedCurve;

            const Tag = enum {
                rsa,
                ecdsa,
                ed25519,

                pub const oids = asn1.Oid.StaticMap(@This()).initComptime(.{
                    .rsa = "1.2.840.113549.1.1.1",
                    .ecdsa = "1.2.840.10045.2.1",
                    .ed25519 = "1.3.101.112",
                });
            };

            pub fn decodeDer(decoder: *der.Decoder) !Algorithm {
                const seq = try decoder.sequence();
                defer decoder.index = seq.slice.end;
                const tag = try decoder.any(Tag);
                switch (tag) {
                    .rsa => {
                        _ = try decoder.element(ExpectedTag.primitive(.null));
                        return .rsa;
                    },
                    .ecdsa => {
                        const curve = try decoder.any(NamedCurve);
                        return .{ .ecdsa = curve };
                    },
                    .ed25519 => return .ed25519,
                }
            }

            pub fn encodeDer(self: Algorithm, encoder: *der.Encoder) !void {
                switch (self) {
                    .rsa => try encoder.any(.{ Tag.rsa, null }),
                    .ecdsa => |curve| try encoder.any(.{ Tag.ecdsa, curve }),
                    .ed25519 => try encoder.any(.{Tag.ed25519}),
                }
            }
        };
    };

    pub fn extensionsIter(self: ToBeSigned) asn1.Iterator(Extension, der.Decoder) {
        const bytes = if (self.extensions) |exts| exts.bytes else "";
        return asn1.Iterator(Extension, der.Decoder){ .decoder = der.Decoder{ .bytes = bytes } };
    }

    pub fn extension(self: ToBeSigned, tag: Extension.Tag) !?Extension {
        var iter = self.extensionsIter();
        while (try iter.next()) |ext| {
            // int comparison safe because of `UnionTag`
            if (@intFromEnum(ext) == @intFromEnum(tag)) return ext;
        }
        return null;
    }

    const Extension = union(UnionTag) {
        key_usage: Known(KeyUsage),
        certificate_policies: Known(Sequence),
        subject_alt_name: Known(Sequence),
        basic_constraints: Known(BasicConstraints),
        key_usage_ext: Known(asn1.List(sequence_tag, KeyUsageExt, std.meta.tags(KeyUsageExt).len)),
        unknown: Unknown,

        pub fn decodeDer(decoder: *der.Decoder) !Extension {
            const ext = try decoder.any(Unknown);

            if (Tag.oids.oidToEnum(ext.tag.encoded)) |tag| {
                switch (tag) {
                    inline else => |t| {
                        const this_tag = comptime std.meta.stringToEnum(
                            std.meta.Tag(Extension),
                            @tagName(t),
                        ).?;
                        const T = std.meta.TagPayload(Extension, this_tag);
                        var decoder2 = der.Decoder{ .bytes = ext.value.bytes };
                        const value = try decoder2.any(std.meta.FieldType(T, .value));
                        const known = T{ .tag = t, .critical = ext.critical, .value = value };
                        return @unionInit(Extension, @tagName(t), known);
                    },
                }
            }
            try ext.expectNotCritical();
            return .{ .unknown = ext };
        }

        pub fn encodeDer(self: @This(), encoder: *der.Encoder) !void {
            switch (self) {
                inline else => |v| try encoder.any(v),
            }
        }

        const Tag = enum {
            // Parts of RFC 5280 4.2.1 relevant to TLS certificate validation.
            key_usage,
            certificate_policies,
            subject_alt_name,
            basic_constraints,
            key_usage_ext,

            pub const oids = asn1.Oid.StaticMap(@This()).initComptime(.{
                .key_usage = "2.5.29.15",
                .certificate_policies = "2.5.29.32",
                .subject_alt_name = "2.5.29.17",
                .basic_constraints = "2.5.29.19",
                .key_usage_ext = "2.5.29.37",
            });
        };

        /// Type that forces keeping this union up-to-date with `Tag`.
        const UnionTag = brk: {
            var info = @typeInfo(Tag).Enum;
            info.fields = info.fields ++ &[_]std.builtin.Type.EnumField{
                .{ .name = "unknown", .value = info.fields.len },
            };
            info.decls = &.{};
            break :brk @Type(.{ .Enum = info });
        };

        fn Known(comptime T: type) type {
            return struct {
                tag: Tag,
                critical: bool = false,
                value: T,

                pub fn encodeDer(self: @This(), encoder: *der.Encoder) !void {
                    const start = encoder.buffer.data.len;
                    try encoder.any(self);
                    try encoder.length(encoder.buffer.data.len - start);
                    try encoder.tag(Tag.init(.octetstring, false, .universal));
                }
            };
        }

        const Unknown = struct {
            tag: asn1.Oid,
            critical: bool = false,
            value: OctectString,

            fn expectNotCritical(self: Unknown) !void {
                if (self.critical) {
                    var buffer: [256]u8 = undefined;
                    var stream = std.io.fixedBufferStream(&buffer);
                    self.tag.toDot(stream.writer()) catch {};

                    log.err("critical unknown extension {s}", .{stream.getWritten()});
                    return error.UnimplementedCriticalExtension;
                }
            }
        };

        /// How `subject_pub_key` may be used.
        const KeyUsage = packed struct {
            encipher_only: bool = false,
            crl_sign: bool = false,
            key_cert_sign: bool = false,
            // MUST be false when basic_constraints.is_ca == false
            key_agreement: bool = false,
            data_encipherment: bool = false,
            key_encipherment: bool = false,
            content_commitment: bool = false,
            digital_signature: bool = false,

            decipher_only: bool = false,

            const Backing = @typeInfo(KeyUsage).Struct.backing_integer.?;
            const T = std.meta.Int(.unsigned, @sizeOf(KeyUsage) * 8);

            pub fn decodeDer(decoder: *der.Decoder) !KeyUsage {
                const key_usage = try decoder.any(asn1.BitString);
                if (key_usage.bitLen() > @bitSizeOf(KeyUsage)) return error.InvalidKeyUsage;

                const int = std.mem.readVarInt(Backing, key_usage.bytes, .big);
                return @bitCast(int);
            }

            pub fn encodeDer(self: KeyUsage, encoder: *der.Encoder) !void {
                const value: Backing = @bitCast(self);
                const oversized: T = value;
                var buffer: [@sizeOf(KeyUsage)]u8 = undefined;
                std.mem.writeInt(T, &buffer, oversized, .big);
                try encoder.any(asn1.BitString.init(&buffer));
            }
        };

        /// Further specifies how `subject_pub_key` may be used.
        pub const KeyUsageExt = enum {
            server_auth,
            client_auth,
            code_signing,
            email_protection,
            time_stamping,
            ocsp_signing,

            pub const oids = asn1.Oid.StaticMap(@This()).initComptime(.{
                .server_auth = "1.3.6.1.5.5.7.3.1",
                .client_auth = "1.3.6.1.5.5.7.3.2",
                .code_signing = "1.3.6.1.5.5.7.3.3",
                .email_protection = "1.3.6.1.5.5.7.3.4",
                .time_stamping = "1.3.6.1.5.5.7.3.8",
                .ocsp_signing = "1.3.6.1.5.5.7.3.9",
            });
        };

        /// Extension specifying if certificate is a CA and maximum number
        /// of non self-issued intermediate certificates that may follow this
        /// certificate in a valid certification path.
        pub const BasicConstraints = struct {
            is_ca: bool = false,
            /// MUST NOT include unless `is_ca`.
            max_path_len: ?PathLen = null,

            pub const PathLen = u16;
        };
    };
};

const AlgorithmIdentifier = union(enum) {
    rsa_pkcs: Hash,
    rsa_pss: RsaPss,
    ecdsa: Ecdsa,
    ed25519: void,

    // RFC 4055 S3.1
    const RsaPss = struct {
        hash: Hash = .sha1,
        mask_gen: MaskGen = .{ .tag = .mgf1, .hash = .sha256 },
        salt_len: u8 = 10,
        trailer: u8 = 1,

        pub const asn1_tags = .{
            .hash = FieldTag.explicit(0, .context_specific),
            .mask_gen = FieldTag.explicit(1, .context_specific),
            .salt_len = FieldTag.explicit(2, .context_specific),
            .trailer = FieldTag.explicit(3, .context_specific),
        };

        const MaskGen = struct {
            tag: MaskGen.Tag,
            hash: Hash,

            const Tag = enum {
                mgf1,

                pub const oids = asn1.Oid.StaticMap(@This()).initComptime(.{
                    .mgf1 = "1.2.840.113549.1.1.8",
                });
            };
        };
    };

    const Ecdsa = struct {
        hash: Hash,
        curve: NamedCurve,

        pub const NamedCurve = enum {
            prime256v1,
            secp256k1,
            secp384r1,
            secp521r1,

            pub const oids = asn1.Oid.StaticMap(@This()).initComptime(.{
                .prime256v1 = "1.2.840.10045.3.1.7",
                .secp256k1 = "1.3.132.0.10",
                .secp384r1 = "1.3.132.0.34",
                .secp521r1 = "1.3.132.0.35",
            });
        };
    };

    pub fn decodeDer(decoder: *der.Decoder) !AlgorithmIdentifier {
        const seq = try decoder.sequence();
        defer decoder.index = seq.slice.end;

        const algo = try decoder.any(Tag);
        switch (algo) {
            inline .rsa_pkcs_sha1,
            .rsa_pkcs_sha224,
            .rsa_pkcs_sha256,
            .rsa_pkcs_sha384,
            .rsa_pkcs_sha512,
            => |t| {
                _ = try decoder.element(ExpectedTag.primitive(.null));
                const hash = std.meta.stringToEnum(Hash, @tagName(t)["rsa_pkcs_".len..]).?;
                return .{ .rsa_pkcs = hash };
            },
            .rsa_pss => return .{ .rsa_pss = try decoder.any(RsaPss) },
            inline .ecdsa_sha224,
            .ecdsa_sha256,
            .ecdsa_sha384,
            .ecdsa_sha512,
            => |t| {
                const curve = try decoder.any(Ecdsa.NamedCurve);
                return .{ .ecdsa = Ecdsa{
                    .hash = std.meta.stringToEnum(Hash, @tagName(t)["ecdsa_".len..]).?,
                    .curve = curve,
                } };
            },
            .ed25519 => return .{ .ed25519 = {} },
        }
    }

    pub fn encodeDer(self: AlgorithmIdentifier, encoder: *der.Encoder) !void {
        switch (self) {
            .rsa_pkcs => |info| {
                const algo = switch (info) {
                    inline else => |t| std.meta.stringToEnum(Tag, "rsa_pkcs_" ++ @tagName(t)).?,
                };
                try encoder.any(.{ algo, null });
            },
            .rsa_pss => |info| try encoder.any(.{ Tag.rsa_pss, info }),
            .ecdsa => |info| {
                const algo = switch (info.hash) {
                    .sha1 => unreachable,
                    inline else => |t| std.meta.stringToEnum(Tag, "ecdsa_" ++ @tagName(t)).?,
                };
                try encoder.any(.{ algo, info.curve });
            },
            .ed25519 => try encoder.any(.{Tag.ed25519}),
        }
    }

    const Tag = enum {
        rsa_pkcs_sha1,
        rsa_pkcs_sha256,
        rsa_pkcs_sha384,
        rsa_pkcs_sha512,
        rsa_pkcs_sha224,
        rsa_pss,
        ecdsa_sha224,
        ecdsa_sha256,
        ecdsa_sha384,
        ecdsa_sha512,
        ed25519,

        pub const oids = asn1.Oid.StaticMap(@This()).initComptime(.{
            .rsa_pkcs_sha1 = "1.2.840.113549.1.1.5",
            .rsa_pkcs_sha256 = "1.2.840.113549.1.1.11",
            .rsa_pkcs_sha384 = "1.2.840.113549.1.1.12",
            .rsa_pkcs_sha512 = "1.2.840.113549.1.1.13",
            .rsa_pkcs_sha224 = "1.2.840.113549.1.1.14",
            .rsa_pss = "1.2.840.113549.1.1.10",
            .ecdsa_sha224 = "1.2.840.10045.4.3.1",
            .ecdsa_sha256 = "1.2.840.10045.4.3.2",
            .ecdsa_sha384 = "1.2.840.10045.4.3.3",
            .ecdsa_sha512 = "1.2.840.10045.4.3.4",
            .ed25519 = "1.3.101.112",
        });
    };

    const Hash = enum {
        sha1,
        sha256,
        sha384,
        sha512,
        sha224,

        pub const oids = asn1.Oid.StaticMap(@This()).initComptime(.{
            .sha1 = "1.3.14.3.2.26",
            .sha256 = "2.16.840.1.101.3.4.2.1",
            .sha384 = "2.16.840.1.101.3.4.2.2",
            .sha512 = "2.16.840.1.101.3.4.2.3",
            .sha224 = "2.16.840.1.101.3.4.2.4",
        });
    };
};

const std = @import("std");
const asn1 = @import("./asn1.zig");
const der = asn1.der;
const Asn1Tag = asn1.encodings.Tag;
const ExpectedTag = asn1.encodings.ExpectedTag;
const FieldTag = asn1.encodings.FieldTag;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const comptimeOid = asn1.Oid.encodeComptime;
const log = std.log.scoped(.certificate);
