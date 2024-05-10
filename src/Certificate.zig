tbs: ToBeSigned,
signature_algo: AlgorithmIdentifier,
signature: asn1.BitString,

pub const ToBeSigned = struct {
    version: Version = .v1,
    serial_number: asn1.Opaque(.{ .number = .integer }),
    signature_algo: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_pub_key: PubKey,

    issuer_uid: ?asn1.BitString = null,
    subject_uid: ?asn1.BitString = null,
    extensions: Extensions = .{},

    pub const asn1_implicit = .{
        .version = asn1.FieldTag{ .number = 0 },
        .issuer_uid = asn1.FieldTag{ .number = 1 },
        .subject_uid = asn1.FieldTag{ .number = 2 },
        .extensions = asn1.FieldTag{ .number = 3 },
    };

    pub const Version = enum(u8) {
        v1 = 0,
        v2 = 1,
        v3 = 2,
        _,
    };

    const Name = asn1.Opaque(.{ .number = .sequence, .constructed = true });

    pub const Validity = struct {
        not_before: DateTime,
        not_after: DateTime,

        pub const DateTime = struct {
            date: Date,
            time: Time,

            pub fn init(
                year: Date.Year,
                month: Date.Month,
                day: Date.Day,
                hour: Time.Hour,
                minute: Time.Minute,
                second: Time.Second,
            ) DateTime {
                return .{ .date = Date.init(year, month, day), .time = Time.init(hour, minute, second) };
            }

            pub const Date = struct {
                year: Year,
                month: Month,
                day: Day,

                pub const Year = u16;
                pub const Month = std.time.epoch.Month;
                pub const Day = std.math.IntFittingRange(1, 31);

                pub fn init(year: Year, month: Month, day: Day) Date {
                    return .{ .year = year, .month = month, .day = day };
                }
            };

            pub const Time = struct {
                hour: Hour,
                minute: Minute,
                second: Second,

                const Hour = std.math.IntFittingRange(0, 23);
                const Minute = std.math.IntFittingRange(0, 59);
                const Second = std.math.IntFittingRange(0, 60);

                pub const DaySeconds = std.math.IntFittingRange(0, std.time.epoch.secs_per_day + 1);

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

                        return .{ .date = date, .time = try parseTime(bytes[6..12]) };
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

                        return .{ .date = date, .time = try parseTime(bytes[8..14]) };
                    },
                    else => return error.InvalidDateTime,
                }
            }

            pub fn encodeDer(self: DateTime, encoder: *der.Encoder) !void {
                const date = self.date;
                const time = self.time;

                try encoder.tagLength(.{ .number = .utc_time }, "yymmddHHmmssZ".len);
                const year: u16 = if (date.year > 2000) date.year - 2000 else date.year - 1900;
                const args = .{ year, date.month.numeric(), date.day, time.hour, time.minute, time.second };
                try encoder.writer.print("{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", args);
                // try der.Encoder.tagLength(writer, .{ .number = .generalized_time }, "yyyymmddHHmmssZ".len);
                // try writer.print("{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{ date.year, date.month.numeric(), date.day, time.hour, time.minute, time.second });
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

    pub const PubKey = struct {
        algorithm: Algorithm,
        key: asn1.BitString,

        const Algorithm = struct {
            tag: Tag.Enum,
            parameters: ?AlgorithmIdentifier.Ecdsa.NamedCurve.Enum = null,

            const Tag = asn1.Oid.Enum(.{
                .{ "1.2.840.113549.1.1.1", .rsa },
                .{ "1.2.840.10045.2.1", .ecdsa },
                .{ "1.3.101.112", .ed25519 },
            });
        };
    };

    // This is a container to avoid allocating []Extension.
    // It contains only the extensions we care to parse and ignores the rest.
    pub const Extensions = struct {
        // subject_key_identifier: ?[]const u8 = null,
        key_usage: ?KeyUsage = null,
        basic_constraints: ?BasicConstraints = null,
        /// See `policiesIter`.
        // policies: ?[]const u8 = null,
        key_usage_ext: ?KeyUsageExt = null,
        /// See `subjectAliasesIter`.
        // subject_aliases: ?[]const u8 = null,

        pub fn decodeDer(decoder: *der.Decoder) !Extensions {
            const seq = try decoder.sequence();

            var res: Extensions = .{};
            while (decoder.index < seq.slice.end) {
                const ext = try decoder.expect(Extension);
                const doc_bytes = ext.value.bytes;
                // var doc_parser = der.Decoder{ .bytes = doc_bytes };
                if (Extension.Tag.oids.get(ext.tag.encoded)) |tag| {
                    switch (tag) {
                        .key_usage => {
                            res.key_usage = try KeyUsage.fromDer(doc_bytes);
                        },
                        .key_usage_ext => {
                            res.key_usage_ext = try KeyUsageExt.fromDer(doc_bytes);
                        },
                        // .subject_alt_name => {
                        //     const seq = try doc_parser.sequence();
                        //     res.subject_aliases = doc_parser.view(seq);
                        // },
                        .basic_constraints => {
                            res.basic_constraints = try BasicConstraints.fromDer(doc_bytes);
                        },
                        // .subject_key_identifier => {
                        //     const string = try doc_parser.element(ExpectedTag.primitive(.octetstring));
                        //     res.subject_key_identifier = doc_parser.view(string);
                        // },
                        // .certificate_policies => {
                        //     const seq = try doc_parser.sequence();
                        //     res.policies = doc_parser.view(seq);
                        // },
                        else => {},
                    }
                } else if (ext.critical) {
                    var buffer: [256]u8 = undefined;
                    var stream = std.io.fixedBufferStream(&buffer);
                    ext.tag.toDot(stream.writer()) catch {};

                    log.err("critical unknown extension {s}", .{stream.getWritten()});
                    return error.UnimplementedCriticalExtension;
                }
            }
            return res;
        }

        const Extension = struct {
            tag: asn1.Oid,
            critical: bool = false,
            value: asn1.Opaque(.{ .number = .octetstring }),

            // .{ "2.5.29.1", .authority_key_identifier }, // deprecated
            // .{ "2.5.29.25", .crl_distribution_points }, // deprecated
            const Tag = asn1.Oid.Enum(.{
                // Fingerprint to identify public key (unused).
                .{ "2.5.29.14", .subject_key_identifier },
                // Purpose of key (see `KeyUsage`).
                .{ "2.5.29.15", .key_usage },
                // Alternative names besides specified `subject`. Usually DNS entries.
                .{ "2.5.29.17", .subject_alt_name },
                // Alternative names besides specified `issuer` (unused).
                // S4.2.1.7 states: Issuer alternative names are not
                // processed as part of the certification path validation algorithm in
                // Section 6.
                .{ "2.5.29.18", .issuer_alt_name },
                // Identify if is CA and maximum depth of valid cert paths including this cert.
                .{ "2.5.29.19", .basic_constraints },
                // Nationality of subject
                .{ "2.5.29.29", .subject_directory_attributes },
                // For CA certificates, indicates a name space within which all subject names in
                // subsequent certificates in a certification path MUST be located (unused).
                .{ "2.5.29.30", .name_constraints },
                // Where to find Certificate Revocation List (unused).
                .{ "2.5.29.31", .crl_distribution_points },
                // Policies that cert was issued under (domain verification, etc.) (unused).
                .{ "2.5.29.32", .certificate_policies },
                // Map of issuing CA policy considered equivalent to subject policy (unused).
                .{ "2.5.29.33", .policy_mappings },
                // For CA certificates, can be used to prohibit policy mapping or require
                // that each certificate in a path contain an acceptable policy
                // identifier.
                .{ "2.5.29.34", .policy_constraints },
                // Fingerprint to identify CA's public key.
                .{ "2.5.29.35", .authority_key_identifier },
                // Purpose of key (see `KeyUsageExt`).
                .{ "2.5.29.37", .key_usage_ext },
                // For CA certificates, indicates that the special anyPolicy OID is NOT
                // considered an explicit match for other certificate policies.
                .{ "2.5.29.54", .inhibit_anypolicy },
            });
        };

        /// How `pub_key` may be used.
        pub const KeyUsage = packed struct {
            digital_signature: bool = false,
            content_commitment: bool = false,
            key_encipherment: bool = false,
            data_encipherment: bool = false,
            key_agreement: bool = false,
            // MUST be false when basic_constraints.is_ca == false
            key_cert_sign: bool = false,
            crl_sign: bool = false,
            encipher_only: bool = false,
            decipher_only: bool = false,

            pub fn decodeDer(parser: *der.Decoder) !KeyUsage {
                const key_usage = try parser.expect(asn1.BitString);
                if (key_usage.bitLen() > @bitSizeOf(KeyUsage)) return error.InvalidKeyUsage;

                const T = std.meta.Int(.unsigned, @bitSizeOf(KeyUsage));
                const int = std.mem.readVarPackedInt(
                    T,
                    key_usage.bytes,
                    0,
                    key_usage.bitLen(),
                    .big,
                    .unsigned,
                );

                return @bitCast(int);
            }

            pub fn encodeDer(self: KeyUsage, encoder: *der.Encoder) !void {
                try encoder.tag(.{ .number = .sequence, .constructed = true });

                try encoder.any(Extension.Tag.oid(.key_usage));
                try encoder.any(true);

                const bytes: []const u8 = std.mem.asBytes(&self);
                try encoder.tag(.{ .number = .octetstring, .constructed = true });
                try encoder.any(asn1.BitString{ .bytes = bytes });
            }
        };

        /// Further specifies how `pub_key` may be used.
        pub const KeyUsageExt = packed struct {
            server_auth: bool = false,
            client_auth: bool = false,
            code_signing: bool = false,
            email_protection: bool = false,
            time_stamping: bool = false,
            ocsp_signing: bool = false,

            pub const Tag =  asn1.Oid.Enum(.{
                .{ "1.3.6.1.5.5.7.3.1", .server_auth },
                .{ "1.3.6.1.5.5.7.3.2", .client_auth },
                .{ "1.3.6.1.5.5.7.3.3", .code_signing },
                .{ "1.3.6.1.5.5.7.3.4", .email_protection },
                .{ "1.3.6.1.5.5.7.3.8", .time_stamping },
                .{ "1.3.6.1.5.5.7.3.9", .ocsp_signing },
            });

            pub fn decodeDer(parser: *der.Decoder) !KeyUsageExt {
                const seq = try parser.sequence();
                defer parser.index = seq.slice.end;

                var res: KeyUsageExt = .{};
                while (parser.index < parser.bytes.len) {
                    const tag = parser.expectEnum(Tag) catch |err| switch (err) {
                        error.UnknownOid => continue,
                        else => return err,
                    };
                    switch (tag) {
                        inline else => |t| @field(res, @tagName(t)) = true,
                    }
                }

                return res;
            }
        };

        pub const PathLen = u16;
        /// Extension specifying if certificate is a CA and maximum number
        /// of non self-issued intermediate certificates that may follow this
        /// Certificate in a valid certification path.
        pub const BasicConstraints = struct {
            is_ca: bool = false,
            /// MUST NOT include unless `is_ca`.
            max_path_len: ?PathLen = null,

            pub fn fromDer(bytes: []const u8) !BasicConstraints {
                var res: BasicConstraints = .{};

                var parser = der.Decoder{ .bytes = bytes };
                _ = try parser.sequence();
                if (!parser.eof()) {
                    res.is_ca = try parser.expect(bool);
                    if (!parser.eof()) {
                        res.max_path_len = try parser.expect(PathLen);
                        if (!res.is_ca) return error.NotCA;
                    }
                }

                return res;
            }
        };
    };
};

pub const AlgorithmIdentifier = struct {
    algorithm: Algorithm,
    params: ?asn1.Any = null,

    const MaskGen = struct {
        tag: Tag.Enum,
        hash: HashTag.Enum,

        const Tag = asn1.Oid.Enum(.{
            .{ "1.2.840.113549.1.1.8", .mgf1 },
        });
    };

    pub const Ecdsa = struct {
        hash: HashTag.Enum,
        curve: NamedCurve.Enum,

        pub const NamedCurve = asn1.Oid.Enum(.{
            .{ "1.2.840.10045.3.1.7", .prime256v1 },
            .{ "1.3.132.0.10", .secp256k1 },
            .{ "1.3.132.0.34", .secp384r1 },
            .{ "1.3.132.0.35", .secp521r1 },
        });
    };

    pub const HashTag = asn1.Oid.Enum(.{
        .{ "1.3.14.3.2.26", .sha1 },
        .{ "2.16.840.1.101.3.4.2.1", .sha256 },
        .{ "2.16.840.1.101.3.4.2.2", .sha384 },
        .{ "2.16.840.1.101.3.4.2.3", .sha512 },
        .{ "2.16.840.1.101.3.4.2.4", .sha224 },
    });

    const Algorithm =  asn1.Oid.Enum(.{
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
};

const std = @import("std");
const asn1 = @import("./asn1.zig");
const der = asn1.der;
const Asn1Tag = asn1.encodings.Tag;
const ExpectedTag = asn1.encodings.ExpectedTag;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const comptimeOid = asn1.Oid.encodeComptime;
const log = std.log.scoped(.certificate);
