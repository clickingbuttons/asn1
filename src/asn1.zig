const std = @import("std");
pub const der = @import("./der.zig");
pub const oid = @import("./oid.zig");

pub const Index = u32;

// https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/asn1-tags.html
pub const Identifier = struct {
    tag: Tag,
    constructed: bool = false,
    class: Class = .universal,

    pub const Class = enum(u2) {
        universal,
        application,
        context_specific,
        private,
    };

    // Universal tags
    // https://learn.microsoft.com/en-us/dotnet/api/system.formats.asn1.universaltagnumber?view=net-8.0
    pub const Tag = enum(u6) {
        boolean = 1,
        integer = 2,
        bitstring = 3,
        octetstring = 4,
        null = 5,
        oid = 6,
        object_descriptor = 7,
        real = 9,
        enumerated = 10,
        embedded = 11,
        string_utf8 = 12,
        oid_relative = 13,
        time = 14,
        // 15 is reserved to mean that the tag is >= 32
        sequence = 16,
        /// Elements may appear in any order.
        sequence_of = 17,
        string_numeric = 18,
        string_printable = 19,
        string_teletex = 20,
        string_videotex = 21,
        string_ia5 = 22,
        utc_time = 23,
        generalized_time = 24,
        string_graphic = 25,
        string_visible = 26,
        string_general = 27,
        string_universal = 28,
        string_char = 29,
        string_bmp = 30,
        date = 31,
        time_of_day = 32,
        date_time = 33,
        duration = 34,
        /// IRI = Internationalized Resource Identifier
        oid_iri = 35,
        oid_iri_relative = 36,
        _,
    };

    // How they come on the wire.
    pub const EncodedId = packed struct(u8) {
        tag: u5,
        constructed: bool,
        class: Identifier.Class,
    };
    pub const EncodedTag = packed struct(u8) {
        tag: u7,
        continues: bool,
    };
};

pub const BitString = struct {
    bytes: []const u8,
    /// Number of bits in rightmost byte that are unused.
    right_padding: u3 = 0,

    pub fn bitLen(self: BitString) usize {
        return self.bytes.len * 8 + self.right_padding;
    }
};

pub const String = struct {
    tag: Tag,
    data: []const u8,

    pub const Tag = enum {
        utf8,
        /// us-ascii ([-][0-9][eE][.])*
        numeric,
        /// us-ascii ([A-Z][a-z][0-9][.?!,][ \t])*
        printable,
        /// iso-8859-1 with escaping into different character sets
        teletex,
        /// iso-8859-1
        videotex,
        /// us-ascii first 128 characters
        ia5,
        /// us-ascii without control characters
        visible,
        /// utf-32-be
        universal,
        /// utf-16-be
        bmp,
        /// character set deferred to runtime
        char,
        /// any standarized character set
        any,
        /// any standarized character set, no control characters
        graphic,
        object_descriptor,
    };
};

/// Lowest common denominator of UTCTime, GeneralizedTime, DATE, and DATE-TIME.
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

    pub fn toUnixEpochSeconds(date: Date) i64 {
        // Euclidean Affine Transform by Cassio and Neri.
        // Shift and correction constants for 1970-01-01.
        const s = 82;
        const K = 719468 + 146097 * s;
        const L = 400 * s;

        const Y_G: u32 = date.year;
        const M_G: u32 = date.month.numeric();
        const D_G: u32 = date.day;
        // Map to computational calendar.
        const J: u32 = if (M_G <= 2) 1 else 0;
        const Y: u32 = Y_G + L - J;
        const M: u32 = if (J != 0) M_G + 12 else M_G;
        const D: u32 = D_G - 1;
        const C: u32 = Y / 100;

        // Rata die.
        const y_star: u32 = 1461 * Y / 4 - C + C / 4;
        const m_star: u32 = (979 * M - 2919) / 32;
        const N: u32 = y_star + m_star + D;
        const days: i32 = @intCast(N - K);

        return @as(i64, days) * std.time.epoch.secs_per_day;
    }
};

/// Lowest common denominator of  UTCTime, GeneralizedTime, TIME-OF-DAY, and DATE-TIME.
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

    pub fn toDaySeconds(t: Time) DaySeconds {
        var sec: DaySeconds = 0;
        sec += @as(DaySeconds, t.hour) * 60 * 60;
        sec += @as(DaySeconds, t.minute) * 60;
        sec += t.second;
        return sec;
    }
};

pub const DateTime = struct {
    date: Date,
    time: Time,

    pub fn init(year: Date.Year, month: Date.Month, day: Date.Day, hour: Time.Hour, minute: Time.Minute, second: Time.Second,) DateTime {
        return .{ .date = Date.init(year, month, day), .time = Time.init(hour, minute, second) };
    }

    pub fn toUnixEpochSeconds(self: DateTime) i64 {
        return self.date.toUnixEpochSeconds() + self.time.toDaySeconds();
    }
};

test {
    _ = der;
    _ = oid;
}
