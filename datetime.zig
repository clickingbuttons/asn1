


// TIME-OF-DAY HH:MM:SS
// UTCTime YYMMDDhhmm[ss](Z|[+-]\{4}d)
// TIME ISO 8601 https://www.w3.org/TR/NOTE-datetime
// DURATION P2Y10M15DT10H20M30S ISO 8601, 4.4.3.2
// DATE-TIME YYYY-MM-DDTHH:MM:SS
// DATE YYYY-MM-DD
// GeneralizedTime YYYYMMDDHH[MM[SS[.fff]]]

/// Lowest common denominator of UTCTime, GeneralizedTime, DATE, and DATE-TIME.

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

pub fn toDaySeconds(t: Time) DaySeconds {
    var sec: DaySeconds = 0;
    sec += @as(DaySeconds, t.hour) * 60 * 60;
    sec += @as(DaySeconds, t.minute) * 60;
    sec += t.second;
    return sec;
}

                pub fn toUnixEpochSeconds(self: DateTime) i64 {
                    return self.date.toUnixEpochSeconds() + self.time.toDaySeconds();
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
    var args = .{ date.year, date.month.numeric(), date.day, time.hour, time.minute, time.second };
    const bytes = switch (format) {
        .utc => brk: {
            args[0] -= if (args[0] >= 2000) 2000 else 1900; // RFC 5280 rules
            break :brk std.fmt.bufPrint(&buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", args);
        },
        .generalized => std.fmt.bufPrint(&buf, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", args),
        .date_time => std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", args),
        } catch unreachable;
    try self.buf.prependSlice(bytes);
    const tag: Tag.Number = switch (format) {
        .utc => .utc_time,
        .generalized => .generalized_time,
        .date_time => .date_time,
    };
    try self.element(Tag{ .tag = tag }, bytes.len);
}




