//! Distinguised Encoding Rules as defined in X.690 and X.691.
//!
//! A version of Basic Encoding Rules (BER) where there is exactly ONE way to
//! represent non-constructed elements. This is useful for cryptographic signatures.
const std = @import("std");

pub const Decoder = @import("./der/Decoder.zig");
pub const Encoder = @import("./der/Encoder.zig");

test {
    _ = Encoder;
    _ = Decoder;
}
