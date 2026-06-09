//! Modified width-w NAF for BoringSSL-style `point_mul_public`.
const std = @import("std");

fn scalarWord0(scalar: [32]u8) u64 {
    return std.mem.readInt(u64, scalar[0..8], .little);
}

pub fn scalarBit(scalar: [32]u8, i: usize) bool {
    if (i >= 256) return false;
    const byte = scalar[i >> 3];
    return ((byte >> @intCast(i & 7)) & 1) != 0;
}

/// `ec_compute_wNAF` for a 32-byte little-endian scalar.
pub fn computeWnaf(out: []i8, scalar: [32]u8, bits: usize, w: usize) void {
    std.debug.assert(w > 0 and w <= 7);
    std.debug.assert(bits != 0);
    std.debug.assert(out.len >= bits + 1);

    const bit: i32 = @intCast(@as(u32, 1) << @intCast(w));
    const next_bit: i32 = bit << 1;
    const mask: i32 = next_bit - 1;

    var window_val: i32 = @intCast(scalarWord0(scalar) & @as(u64, @bitCast(@as(i64, mask))));
    var j: usize = 0;
    while (j < bits + 1) : (j += 1) {
        var digit: i32 = 0;
        if ((window_val & 1) != 0) {
            if ((window_val & bit) != 0) {
                digit = window_val - next_bit;
                if (j + w + 1 >= bits) {
                    digit = window_val & (mask >> 1);
                }
            } else {
                digit = window_val;
            }
            window_val -= digit;
        }
        out[j] = @intCast(digit);
        window_val >>= 1;
        if (scalarBit(scalar, j + w + 1)) window_val += bit;
    }
}

test "computeWnaf length 257 for 256-bit scalar" {
    var wnaf: [257]i8 = @splat(0);
    const s: [32]u8 = @splat(0xab);
    computeWnaf(&wnaf, s, 256, 4);
    try std.testing.expect(wnaf[256] == 0);
}
