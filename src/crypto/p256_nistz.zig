//! Gueron–Krasnov base-point scalar multiply using BoringSSL nistz tables.
const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;

const p256 = @import("p256.zig");
const P256 = p256.P256;
const Fe = P256.Fe;
const table = @import("p256/nistz_table.zig");

pub const enabled = builtin.cpu.arch == .aarch64 or builtin.cpu.arch == .x86_64;

const IdentityElementError = crypto.errors.IdentityElementError;

fn feFromMontgomeryLimbs(limbs: [4]u64) Fe {
    return .{ .limbs = limbs };
}

fn loadWindow(s: [32]u8, i: usize) u64 {
    const kMask: u64 = (1 << 8) - 1;
    if (i == 0) return (@as(u64, s[0]) << 1) & kMask;
    const first_bit = 7 * i - 1;
    const idx = first_bit / 8;
    const wvalue = @as(u64, s[idx]) | (@as(u64, if (idx < 31) s[idx + 1] else 0) << 8);
    return (wvalue >> @intCast(first_bit % 8)) & kMask;
}

fn boothRecodeW7(in: u64) u64 {
    const s = ~((in >> 7) -% 1);
    var d = (@as(u64, 1) << 8) -% in -% 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);
    return (d << 1) + (s & 1);
}

fn selectAffine(row: table.Row, idx: usize, row_i: usize) table.AffineMont {
    const limit: usize = if (row_i == 36) 16 else 64;
    if (idx >= limit) return .{ .x = @splat(0), .y = @splat(0) };
    return row[idx];
}

/// Variable-time k*G using nistz precomputed affine table (signing hot path).
pub fn mulBase(s: [32]u8) IdentityElementError!P256 {
    var ret_is_zero = true;
    var ret = P256.identityElement;

    var i: isize = 36;
    while (i >= 0) : (i -= 1) {
        const row_i: usize = @intCast(i);
        const wvalue = boothRecodeW7(loadWindow(s, row_i));
        const mag: usize = @intCast(wvalue >> 1);
        if (mag == 0) {
            @branchHint(.unlikely);
            continue;
        }

        const pt = selectAffine(table.ecp_nistz256_precomputed[row_i], mag - 1, row_i);
        var y = feFromMontgomeryLimbs(pt.y);
        if ((wvalue & 1) != 0) y = y.neg();
        const t = P256{ .x = feFromMontgomeryLimbs(pt.x), .y = y, .z = Fe.one };

        if (!ret_is_zero) {
            ret = ret.addMixed(.{ .x = t.x, .y = t.y });
        } else {
            ret = t;
            ret_is_zero = false;
        }
    }

    try ret.rejectIdentity();
    return ret;
}

test "addMixed from identity yields table point" {
    const g = P256.basePoint.affineCoordinates();
    const r = P256.identityElement.addMixed(g);
    try std.testing.expect(r.equivalent(P256.basePoint));
}

test "nistz mulBase matches mulPublic" {
    var s_be: [32]u8 = @splat(0);
    var n: u32 = 1;
    while (n < 500) : (n += 1) {
        @memset(&s_be, 0);
        std.mem.writeInt(u32, s_be[28..32], n, .big);
        const s = Fe.orderSwap(s_be);
        const a = try mulBase(s);
        const b = try P256.basePoint.mulPublic(s_be, .big);
        try std.testing.expect(a.equivalent(b));
    }
}

test "nistz base multiply matches scalar 1" {
    var s_be: [32]u8 = @splat(0);
    s_be[31] = 1;
    const s = Fe.orderSwap(s_be);
    const q = try mulBase(s);
    try std.testing.expect(q.equivalent(P256.basePoint));
}
