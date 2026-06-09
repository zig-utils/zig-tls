//! Fast constant-time X25519 public-key generation via a fixed-base comb.
//!
//! X25519 keygen is a *fixed-base* scalar multiplication (k·G), so it can use a
//! precomputed comb instead of a Montgomery ladder. We compute k·B on Edwards25519
//! with a 4-bit windowed table (no point doublings at runtime, only 64 additions),
//! then map the Edwards point to the Montgomery u-coordinate:
//!
//!     u = (Z + Y) / (Z - Y)   where y_affine = Y/Z
//!
//! This matches `std.crypto.dh.X25519.recoverPublicKey` for every clamped scalar,
//! but is roughly 2× faster because the comb avoids the ~255 ladder steps.
const std = @import("std");
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Fe = Edwards25519.Fe;

const window_bits = 4;
const n_windows = 256 / window_bits; // 64
const table_entries = 1 << window_bits; // 16

/// `base_table[j][d] = d · 16^j · B` (with `[j][0]` = identity).
const base_table = buildTable();

fn buildTable() [n_windows][table_entries]Edwards25519 {
    @setEvalBranchQuota(20_000_000);
    var t: [n_windows][table_entries]Edwards25519 = undefined;
    var base = Edwards25519.basePoint;
    var j: usize = 0;
    while (j < n_windows) : (j += 1) {
        t[j][0] = Edwards25519.identityElement;
        t[j][1] = base;
        var d: usize = 2;
        while (d < table_entries) : (d += 1) {
            t[j][d] = t[j][d - 1].add(base);
        }
        // Advance the window base by 2^4 for the next nibble position.
        base = base.dbl().dbl().dbl().dbl();
    }
    return t;
}

/// Constant-time equality: returns 1 when `a == b`, else 0.
inline fn ctEq(a: u8, b: u8) u64 {
    const x: u64 = @as(u64, a) ^ @as(u64, b);
    return ((x -% 1) >> 8) & 1;
}

/// Constant-time table lookup of `base_table[window][nibble]`.
inline fn selectWindow(window: usize, nibble: u8) Edwards25519 {
    var r = Edwards25519.identityElement;
    const row = &base_table[window];
    comptime var di: usize = 1;
    inline while (di < table_entries) : (di += 1) {
        const c = ctEq(nibble, @intCast(di));
        r.x.cMov(row[di].x, c);
        r.y.cMov(row[di].y, c);
        r.z.cMov(row[di].z, c);
        r.t.cMov(row[di].t, c);
    }
    return r;
}

/// Compute `k · B` on Edwards25519 using the fixed-base comb (constant-time).
fn combMul(k: [32]u8) Edwards25519 {
    var q = Edwards25519.identityElement;
    var j: usize = 0;
    while (j < n_windows) : (j += 1) {
        const byte = k[j >> 1];
        const nibble: u8 = if (j & 1 == 0) (byte & 0x0f) else (byte >> 4);
        q = q.add(selectWindow(j, nibble));
    }
    return q;
}

/// Compute the X25519 public key for `seed` (clamps internally).
/// Equivalent to `std.crypto.dh.X25519.recoverPublicKey`.
pub fn recoverPublicKey(seed: [32]u8) [32]u8 {
    var k = seed;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    const p = combMul(k);
    const u = p.z.add(p.y).mul(p.z.sub(p.y).invert());
    return u.toBytes();
}

const testing = std.testing;

test "x25519 comb recoverPublicKey matches std" {
    const X25519 = std.crypto.dh.X25519;
    var seed: [32]u8 = undefined;
    var n: u32 = 0;
    while (n < 64) : (n += 1) {
        std.crypto.hash.sha2.Sha256.hash(std.mem.asBytes(&n), &seed, .{});
        const expected = try X25519.recoverPublicKey(seed);
        const got = recoverPublicKey(seed);
        try testing.expectEqualSlices(u8, &expected, &got);
    }
}

test "x25519 comb matches std rfc7748 vector" {
    const X25519 = std.crypto.dh.X25519;
    const seed = [32]u8{ 0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4 };
    const expected = try X25519.recoverPublicKey(seed);
    try testing.expectEqualSlices(u8, &expected, &recoverPublicKey(seed));
}
