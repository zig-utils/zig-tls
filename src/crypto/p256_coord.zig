//! BoringSSL Bedrock P-256 coordinate add/sub (p256_field_64.br.c.inc).
//! Mul/square use Montgomery assembly; add/sub use saturated limb reduction.
pub const hw = @import("hw_p256.zig");
const fiat = @import("p256_fiat_hw.zig");

pub const Limb = u64;
pub const Coord = [4]Limb;

const p0: Limb = 0xffffffffffffffff;
const p1: Limb = 0xffffffff;
const p2: Limb = 0;
const p3: Limb = 0xffffffff00000001;

fn fullAdd(a: Limb, b: Limb, carry: Limb) struct { sum: Limb, carry: Limb } {
    const wide = @as(u128, a) + @as(u128, b) + @as(u128, carry);
    return .{ .sum = @truncate(wide), .carry = @truncate(wide >> 64) };
}

fn fullSub(a: Limb, b: Limb, borrow: Limb) struct { diff: Limb, borrow: Limb } {
    const subtrahend = @as(u128, b) + @as(u128, borrow);
    const bor: Limb = if (@as(u128, a) < subtrahend) 1 else 0;
    return .{ .diff = @truncate(@as(u128, a) -% subtrahend), .borrow = bor };
}

pub fn add(out: *Coord, x: Coord, y: Coord) void {
    var carry: Limb = 0;
    var t: [4]Limb = undefined;
    inline for (0..4) |i| {
        const r = fullAdd(x[i], y[i], carry);
        t[i] = r.sum;
        carry = r.carry;
    }

    var borrow: Limb = 0;
    var r: [4]Limb = undefined;
    inline for (0..4) |i| {
        const p = ([4]Limb{ p0, p1, p2, p3 })[i];
        const s = fullSub(t[i], p, borrow);
        r[i] = s.diff;
        borrow = s.borrow;
    }
    const final_borrow = fullSub(carry, 0, borrow);

    inline for (0..4) |i| {
        out.*[i] = if (final_borrow.borrow != 0) t[i] else r[i];
    }
}

pub fn subCoord(out: *Coord, x: Coord, y: Coord) void {
    var borrow: Limb = 0;
    var t: [4]Limb = undefined;
    inline for (0..4) |i| {
        const s = fullSub(x[i], y[i], borrow);
        t[i] = s.diff;
        borrow = s.borrow;
    }

    const mask: Limb = 0 -% borrow;
    var carry: Limb = 0;
    var r: [4]Limb = undefined;
    const adds = [4]Limb{ mask, mask & 0xffffffff, 0, mask & 0xffffffff00000001 };
    inline for (0..4) |i| {
        const s = fullAdd(t[i], adds[i], carry);
        r[i] = s.sum;
        carry = s.carry;
    }
    out.* = r;
}

pub fn nonzero(x: Coord) bool {
    return (x[0] | x[1] | x[2] | x[3]) != 0;
}

pub fn mul(out: *Coord, x: Coord, y: Coord) void {
    if (!@inComptime() and hw.enabled) {
        hw.mul(out, x, y);
    } else {
        fiat.mul(out, x, y);
    }
}

pub fn sqr(out: *Coord, x: Coord) void {
    if (!@inComptime() and hw.enabled) {
        hw.square(out, x);
    } else {
        fiat.square(out, x);
    }
}

/// Jacobian + affine mixed add (BoringSSL `p256_point_add_affine_nz_nz_neq`).
pub fn addMixedAffine(out: *[3]Coord, p: [3]Coord, q: [2]Coord) bool {
    var z1z1: Coord = undefined;
    var u2c: Coord = undefined;
    var h: Coord = undefined;
    var s2: Coord = undefined;
    var r: Coord = undefined;
    var Hsqr: Coord = undefined;
    var Hcub: Coord = undefined;

    sqr(&z1z1, p[2]);
    mul(&u2c, q[0], z1z1);
    subCoord(&h, u2c, p[0]);
    mul(&s2, p[2], z1z1);
    mul(&out[2], h, p[2]);
    mul(&s2, s2, q[1]);
    subCoord(&r, s2, p[1]);
    sqr(&Hsqr, h);
    sqr(&out[0], r);
    mul(&Hcub, Hsqr, h);
    mul(&u2c, p[0], Hsqr);
    const ok = nonzero(Hcub) or nonzero(out[0]);
    subCoord(&out[0], out[0], Hcub);
    subCoord(&out[0], out[0], u2c);
    subCoord(&out[0], out[0], u2c);
    subCoord(&h, u2c, out[0]);
    mul(&s2, Hcub, p[1]);
    mul(&h, h, r);
    subCoord(&out[1], h, s2);
    return ok;
}

const std = @import("std");

test "bedrock coord sub matches fiat Montgomery sub" {
    var one: fiat.MontgomeryDomainFieldElement = undefined;
    fiat.setOne(&one);
    var two_fiat: fiat.MontgomeryDomainFieldElement = undefined;
    fiat.add(&two_fiat, one, one);
    var diff_fiat: fiat.MontgomeryDomainFieldElement = undefined;
    fiat.sub(&diff_fiat, two_fiat, one);
    var diff_coord: Coord = undefined;
    subCoord(&diff_coord, two_fiat, one);
    try std.testing.expectEqual(one, diff_fiat);
    try std.testing.expectEqual(one, diff_coord);
}

test "bedrock coord add matches fiat Montgomery add" {
    var one: fiat.MontgomeryDomainFieldElement = undefined;
    fiat.setOne(&one);
    var two_fiat: fiat.MontgomeryDomainFieldElement = undefined;
    fiat.add(&two_fiat, one, one);
    var two_coord: Coord = undefined;
    add(&two_coord, one, one);
    try std.testing.expectEqual(two_fiat, two_coord);
}

test "bedrock coord add/sub self-consistency" {
    const a: Coord = .{ 1, 2, 3, 4 };
    const b: Coord = .{ 5, 6, 7, 8 };
    var sum: Coord = undefined;
    var diff: Coord = undefined;
    add(&sum, a, b);
    subCoord(&diff, sum, b);
    try std.testing.expectEqual(a, diff);
}
