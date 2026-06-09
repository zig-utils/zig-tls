//! Gueron–Krasnov base-point scalar multiply using BoringSSL nistz tables.
const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;

const p256 = @import("p256.zig");
const P256 = p256.P256;
const Fe = P256.Fe;
const table = @import("p256/nistz_table.zig");
const coord = @import("p256_coord.zig");
const field_inv_sqr = @import("p256/field_inv_sqr_chain.zig");
const fiat = @import("p256_fiat_hw.zig");
const bedrock_c = @import("bedrock_c_enabled.zig");

pub const enabled = builtin.cpu.arch == .aarch64 or builtin.cpu.arch == .x86_64;

const IdentityElementError = crypto.errors.IdentityElementError;

const Jacobian = [3]coord.Coord;

fn feFromMontgomeryLimbs(limbs: [4]u64) Fe {
    return .{ .limbs = limbs };
}

fn montgomeryOne() coord.Coord {
    var one: coord.Coord = undefined;
    fiat.setOne(&one);
    return one;
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

fn jacobianToP256(j: Jacobian) IdentityElementError!P256 {
    if (!coord.nonzero(j[2])) return error.IdentityElement;
    const X = Fe{ .limbs = j[0] };
    const Y = Fe{ .limbs = j[1] };
    const Z = Fe{ .limbs = j[2] };
    const z_inv2 = field_inv_sqr.invSqrMont(Z);
    const z_inv4 = z_inv2.sq();
    const yz = Y.mul(Z);
    return P256{
        .x = X.mul(z_inv2),
        .y = yz.mul(z_inv4),
        .z = Fe.one,
    };
}

fn mulBaseProjective(s: [32]u8) IdentityElementError!P256 {
    const ret = mulBaseProjectiveVarTime(s);
    try ret.rejectIdentity();
    return ret;
}

fn accumulateW7Window(
    acc: *P256,
    ret_is_zero: *bool,
    row: table.Row,
    row_i: usize,
    wvalue: u64,
) void {
    const mag: usize = @intCast(wvalue >> 1);
    if (mag == 0) return;

    const pt = selectAffine(row, mag - 1, row_i);
    var y_limbs = pt.y;
    if ((wvalue & 1) != 0) {
        var y_neg: coord.Coord = undefined;
        fiat.opp(&y_neg, pt.y);
        y_limbs = y_neg;
    }
    const qx = feFromMontgomeryLimbs(pt.x);
    const qy = feFromMontgomeryLimbs(y_limbs);

    if (!ret_is_zero.*) {
        acc.* = acc.addMixedVarTime(.{ .x = qx, .y = qy });
    } else {
        acc.* = .{ .x = qx, .y = qy, .z = Fe.one };
        ret_is_zero.* = false;
    }
}

fn mulAffineTableVarTime(s: [32]u8, precomputed: *const [37]table.Row) P256 {
    var ret_is_zero = true;
    var acc = P256.identityElement;

    var i: isize = 36;
    while (i >= 0) : (i -= 1) {
        const row_i: usize = @intCast(i);
        const wvalue = boothRecodeW7(loadWindow(s, row_i));
        accumulateW7Window(&acc, &ret_is_zero, precomputed[row_i], row_i, wvalue);
    }

    return acc;
}

fn mulBaseProjectiveVarTime(s: [32]u8) P256 {
    return mulAffineTableVarTime(s, &table.ecp_nistz256_precomputed);
}

/// Build a Gueron–Krasnov 37×64 affine table for variable-time `k·P` (ECDSA verify).
pub fn buildPrecomputedTable(p: P256) [37]table.Row {
    var rows: [37]table.Row = undefined;
    var row_base = p;

    for (0..37) |row_i| {
        const limit: usize = if (row_i == 36) 16 else 64;
        var acc = row_base;
        for (0..limit) |idx| {
            const aff = acc.affineCoordinatesVarTime();
            rows[row_i][idx] = .{ .x = aff.x.limbs, .y = aff.y.limbs };
            acc = acc.add(row_base);
        }
        if (row_i < 36) {
            for (0..7) |_| row_base = row_base.dbl();
        }
    }
    return rows;
}

const MulPublicTableCache = struct {
    hash: u64 = 0,
    table: [37]table.Row = undefined,
    ready: bool = false,
};
var mul_public_table_cache: MulPublicTableCache = .{};

fn hashPoint(p: P256) u64 {
    const aff = p.affineCoordinatesVarTime();
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..32], &aff.x.toBytes(.big));
    @memcpy(buf[32..64], &aff.y.toBytes(.big));
    return std.hash.Wyhash.hash(0, &buf);
}

/// Cached 37×64 w7 table for repeated verify against the same public key.
pub fn mulPublicTableFor(p: P256) *const [37]table.Row {
    const h = hashPoint(p);
    if (mul_public_table_cache.ready and mul_public_table_cache.hash == h) {
        return &mul_public_table_cache.table;
    }
    mul_public_table_cache.table = buildPrecomputedTable(p);
    mul_public_table_cache.hash = h;
    mul_public_table_cache.ready = true;
    return &mul_public_table_cache.table;
}

/// Variable-time k·P using a precomputed w7 table (ECDSA verify hot path).
pub fn mulPublicVarTimeFromTable(s: [32]u8, precomputed: *const [37]table.Row) P256 {
    return mulAffineTableVarTime(s, precomputed);
}

/// Base-point w7 table (`k·G`).
pub fn basePrecomputedTable() *const [37]table.Row {
    return &table.ecp_nistz256_precomputed;
}

/// Unified w7 double-base mul (u1·G + u2·Q) for ECDSA verify.
pub fn mulDoubleBaseVarTimeFromTables(
    s1: [32]u8,
    s2: [32]u8,
    table1: *const [37]table.Row,
    table2: *const [37]table.Row,
) P256 {
    var ret_is_zero = true;
    var acc = P256.identityElement;

    var i: isize = 36;
    while (i >= 0) : (i -= 1) {
        const row_i: usize = @intCast(i);
        accumulateW7Window(&acc, &ret_is_zero, table1[row_i], row_i, boothRecodeW7(loadWindow(s1, row_i)));
        accumulateW7Window(&acc, &ret_is_zero, table2[row_i], row_i, boothRecodeW7(loadWindow(s2, row_i)));
    }

    return acc;
}

/// Variable-time k*G without identity check (ECDSA sign hot path).
pub fn mulBaseVarTime(s: [32]u8) P256 {
    if (!@inComptime() and bedrock_c.enabled) {
        return mulBaseBedrockC(s) catch unreachable;
    }
    if (!@inComptime() and coord.hw.enabled and use_bedrock_mul_base) {
        return mulBaseJacobian(s) catch unreachable;
    }
    return mulBaseProjectiveVarTime(s);
}

fn mulBaseJacobian(s: [32]u8) IdentityElementError!P256 {
    var ret_is_zero = true;
    var acc: Jacobian = .{ @splat(0), @splat(0), @splat(0) };
    const one_z = montgomeryOne();

    var i: isize = 36;
    while (i >= 0) : (i -= 1) {
        const row_i: usize = @intCast(i);
        const wvalue = boothRecodeW7(loadWindow(s, row_i));
        const mag: usize = @intCast(wvalue >> 1);
        if (mag == 0) continue;

        const pt = selectAffine(table.ecp_nistz256_precomputed[row_i], mag - 1, row_i);
        var y_limbs = pt.y;
        if ((wvalue & 1) != 0) {
            var y_neg: coord.Coord = undefined;
            fiat.opp(&y_neg, pt.y);
            y_limbs = y_neg;
        }
        const q_affine: [2]coord.Coord = .{ pt.x, y_limbs };

        if (!ret_is_zero) {
            var out: Jacobian = undefined;
            coord.addMixedAffineOrDouble(&out, acc, q_affine);
            acc = out;
        } else {
            acc = .{ pt.x, y_limbs, one_z };
            ret_is_zero = false;
        }
    }

    return jacobianToP256(acc);
}

fn mulBaseBedrockC(s: [32]u8) IdentityElementError!P256 {
    const mul = @extern(*const fn (out: *[3][4]u64, scalar: *const [32]u8) callconv(.c) void, .{ .name = "p256_bedrock_mul_base" });
    var j: [3][4]u64 = undefined;
    mul(&j, &s);
    return jacobianToP256(.{ j[0], j[1], j[2] });
}

/// Bedrock Jacobian accumulation in Zig (Bedrock `p256_point_double`).
pub const use_bedrock_mul_base = false;

/// Variable-time k*G using nistz precomputed affine table (signing hot path).
pub fn mulBase(s: [32]u8) IdentityElementError!P256 {
    if (!@inComptime() and bedrock_c.enabled) return mulBaseBedrockC(s);
    if (!@inComptime() and coord.hw.enabled and use_bedrock_mul_base) return mulBaseJacobian(s);
    return mulBaseProjective(s);
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

test "jacobian mulBase matches projective mulBase" {
    if (!coord.hw.enabled) return error.SkipZigTest;
    var s_be: [32]u8 = @splat(0);
    var n: u32 = 1;
    while (n < 500) : (n += 1) {
        @memset(&s_be, 0);
        std.mem.writeInt(u32, s_be[28..32], n, .big);
        const s = Fe.orderSwap(s_be);
        const j = try mulBaseJacobian(s);
        const p = try mulBaseProjective(s);
        try std.testing.expect(j.equivalent(p));
    }
}

test "buildPrecomputedTable matches mulPublic" {
    if (!enabled) return error.SkipZigTest;
    const pc = buildPrecomputedTable(P256.basePoint);
    var s_be: [32]u8 = @splat(0);
    var n: u32 = 1;
    while (n < 200) : (n += 1) {
        @memset(&s_be, 0);
        std.mem.writeInt(u32, s_be[28..32], n, .big);
        const s = Fe.orderSwap(s_be);
        const a = mulPublicVarTimeFromTable(s, &pc);
        const b = try P256.basePoint.mulPublic(s_be, .big);
        try std.testing.expect(a.equivalent(b));
    }
}

test "mulDoubleBaseVarTimeFromTables matches split mul" {
    if (!enabled) return error.SkipZigTest;
    const q_pc = buildPrecomputedTable(P256.basePoint);
    const s1: [32]u8 = @splat(0x11);
    const s2: [32]u8 = @splat(0x22);
    const unified = mulDoubleBaseVarTimeFromTables(s1, s2, basePrecomputedTable(), &q_pc);
    const split = mulBaseVarTime(s1).add(mulPublicVarTimeFromTable(s2, &q_pc));
    try std.testing.expect(unified.equivalent(split));
}
