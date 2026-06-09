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
const wnaf = @import("p256_wnaf.zig");
const g_precomp = @import("p256_g_precomp.zig");

pub const enabled = builtin.cpu.arch == .aarch64 or builtin.cpu.arch == .x86_64;
pub const TableRows = [37]table.Row;

/// BoringSSL `point_mul_public` interleaved wNAF (experimental; slower than w7 Shamir here).
pub const use_wnaf_mul_public = false;

const IdentityElementError = crypto.errors.IdentityElementError;

const Jacobian = [3]coord.Coord;

/// Bedrock Jacobian w7 accumulation for pubkey table build on AArch64.
pub const use_bedrock_verify_accum = coord.hw.enabled;

/// Jacobian unified w7 double-base verify (faster than projective on AArch64).
pub const use_jacobian_double_base = use_bedrock_verify_accum;

fn feFromMontgomeryLimbs(limbs: [4]u64) Fe {
    return .{ .limbs = limbs };
}

fn montgomeryOne() coord.Coord {
    var one: coord.Coord = undefined;
    fiat.setOne(&one);
    return one;
}

fn precomputeW7Windows(s: [32]u8) [37]u64 {
    var w: [37]u64 = undefined;
    for (0..37) |row_i| w[row_i] = boothRecodeW7(loadWindow(s, row_i));
    return w;
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

fn jacobianToAffineMont(j: Jacobian) table.AffineMont {
    const Z = Fe{ .limbs = j[2] };
    const z_inv = Z.invertVarTime();
    return jacobianToAffineMontWithZInv(j, z_inv);
}

fn jacobianToAffineMontWithZInv(j: Jacobian, z_inv: Fe) table.AffineMont {
    var z_inv2: coord.Coord = undefined;
    coord.sqr(&z_inv2, z_inv.limbs);
    var z_inv3: coord.Coord = undefined;
    coord.mul(&z_inv3, z_inv2, z_inv.limbs);
    var x_out: coord.Coord = undefined;
    var y_out: coord.Coord = undefined;
    coord.mul(&x_out, j[0], z_inv2);
    coord.mul(&y_out, j[1], z_inv3);
    return .{ .x = x_out, .y = y_out };
}

/// Affine x from Jacobian (ECDSA verify: skip full normalization).
fn jacobianXCoord(j: Jacobian) Fe {
    const Z = Fe{ .limbs = j[2] };
    const z_inv2 = field_inv_sqr.invSqrMont(Z);
    return (Fe{ .limbs = j[0] }).mul(z_inv2);
}

fn batchInvertFe(limit: usize, out: []Fe, inputs: []const Fe) void {
    std.debug.assert(limit > 0 and limit <= 64);
    var acc: [64]Fe = undefined;
    acc[0] = inputs[0];
    var i: usize = 1;
    while (i < limit) : (i += 1) {
        acc[i] = acc[i - 1].mul(inputs[i]);
    }
    var inv = acc[limit - 1].invertVarTime();
    i = limit;
    while (i > 0) : (i -= 1) {
        const idx = i - 1;
        if (idx == 0) {
            out[0] = inv;
        } else {
            out[idx] = inv.mul(acc[idx - 1]);
        }
        inv = inv.mul(inputs[idx]);
    }
}

fn buildTableRow(row_base_j: Jacobian, limit: usize) table.Row {
    const one_z = montgomeryOne();
    const row_aff = jacobianToAffineMont(row_base_j);
    const base_xy: [2]coord.Coord = .{ row_aff.x, row_aff.y };

    var jacs: [64]Jacobian = undefined;
    jacs[0] = .{ base_xy[0], base_xy[1], one_z };
    var idx: usize = 1;
    while (idx < limit) : (idx += 1) {
        var out: Jacobian = undefined;
        coord.addMixedAffineOrDouble(&out, jacs[idx - 1], base_xy);
        jacs[idx] = out;
    }

    var z_fe: [64]Fe = undefined;
    var z_inv: [64]Fe = undefined;
    for (0..limit) |j| z_fe[j] = Fe{ .limbs = jacs[j][2] };
    batchInvertFe(limit, z_inv[0..limit], z_fe[0..limit]);

    var row: table.Row = undefined;
    for (0..limit) |j| {
        row[j] = jacobianToAffineMontWithZInv(jacs[j], z_inv[j]);
    }
    return row;
}

fn jacobianToP256(j: Jacobian) IdentityElementError!P256 {
    if (!coord.nonzero(j[2])) return error.IdentityElement;
    const aff = jacobianToAffineMont(j);
    return .{
        .x = feFromMontgomeryLimbs(aff.x),
        .y = feFromMontgomeryLimbs(aff.y),
        .z = Fe.one,
    };
}

fn p256ToJacobian(p: P256) Jacobian {
    return .{ p.x.limbs, p.y.limbs, p.z.limbs };
}

pub fn publicKeyHash(p: P256) u64 {
    const aff = p.affineCoordinatesVarTime();
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..32], &aff.x.toBytes(.big));
    @memcpy(buf[32..64], &aff.y.toBytes(.big));
    return std.hash.Wyhash.hash(0, &buf);
}

/// Heap-owned 37×64 w7 precompute table for a single P-256 public key.
pub const W7Table = struct {
    pubkey_hash: u64,
    rows: TableRows,

    pub fn create(allocator: std.mem.Allocator, p: P256) !*W7Table {
        const self = try allocator.create(W7Table);
        self.* = .{
            .pubkey_hash = publicKeyHash(p),
            .rows = buildPrecomputedTable(p),
        };
        return self;
    }

    pub fn deinit(allocator: std.mem.Allocator, self: *W7Table) void {
        allocator.destroy(self);
    }

    pub fn rowsPtr(self: *const W7Table) *const TableRows {
        return &self.rows;
    }

    pub fn matchesPublicKey(self: *const W7Table, p: P256) bool {
        return self.pubkey_hash == publicKeyHash(p);
    }
};

fn accumulateW7WindowProjective(
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

fn accumulateW7WindowJacobian(
    acc: *Jacobian,
    ret_is_zero: *bool,
    one_z: coord.Coord,
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
    const q_affine: [2]coord.Coord = .{ pt.x, y_limbs };

    if (!ret_is_zero.*) {
        var out: Jacobian = undefined;
        coord.addMixedAffineOrDouble(&out, acc.*, q_affine);
        acc.* = out;
    } else {
        acc.* = .{ pt.x, y_limbs, one_z };
        ret_is_zero.* = false;
    }
}

/// Fused G+Q window accumulate (one branch on both magnitudes zero).
fn accumulateW7DoubleWindowJacobian(
    acc: *Jacobian,
    ret_is_zero: *bool,
    one_z: coord.Coord,
    row1: table.Row,
    row2: table.Row,
    row_i: usize,
    w1: u64,
    w2: u64,
) void {
    const mag1: usize = @intCast(w1 >> 1);
    const mag2: usize = @intCast(w2 >> 1);
    if (mag1 == 0 and mag2 == 0) return;

    if (mag1 != 0) {
        const pt = selectAffine(row1, mag1 - 1, row_i);
        var y_limbs = pt.y;
        if ((w1 & 1) != 0) {
            var y_neg: coord.Coord = undefined;
            fiat.opp(&y_neg, pt.y);
            y_limbs = y_neg;
        }
        const q_affine: [2]coord.Coord = .{ pt.x, y_limbs };
        if (!ret_is_zero.*) {
            var out: Jacobian = undefined;
            coord.addMixedAffineOrDouble(&out, acc.*, q_affine);
            acc.* = out;
        } else {
            acc.* = .{ pt.x, y_limbs, one_z };
            ret_is_zero.* = false;
        }
    }

    if (mag2 != 0) {
        const pt = selectAffine(row2, mag2 - 1, row_i);
        var y_limbs = pt.y;
        if ((w2 & 1) != 0) {
            var y_neg: coord.Coord = undefined;
            fiat.opp(&y_neg, pt.y);
            y_limbs = y_neg;
        }
        const q_affine: [2]coord.Coord = .{ pt.x, y_limbs };
        if (!ret_is_zero.*) {
            var out: Jacobian = undefined;
            coord.addMixedAffineOrDouble(&out, acc.*, q_affine);
            acc.* = out;
        } else {
            acc.* = .{ pt.x, y_limbs, one_z };
            ret_is_zero.* = false;
        }
    }
}

fn accumulateW7WindowProjectiveFromParts(
    acc: *P256,
    ret_is_zero: *bool,
    row: table.Row,
    row_i: usize,
    wvalue: u64,
    mag: usize,
) void {
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

fn accumulateW7DoubleWindowProjective(
    acc: *P256,
    ret_is_zero: *bool,
    row1: table.Row,
    row2: table.Row,
    row_i: usize,
    w1: u64,
    w2: u64,
) void {
    const mag1: usize = @intCast(w1 >> 1);
    const mag2: usize = @intCast(w2 >> 1);
    if (mag1 == 0 and mag2 == 0) return;
    if (mag1 != 0) accumulateW7WindowProjectiveFromParts(acc, ret_is_zero, row1, row_i, w1, mag1);
    if (mag2 != 0) accumulateW7WindowProjectiveFromParts(acc, ret_is_zero, row2, row_i, w2, mag2);
}

fn mulAffineTableProjectiveVarTime(s: [32]u8, precomputed: *const TableRows) P256 {
    var ret_is_zero = true;
    var acc = P256.identityElement;

    var i: isize = 36;
    while (i >= 0) : (i -= 1) {
        const row_i: usize = @intCast(i);
        const wvalue = boothRecodeW7(loadWindow(s, row_i));
        accumulateW7WindowProjective(&acc, &ret_is_zero, precomputed[row_i], row_i, wvalue);
    }

    return acc;
}

fn mulAffineTableJacobianVarTime(s: [32]u8, precomputed: *const TableRows) P256 {
    var ret_is_zero = true;
    var acc: Jacobian = .{ @splat(0), @splat(0), @splat(0) };
    const one_z = montgomeryOne();

    var i: isize = 36;
    while (i >= 0) : (i -= 1) {
        const row_i: usize = @intCast(i);
        const wvalue = boothRecodeW7(loadWindow(s, row_i));
        accumulateW7WindowJacobian(&acc, &ret_is_zero, one_z, precomputed[row_i], row_i, wvalue);
    }

    return jacobianToP256(acc) catch unreachable;
}

fn mulAffineTableVarTime(s: [32]u8, precomputed: *const TableRows) P256 {
    if (use_bedrock_verify_accum) return mulAffineTableJacobianVarTime(s, precomputed);
    return mulAffineTableProjectiveVarTime(s, precomputed);
}

fn mulBaseProjectiveVarTime(s: [32]u8) P256 {
    return mulAffineTableVarTime(s, &table.ecp_nistz256_precomputed);
}

/// Build a Gueron–Krasnov 37×64 affine table (batch Z⁻¹ per row when Bedrock enabled).
pub fn buildPrecomputedTable(p: P256) TableRows {
    if (!use_bedrock_verify_accum) return buildPrecomputedTableProjective(p);

    var rows: TableRows = undefined;
    var row_j = p256ToJacobian(p);

    for (0..37) |row_i| {
        const limit: usize = if (row_i == 36) 16 else 64;
        rows[row_i] = buildTableRow(row_j, limit);
        if (row_i < 36) {
            for (0..7) |_| {
                var out: Jacobian = undefined;
                coord.doublePoint(&out, row_j);
                row_j = out;
            }
        }
    }
    return rows;
}

fn buildPrecomputedTableProjective(p: P256) TableRows {
    var rows: TableRows = undefined;
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

/// Variable-time k·P using a precomputed w7 table (ECDSA verify hot path).
pub fn mulPublicVarTimeFromTable(s: [32]u8, precomputed: *const TableRows) P256 {
    return mulAffineTableVarTime(s, precomputed);
}

/// Base-point w7 table (`k·G`).
pub fn basePrecomputedTable() *const TableRows {
    return &table.ecp_nistz256_precomputed;
}

fn mulDoubleBaseBedrockC(s1: [32]u8, s2: [32]u8, table2: *const TableRows) Jacobian {
    const mul = @extern(
        *const fn (out: *[3][4]u64, s1: *const [32]u8, s2: *const [32]u8, q_table: *const TableRows) callconv(.c) void,
        .{ .name = "p256_bedrock_mul_double_base_jacobian" },
    );
    var j: [3][4]u64 = undefined;
    mul(&j, &s1, &s2, table2);
    return .{ j[0], j[1], j[2] };
}

fn mulDoubleBaseJacobianFromTables(
    s1: [32]u8,
    s2: [32]u8,
    table1: *const TableRows,
    table2: *const TableRows,
) Jacobian {
    if (!@inComptime() and bedrock_c.enabled)
        return mulDoubleBaseBedrockC(s1, s2, table2);

    const w1 = precomputeW7Windows(s1);
    const w2 = precomputeW7Windows(s2);
    var ret_is_zero = true;
    var acc: Jacobian = .{ @splat(0), @splat(0), @splat(0) };
    const one_z = montgomeryOne();

    inline for (0..37) |step| {
        const row_i = 36 - step;
        accumulateW7DoubleWindowJacobian(&acc, &ret_is_zero, one_z, table1[row_i], table2[row_i], row_i, w1[row_i], w2[row_i]);
    }

    return acc;
}

/// Unified w7 double-base mul (u1·G + u2·Q) for ECDSA verify.
pub fn mulDoubleBaseVarTimeFromTables(
    s1: [32]u8,
    s2: [32]u8,
    table1: *const TableRows,
    table2: *const TableRows,
) P256 {
    if (!use_jacobian_double_base) return mulDoubleBaseProjectiveFromTables(s1, s2, table1, table2);
    const acc = mulDoubleBaseJacobianFromTables(s1, s2, table1, table2);
    return jacobianToP256(acc) catch unreachable;
}

/// Double-base mul returning affine x only (ECDSA verify hot path).
pub fn mulDoubleBaseVarTimeXFromTables(
    s1: [32]u8,
    s2: [32]u8,
    table1: *const TableRows,
    table2: *const TableRows,
) Fe {
    if (!use_jacobian_double_base) {
        const p = mulDoubleBaseProjectiveFromTables(s1, s2, table1, table2);
        return p.xCoordVarTime();
    }
    const acc = mulDoubleBaseJacobianFromTables(s1, s2, table1, table2);
    return jacobianXCoord(acc);
}

fn buildPubWnafPrecompAffine(p: P256) [8]p256.AffineCoordinates {
    var pre: [8]P256 = undefined;
    pre[0] = p;
    const p2 = p.dbl();
    var i: usize = 1;
    while (i < 8) : (i += 1) pre[i] = pre[i - 1].add(p2);
    var out: [8]p256.AffineCoordinates = undefined;
    for (&pre, &out) |*pt, *a| a.* = pt.affineCoordinatesVarTime();
    return out;
}

fn accumulateGWindowProjective(
    acc: *P256,
    ret_is_zero: *bool,
    g_scalar: [32]u8,
    i: isize,
) void {
    if (i > 31) return;
    var j: isize = 1;
    while (j >= 0) : (j -= 1) {
        var bits: u64 = 0;
        var k: isize = 3;
        while (k >= 0) : (k -= 1) {
            if (wnaf.scalarBit(g_scalar, @intCast(i + j * 32 + k * 64)))
                bits |= @as(u64, 1) << @intCast(k);
        }
        if (bits == 0) continue;
        const pt = g_precomp.g_pre_comp[@intCast(j)][@intCast(bits - 1)];
        const qx = feFromMontgomeryLimbs(pt[0]);
        const qy = feFromMontgomeryLimbs(pt[1]);
        if (!ret_is_zero.*) {
            acc.* = acc.addMixedVarTime(.{ .x = qx, .y = qy });
        } else {
            acc.* = .{ .x = qx, .y = qy, .z = Fe.one };
            ret_is_zero.* = false;
        }
    }
}

fn accumulatePWnafDigitProjective(
    acc: *P256,
    ret_is_zero: *bool,
    p_pre_affine: *const [8]p256.AffineCoordinates,
    digit: i8,
) void {
    if (digit == 0) return;
    const mag: usize = @intCast(@as(u32, @intCast(if (digit < 0) -digit else digit)) >> 1);
    var aff = p_pre_affine[mag];
    if (digit < 0) aff.y = aff.y.neg();
    if (!ret_is_zero.*) {
        acc.* = acc.addMixedVarTime(aff);
    } else {
        acc.* = .{ .x = aff.x, .y = aff.y, .z = Fe.one };
        ret_is_zero.* = false;
    }
}

/// BoringSSL `ec_GFp_nistp256_point_mul_public` (g_scalar·G + p_scalar·Q).
pub fn mulDoubleBaseVarTimePublicWnaf(g_scalar: [32]u8, p: P256, p_scalar: [32]u8) P256 {
    var p_wnaf: [257]i8 = undefined;
    wnaf.computeWnaf(&p_wnaf, p_scalar, 256, 4);
    const p_pre = buildPubWnafPrecompAffine(p);

    var ret_is_zero = true;
    var acc = P256.identityElement;

    var i: isize = 256;
    while (i >= 0) : (i -= 1) {
        if (!ret_is_zero) acc = acc.dbl();
        accumulateGWindowProjective(&acc, &ret_is_zero, g_scalar, i);
        accumulatePWnafDigitProjective(&acc, &ret_is_zero, &p_pre, p_wnaf[@intCast(i)]);
    }
    return acc;
}

/// `point_mul_public` returning affine x only (ECDSA verify hot path).
pub fn mulDoubleBaseVarTimeXPublicWnaf(g_scalar: [32]u8, p: P256, p_scalar: [32]u8) Fe {
    return mulDoubleBaseVarTimePublicWnaf(g_scalar, p, p_scalar).xCoordVarTime();
}

pub fn mulDoubleBaseVarTimeXPublicWnafBedrockC(g_scalar: [32]u8, p: P256, p_scalar: [32]u8) Fe {
    const mul = @extern(
        *const fn (out: *[3][4]u64, g_scalar: *const [32]u8, p_in: *const [3][4]u64, p_scalar: *const [32]u8) callconv(.c) void,
        .{ .name = "p256_bedrock_point_mul_public" },
    );
    var j: [3][4]u64 = undefined;
    const pj = p256ToJacobian(p);
    mul(&j, &g_scalar, &pj, &p_scalar);
    return jacobianXCoord(.{ j[0], j[1], j[2] });
}

/// Bedrock C `point_mul_public` when `-Dbedrock-c-mul-base=true`.
pub const use_bedrock_mul_public_c = false;

fn mulDoubleBaseProjectiveFromTables(
    s1: [32]u8,
    s2: [32]u8,
    table1: *const TableRows,
    table2: *const TableRows,
) P256 {
    const w1 = precomputeW7Windows(s1);
    const w2 = precomputeW7Windows(s2);
    var ret_is_zero = true;
    var acc = P256.identityElement;

    inline for (0..37) |step| {
        const row_i = 36 - step;
        accumulateW7DoubleWindowProjective(&acc, &ret_is_zero, table1[row_i], table2[row_i], row_i, w1[row_i], w2[row_i]);
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

fn mulBaseProjective(s: [32]u8) IdentityElementError!P256 {
    const ret = mulBaseProjectiveVarTime(s);
    try ret.rejectIdentity();
    return ret;
}

fn mulBaseJacobian(s: [32]u8) IdentityElementError!P256 {
    var ret_is_zero = true;
    var acc: Jacobian = .{ @splat(0), @splat(0), @splat(0) };
    const one_z = montgomeryOne();

    var i: isize = 36;
    while (i >= 0) : (i -= 1) {
        const row_i: usize = @intCast(i);
        const wvalue = boothRecodeW7(loadWindow(s, row_i));
        accumulateW7WindowJacobian(&acc, &ret_is_zero, one_z, table.ecp_nistz256_precomputed[row_i], row_i, wvalue);
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

test "batch table row matches per-entry affine conversion" {
    if (!use_bedrock_verify_accum) return error.SkipZigTest;
    const row_j = p256ToJacobian(P256.basePoint);
    const batch = buildTableRow(row_j, 16);
    const one_z = montgomeryOne();
    const row_aff = jacobianToAffineMont(row_j);
    const base_xy: [2]coord.Coord = .{ row_aff.x, row_aff.y };
    var acc: Jacobian = .{ base_xy[0], base_xy[1], one_z };
    var idx: usize = 0;
    while (idx < 16) : (idx += 1) {
        const slow = jacobianToAffineMont(acc);
        try std.testing.expectEqual(batch[idx].x, slow.x);
        try std.testing.expectEqual(batch[idx].y, slow.y);
        if (idx + 1 < 16) {
            var out: Jacobian = undefined;
            coord.addMixedAffineOrDouble(&out, acc, base_xy);
            acc = out;
        }
    }
}

test "mulDoubleBaseVarTimePublicWnaf matches w7 Shamir" {
    if (!enabled) return error.SkipZigTest;
    const q_pc = buildPrecomputedTable(P256.basePoint);
    const s1: [32]u8 = @splat(0x11);
    const s2: [32]u8 = @splat(0x22);
    const wnaf_p = mulDoubleBaseVarTimePublicWnaf(s1, P256.basePoint, s2);
    const shamir = mulDoubleBaseVarTimeFromTables(s1, s2, basePrecomputedTable(), &q_pc);
    try std.testing.expect(wnaf_p.equivalent(shamir));
}

test "mulDoubleBaseVarTimeXPublicWnaf matches split mul" {
    if (!enabled) return error.SkipZigTest;
    const s1: [32]u8 = @splat(0x11);
    const s2: [32]u8 = @splat(0x33);
    const x = mulDoubleBaseVarTimeXPublicWnaf(s1, P256.basePoint, s2);
    const split = mulBaseVarTime(s1).add(mulPublicVarTimeFromTable(s2, &buildPrecomputedTable(P256.basePoint)));
    try std.testing.expect(x.equivalent(split.xCoordVarTime()));
}

test "mulDoubleBaseVarTimeXFromTables matches full point" {
    if (!enabled) return error.SkipZigTest;
    const q_pc = buildPrecomputedTable(P256.basePoint);
    const s1: [32]u8 = @splat(0x11);
    const s2: [32]u8 = @splat(0x22);
    const x = mulDoubleBaseVarTimeXFromTables(s1, s2, basePrecomputedTable(), &q_pc);
    const p = mulDoubleBaseVarTimeFromTables(s1, s2, basePrecomputedTable(), &q_pc);
    try std.testing.expect(x.equivalent(p.xCoordVarTime()));
}

test "W7Table heap roundtrip" {
    if (!enabled) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const t = try W7Table.create(gpa, P256.basePoint);
    defer W7Table.deinit(gpa, t);
    try std.testing.expect(t.matchesPublicKey(P256.basePoint));
    const s: [32]u8 = @splat(0x33);
    const a = mulPublicVarTimeFromTable(s, t.rowsPtr());
    const b = try P256.basePoint.mulPublic(Fe.orderSwap(s), .little);
    try std.testing.expect(a.equivalent(b));
}
