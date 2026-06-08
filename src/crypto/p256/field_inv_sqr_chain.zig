//! P-256 field (z^-2) mod p in Montgomery domain (BoringSSL ecp_nistz256_mod_inverse_sqr_mont).
const common = @import("common.zig");

const Fe = common.Field(.{
    .fiat = @import("../p256_fiat_hw.zig"),
    .field_order = 115792089210356248762697446949407573530086143415290314195533631308867097853951,
    .field_bits = 256,
    .saturated_bits = 256,
    .encoded_length = 32,
});

fn sqn(a: Fe, n: usize) Fe {
    var r = a;
    var i: usize = 0;
    while (i < n) : (i += 1) r = r.sq();
    return r;
}

/// Returns a^(-2) mod p (input and output in Montgomery domain).
pub fn invSqrMont(a: Fe) Fe {
    const x2 = a.sq().mul(a);
    const x3 = x2.sq().mul(a);
    const x6 = sqn(x3, 3).mul(x3);
    const x12 = sqn(x6, 6).mul(x6);
    const x15 = sqn(x12, 3).mul(x3);
    const x30 = sqn(x15, 15).mul(x15);
    const x32 = sqn(x30, 2).mul(x2);

    var ret = sqn(x32, 32).mul(a);
    ret = sqn(ret, 128).mul(x32);
    ret = sqn(ret, 32).mul(x32);
    ret = sqn(ret, 30).mul(x30);
    return ret.sq().sq();
}

const std = @import("std");

test "invSqrMont matches invert then square" {
    var one: Fe = undefined;
    @import("../p256_fiat_hw.zig").setOne(&one.limbs);
    var two: Fe = undefined;
    @import("../p256_fiat_hw.zig").add(&two.limbs, one.limbs, one.limbs);
    const inv = two.invert();
    const ref = inv.sq();
    try std.testing.expect(invSqrMont(two).equivalent(ref));
}
