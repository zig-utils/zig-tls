//! Fixed addition chain for P-256 scalar inversion (a^(n-2) mod L).
//! Brian Smith chain (292 steps). See briansmith.org/ecc-inversion-addition-chains-01
const common = @import("common.zig");

const Fe = common.Field(.{
    .fiat = @import("../p256_scalar_fiat_hw.zig"),
    .field_order = 115792089210356248762697446949407573529996955224135760342422259061068512044369,
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

fn chain(a: Fe, doubles: usize, addend: Fe) Fe {
    return sqn(a, doubles).mul(addend);
}

/// Variable-time scalar inverse using a fixed addition chain for L-2.
pub fn invert(a: Fe) Fe {
    const one = a;
    const _1 = one;
    const _10 = sqn(_1, 1);
    const _11 = _10.mul(_1);
    const _101 = _10.mul(_11);
    const _111 = _10.mul(_101);
    const _1010 = sqn(_101, 1);
    const _1111 = _101.mul(_1010);
    const _10101 = sqn(_1010, 1).mul(_1);
    const _101010 = sqn(_10101, 1);
    const _101111 = _101.mul(_101010);
    const x6 = _10101.mul(_101010);
    const x8 = chain(x6, 2, _11);
    const x16 = chain(x8, 8, x8);
    const x32 = chain(x16, 16, x16);

    var r = chain(x32, 64, x32);
    r = chain(r, 32, x32);
    r = chain(r, 6, _101111);
    r = chain(r, 5, _111);
    r = chain(r, 4, _11);
    r = chain(r, 5, _1111);
    r = chain(r, 5, _10101);
    r = chain(r, 4, _101);
    r = chain(r, 3, _101);
    r = chain(r, 3, _101);
    r = chain(r, 5, _111);
    r = chain(r, 9, _101111);
    r = chain(r, 6, _1111);
    r = chain(r, 2, _1);
    r = chain(r, 5, _1);
    r = chain(r, 6, _1111);
    r = chain(r, 5, _111);
    r = chain(r, 4, _111);
    r = chain(r, 5, _111);
    r = chain(r, 5, _101);
    r = chain(r, 3, _11);
    r = chain(r, 10, _101111);
    r = chain(r, 2, _11);
    r = chain(r, 5, _11);
    r = chain(r, 5, _11);
    r = chain(r, 3, _1);
    r = chain(r, 7, _10101);
    return chain(r, 6, _1111);
}
