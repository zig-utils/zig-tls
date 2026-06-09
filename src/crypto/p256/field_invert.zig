//! P-256 field inverse via z^-2 chain (Brian Smith / BoringSSL inv_square + multiply).
//! a^{-1} = a^{-2} * a because invSqrMont computes a^{p-3}.
const common = @import("common.zig");
const inv_sqr = @import("field_inv_sqr_chain.zig");

const Fe = common.Field(.{
    .fiat = @import("../p256_fiat_hw.zig"),
    .field_order = 115792089210356248762697446949407573530086143415290314195533631308867097853951,
    .field_bits = 256,
    .saturated_bits = 256,
    .encoded_length = 32,
});

/// Variable-time field inverse (Montgomery domain).
pub fn invertVarTime(a: Fe) Fe {
    return inv_sqr.invSqrMont(a).mul(a);
}

const std = @import("std");

test "field invertVarTime matches invert" {
    var one: Fe = undefined;
    @import("../p256_fiat_hw.zig").setOne(&one.limbs);
    var two: Fe = undefined;
    @import("../p256_fiat_hw.zig").add(&two.limbs, one.limbs, one.limbs);
    try std.testing.expect(invertVarTime(two).equivalent(two.invert()));
}

test "field invertVarTime matches invert on sample values" {
    var one: Fe = undefined;
    @import("../p256_fiat_hw.zig").setOne(&one.limbs);
    var n: u32 = 3;
    while (n < 200) : (n += 1) {
        var limbs: Fe = undefined;
        @import("../p256_fiat_hw.zig").add(&limbs.limbs, one.limbs, one.limbs);
        var i: u32 = 2;
        while (i < n) : (i += 1) {
            var tmp: Fe = undefined;
            @import("../p256_fiat_hw.zig").add(&tmp.limbs, limbs.limbs, one.limbs);
            limbs = tmp;
        }
        try std.testing.expect(invertVarTime(limbs).equivalent(limbs.invert()));
    }
}
