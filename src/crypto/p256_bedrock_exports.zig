//! C ABI hooks for Bedrock P-256 point math (optional `-Dbedrock-c-mul-base`).
const coord = @import("p256_coord.zig");
const fiat = @import("p256_fiat_hw.zig");

export fn zig_tls_p256_coord_mul(out: *[4]u64, x: *const [4]u64, y: *const [4]u64) void {
    var o: coord.Coord = undefined;
    coord.mul(&o, x.*, y.*);
    out.* = o;
}

export fn zig_tls_p256_coord_sqr(out: *[4]u64, x: *const [4]u64) void {
    var o: coord.Coord = undefined;
    coord.sqr(&o, x.*);
    out.* = o;
}

export fn zig_tls_p256_fiat_opp(out: *[4]u64, x: *const [4]u64) void {
    var o: fiat.MontgomeryDomainFieldElement = undefined;
    fiat.opp(&o, x.*);
    out.* = o;
}

export fn zig_tls_p256_fiat_set_one(out: *[4]u64) void {
    var o: fiat.MontgomeryDomainFieldElement = undefined;
    fiat.setOne(&o);
    out.* = o;
}
