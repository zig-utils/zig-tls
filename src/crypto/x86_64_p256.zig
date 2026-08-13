//! x86_64 P-256 Montgomery arithmetic (BoringSSL fiat ADX + ord kernels).
const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .x86_64 and
    @import("build_options").hw_crypto_asm and
    (builtin.os.tag == .macos or builtin.os.tag == .linux);

const use_adx = enabled and builtin.cpu.hasAll(.x86, &.{ .adx, .bmi2 });

pub const Limb = u64;
pub const Fe = [4]Limb;

extern "C" fn fiat_p256_adx_mul(out: *Fe, a: *const Fe, b: *const Fe) void;
extern "C" fn fiat_p256_adx_sqr(out: *Fe, a: *const Fe) void;
extern "C" fn ecp_nistz256_ord_mul_mont_adx(res: *Fe, a: *const Fe, b: *const Fe) void;
extern "C" fn ecp_nistz256_ord_sqr_mont_adx(res: *Fe, a: *const Fe, rep: Limb) void;
extern "C" fn ecp_nistz256_ord_mul_mont_nohw(res: *Fe, a: *const Fe, b: *const Fe) void;
extern "C" fn ecp_nistz256_ord_sqr_mont_nohw(res: *Fe, a: *const Fe, rep: Limb) void;

pub fn mulMont(out: *Fe, a: *const Fe, b: *const Fe) void {
    if (use_adx) {
        fiat_p256_adx_mul(out, a, b);
    }
}

pub fn sqrMont(out: *Fe, a: *const Fe) void {
    if (use_adx) {
        fiat_p256_adx_sqr(out, a);
    }
}

pub fn ordMulMont(out: *Fe, a: *const Fe, b: *const Fe) void {
    if (use_adx) {
        ecp_nistz256_ord_mul_mont_adx(out, a, b);
    } else {
        ecp_nistz256_ord_mul_mont_nohw(out, a, b);
    }
}

pub fn ordSqrMont(out: *Fe, a: *const Fe, rep: Limb) void {
    if (use_adx) {
        ecp_nistz256_ord_sqr_mont_adx(out, a, rep);
    } else {
        ecp_nistz256_ord_sqr_mont_nohw(out, a, rep);
    }
}

pub const field_enabled = use_adx;
