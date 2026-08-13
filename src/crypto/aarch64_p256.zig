//! AArch64 P-256 Montgomery arithmetic (BoringSSL ecp_nistz256).
const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .aarch64 and
    @import("build_options").hw_crypto_asm and
    (builtin.os.tag == .macos or builtin.os.tag == .linux);

pub const Limb = u64;
pub const Fe = [4]Limb;

extern "C" fn ecp_nistz256_mul_mont(
    pr: *Fe,
    py: *const Fe,
    y0: Limb,
    x0: Limb,
    x1: Limb,
    x2: Limb,
    x3: Limb,
) void;

extern "C" fn ecp_nistz256_sqr_mont(
    pr: *Fe,
    py: *const Fe,
    y0: Limb,
    x0: Limb,
    x1: Limb,
    x2: Limb,
    x3: Limb,
) void;

extern "C" fn ecp_nistz256_ord_mul_mont(res: *Fe, a: *const Fe, b: *const Fe) void;

extern "C" fn ecp_nistz256_ord_sqr_mont(res: *Fe, a: *const Fe, rep: Limb) void;

pub fn mulMont(out: *Fe, a: *const Fe, b: *const Fe) void {
    ecp_nistz256_mul_mont(out, b, b[0], a[0], a[1], a[2], a[3]);
}

pub fn sqrMont(out: *Fe, a: *const Fe) void {
    ecp_nistz256_sqr_mont(out, a, a[0], a[0], a[1], a[2], a[3]);
}

pub fn ordMulMont(out: *Fe, a: *const Fe, b: *const Fe) void {
    ecp_nistz256_ord_mul_mont(out, a, b);
}

pub fn ordSqrMont(out: *Fe, a: *const Fe, rep: Limb) void {
    ecp_nistz256_ord_sqr_mont(out, a, rep);
}
