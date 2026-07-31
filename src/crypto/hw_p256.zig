//! P-256 field/scalar Montgomery mul/sqr dispatch (BoringSSL-derived assembly).
const aarch64_p256 = @import("aarch64_p256.zig");
const x86_64_p256 = @import("x86_64_p256.zig");

pub const MontgomeryDomainFieldElement = [4]u64;

pub const enabled = aarch64_p256.enabled or x86_64_p256.enabled;

/// Whether the *field* mul/square kernels are actually available.
///
/// Narrower than `enabled`: on x86_64 the field kernels need ADX+BMI2, which a
/// baseline build (any cross-compile, and most distro builds) does not enable,
/// while the scalar/ord kernels still work. Gating field arithmetic on
/// `enabled` therefore calls a routine that cannot run, and the result is
/// whatever was already in the output buffer.
pub const field_enabled = aarch64_p256.enabled or x86_64_p256.field_enabled;
const field_hw = field_enabled;

pub fn mul(out: *MontgomeryDomainFieldElement, a: MontgomeryDomainFieldElement, b: MontgomeryDomainFieldElement) void {
    if (aarch64_p256.enabled) {
        aarch64_p256.mulMont(out, &a, &b);
        return;
    }
    if (x86_64_p256.field_enabled) {
        x86_64_p256.mulMont(out, &a, &b);
        return;
    }
    // Reaching here means a caller gated on the wrong flag. Returning would
    // leave `out` undefined and produce silently wrong arithmetic - which is
    // how this shipped as garbage ECDSA signatures.
    unreachable;
}

pub fn square(out: *MontgomeryDomainFieldElement, a: MontgomeryDomainFieldElement) void {
    if (aarch64_p256.enabled) {
        aarch64_p256.sqrMont(out, &a);
        return;
    }
    if (x86_64_p256.field_enabled) {
        x86_64_p256.sqrMont(out, &a);
        return;
    }
    unreachable;
}

pub fn ordMul(out: *MontgomeryDomainFieldElement, a: MontgomeryDomainFieldElement, b: MontgomeryDomainFieldElement) void {
    if (aarch64_p256.enabled) {
        aarch64_p256.ordMulMont(out, &a, &b);
        return;
    }
    if (x86_64_p256.enabled) {
        x86_64_p256.ordMulMont(out, &a, &b);
    }
}

pub fn ordSquare(out: *MontgomeryDomainFieldElement, a: MontgomeryDomainFieldElement) void {
    if (aarch64_p256.enabled) {
        aarch64_p256.ordSqrMont(out, &a, 1);
        return;
    }
    if (x86_64_p256.enabled) {
        x86_64_p256.ordSqrMont(out, &a, 1);
    }
}
