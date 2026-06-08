//! P-256 field/scalar Montgomery mul/sqr dispatch (BoringSSL-derived assembly).
const aarch64_p256 = @import("aarch64_p256.zig");
const x86_64_p256 = @import("x86_64_p256.zig");

pub const MontgomeryDomainFieldElement = [4]u64;

pub const enabled = aarch64_p256.enabled or x86_64_p256.enabled;
const field_hw = aarch64_p256.enabled or x86_64_p256.field_enabled;

pub fn mul(out: *MontgomeryDomainFieldElement, a: MontgomeryDomainFieldElement, b: MontgomeryDomainFieldElement) void {
    if (aarch64_p256.enabled) {
        aarch64_p256.mulMont(out, &a, &b);
        return;
    }
    if (x86_64_p256.field_enabled) {
        x86_64_p256.mulMont(out, &a, &b);
    }
}

pub fn square(out: *MontgomeryDomainFieldElement, a: MontgomeryDomainFieldElement) void {
    if (aarch64_p256.enabled) {
        aarch64_p256.sqrMont(out, &a);
        return;
    }
    if (x86_64_p256.field_enabled) {
        x86_64_p256.sqrMont(out, &a);
    }
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
