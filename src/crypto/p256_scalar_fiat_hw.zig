//! P-256 scalar field: fiat with optional BoringSSL ord mul/square.
const hw = @import("hw_p256.zig");
const std_fiat = @import("p256/p256_scalar_64.zig");

pub const MontgomeryDomainFieldElement = std_fiat.MontgomeryDomainFieldElement;
pub const NonMontgomeryDomainFieldElement = std_fiat.NonMontgomeryDomainFieldElement;

pub const add = std_fiat.add;
pub const sub = std_fiat.sub;
pub const opp = std_fiat.opp;
pub const fromMontgomery = std_fiat.fromMontgomery;
pub const toMontgomery = std_fiat.toMontgomery;
pub const nonzero = std_fiat.nonzero;
pub const selectznz = std_fiat.selectznz;
pub const toBytes = std_fiat.toBytes;
pub const fromBytes = std_fiat.fromBytes;
pub const setOne = std_fiat.setOne;
pub const msat = std_fiat.msat;
pub const divstep = std_fiat.divstep;
pub const divstepPrecomp = std_fiat.divstepPrecomp;

pub fn mul(out1: *MontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement, arg2: MontgomeryDomainFieldElement) void {
    if (!@inComptime() and hw.enabled) {
        hw.ordMul(out1, arg1, arg2);
    } else {
        std_fiat.mul(out1, arg1, arg2);
    }
}

pub fn square(out1: *MontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement) void {
    if (!@inComptime() and hw.enabled) {
        hw.ordSquare(out1, arg1);
    } else {
        std_fiat.square(out1, arg1);
    }
}
