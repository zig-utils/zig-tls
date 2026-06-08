//! P-256 coordinate field: fiat with optional BoringSSL mul/square.
const aarch64_p256 = @import("aarch64_p256.zig");
const x86_64_p256 = @import("x86_64_p256.zig");
const hw = @import("hw_p256.zig");
const std_fiat = @import("p256/p256_64.zig");

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

const field_hw = aarch64_p256.enabled or x86_64_p256.field_enabled;

pub fn mul(out1: *MontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement, arg2: MontgomeryDomainFieldElement) void {
    if (!@inComptime() and field_hw) {
        hw.mul(out1, arg1, arg2);
    } else {
        std_fiat.mul(out1, arg1, arg2);
    }
}

pub fn square(out1: *MontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement) void {
    if (!@inComptime() and field_hw) {
        hw.square(out1, arg1);
    } else {
        std_fiat.square(out1, arg1);
    }
}
