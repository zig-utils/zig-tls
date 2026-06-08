//! ECDSA P-256/SHA-256 using hardware-accelerated field arithmetic when available.
const std = @import("std");
const crypto = std.crypto;

pub const P256 = @import("p256.zig").P256;
pub const EcdsaP256Sha256 = crypto.sign.ecdsa.Ecdsa(P256, crypto.hash.sha2.Sha256);

test "hw P-256 ECDSA sign and verify roundtrip" {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const msg = "TLS 1.3, server CertificateVerify";
    const sig = try kp.sign(msg, null);
    try sig.verify(msg, kp.public_key);
}
