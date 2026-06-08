//! ECDSA P-256/SHA-256 using hardware-accelerated field arithmetic when available.
const std = @import("std");
const crypto = std.crypto;

pub const P256 = @import("p256.zig").P256;
pub const EcdsaP256Sha256 = crypto.sign.ecdsa.Ecdsa(P256, crypto.hash.sha2.Sha256);

const EncodingError = crypto.errors.EncodingError;
const Signature = EcdsaP256Sha256.Signature;

fn parseTlsDerP256(der: []const u8, sig: *Signature) bool {
    if (der.len < 8 or der[0] != 0x30) return false;
    if (@as(usize, der[1]) + 2 != der.len) return false;

    var i: usize = 2;
    inline for (0..2) |n| {
        if (der[i] != 0x02) return false;
        i += 1;
        const int_len = der[i];
        i += 1;
        if (int_len < 32 or int_len > 33) return false;
        if (int_len == 33 and der[i] != 0) return false;
        const src = if (int_len == 33) der[i + 1 .. i + 33] else der[i .. i + 32];
        const dst = if (n == 0) sig.r[0..32] else sig.s[0..32];
        @memcpy(dst, src);
        i += int_len;
    }
    return i == der.len;
}

/// Parse a TLS CertificateVerify ECDSA-P256 signature without the generic DER reader.
pub fn signatureFromDerTls(der: []const u8) EncodingError!Signature {
    if (der.len == 72 and der[0] == 0x30 and der[1] == 0x44 and der[2] == 0x02 and der[3] == 0x20 and der[36] == 0x02 and der[37] == 0x20) {
        var sig: Signature = undefined;
        @memcpy(sig.r[0..32], der[4..36]);
        @memcpy(sig.s[0..32], der[38..70]);
        return sig;
    }
    var sig: Signature = undefined;
    if (parseTlsDerP256(der, &sig)) return sig;
    return Signature.fromDer(der);
}

test "signatureFromDerTls matches fromDer" {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const msg = "TLS 1.3, server CertificateVerify";
    const sig = try kp.sign(msg, null);
    var der_buf: [Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);
    const fast = try signatureFromDerTls(der);
    try std.testing.expectEqualSlices(u8, &sig.r, &fast.r);
    try std.testing.expectEqualSlices(u8, &sig.s, &fast.s);
}

test "hw P-256 ECDSA sign and verify roundtrip" {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const msg = "TLS 1.3, server CertificateVerify";
    const sig = try kp.sign(msg, null);
    try sig.verify(msg, kp.public_key);
}
