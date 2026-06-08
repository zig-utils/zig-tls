//! ECDSA P-256/SHA-256 using hardware-accelerated field arithmetic when available.
const std = @import("std");
const crypto = std.crypto;

const p256 = @import("p256.zig");
pub const P256 = p256.P256;
const AffineCoordinates = p256.AffineCoordinates;
pub const EcdsaP256Sha256 = crypto.sign.ecdsa.Ecdsa(P256, crypto.hash.sha2.Sha256);

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const SignatureVerificationError = crypto.errors.SignatureVerificationError;
const Signature = EcdsaP256Sha256.Signature;
const PublicKey = EcdsaP256Sha256.PublicKey;
const scalar = P256.scalar;

fn hashToScalar(msg_hash: [crypto.hash.sha2.Sha256.digest_length]u8) scalar.Scalar {
    var xs: [48]u8 = @splat(0);
    @memcpy(xs[48 - msg_hash.len ..], msg_hash[0..]);
    return scalar.Scalar.fromBytes48(xs, .big);
}

fn feBytesToScalar(x_bytes: [P256.Fe.encoded_length]u8) scalar.Scalar {
    var xs: [48]u8 = @splat(0);
    @memcpy(xs[48 - x_bytes.len ..], x_bytes[0..]);
    return scalar.Scalar.fromBytes48(xs, .big);
}

/// Verify a prehashed message using Shamir double-base mul (u1*G + u2*Q).
pub fn verifyPrehashed(
    sig: Signature,
    msg_hash: [crypto.hash.sha2.Sha256.digest_length]u8,
    public_key: PublicKey,
    mul_pc: ?*const [9]AffineCoordinates,
) (IdentityElementError || NonCanonicalError || SignatureVerificationError)!void {
    const r = try scalar.Scalar.fromBytes(sig.r, .big);
    const s = try scalar.Scalar.fromBytes(sig.s, .big);
    if (r.isZero() or s.isZero()) return error.IdentityElement;

    const z = hashToScalar(msg_hash);
    if (z.isZero()) return error.SignatureVerificationFailed;

    const s_inv = s.invertVarTime();
    const v1 = z.mul(s_inv).toBytes(.little);
    const v2 = r.mul(s_inv).toBytes(.little);
    const sum = try P256.mulDoubleBasePublic(P256.basePoint, v1, public_key.p, v2, .little, mul_pc);
    const vr = feBytesToScalar(sum.affineCoordinatesVarTime().x.toBytes(.big));
    if (!r.equivalent(vr)) return error.SignatureVerificationFailed;
}

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

/// Encode a TLS CertificateVerify ECDSA-P256 signature (fixed 72-byte layout when canonical).
pub fn signatureToDerTls(sig: Signature, buf: *[Signature.der_encoded_length_max]u8) []const u8 {
    if (sig.r[0] < 0x80 and sig.s[0] < 0x80) {
        buf[0] = 0x30;
        buf[1] = 0x44;
        buf[2] = 0x02;
        buf[3] = 0x20;
        @memcpy(buf[4..36], &sig.r);
        buf[36] = 0x02;
        buf[37] = 0x20;
        @memcpy(buf[38..70], &sig.s);
        return buf[0..72];
    }
    return sig.toDer(buf);
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

test "signatureToDerTls roundtrips signatureFromDerTls" {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const msg = "TLS 1.3, server CertificateVerify";
    const sig = try kp.sign(msg, null);
    var der_buf: [Signature.der_encoded_length_max]u8 = undefined;
    const der = signatureToDerTls(sig, &der_buf);
    const parsed = try signatureFromDerTls(der);
    try std.testing.expectEqualSlices(u8, &sig.r, &parsed.r);
    try std.testing.expectEqualSlices(u8, &sig.s, &parsed.s);
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

test "verifyPrehashed matches std verifyPrehashed" {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const msg = "TLS 1.3, server CertificateVerify";
    const sig = try kp.sign(msg, null);
    var digest: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
    const mul_pc = try P256.precomputeMulPublicAffine(kp.public_key.p);
    try verifyPrehashed(sig, digest, kp.public_key, &mul_pc);
    try sig.verifyPrehashed(digest, kp.public_key);
}

test "hw P-256 ECDSA sign and verify roundtrip" {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const msg = "TLS 1.3, server CertificateVerify";
    const sig = try kp.sign(msg, null);
    try sig.verify(msg, kp.public_key);
}
