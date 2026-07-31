//! ECDSA P-256/SHA-256 using hardware-accelerated field arithmetic when available.
const std = @import("std");
const crypto = std.crypto;

const p256 = @import("p256.zig");
const nistz_base = @import("p256_nistz.zig");
pub const nistz = nistz_base;
pub const W7Table = nistz_base.W7Table;
pub const TableRows = nistz_base.TableRows;
pub const P256 = p256.P256;
const AffineCoordinates = p256.AffineCoordinates;
const Fe = P256.Fe;
pub const EcdsaP256Sha256 = crypto.sign.ecdsa.Ecdsa(P256, crypto.hash.sha2.Sha256);

const Prf = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256);
const noise_length = EcdsaP256Sha256.noise_length;

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

/// RFC6979 nonce for TLS (`noise == null`); matches `deterministicScalar` but avoids
/// zeroing the full 129-byte HMAC input buffer.
fn deterministicScalarNoiseless(
    h: [crypto.hash.sha2.Sha256.digest_length]u8,
    secret_key: scalar.CompressedScalar,
) scalar.Scalar {
    var k: [h.len]u8 = @splat(0);
    var m: [h.len + 1 + noise_length + secret_key.len + h.len]u8 = undefined;
    var t: [scalar.encoded_length]u8 = @splat(0);
    const m_v = m[0..h.len];
    const m_i = &m[m_v.len];
    const m_z = m[m_v.len + 1 ..][0..noise_length];
    const m_x = m[m_v.len + 1 + noise_length ..][0..secret_key.len];
    const m_h = m[m.len - h.len ..];

    @memset(m_v, 0x01);
    m_i.* = 0x00;
    @memset(m_z, 0);
    @memcpy(m_x, &secret_key);
    @memcpy(m_h, &h);
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    m_i.* = 0x01;
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    while (true) {
        var t_off: usize = 0;
        while (t_off < t.len) : (t_off += m_v.len) {
            const t_end = @min(t_off + m_v.len, t.len);
            Prf.create(m_v, m_v, &k);
            @memcpy(t[t_off..t_end], m_v[0 .. t_end - t_off]);
        }
        if (scalar.Scalar.fromBytes(t, .big)) |s| return s else |_| {}
        m_i.* = 0x00;
        Prf.create(&k, m[0 .. m_v.len + 1], &k);
        Prf.create(m_v, m_v, &k);
    }
}

fn deterministicScalar(
    h: [crypto.hash.sha2.Sha256.digest_length]u8,
    secret_key: scalar.CompressedScalar,
    noise: ?[noise_length]u8,
) scalar.Scalar {
    var k: [h.len]u8 = @splat(0);
    var m: [h.len + 1 + noise_length + secret_key.len + h.len]u8 = @splat(0);
    var t: [scalar.encoded_length]u8 = @splat(0);
    const m_v = m[0..h.len];
    const m_i = &m[m_v.len];
    const m_z = m[m_v.len + 1 ..][0..noise_length];
    const m_x = m[m_v.len + 1 + noise_length ..][0..secret_key.len];
    const m_h = m[m.len - h.len ..];

    @memset(m_v, 0x01);
    m_i.* = 0x00;
    if (noise) |n| @memcpy(m_z, &n);
    @memcpy(m_x, &secret_key);
    @memcpy(m_h, &h);
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    m_i.* = 0x01;
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    while (true) {
        var t_off: usize = 0;
        while (t_off < t.len) : (t_off += m_v.len) {
            const t_end = @min(t_off + m_v.len, t.len);
            Prf.create(m_v, m_v, &k);
            @memcpy(t[t_off..t_end], m_v[0 .. t_end - t_off]);
        }
        if (scalar.Scalar.fromBytes(t, .big)) |s| return s else |_| {}
        m_i.* = 0x00;
        Prf.create(&k, m[0 .. m_v.len + 1], &k);
        Prf.create(m_v, m_v, &k);
    }
}

/// CertificateVerify sign with cached private scalar (TLS 1.3 server hot path).
pub fn signCertificateVerifyTls(
    secret_key: scalar.CompressedScalar,
    msg_hash: [crypto.hash.sha2.Sha256.digest_length]u8,
    d: scalar.Scalar,
) (IdentityElementError || NonCanonicalError)!Signature {
    const z = hashToScalar(msg_hash);
    const k = deterministicScalarNoiseless(msg_hash, secret_key);
    const k_le = Fe.orderSwap(k.toBytes(.big));
    const x_fe = if (nistz_base.enabled)
        nistz_base.mulBaseVarTimeX(k_le)
    else
        (try P256.basePoint.mul(k.toBytes(.big), .big)).xCoordVarTime();
    const r = feBytesToScalar(x_fe.toBytes(.big));
    if (r.isZero()) return error.IdentityElement;

    const s = k.invertVarTime().mul(z.add(r.mul(d)));
    if (s.isZero()) return error.IdentityElement;

    return Signature{ .r = r.toBytes(.big), .s = s.toBytes(.big) };
}

/// Fast TLS CertificateVerify sign: nistz mulBase, x-only affine, var-time scalar invert.
pub fn signPrehashed(
    key_pair: EcdsaP256Sha256.KeyPair,
    msg_hash: [crypto.hash.sha2.Sha256.digest_length]u8,
    noise: ?[noise_length]u8,
    secret_scalar: ?scalar.Scalar,
) (IdentityElementError || NonCanonicalError)!Signature {
    const z = hashToScalar(msg_hash);
    const k = if (noise == null)
        deterministicScalarNoiseless(msg_hash, key_pair.secret_key.bytes)
    else
        deterministicScalar(msg_hash, key_pair.secret_key.bytes, noise);
    const k_le = Fe.orderSwap(k.toBytes(.big));
    const x_fe = if (nistz_base.enabled)
        nistz_base.mulBaseVarTimeX(k_le)
    else
        (try P256.basePoint.mul(k.toBytes(.big), .big)).xCoordVarTime();
    const r = feBytesToScalar(x_fe.toBytes(.big));
    if (r.isZero()) return error.IdentityElement;

    const k_inv = k.invertVarTime();
    const d = secret_scalar orelse try scalar.Scalar.fromBytes(key_pair.secret_key.bytes, .big);
    const s = k_inv.mul(z.add(r.mul(d)));
    if (s.isZero()) return error.IdentityElement;

    return Signature{ .r = r.toBytes(.big), .s = s.toBytes(.big) };
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
    mul_w7_table: ?*const TableRows,
) (IdentityElementError || NonCanonicalError || SignatureVerificationError)!void {
    const r = try scalar.Scalar.fromBytes(sig.r, .big);
    const s = try scalar.Scalar.fromBytes(sig.s, .big);
    if (r.isZero() or s.isZero()) return error.IdentityElement;

    const z = hashToScalar(msg_hash);
    if (z.isZero()) return error.SignatureVerificationFailed;

    const s_inv = s.invertVarTime();
    const v1 = z.mul(s_inv).toBytes(.little);
    const v2 = r.mul(s_inv).toBytes(.little);
    const x_fe = if (nistz_base.enabled and nistz_base.use_bedrock_mul_public_c) blk: {
        break :blk nistz_base.mulDoubleBaseVarTimeXPublicWnafBedrockC(v1, public_key.p, v2);
    } else if (nistz_base.enabled and nistz_base.use_wnaf_mul_public) blk: {
        break :blk nistz_base.mulDoubleBaseVarTimeXPublicWnaf(v1, public_key.p, v2);
    } else if (nistz_base.enabled and mul_w7_table != null) blk: {
        break :blk nistz_base.mulDoubleBaseVarTimeXFromTables(
            v1,
            v2,
            nistz_base.basePrecomputedTable(),
            mul_w7_table.?,
        );
    } else blk: {
        const sum = try P256.mulDoubleBaseVerify(P256.basePoint, v1, public_key.p, v2, .little, mul_pc, mul_w7_table);
        break :blk sum.xCoordVarTime();
    };
    const vr = feBytesToScalar(x_fe.toBytes(.big));
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
        // 70, not 72: SEQUENCE header (2) + INTEGER r (2 + 32) + INTEGER s
        // (2 + 32). The declared SEQUENCE length above is 0x44 = 68 = 70 - 2,
        // so returning 72 appends two uninitialised bytes after a structure
        // that says it has ended. This library's own parser accepted the
        // 72-byte form, so it agreed with itself and every round-trip test
        // passed - while OpenSSL and every other stack rejected the trailing
        // garbage and the handshake died as BAD_SIGNATURE.
        return buf[0..70];
    }
    return sig.toDer(buf);
}

/// Parse a TLS CertificateVerify ECDSA-P256 signature without the generic DER reader.
pub fn signatureFromDerTls(der: []const u8) EncodingError!Signature {
    // 70 is the correct length; 72 is tolerated so a peer still running the
    // older encoder stays interoperable.
    if ((der.len == 70 or der.len == 72) and der[0] == 0x30 and der[1] == 0x44 and der[2] == 0x02 and der[3] == 0x20 and der[36] == 0x02 and der[37] == 0x20) {
        var sig: Signature = undefined;
        @memcpy(sig.r[0..32], der[4..36]);
        @memcpy(sig.s[0..32], der[38..70]);
        return sig;
    }
    var sig: Signature = undefined;
    if (parseTlsDerP256(der, &sig)) return sig;
    return Signature.fromDer(der);
}

test "deterministicScalarNoiseless matches deterministicScalar" {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const digest: [32]u8 = @splat(0xaa);
    const a = deterministicScalarNoiseless(digest, kp.secret_key.bytes);
    const b = deterministicScalar(digest, kp.secret_key.bytes, null);
    try std.testing.expect(a.equivalent(b));
}

test "signCertificateVerifyTls matches signPrehashed" {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const d = try scalar.Scalar.fromBytes(kp.secret_key.bytes, .big);
    const msg = "TLS 1.3, server CertificateVerify";
    var digest: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
    const a = try signCertificateVerifyTls(kp.secret_key.bytes, digest, d);
    const b = try signPrehashed(kp, digest, null, d);
    try std.testing.expectEqualSlices(u8, &a.r, &b.r);
    try std.testing.expectEqualSlices(u8, &a.s, &b.s);
    const w7 = try W7Table.create(std.testing.allocator, kp.public_key.p);
    defer W7Table.deinit(std.testing.allocator, w7);
    try verifyPrehashed(a, digest, kp.public_key, null, w7.rowsPtr());
}

test "signCertificateVerifyTls verifies with transcript digest" {
    const Transcript = @import("../transcript.zig").Transcript;
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const d = try scalar.Scalar.fromBytes(kp.secret_key.bytes, .big);
    var t: Transcript = .{};
    t.use(.sha256);
    t.update("client hello bytes");
    t.update("server hello bytes");
    var digest: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    t.serverCertificateVerifyDigest(&digest);
    const sig = try signCertificateVerifyTls(kp.secret_key.bytes, digest, d);
    const w7 = try W7Table.create(std.testing.allocator, kp.public_key.p);
    defer W7Table.deinit(std.testing.allocator, w7);
    try verifyPrehashed(sig, digest, kp.public_key, null, w7.rowsPtr());
    try sig.verifyPrehashed(digest, kp.public_key);
}

test "signPrehashed matches std signPrehashed" {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const msg = "TLS 1.3, server CertificateVerify";
    var digest: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
    const std_sig = try kp.signPrehashed(digest, null);
    const fast_sig = try signPrehashed(kp, digest, null, null);
    try std.testing.expectEqualSlices(u8, &std_sig.r, &fast_sig.r);
    try std.testing.expectEqualSlices(u8, &std_sig.s, &fast_sig.s);
    try fast_sig.verifyPrehashed(digest, kp.public_key);
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
    const w7 = try W7Table.create(std.testing.allocator, kp.public_key.p);
    defer W7Table.deinit(std.testing.allocator, w7);
    try verifyPrehashed(sig, digest, kp.public_key, &mul_pc, w7.rowsPtr());
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

// The fast DER encoder has to agree with the length it declares, and with
// every other TLS stack - not merely with this library's own parser.
//
// It returned 72 bytes for a structure whose SEQUENCE header says 68 (so 70
// total), leaving two uninitialised bytes past the end. signatureFromDerTls
// accepted that form, so encode/decode round-tripped here and the defect was
// invisible in-tree. OpenSSL rejects trailing garbage, so every TLS 1.3
// handshake using a P-256 certificate failed with BAD_SIGNATURE, reported by
// the peer as a decrypt_error alert that names nothing useful.
test "fast P-256 DER signature is exactly as long as it claims" {
    const testing = std.testing;

    var sig: Signature = undefined;
    // High bit clear in both, so the fast path is taken.
    @memset(&sig.r, 0x11);
    @memset(&sig.s, 0x22);

    var buf: [Signature.der_encoded_length_max]u8 = undefined;
    const der = signatureToDerTls(sig, &buf);

    try testing.expectEqual(@as(usize, 70), der.len);
    try testing.expectEqual(@as(u8, 0x30), der[0]);
    // A DER SEQUENCE's length field counts every byte after it.
    try testing.expectEqual(der.len - 2, @as(usize, der[1]));

    // And it must survive the generic reader, which is what a peer uses.
    const parsed = try Signature.fromDer(der);
    try testing.expectEqualSlices(u8, &sig.r, &parsed.r);
    try testing.expectEqualSlices(u8, &sig.s, &parsed.s);
}

test "P-256 DER round-trips through the fast parser" {
    const testing = std.testing;
    var sig: Signature = undefined;
    @memset(&sig.r, 0x11);
    @memset(&sig.s, 0x22);

    var buf: [Signature.der_encoded_length_max]u8 = undefined;
    const parsed = try signatureFromDerTls(signatureToDerTls(sig, &buf));

    try testing.expectEqualSlices(u8, &sig.r, &parsed.r);
    try testing.expectEqualSlices(u8, &sig.s, &parsed.s);
}
