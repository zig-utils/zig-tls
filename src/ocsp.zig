//! Minimal OCSP staple checks for TLS status_request responses (RFC 6960).
const std = @import("std");
const crypto = std.crypto;
const Certificate = crypto.Certificate;
const ecdsa_p256 = @import("crypto/ecdsa_p256.zig");
const rsa = @import("rsa/rsa.zig");

/// Staple was present but could not be parsed or was not successful.
pub const StapleError = error{
    OcspMalformed,
    OcspUnsuccessful,
    OcspCertMismatch,
    OcspExpired,
    OcspBadSignature,
};

const sha1_rsa_oid = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 };
const sha256_rsa_oid = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
const ecdsa_sha256_oid = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const ext_key_usage_oid = [_]u8{ 0x55, 0x1d, 0x25 };
const ocsp_signing_oid = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };

pub const ValidateContext = struct {
    now_sec: i64 = 0,
    /// DER of the certificate that issued the leaf (from the TLS chain), if sent.
    leaf_issuer_der: ?[]const u8 = null,
    root_ca: Certificate.Bundle = .empty,
};

/// Parse `status_request` extension bytes on a TLS 1.3 Certificate entry.
pub fn parseTls13StatusRequestExtension(ext_list: []const u8) ?[]const u8 {
    var idx: usize = 0;
    while (idx + 4 <= ext_list.len) {
        const ext_type = std.mem.readInt(u16, ext_list[idx..][0..2], .big);
        const ext_len = std.mem.readInt(u16, ext_list[idx + 2 ..][0..2], .big);
        idx += 4;
        if (idx + ext_len > ext_list.len) return null;
        const body = ext_list[idx .. idx + ext_len];
        idx += ext_len;
        if (@as(u16, @backingInt(@import("protocol.zig").Extension.status_request)) == ext_type) {
            // TLS 1.3: body is opaque OCSPResponse (no status_type wrapper).
            return body;
        }
    }
    return null;
}

/// Validate a stapled OCSP response for the leaf certificate.
pub fn validateStaple(staple: []const u8, leaf_der: []const u8, ctx: ValidateContext) StapleError!void {
    if (staple.len < 3 or staple[0] != 0x30) return error.OcspMalformed;
    const status = parseResponseStatus(staple) orelse return error.OcspMalformed;
    if (status != 0) return error.OcspUnsuccessful;
    const basic = locateBasicOcspResponse(staple) orelse return;
    try validateBasicResponse(basic, leaf_der, ctx);
}

fn parseResponseStatus(staple: []const u8) ?u8 {
    var d = DerDecoder.init(staple);
    const seq = d.sequence() orelse return null;
    if (seq.len < 3) return null;
    if (d.byte() != 0x0a) return null; // ENUMERATED
    const len = d.byte() orelse return null;
    if (len != 1) return null;
    return d.byte();
}

fn locateBasicOcspResponse(staple: []const u8) ?[]const u8 {
    var d = DerDecoder.init(staple);
    const seq = d.sequence() orelse return null;
    _ = seq;
    _ = d.byte() orelse return null; // status enum tag
    _ = d.byte() orelse return null;
    _ = d.byte() orelse return null; // status value
    if (d.remaining() == 0) return null;
    if (d.byte() != 0xa0) return null; // [0] IMPLICIT
    const outer_len = d.decodeLength() orelse return null;
    if (outer_len > d.remaining()) return null;
    const bytes_start = d.pos;
    if (d.byte() != 0x30) return null;
    const inner_len = d.decodeLength() orelse return null;
    if (d.byte() != 0x06) return null; // OID tag
    const oid_len = d.byte() orelse return null;
    if (oid_len != 9 or d.pos + oid_len > d.buf.len) return null;
    const oid = d.buf[d.pos .. d.pos + oid_len];
    d.pos += oid_len;
    if (!std.mem.eql(u8, &[_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 }, oid))
        return null;
    const total = d.pos - bytes_start + inner_len - (1 + 1 + oid_len);
    return d.buf[bytes_start .. bytes_start + total];
}

fn validateBasicResponse(basic: []const u8, leaf_der: []const u8, ctx: ValidateContext) StapleError!void {
    const now_sec = ctx.now_sec;
    var d = DerDecoder.init(basic);
    _ = d.sequence() orelse return error.OcspMalformed;
    const tbs_start = d.pos;
    _ = d.sequence() orelse return error.OcspMalformed;
    const tbs_end = d.pos;
    const tbs_bytes = basic[tbs_start..tbs_end];

    var tbs_dec = DerDecoder.init(tbs_bytes);
    _ = tbs_dec.sequence() orelse return error.OcspMalformed;
    _ = tbs_dec.integer() orelse return error.OcspMalformed; // version
    _ = tbs_dec.skipObject() orelse return error.OcspMalformed; // responderID
    _ = tbs_dec.generalizedTime() orelse return error.OcspMalformed; // producedAt
    const responses = tbs_dec.sequence() orelse return error.OcspMalformed;
    if (responses.len == 0) return error.OcspMalformed;
    const single = tbs_dec.sequence() orelse return error.OcspMalformed;
    _ = single;
    try validateCertId(&tbs_dec, leaf_der);
    const cert_status = tbs_dec.enumerated() orelse return error.OcspMalformed;
    if (cert_status != 0) return error.OcspUnsuccessful;
    const this_update = tbs_dec.generalizedTime() orelse return error.OcspMalformed;
    if (now_sec > 0 and now_sec < this_update) return error.OcspExpired;
    if (tbs_dec.remaining() > 0 and tbs_dec.peekTag() == 0x18) {
        const next_update = tbs_dec.generalizedTime() orelse return error.OcspMalformed;
        if (now_sec > 0 and now_sec > next_update) return error.OcspExpired;
    }

    const sig_oid = parseAlgorithmIdentifier(&d) orelse return error.OcspMalformed;
    const sig_bytes = parseBitString(&d) orelse return error.OcspMalformed;
    const responder_der = parseFirstResponderCert(&d) orelse return error.OcspBadSignature;
    try verifyOcspSignature(tbs_bytes, sig_oid, sig_bytes, responder_der);
    try validateResponderCert(responder_der, leaf_der, ctx);
}

fn validateResponderCert(responder_der: []const u8, leaf_der: []const u8, ctx: ValidateContext) StapleError!void {
    const responder: Certificate = .{ .buffer = responder_der, .index = 0 };
    const responder_parsed = responder.parse() catch return error.OcspMalformed;
    if (ctx.now_sec > 0) {
        if (ctx.now_sec < responder_parsed.validity.not_before or ctx.now_sec > responder_parsed.validity.not_after)
            return error.OcspExpired;
    }
    const leaf: Certificate = .{ .buffer = leaf_der, .index = 0 };
    const leaf_parsed = leaf.parse() catch return error.OcspMalformed;
    if (!std.mem.eql(u8, responder_parsed.issuer(), leaf_parsed.issuer()))
        return error.OcspBadSignature;
    if (!certHasOcspSigningEku(responder_der) and
        !std.mem.eql(u8, responder_parsed.subject(), leaf_parsed.issuer()))
        return error.OcspBadSignature;

    if (ctx.leaf_issuer_der) |issuer_der| {
        const issuer: Certificate = .{ .buffer = issuer_der, .index = 0 };
        const issuer_parsed = issuer.parse() catch return error.OcspMalformed;
        responder_parsed.verify(issuer_parsed, ctx.now_sec) catch return error.OcspBadSignature;
        return;
    }
    const bytes_index = ctx.root_ca.find(leaf_parsed.issuer()) orelse return error.OcspBadSignature;
    const issuer_entry: Certificate = .{ .buffer = ctx.root_ca.bytes.items, .index = bytes_index };
    const issuer_parsed = issuer_entry.parse() catch return error.OcspBadSignature;
    responder_parsed.verify(issuer_parsed, ctx.now_sec) catch return error.OcspBadSignature;
}

fn certHasOcspSigningEku(cert_der: []const u8) bool {
    var d = DerDecoder.init(cert_der);
    _ = d.sequence() orelse return false;
    const tbs_start = d.pos;
    _ = d.sequence() orelse return false;
    const tbs_end = d.pos;
    var tbs = DerDecoder.init(cert_der[tbs_start..tbs_end]);
    _ = tbs.sequence() orelse return false;
    if (tbs.remaining() > 0 and tbs.peekTag() == 0xa0) _ = tbs.skipObject() orelse return false;
    _ = tbs.integer() orelse return false;
    _ = tbs.sequence() orelse return false;
    _ = tbs.sequence() orelse return false;
    _ = tbs.sequence() orelse return false;
    _ = tbs.sequence() orelse return false;
    _ = tbs.sequence() orelse return false;
    if (tbs.remaining() == 0 or tbs.peekTag() != 0xa3) return false;
    _ = tbs.byte() orelse return false;
    const ext_len = tbs.decodeLength() orelse return false;
    const ext_bytes = tbs.slice(ext_len) orelse return false;
    return extensionsContainOcspSigning(ext_bytes);
}

fn extensionsContainOcspSigning(ext_bytes: []const u8) bool {
    var d = DerDecoder.init(ext_bytes);
    _ = d.sequence() orelse return false;
    while (d.remaining() > 0) {
        _ = d.sequence() orelse return false;
        if (d.byte() != 0x06) return false;
        const oid_len = d.byte() orelse return false;
        const oid = d.slice(oid_len) orelse return false;
        if (!std.mem.eql(u8, oid, &ext_key_usage_oid)) {
            if (d.peekTag() == 0x01) _ = d.skipObject() orelse return false;
            _ = d.skipObject() orelse return false;
            continue;
        }
        if (d.peekTag() == 0x01) _ = d.skipObject() orelse return false;
        if (d.byte() != 0x04) return false;
        const val_len = d.byte() orelse return false;
        const val = d.slice(val_len) orelse return false;
        if (extValueHasOid(val, &ocsp_signing_oid)) return true;
    }
    return false;
}

fn extValueHasOid(ext_value: []const u8, oid: []const u8) bool {
    var d = DerDecoder.init(ext_value);
    _ = d.sequence() orelse return false;
    while (d.remaining() > 0) {
        if (d.byte() != 0x06) return false;
        const oid_len = d.byte() orelse return false;
        const got = d.slice(oid_len) orelse return false;
        if (std.mem.eql(u8, got, oid)) return true;
    }
    return false;
}

fn parseAlgorithmIdentifier(d: *DerDecoder) ?[]const u8 {
    _ = d.sequence() orelse return null;
    if (d.byte() != 0x06) return null;
    const oid_len = d.byte() orelse return null;
    return d.slice(oid_len);
}

fn parseBitString(d: *DerDecoder) ?[]const u8 {
    if (d.byte() != 0x03) return null;
    const len = d.decodeLength() orelse return null;
    if (len < 1) return null;
    _ = d.byte() orelse return null;
    return d.slice(len - 1);
}

fn parseFirstResponderCert(d: *DerDecoder) ?[]const u8 {
    if (d.remaining() == 0 or d.peekTag() != 0xa0) return null;
    _ = d.byte() orelse return null;
    const wrap_len = d.decodeLength() orelse return null;
    const wrap_end = d.pos + wrap_len;
    if (wrap_end > d.buf.len or d.buf[d.pos] != 0x30) return null;
    const cert_start = d.pos;
    _ = d.sequence() orelse return null;
    const cert_end = d.pos;
    d.pos = wrap_end;
    return d.buf[cert_start..cert_end];
}

fn verifyOcspSignature(tbs: []const u8, sig_oid: []const u8, sig: []const u8, responder_der: []const u8) StapleError!void {
    const entry: Certificate = .{ .buffer = responder_der, .index = 0 };
    const parsed = entry.parse() catch return error.OcspBadSignature;
    const pub_key = parsed.pubKey();

    if (std.mem.eql(u8, sig_oid, &sha1_rsa_oid)) {
        if (parsed.pub_key_algo != .rsaEncryption) return error.OcspBadSignature;
        const pk = rsa.PublicKey.fromDer(pub_key) catch return error.OcspBadSignature;
        const signature = rsa.PKCS1v1_5(crypto.hash.Sha1).Signature{ .bytes = sig };
        signature.verify(tbs, pk) catch return error.OcspBadSignature;
        return;
    }
    if (std.mem.eql(u8, sig_oid, &sha256_rsa_oid)) {
        if (parsed.pub_key_algo != .rsaEncryption) return error.OcspBadSignature;
        const pk = rsa.PublicKey.fromDer(pub_key) catch return error.OcspBadSignature;
        const signature = rsa.PKCS1v1_5(crypto.hash.sha2.Sha256).Signature{ .bytes = sig };
        signature.verify(tbs, pk) catch return error.OcspBadSignature;
        return;
    }

    if (std.mem.eql(u8, sig_oid, &ecdsa_sha256_oid)) {
        if (parsed.pub_key_algo != .X9_62_id_ecPublicKey) return error.OcspBadSignature;
        if (parsed.pub_key_algo.X9_62_id_ecPublicKey != .X9_62_prime256v1) return error.OcspBadSignature;
        const key = ecdsa_p256.EcdsaP256Sha256.PublicKey.fromSec1(pub_key) catch return error.OcspBadSignature;
        const signature = ecdsa_p256.signatureFromDerTls(sig) catch return error.OcspBadSignature;
        var digest: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(tbs, &digest, .{});
        ecdsa_p256.verifyPrehashed(signature, digest, key, null, null) catch return error.OcspBadSignature;
        return;
    }

    return error.OcspBadSignature;
}

fn validateCertId(d: *DerDecoder, leaf_der: []const u8) StapleError!void {
    const seq = d.sequence() orelse return error.OcspMalformed;
    _ = seq;
    const hash_alg = d.sequence() orelse return error.OcspMalformed;
    _ = hash_alg;
    if (d.byte() != 0x04) return error.OcspMalformed;
    const hash_len = d.byte() orelse return error.OcspMalformed;
    const hash_val = d.slice(hash_len) orelse return error.OcspMalformed;
    const issuer_seq = d.sequence() orelse return error.OcspMalformed;
    _ = issuer_seq;
    _ = d.skipObject() orelse return error.OcspMalformed;
    _ = d.skipObject() orelse return error.OcspMalformed;
    const serial = d.integer() orelse return error.OcspMalformed;
    if (hash_len == 20) {
        var sha1: [20]u8 = undefined;
        crypto.hash.Sha1.hash(leaf_der, &sha1, .{});
        if (!std.mem.eql(u8, &sha1, hash_val)) return error.OcspCertMismatch;
    }
    const leaf_serial = leafSerialNumber(leaf_der) orelse return error.OcspMalformed;
    if (!std.mem.eql(u8, leaf_serial, serial)) return error.OcspCertMismatch;
}

fn leafSerialNumber(leaf_der: []const u8) ?[]const u8 {
    var d = DerDecoder.init(leaf_der);
    _ = d.sequence() orelse return null;
    if (d.remaining() > 0 and d.peekTag() == 0xa0) {
        _ = d.skipObject() orelse return null;
    }
    return d.integer();
}

const DerDecoder = struct {
    buf: []const u8,
    pos: usize = 0,

    fn init(buf: []const u8) DerDecoder {
        return .{ .buf = buf };
    }

    fn remaining(self: DerDecoder) usize {
        return self.buf.len - self.pos;
    }

    fn peekTag(self: DerDecoder) u8 {
        return self.buf[self.pos];
    }

    fn byte(self: *DerDecoder) ?u8 {
        if (self.pos >= self.buf.len) return null;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    fn slice(self: *DerDecoder, len: usize) ?[]const u8 {
        if (self.pos + len > self.buf.len) return null;
        const s = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return s;
    }

    fn decodeLength(self: *DerDecoder) ?usize {
        const b = self.byte() orelse return null;
        if (b < 0x80) return b;
        const nbytes = b & 0x7f;
        if (nbytes == 0 or nbytes > 4) return null;
        var len: usize = 0;
        var i: usize = 0;
        while (i < nbytes) : (i += 1) {
            const x = self.byte() orelse return null;
            len = (len << 8) | x;
        }
        return len;
    }

    fn sequence(self: *DerDecoder) ?struct { len: usize } {
        if (self.byte() != 0x30) return null;
        const len = self.decodeLength() orelse return null;
        if (self.pos + len > self.buf.len) return null;
        return .{ .len = len };
    }

    fn integer(self: *DerDecoder) ?[]const u8 {
        if (self.byte() != 0x02) return null;
        const len = self.byte() orelse return null;
        return self.slice(len);
    }

    fn enumerated(self: *DerDecoder) ?u8 {
        if (self.byte() != 0x0a) return null;
        const len = self.byte() orelse return null;
        if (len != 1) return null;
        return self.byte();
    }

    fn generalizedTime(self: *DerDecoder) ?i64 {
        if (self.byte() != 0x18) return null;
        const len = self.byte() orelse return null;
        const s = self.slice(len) orelse return null;
        return parseGeneralizedTime(s);
    }

    fn skipObject(self: *DerDecoder) ?void {
        _ = self.byte() orelse return null;
        const len = self.decodeLength() orelse return null;
        _ = self.slice(len) orelse return null;
        return {};
    }

    fn skipTo(self: *DerDecoder, end: usize) ?void {
        if (end > self.buf.len) return null;
        self.pos = end;
        return {};
    }
};

fn parseGeneralizedTime(s: []const u8) ?i64 {
    if (s.len < 14) return null;
    const digits = if (s[s.len - 1] == 'Z') s[0 .. s.len - 1] else s;
    if (digits.len < 14) return null;
    const year = std.fmt.parseInt(u16, digits[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u8, digits[4..6], 10) catch return null;
    const day = std.fmt.parseInt(u8, digits[6..8], 10) catch return null;
    const hour = std.fmt.parseInt(u8, digits[8..10], 10) catch return null;
    const min = std.fmt.parseInt(u8, digits[10..12], 10) catch return null;
    const sec = std.fmt.parseInt(u8, digits[12..14], 10) catch return null;
    const day_sec = @as(i64, hour) * 3600 + @as(i64, min) * 60 + sec;
    return generalizedTimeToEpochSec(year, month, day) + day_sec;
}

fn generalizedTimeToEpochSec(year: u16, month: u8, day: u8) i64 {
    const s = 82;
    const K = 719468 + 146097 * s;
    const L = 400 * s;
    const Y_G: u32 = year;
    const M_G: u32 = month;
    const D_G: u32 = day;
    const J: u32 = if (M_G <= 2) 1 else 0;
    const Y: u32 = Y_G + L - J;
    const M: u32 = if (J != 0) M_G + 12 else M_G;
    const D: u32 = D_G - 1;
    const C: u32 = Y / 100;
    const y_star: u32 = 1461 * Y / 4 - C + C / 4;
    const m_star: u32 = (979 * M - 2919) / 32;
    const N: u32 = y_star + m_star + D;
    const days: i32 = @intCast(N - K);
    return @as(i64, days) * std.time.epoch.secs_per_day;
}

test "validateStaple rejects unsuccessful response status" {
    const staple = [_]u8{ 0x30, 0x03, 0x0a, 0x01, 0x01 };
    const leaf = [_]u8{ 0x30, 0x00 };
    try std.testing.expectError(error.OcspUnsuccessful, validateStaple(&staple, &leaf, .{}));
}

test "verifyOcspSignature accepts ECDSA-P256 SHA256 over TBS" {
    const common = @import("handshake_common.zig");
    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIBfDCCASOgAwIBAgIUQLqOnCo7H/bJUF1Szr+llCjaUDQwCgYIKoZIzj0EAwIw
        \\FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYwODE2NDI0NVoXDTM2MDYwNTE2
        \\NDI0NVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
        \\AQcDQgAEn33K13S5Q8LcxDFMdsmKOFszNXyW7wOyxZfvDxbpa0k5uuzT9ex4G20Q
        \\q0dJ3jaRBz8MMglQClooPnY3Z3iNJKNTMFEwHQYDVR0OBBYEFKCBVZdchts7bXZB
        \\ZWuL8eNAdz/YMB8GA1UdIwQYMBaAFKCBVZdchts7bXZBZWuL8eNAdz/YMA8GA1Ud
        \\EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgcbi5sqviAW6/cB5IceGx2aBG
        \\mURelDq3gDVCXdGXhuoCIHgffOqfX89M1r8Hax8HY7MACM+wnevA7UDIurNdCUUU
        \\-----END CERTIFICATE-----
    ;
    const key_pem =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MHcCAQEEIKpmzT0Wdz4OucLI2ZaHsBjBsSLW4rqsmjMoDhmegFKdoAoGCCqGSM49
        \\AwEHoUQDQgAEn33K13S5Q8LcxDFMdsmKOFszNXyW7wOyxZfvDxbpa0k5uuzT9ex4
        \\G20Qq0dJ3jaRBz8MMglQClooPnY3Z3iNJA==
        \\-----END EC PRIVATE KEY-----
    ;
    var pair = try common.CertKeyPair.fromPem(std.testing.allocator, cert_pem, key_pem);
    defer pair.deinit(std.testing.allocator);
    const kp = pair.ecdsa_key_pair.?.ecdsa_secp256r1_sha256;
    const tbs = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 };
    var digest: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(&tbs, &digest, .{});
    const sig = try ecdsa_p256.signPrehashed(kp, digest, null, null);
    var sig_buf: [ecdsa_p256.EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = ecdsa_p256.signatureToDerTls(sig, &sig_buf);
    try verifyOcspSignature(&tbs, &ecdsa_sha256_oid, sig_der, pair.bundle.bytes.items);
}

test "parseTls13StatusRequestExtension extracts staple" {
    var ext: [16]u8 = undefined;
    @memset(&ext, 0);
    std.mem.writeInt(u16, ext[0..2], 5, .big); // status_request
    std.mem.writeInt(u16, ext[2..4], 8, .big); // body len
    ext[4] = 0x30;
    ext[5] = 0x06;
    const got = parseTls13StatusRequestExtension(ext[0..12]).?;
    try std.testing.expectEqual(@as(usize, 8), got.len);
    try std.testing.expectEqual(@as(u8, 0x30), got[0]);
}
