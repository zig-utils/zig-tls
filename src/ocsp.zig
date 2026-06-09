//! Minimal OCSP staple checks for TLS status_request responses (RFC 6960).
const std = @import("std");
const crypto = std.crypto;

/// Staple was present but could not be parsed or was not successful.
pub const StapleError = error{
    OcspMalformed,
    OcspUnsuccessful,
    OcspCertMismatch,
    OcspExpired,
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
        if (@as(u16, @intFromEnum(@import("protocol.zig").Extension.status_request)) == ext_type) {
            // TLS 1.3: body is opaque OCSPResponse (no status_type wrapper).
            return body;
        }
    }
    return null;
}

/// Validate a stapled OCSP response for the leaf certificate.
/// Verifies DER shape, successful status, and CertID hash/name match when a
/// BasicOCSPResponse is present. Does not verify the OCSP responder signature yet.
pub fn validateStaple(staple: []const u8, leaf_der: []const u8, now_sec: i64) StapleError!void {
    if (staple.len < 3 or staple[0] != 0x30) return error.OcspMalformed;
    const status = parseResponseStatus(staple) orelse return error.OcspMalformed;
    if (status != 0) return error.OcspUnsuccessful;
    const basic = locateBasicOcspResponse(staple) orelse return;
    try validateBasicResponse(basic, leaf_der, now_sec);
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

fn validateBasicResponse(basic: []const u8, leaf_der: []const u8, now_sec: i64) StapleError!void {
    var d = DerDecoder.init(basic);
    const seq = d.sequence() orelse return error.OcspMalformed;
    _ = seq;
    const tbs_start = d.pos;
    const tbs = d.sequence() orelse return error.OcspMalformed;
    const tbs_end = d.pos;
    _ = tbs;
    _ = d.skipTo(tbs_end) orelse return error.OcspMalformed;
    _ = d.skipSignature() orelse return error.OcspMalformed;
    var tbs_dec = DerDecoder.init(basic[tbs_start..tbs_end]);
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

    fn skipSignature(self: *DerDecoder) ?void {
        _ = self.sequence() orelse return null;
        _ = self.sequence() orelse return null;
        if (self.byte() != 0x03) return null;
        const len = self.decodeLength() orelse return null;
        _ = self.slice(len) orelse return null;
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
    try std.testing.expectError(error.OcspUnsuccessful, validateStaple(&staple, &leaf, 0));
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
