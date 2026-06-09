//! TLS 1.3 HKDF-Expand-Label helpers with comptime-built info buffers.
const std = @import("std");
const mem = std.mem;

const tls13_prefix = "tls13 ";

/// HKDF-Expand-Label with empty context (common for key/iv/finished labels).
pub fn expandLabelEmpty(
    comptime Hkdf: type,
    secret: [Hkdf.prk_length]u8,
    comptime label: []const u8,
    comptime out_len: usize,
) [out_len]u8 {
    comptime {
        if (tls13_prefix.len + label.len > 255) @compileError("HKDF label too long");
    }
    const info_len = 2 + 1 + tls13_prefix.len + label.len + 1;
    var info: [info_len]u8 = undefined;
    mem.writeInt(u16, info[0..2], out_len, .big);
    info[2] = @intCast(tls13_prefix.len + label.len);
    @memcpy(info[3..][0..tls13_prefix.len], tls13_prefix);
    @memcpy(info[3 + tls13_prefix.len ..][0..label.len], label);
    info[info_len - 1] = 0;
    var out: [out_len]u8 = undefined;
    Hkdf.expand(&out, info[0..info_len], secret);
    return out;
}

const crypto = std.crypto;
const hkdfExpandLabel = crypto.tls.hkdfExpandLabel;

test "expandLabelEmpty matches hkdfExpandLabel" {
    const Hmac = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256);
    const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);
    var secret: [32]u8 = undefined;
    @memset(&secret, 0x42);
    const a = expandLabelEmpty(Hkdf, secret, "key", 16);
    const b = hkdfExpandLabel(Hkdf, secret, "key", "", 16);
    try std.testing.expectEqualSlices(u8, &a, &b);
    const c = expandLabelEmpty(Hkdf, secret, "iv", 12);
    const d = hkdfExpandLabel(Hkdf, secret, "iv", "", 12);
    try std.testing.expectEqualSlices(u8, &c, &d);
}
