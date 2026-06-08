const std = @import("std");
const mem = std.mem;
const CipherSuite = @import("cipher.zig").CipherSuite;
const cipher_suites = @import("cipher.zig").cipher_suites;

/// OpenSSL / IANA cipher suite name for each supported suite.
pub fn opensslName(cs: CipherSuite) ?[]const u8 {
    return switch (cs) {
        .ECDHE_ECDSA_WITH_AES_128_CBC_SHA => "ECDHE-ECDSA-AES128-SHA",
        .ECDHE_RSA_WITH_AES_128_CBC_SHA => "ECDHE-RSA-AES128-SHA",
        .RSA_WITH_AES_128_CBC_SHA => "AES128-SHA",
        .ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => "ECDHE-ECDSA-AES128-SHA256",
        .ECDHE_RSA_WITH_AES_128_CBC_SHA256 => "ECDHE-RSA-AES128-SHA256",
        .RSA_WITH_AES_128_CBC_SHA256 => "AES128-SHA256",
        .ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => "ECDHE-ECDSA-AES256-SHA384",
        .ECDHE_RSA_WITH_AES_256_CBC_SHA384 => "ECDHE-RSA-AES256-SHA384",
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "ECDHE-ECDSA-AES128-GCM-SHA256",
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "ECDHE-ECDSA-AES256-GCM-SHA384",
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "ECDHE-RSA-AES128-GCM-SHA256",
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "ECDHE-RSA-AES256-GCM-SHA384",
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-RSA-CHACHA20-POLY1305",
        .AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        .AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        .CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        .AEGIS_128L_SHA256 => "TLS_AEGIS_128L_SHA256",
        else => null,
    };
}

/// Parse an OpenSSL-style colon-separated cipher list into preference-ordered suites.
/// Supports `@SECLEVEL=n` prefix (ignored for ordering; suites still filtered by grade).
pub fn parseCipherList(allocator: mem.Allocator, ciphers: []const u8) ![]CipherSuite {
    var result: std.ArrayListUnmanaged(CipherSuite) = .empty;
    errdefer result.deinit(allocator);

    var it = mem.splitScalar(u8, ciphers, ':');
    while (it.next()) |token| {
        if (token.len == 0) continue;
        if (mem.startsWith(u8, token, "@SECLEVEL=")) continue;
        if (fromOpensslName(token)) |cs| {
            try result.append(allocator, cs);
        } else {
            return error.TlsNoSupportedCiphers;
        }
    }
    if (result.items.len == 0) return error.TlsNoSupportedCiphers;
    return try result.toOwnedSlice(allocator);
}

/// Look up a cipher suite by OpenSSL name (case-sensitive).
pub fn fromOpensslName(name: []const u8) ?CipherSuite {
    inline for (cipher_suites.all) |cs| {
        if (opensslName(cs)) |n| {
            if (mem.eql(u8, n, name)) return cs;
        }
    }
    return null;
}

/// Return all valid OpenSSL cipher names for validation (e.g. Bun `validateCiphers`).
pub fn validNames(allocator: mem.Allocator) ![]const []const u8 {
    var names: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer names.deinit(allocator);
    inline for (cipher_suites.all) |cs| {
        if (opensslName(cs)) |n| try names.append(allocator, n);
    }
    return try names.toOwnedSlice(allocator);
}

const testing = std.testing;

test "fromOpensslName" {
    try testing.expectEqual(CipherSuite.AES_256_GCM_SHA384, fromOpensslName("TLS_AES_256_GCM_SHA384"));
    try testing.expectEqual(CipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256, fromOpensslName("ECDHE-RSA-AES128-GCM-SHA256"));
}

test "parseCipherList" {
    const list = try parseCipherList(testing.allocator, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    defer testing.allocator.free(list);
    try testing.expectEqual(2, list.len);
    try testing.expectEqual(CipherSuite.AES_256_GCM_SHA384, list[0]);
    try testing.expectEqual(CipherSuite.CHACHA20_POLY1305_SHA256, list[1]);
}
