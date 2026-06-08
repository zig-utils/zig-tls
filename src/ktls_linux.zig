//! Linux kernel TLS offload via setsockopt(TCP_ULP) + TLS_TX/RX.
const std = @import("std");
const posix = std.posix;
const Ktls = @import("Ktls.zig");

const SOL_TCP = 6;
const TCP_ULP: c_int = 31;
const SOL_TLS: c_int = 282;
const TLS_TX: c_int = 1;
const TLS_RX: c_int = 2;

pub const Error = error{
    UnsupportedOS,
    KtlsEnableFailed,
};

pub fn enable(fd: posix.socket_t, ktls: Ktls) Error!void {
    if (@import("builtin").os.tag != .linux) return error.UnsupportedOS;

    const ulp = "tls";
    posix.setsockopt(fd, SOL_TCP, TCP_ULP, std.mem.asBytes(&ulp[0])) catch return error.KtlsEnableFailed;

    const tx = ktls.txBytes();
    posix.setsockopt(fd, SOL_TLS, TLS_TX, tx) catch return error.KtlsEnableFailed;

    const rx = ktls.rxBytes();
    posix.setsockopt(fd, SOL_TLS, TLS_RX, rx) catch return error.KtlsEnableFailed;
}

pub fn isSupported(cipher: @import("cipher.zig").Cipher) bool {
    return switch (cipher) {
        .AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        => true,
        else => false,
    };
}
