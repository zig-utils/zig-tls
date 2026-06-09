//! Isolated P-256 ECDSA / double-base micro-benchmarks (handshake breakdown).
const std = @import("std");
const Io = std.Io;
const tls = @import("tls");
const ecdsa = tls.ecdsa_p256;

const crypto_iterations: u32 = if (@import("builtin").mode == .Debug) 1_000 else 100_000;

pub fn run(
    io: Io,
    w: anytype,
    allocator: std.mem.Allocator,
    cert_key: *tls.config.CertKeyPair,
    cert_hs_per_sec: f64,
    verify_hs_per_sec: f64,
) !void {
    const kp = cert_key.ecdsa_key_pair.?.ecdsa_secp256r1_sha256;
    const w7 = cert_key.ecdsa_p256_w7_table orelse return;
    const server_w7 = w7.rowsPtr();

    const digest: [32]u8 = @splat(0xaa);
    const sig = try ecdsa.signPrehashed(kp, digest, null);
    const pk = kp.public_key;
    const v1: [32]u8 = @splat(0x11);
    const v2: [32]u8 = @splat(0x42);

    try w.print("{s}\n", .{"--- crypto micro-benchmarks ---"});

    var i: u32 = 0;
    while (i < 64) : (i += 1) {
        try ecdsa.verifyPrehashed(sig, digest, pk, null, server_w7);
    }
    var start = Io.Clock.awake.now(io).nanoseconds;
    i = 0;
    while (i < crypto_iterations) : (i += 1) {
        try ecdsa.verifyPrehashed(sig, digest, pk, null, server_w7);
    }
    var elapsed_ns = Io.Clock.awake.now(io).nanoseconds - start;
    const verify_rate = rate(crypto_iterations, elapsed_ns);
    try w.print("{s:<50} {d:>10.0} /s\n", .{ "ECDSA P-256 verifyPrehashed", verify_rate });

    i = 0;
    while (i < 64) : (i += 1) {
        _ = ecdsa.nistz.mulDoubleBaseVarTimeXFromTables(v1, v2, ecdsa.nistz.basePrecomputedTable(), server_w7);
    }
    start = Io.Clock.awake.now(io).nanoseconds;
    i = 0;
    while (i < crypto_iterations) : (i += 1) {
        _ = ecdsa.nistz.mulDoubleBaseVarTimeXFromTables(v1, v2, ecdsa.nistz.basePrecomputedTable(), server_w7);
    }
    elapsed_ns = Io.Clock.awake.now(io).nanoseconds - start;
    const double_base_rate = rate(crypto_iterations, elapsed_ns);
    try w.print("{s:<50} {d:>10.0} /s\n", .{ "P-256 w7 double-base (x only)", double_base_rate });

    if (cert_hs_per_sec > 0 and verify_hs_per_sec > 0 and verify_rate > 0) {
        const ecdsa_ns = 1e9 / verify_rate;
        const cert_other_ns = (1e9 / cert_hs_per_sec) - ecdsa_ns;
        const verify_other_ns = (1e9 / verify_hs_per_sec) - ecdsa_ns;
        const chain_ns = verify_other_ns - cert_other_ns;
        try w.print("{s}\n", .{"--- handshake breakdown (estimated from rates) ---"});
        try w.print("{s:<50} {d:>10.0} ns\n", .{ "ECDSA verify per handshake", ecdsa_ns });
        try w.print("{s:<50} {d:>10.0} ns\n", .{ "non-ECDSA (cert row)", @max(cert_other_ns, 0) });
        try w.print("{s:<50} {d:>10.0} ns\n", .{ "chain/hostname extra (verify row)", @max(chain_ns, 0) });
        const ecdsa_pct = (ecdsa_ns / (1e9 / verify_hs_per_sec)) * 100;
        try w.print("{s:<50} {d:>9.1}%\n", .{ "ECDSA share of verify handshake", ecdsa_pct });
    }
    _ = allocator;
}

fn rate(n: u32, elapsed_ns: i96) f64 {
    return @as(f64, @floatFromInt(n)) / (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
}
