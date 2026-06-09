//! Isolated crypto micro-benchmarks and handshake breakdown estimates.
const std = @import("std");
const Io = std.Io;
const crypto = std.crypto;
const tls = @import("tls");
const ecdsa = tls.ecdsa_p256;

const crypto_iterations: u32 = if (@import("builtin").mode == .Debug) 1_000 else 100_000;
const handshake_record_len: usize = 2048;

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
        ecdsa.verifyPrehashed(sig, digest, pk, null, server_w7) catch unreachable;
    }
    var start = Io.Clock.awake.now(io).nanoseconds;
    i = 0;
    while (i < crypto_iterations) : (i += 1) {
        ecdsa.verifyPrehashed(sig, digest, pk, null, server_w7) catch unreachable;
    }
    const verify_rate = rate(crypto_iterations, Io.Clock.awake.now(io).nanoseconds - start);
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
    const double_base_rate = rate(crypto_iterations, Io.Clock.awake.now(io).nanoseconds - start);
    try w.print("{s:<50} {d:>10.0} /s\n", .{ "P-256 w7 double-base (x only)", double_base_rate });

    var x25519_seed: [32]u8 = undefined;
    @memset(&x25519_seed, 0x55);
    const x25519_kp = crypto.dh.X25519.KeyPair.generateDeterministic(x25519_seed) catch unreachable;
    const server_pk: [32]u8 = @splat(0x66);
    i = 0;
    while (i < 64) : (i += 1) {
        _ = crypto.dh.X25519.scalarmult(x25519_kp.secret_key, server_pk) catch unreachable;
    }
    start = Io.Clock.awake.now(io).nanoseconds;
    i = 0;
    while (i < crypto_iterations) : (i += 1) {
        _ = crypto.dh.X25519.scalarmult(x25519_kp.secret_key, server_pk) catch unreachable;
    }
    const x25519_rate = rate(crypto_iterations, Io.Clock.awake.now(io).nanoseconds - start);
    try w.print("{s:<50} {d:>10.0} /s\n", .{ "X25519 ECDHE scalarmult", x25519_rate });

    const hello_buf: [handshake_record_len]u8 = @splat(0xab);
    i = 0;
    while (i < 64) : (i += 1) {
        var h = crypto.hash.sha2.Sha256.init(.{});
        h.update(&hello_buf);
        var out: [32]u8 = undefined;
        _ = h.final(out[0..]);
    }
    start = Io.Clock.awake.now(io).nanoseconds;
    i = 0;
    while (i < crypto_iterations) : (i += 1) {
        var h = crypto.hash.sha2.Sha256.init(.{});
        h.update(&hello_buf);
        var out: [32]u8 = undefined;
        _ = h.final(out[0..]);
    }
    const sha_rate = rate(crypto_iterations, Io.Clock.awake.now(io).nanoseconds - start);
    try w.print("{s:<50} {d:>10.0} /s\n", .{ "SHA-256 update 2 KiB", sha_rate });

    const gcm_key: [16]u8 = @splat(0x42);
    var gcm_ctx = tls.aes_gcm_cached.CachedAesGcm(crypto.core.aes.Aes128).fromKey(gcm_key);
    var gcm_buf: [handshake_record_len + 32]u8 = undefined;
    const gcm_ct = gcm_buf[5 .. 5 + handshake_record_len + 1];
    var gcm_tag: [16]u8 = undefined;
    const gcm_ad: *const [5]u8 = gcm_buf[0..5];
    gcm_buf[0] = 0x17;
    gcm_buf[1] = 0x03;
    gcm_buf[2] = 0x03;
    std.mem.writeInt(u16, gcm_buf[3..5], @as(u16, @intCast(handshake_record_len + 1 + 16)), .big);
    const gcm_npub: [12]u8 = @splat(0x01);
    const gcm_iters = crypto_iterations / 10;
    i = 0;
    while (i < 64) : (i += 1) {
        gcm_ctx.encryptTls13(gcm_ct, &gcm_tag, gcm_ct[0 .. handshake_record_len + 1], gcm_ad, gcm_npub);
    }
    start = Io.Clock.awake.now(io).nanoseconds;
    i = 0;
    while (i < gcm_iters) : (i += 1) {
        gcm_ctx.encryptTls13(gcm_ct, &gcm_tag, gcm_ct[0 .. handshake_record_len + 1], gcm_ad, gcm_npub);
    }
    const gcm_rate = rate(gcm_iters, Io.Clock.awake.now(io).nanoseconds - start);
    try w.print("{s:<50} {d:>10.0} /s\n", .{ "AES-128-GCM TLS 1.3 ~2 KiB encrypt", gcm_rate });

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
