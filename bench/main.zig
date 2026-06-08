const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const tls = @import("tls");
const certs = @import("certs.zig");

pub const std_options: std.Options = .{
    .log_level = if (builtin.mode == .Debug) .warn else .err,
};

const iterations: u32 = if (builtin.mode == .Debug) 100 else 10_000;
const transfer_bytes: usize = 16 * 1024;
const transfer_iterations: u32 = if (builtin.mode == .Debug) 50 else 5_000;

const bench_groups = &[_]tls.config.NamedGroup{.x25519};

const bench_cipher_128 = &[_]tls.config.CipherSuite{.AES_128_GCM_SHA256};
const bench_cipher_256 = &[_]tls.config.CipherSuite{.AES_256_GCM_SHA384};

const bench_client_opt = tls.config.Client{
    .host = "localhost",
    .root_ca = .empty,
    .insecure_skip_verify = true,
    .cipher_suites = bench_cipher_128,
    .named_groups = bench_groups,
    .min_version = .tls_1_3,
    .max_version = .tls_1_3,
};

const bench_server_opt = tls.config.Server{
    .auth = null,
    .cipher_suites = bench_cipher_128,
    .named_groups = bench_groups,
    .send_hello_retry_for_preferred_group = false,
    .min_version = .tls_1_3,
    .max_version = .tls_1_3,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var cert_key = try tls.config.CertKeyPair.fromPem(allocator, certs.cert_pem, certs.key_pem);
    defer cert_key.deinit(allocator);

    var stdout_buffer: [0x400]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("zig-tls benchmark (iterations={d}, transfer={d} bytes)\n", .{ iterations, transfer_bytes });
    try stdout.print("{s:<50} {s:>12}\n", .{ "benchmark", "result" });
    try stdout.print("{s}\n", .{@as([64]u8, @splat('-'))});

    try benchHandshake(init.io, stdout, bench_server_opt, "handshake TLS 1.3 (minimal ECDHE)");
    const cert_server_opt = tls.config.Server{
        .auth = &cert_key,
        .cipher_suites = bench_cipher_128,
        .named_groups = bench_groups,
        .send_hello_retry_for_preferred_group = false,
        .min_version = .tls_1_3,
        .max_version = .tls_1_3,
    };
    try benchHandshake(init.io, stdout, cert_server_opt, "handshake TLS 1.3 (ECDHE + cert)");

    try benchTransfer(init.io, stdout, bench_cipher_128, .AES_128_GCM_SHA256, "transfer TLS 1.3 record crypto send (AES-128)");
    try benchTransferRecv(init.io, stdout, bench_cipher_128, .AES_128_GCM_SHA256, "transfer TLS 1.3 record crypto recv (AES-128)");
    try benchTransfer(init.io, stdout, bench_cipher_256, .AES_256_GCM_SHA384, "transfer TLS 1.3 record crypto send (AES-256)");
    try benchTransferRecv(init.io, stdout, bench_cipher_256, .AES_256_GCM_SHA384, "transfer TLS 1.3 record crypto recv (AES-256)");
    try stdout.flush();
}

fn benchTime(io: Io) i96 {
    return Io.Clock.awake.now(io).nanoseconds;
}

fn pumpHandshake(cli: *tls.nonblock.Client, srv: *tls.nonblock.Server) !void {
    var cs_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [tls.max_ciphertext_record_len]u8 = undefined;

    var cr = try cli.run(&.{}, &cs_buf);
    var sr = try srv.run(cr.send, &sc_buf);
    while (!cli.done()) {
        cr = try cli.run(sr.send, &cs_buf);
        sr = try srv.run(cr.send, &sc_buf);
    }
}

fn benchHandshake(io: Io, w: anytype, server_opt: tls.config.Server, label: []const u8) !void {
    const start = benchTime(io);
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        var cli = tls.nonblock.Client.init(bench_client_opt);
        var srv = tls.nonblock.Server.init(server_opt);
        try pumpHandshake(&cli, &srv);
    }
    const elapsed_ns = benchTime(io) - start;
    const handshakes_per_sec = @as(f64, @floatFromInt(iterations)) /
        (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    try w.print("{s:<50} {d:>10.2} /s\n", .{ label, handshakes_per_sec });
}

fn benchRecordCryptoSend(
    io: Io,
    w: anytype,
    label: []const u8,
    sender: *tls.Cipher,
    comptime suite: tls.config.CipherSuite,
) !void {
    var send_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    const payload = send_buf[tls.record_header_len .. tls.record_header_len + transfer_bytes];
    @memset(payload, 'x');

    const start = benchTime(io);
    var i: u32 = 0;
    while (i < transfer_iterations) : (i += 1) {
        _ = switch (suite) {
            .AES_128_GCM_SHA256 => try sender.AES_128_GCM_SHA256.encryptApplication(send_buf[0..], transfer_bytes),
            .AES_256_GCM_SHA384 => try sender.AES_256_GCM_SHA384.encryptApplication(send_buf[0..], transfer_bytes),
            else => @compileError("bench supports AES-128/256 GCM only"),
        };
    }
    const elapsed_ns = benchTime(io) - start;
    const total_mb = @as(f64, @floatFromInt(transfer_bytes * transfer_iterations)) / (1024 * 1024);
    const mb_per_sec = total_mb / (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    try w.print("{s:<50} {d:>10.2} MB/s\n", .{ label, mb_per_sec });
}

fn benchRecordCryptoRecv(
    io: Io,
    w: anytype,
    label: []const u8,
    sender: *tls.Cipher,
    receiver: *tls.Cipher,
    comptime suite: tls.config.CipherSuite,
) !void {
    var send_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    const payload = send_buf[tls.record_header_len .. tls.record_header_len + transfer_bytes];
    @memset(payload, 'x');

    const enc_len = switch (suite) {
        .AES_128_GCM_SHA256 => blk: {
            const sender_aes = &sender.AES_128_GCM_SHA256;
            sender_aes.encrypt_seq = 0;
            sender_aes.encrypt_npub = sender_aes.encrypt_iv;
            break :blk try sender_aes.encryptApplication(send_buf[0..], transfer_bytes);
        },
        .AES_256_GCM_SHA384 => blk: {
            const sender_aes = &sender.AES_256_GCM_SHA384;
            sender_aes.encrypt_seq = 0;
            sender_aes.encrypt_npub = sender_aes.encrypt_iv;
            break :blk try sender_aes.encryptApplication(send_buf[0..], transfer_bytes);
        },
        else => @compileError("bench supports AES-128/256 GCM only"),
    };

    var cipher_template: [tls.max_ciphertext_record_len]u8 = undefined;
    @memcpy(cipher_template[0..enc_len], send_buf[0..enc_len]);

    var work_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    const start = benchTime(io);
    var i: u32 = 0;
    while (i < transfer_iterations) : (i += 1) {
        @memcpy(work_buf[0..enc_len], cipher_template[0..enc_len]);
        switch (suite) {
            .AES_128_GCM_SHA256 => {
                const receiver_aes = &receiver.AES_128_GCM_SHA256;
                receiver_aes.decrypt_seq = 0;
                receiver_aes.decrypt_npub = receiver_aes.decrypt_iv;
                _ = try receiver_aes.decryptRecordInPlace(work_buf[0..enc_len]);
            },
            .AES_256_GCM_SHA384 => {
                const receiver_aes = &receiver.AES_256_GCM_SHA384;
                receiver_aes.decrypt_seq = 0;
                receiver_aes.decrypt_npub = receiver_aes.decrypt_iv;
                _ = try receiver_aes.decryptRecordInPlace(work_buf[0..enc_len]);
            },
            else => unreachable,
        }
    }
    const elapsed_ns = benchTime(io) - start;
    const total_mb = @as(f64, @floatFromInt(transfer_bytes * transfer_iterations)) / (1024 * 1024);
    const mb_per_sec = total_mb / (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    try w.print("{s:<50} {d:>10.2} MB/s\n", .{ label, mb_per_sec });
}

fn benchTransfer(
    io: Io,
    w: anytype,
    cipher_list: []const tls.config.CipherSuite,
    comptime suite: tls.config.CipherSuite,
    label: []const u8,
) !void {
    var cli_cipher, _ = try setupConnection(cipher_list);
    try benchRecordCryptoSend(io, w, label, &cli_cipher, suite);
}

fn benchTransferRecv(
    io: Io,
    w: anytype,
    cipher_list: []const tls.config.CipherSuite,
    comptime suite: tls.config.CipherSuite,
    label: []const u8,
) !void {
    var cli_cipher, var srv_cipher = try setupConnection(cipher_list);
    try benchRecordCryptoRecv(io, w, label, &cli_cipher, &srv_cipher, suite);
}

fn setupConnection(cipher_list: []const tls.config.CipherSuite) !struct { tls.Cipher, tls.Cipher } {
    var cli_opt = bench_client_opt;
    cli_opt.cipher_suites = cipher_list;
    var srv_opt = bench_server_opt;
    srv_opt.cipher_suites = cipher_list;
    var cli = tls.nonblock.Client.init(cli_opt);
    var srv = tls.nonblock.Server.init(srv_opt);
    try pumpHandshake(&cli, &srv);
    return .{ cli.cipher().?, srv.cipher().? };
}
