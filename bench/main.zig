const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const tls = @import("tls");

pub const std_options: std.Options = .{
    .log_level = if (builtin.mode == .Debug) .warn else .err,
};

const iterations: u32 = if (builtin.mode == .Debug) 100 else 10_000;
const transfer_bytes: usize = 16 * 1024;
const transfer_iterations: u32 = if (builtin.mode == .Debug) 50 else 5_000;

const bench_groups = &[_]tls.config.NamedGroup{.x25519};

const bench_cipher = &[_]tls.config.CipherSuite{.AES_128_GCM_SHA256};

const bench_client_opt = tls.config.Client{
    .host = "localhost",
    .root_ca = .empty,
    .insecure_skip_verify = true,
    .cipher_suites = bench_cipher,
    .named_groups = bench_groups,
    .min_version = .tls_1_3,
    .max_version = .tls_1_3,
};

const bench_server_opt = tls.config.Server{
    .auth = null,
    .cipher_suites = bench_cipher,
    .named_groups = bench_groups,
    .send_hello_retry_for_preferred_group = false,
    .min_version = .tls_1_3,
    .max_version = .tls_1_3,
};

pub fn main(init: std.process.Init) !void {
    var stdout_buffer: [0x400]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("zig-tls benchmark (iterations={d}, transfer={d} bytes)\n", .{ iterations, transfer_bytes });
    try stdout.print("{s:<50} {s:>12}\n", .{ "benchmark", "result" });
    try stdout.print("{s}\n", .{@as([64]u8, @splat('-'))});

    try benchHandshake(init.io, stdout, "full handshake TLS 1.3");
    try benchTransfer(init.io, stdout, "transfer TLS 1.3 send");
    try benchTransferRecv(init.io, stdout, "transfer TLS 1.3 recv");
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

fn benchHandshake(io: Io, w: anytype, label: []const u8) !void {
    const start = benchTime(io);
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        var cli = tls.nonblock.Client.init(bench_client_opt);
        var srv = tls.nonblock.Server.init(bench_server_opt);
        try pumpHandshake(&cli, &srv);
    }
    const elapsed_ns = benchTime(io) - start;
    const handshakes_per_sec = @as(f64, @floatFromInt(iterations)) /
        (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    try w.print("{s:<50} {d:>10.2} /s\n", .{ label, handshakes_per_sec });
}

fn benchTransferDir(
    io: Io,
    w: anytype,
    label: []const u8,
    sender: *tls.Cipher,
    receiver: *tls.Cipher,
) !void {
    var send_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    const payload = send_buf[tls.record_header_len .. tls.record_header_len + transfer_bytes];
    @memset(payload, 'x');

    const start = benchTime(io);
    var i: u32 = 0;
    // Monomorphized AES-128-GCM path (bench pins this cipher suite).
    const sender_aes = &sender.AES_128_GCM_SHA256;
    const receiver_aes = &receiver.AES_128_GCM_SHA256;
    while (i < transfer_iterations) : (i += 1) {
        const enc_len = try sender_aes.encryptApplication(send_buf[0..], transfer_bytes);
        _ = try receiver_aes.decryptRecordInPlace(send_buf[0..enc_len]);
    }
    const elapsed_ns = benchTime(io) - start;
    const total_mb = @as(f64, @floatFromInt(transfer_bytes * transfer_iterations)) / (1024 * 1024);
    const mb_per_sec = total_mb / (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    try w.print("{s:<50} {d:>10.2} MB/s\n", .{ label, mb_per_sec });
}

fn benchTransfer(io: Io, w: anytype, label: []const u8) !void {
    var cli_cipher, var srv_cipher = try setupConnection();
    try benchTransferDir(io, w, label, &cli_cipher, &srv_cipher);
}

fn benchTransferRecv(io: Io, w: anytype, label: []const u8) !void {
    var cli_cipher, var srv_cipher = try setupConnection();
    try benchTransferDir(io, w, label, &srv_cipher, &cli_cipher);
}

fn setupConnection() !struct { tls.Cipher, tls.Cipher } {
    var cli = tls.nonblock.Client.init(bench_client_opt);
    var srv = tls.nonblock.Server.init(bench_server_opt);
    try pumpHandshake(&cli, &srv);
    return .{ cli.cipher().?, srv.cipher().? };
}
