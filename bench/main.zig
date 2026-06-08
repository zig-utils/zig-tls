const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const tls = @import("tls");

const iterations: u32 = if (builtin.mode == .Debug) 100 else 10_000;
const transfer_bytes: usize = 16 * 1024;
const transfer_iterations: u32 = if (builtin.mode == .Debug) 50 else 5_000;

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

fn benchHandshake(io: Io, w: anytype, label: []const u8) !void {
    var sc_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var cs_buf: [tls.max_ciphertext_record_len]u8 = undefined;

    const start = benchTime(io);
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        var cli = tls.nonblock.Client.init(.{
            .root_ca = .empty,
            .host = "localhost",
            .insecure_skip_verify = true,
        });
        var srv = tls.nonblock.Server.init(.{ .auth = null });

        _ = try cli.run(&sc_buf, &cs_buf);
        _ = try srv.run(&cs_buf, &sc_buf);
        while (!cli.done()) {
            _ = try cli.run(&sc_buf, &cs_buf);
            _ = try srv.run(&cs_buf, &sc_buf);
        }
    }
    const elapsed_ns = benchTime(io) - start;
    const handshakes_per_sec = @as(f64, @floatFromInt(iterations)) /
        (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    try w.print("{s:<50} {d:>10.2} /s\n", .{ label, handshakes_per_sec });
}

fn benchTransfer(io: Io, w: anytype, label: []const u8) !void {
    const cli_cipher, const srv_cipher = try setupConnection();
    var cli = tls.nonblock.Connection.init(cli_cipher);
    var srv = tls.nonblock.Connection.init(srv_cipher);

    var send_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var recv_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var payload_buf: [transfer_bytes]u8 = undefined;
    @memset(&payload_buf, 'x');
    const payload = payload_buf[0..];

    const start = benchTime(io);
    var i: u32 = 0;
    while (i < transfer_iterations) : (i += 1) {
        const e = try cli.encrypt(payload, &send_buf);
        const d = try srv.decrypt(e.ciphertext, &recv_buf);
        _ = d;
    }
    const elapsed_ns = benchTime(io) - start;
    const total_mb = @as(f64, @floatFromInt(transfer_bytes * transfer_iterations)) / (1024 * 1024);
    const mb_per_sec = total_mb / (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    try w.print("{s:<50} {d:>10.2} MB/s\n", .{ label, mb_per_sec });
}

fn benchTransferRecv(io: Io, w: anytype, label: []const u8) !void {
    const cli_cipher, const srv_cipher = try setupConnection();
    var cli = tls.nonblock.Connection.init(cli_cipher);
    var srv = tls.nonblock.Connection.init(srv_cipher);

    var send_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var recv_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var payload_buf: [transfer_bytes]u8 = undefined;
    @memset(&payload_buf, 'x');
    const payload = payload_buf[0..];

    const start = benchTime(io);
    var i: u32 = 0;
    while (i < transfer_iterations) : (i += 1) {
        const e = try srv.encrypt(payload, &send_buf);
        const d = try cli.decrypt(e.ciphertext, &recv_buf);
        _ = d;
    }
    const elapsed_ns = benchTime(io) - start;
    const total_mb = @as(f64, @floatFromInt(transfer_bytes * transfer_iterations)) / (1024 * 1024);
    const mb_per_sec = total_mb / (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)));
    try w.print("{s:<50} {d:>10.2} MB/s\n", .{ label, mb_per_sec });
}

fn setupConnection() !struct { tls.Cipher, tls.Cipher } {
    var sc_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var cs_buf: [tls.max_ciphertext_record_len]u8 = undefined;

    var cli = tls.nonblock.Client.init(.{
        .root_ca = .empty,
        .host = "localhost",
        .insecure_skip_verify = true,
    });
    var srv = tls.nonblock.Server.init(.{ .auth = null });

    _ = try cli.run(&sc_buf, &cs_buf);
    _ = try srv.run(&cs_buf, &sc_buf);
    while (!cli.done()) {
        _ = try cli.run(&sc_buf, &cs_buf);
        _ = try srv.run(&cs_buf, &sc_buf);
    }
    return .{ cli.cipher().?, srv.cipher().? };
}
