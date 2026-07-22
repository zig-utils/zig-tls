//! Minimal TLS 1.3 echo server for local interop (testssl.sh, openssl s_client).
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const tls = @import("tls");
const certs = @import("certs");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    const port = parsePort(&init.minimal.args) orelse 8443;

    var cert_key = try tls.config.CertKeyPair.fromPem(allocator, certs.cert_pem, certs.key_pem);
    defer cert_key.deinit(allocator);

    const address = net.IpAddress{ .ip4 = net.Ip4Address.loopback(port) };
    var server = try net.IpAddress.listen(&address, io, .{ .reuse_address = true });
    defer server.deinit(io);

    std.log.info("TLS echo server on 127.0.0.1:{d} (Ctrl+C to stop)", .{port});

    while (true) {
        var stream = try server.accept(io);
        handleConnection(io, &stream, &cert_key) catch |err| {
            std.log.warn("connection failed: {}", .{err});
        };
        stream.close(io);
    }
}

fn handleConnection(io: Io, stream: *const net.Stream, cert_key: *tls.config.CertKeyPair) !void {
    var input_buf: [tls.input_buffer_len]u8 = undefined;
    var output_buf: [tls.output_buffer_len]u8 = undefined;
    var reader = stream.reader(io, &input_buf);
    var writer = stream.writer(io, &output_buf);

    var conn = try tls.server(&reader.interface, &writer.interface, .{
        .auth = cert_key,
        .cipher_suites = tls.config.cipher_suites.secure,
        .named_groups = &[_]tls.config.NamedGroup{.x25519},
        .min_version = .tls_1_3,
        .max_version = .tls_1_3,
    });

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try conn.read(&buf);
        if (n == 0) break;
        try conn.writeAll(buf[0..n]);
    }
}

fn parsePort(args: *const std.process.Args) ?u16 {
    var it = std.process.Args.Iterator.init(args.*);
    _ = it.skip();
    const arg = it.next() orelse return null;
    return std.fmt.parseInt(u16, arg, 10) catch null;
}
