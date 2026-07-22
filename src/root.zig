const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

comptime {
    if (@import("crypto/bedrock_c_enabled.zig").enabled) {
        _ = @import("crypto/p256_bedrock_exports.zig");
    }
}

pub const max_ciphertext_record_len = @import("cipher.zig").max_ciphertext_record_len;

/// Buffer of this size will fit any tls ciphertext record sent by other side.
/// To decrytp we need full record, smalled buffer will not work in general
/// case. Bigger can be used for performance reason.
pub const input_buffer_len = max_ciphertext_record_len; // 16645 bytes

/// Needed output buffer during handshake is the size of the tls hello message,
/// which is (when client authentication is not used) ~1600 bytes. After
/// handshake it limits how big tls record can be produced. This suggested value
/// can hold max ciphertext record produced with this implementation.
pub const output_buffer_len = @import("cipher.zig").max_encrypted_record_len; // 16469 bytes

pub const Connection = @import("connection.zig").Connection;

/// P-256 ECDSA (CertificateVerify hot path, bench micro-benchmarks).
pub const ecdsa_p256 = @import("crypto/ecdsa_p256.zig");

/// Low-level RSA primitives (PKCS#1 v1.5 / PSS sign+verify, public/private key
/// parsing incl. SPKI). Exposed so consumers can do RSA outside the TLS
/// handshake — e.g. DKIM signing/verification.
pub const rsa = @import("rsa/rsa.zig");

const handshake = struct {
    const Client = @import("handshake_client.zig").Handshake;
    const Server = @import("handshake_server.zig").Handshake;
};

/// Upgrades existing stream to the tls connection by the client tls handshake.
pub inline fn clientFromStream(stream: anytype, opt: config.Client) !Connection {
    const input, const output = streamToRaderWriter(stream);
    return try client(input, output, opt);
}

pub fn client(input: *Io.Reader, output: *Io.Writer, opt: config.Client) !Connection {
    assert(input.buffer.len >= input_buffer_len);
    assert(output.buffer.len >= 2048); // client hello requires: 1572 + opt.host.len

    var hc: handshake.Client = .{ .input = input, .output = output };
    const cipher, const session_resumption_secret_idx = try hc.handshake(opt);
    return .{
        .cipher = cipher,
        .input = input,
        .output = output,
        .session_resumption_secret_idx = session_resumption_secret_idx,
        .session_resumption = opt.session_resumption,
    };
}

/// Upgrades existing stream to the tls connection by the server side tls handshake.
pub inline fn serverFromStream(stream: anytype, opt: config.Server) !Connection {
    const input, const output = streamToRaderWriter(stream);
    return try server(input, output, opt);
}

pub fn server(input: *Io.Reader, output: *Io.Writer, opt: config.Server) !Connection {
    var hs: handshake.Server = .{ .input = input, .output = output };
    const cipher = try hs.handshake(opt);
    return .{
        .cipher = cipher,
        .input = input,
        .output = output,
    };
}

/// With default buffer sizes
inline fn streamToRaderWriter(stream: anytype) struct { *Io.Reader, *Io.Writer } {
    var input_buf: [input_buffer_len]u8 = undefined;
    var output_buf: [output_buffer_len]u8 = undefined;
    var reader = stream.reader(&input_buf);
    var writer = stream.writer(&output_buf);
    const input = if (@hasField(@TypeOf(reader), "interface")) &reader.interface else reader.interface();
    const output = &writer.interface;
    return .{ input, output };
}

pub const Cipher = @import("cipher.zig").Cipher;
pub const Record = @import("record.zig").Record;
pub const record_header_len = @import("record.zig").header_len;
pub const config = struct {
    pub const proto = @import("protocol.zig");
    const common = @import("handshake_common.zig");

    pub const CipherSuite = @import("cipher.zig").CipherSuite;
    pub const PrivateKey = @import("PrivateKey.zig");
    pub const NamedGroup = proto.NamedGroup;
    pub const Version = proto.Version;
    pub const ContentType = proto.ContentType;
    pub const Record = @import("record.zig").Record;
    pub const cert = common.cert;
    pub const CertKeyPair = common.CertKeyPair;
    pub const W7Table = @import("crypto/ecdsa_p256.zig").W7Table;

    pub const cipher_suites = @import("cipher.zig").cipher_suites;
    pub const key_log = @import("key_log.zig");

    pub const Client = @import("handshake_client.zig").Options;
    pub const Server = @import("handshake_server.zig").Options;
    pub const alpn = @import("alpn.zig");
    pub const cipher_names = @import("cipher_names.zig");
    pub const session_ticket = @import("session_ticket.zig");
};

pub const alpn = @import("alpn.zig");
pub const cipher_names = @import("cipher_names.zig");
pub const session_ticket = @import("session_ticket.zig");
pub const embed = @import("embed.zig");
pub const ktls_linux = @import("ktls_linux.zig");

/// Non-blocking client/server handshake and connection. Handshake produces
/// cipher used in connection to encrypt data for sending and decrypt received
/// data.
pub const nonblock = struct {
    pub const Client = @import("handshake_client.zig").NonBlock;
    pub const Server = @import("handshake_server.zig").NonBlock;
    pub const Connection = @import("connection.zig").NonBlock;
};

pub const Ktls = @import("Ktls.zig");
pub const aes_gcm_cached = @import("aes_gcm_cached.zig");
pub const tls_hkdf = @import("tls_hkdf.zig");
pub const x25519_base = @import("crypto/x25519_base.zig");

/// libFuzzer / audit hooks for untrusted handshake bytes (no panics).
pub const fuzz = struct {
    pub const parseClientHello = @import("handshake_server.zig").Handshake.fuzzReadClientHello;
    pub const parseServerHello = @import("handshake_client.zig").Handshake.fuzzParseServerHello;
};

fn pumpNonblockHandshake(cli: *nonblock.Client, srv: *nonblock.Server) !void {
    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;

    var cr = try cli.run(&.{}, &cs_buf);
    var sr = try srv.run(cr.send, &sc_buf);
    while (!cli.done()) {
        cr = try cli.run(sr.send, &cs_buf);
        sr = try srv.run(cr.send, &sc_buf);
    }
}

test "0-RTT early data server decrypt" {
    const testing = @import("std").testing;
    const allocator = testing.allocator;
    const SessionResumption = @import("handshake_client.zig").Options.SessionResumption;

    const groups = &[_]config.NamedGroup{.x25519};
    const ciphers = &[_]config.CipherSuite{.AES_128_GCM_SHA256};
    const keys = session_ticket.TicketKeys.random();

    var master_secret: [48]u8 = @splat(0xCD);
    const state: session_ticket.SessionState = .{
        .tls_version = .tls_1_3,
        .cipher_suite = .AES_128_GCM_SHA256,
        .named_group = .x25519,
        .master_secret = master_secret,
        .session_timeout_secs = 3600,
    };
    var mgr = session_ticket.Manager.init(keys);
    const issued = try mgr.issueTicket(allocator, state);
    defer allocator.free(issued.identity);

    var resumption = SessionResumption.init(allocator);
    defer resumption.deinit();
    const secret_idx = try resumption.appendSecret(.sha256, master_secret[0..32]);
    var ticket_buf: [4096]u8 = undefined;
    const ticket_msg = try session_ticket.makeNewSessionTicket(
        &ticket_buf,
        issued.lifetime,
        issued.age_add,
        issued.nonce,
        issued.identity,
    );
    try resumption.pushTicket(ticket_msg, secret_idx);

    const server_opt = config.Server{
        .auth = null,
        .cipher_suites = ciphers,
        .named_groups = groups,
        .session_tickets = .{ .keys = keys },
        .send_hello_retry_for_preferred_group = false,
        .max_early_data_size = 16384,
        .min_version = .tls_1_3,
        .max_version = .tls_1_3,
    };
    const early_payload = "early-secret-payload";
    const client_opt = config.Client{
        .host = "localhost",
        .root_ca = .empty,
        .insecure_skip_verify = true,
        .cipher_suites = ciphers,
        .named_groups = groups,
        .session_resumption = &resumption,
        .early_data = early_payload,
        .min_version = .tls_1_3,
        .max_version = .tls_1_3,
    };

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var cli = nonblock.Client.init(client_opt);
    var srv = nonblock.Server.init(server_opt);

    const cr = try cli.run(&.{}, &cs_buf);
    const sr = try srv.run(cr.send, &sc_buf);
    try testing.expect(srv.inner.accept_early_data);
    try testing.expect(srv.inner.psk_resumed);
    try testing.expectEqualStrings(early_payload, srv.earlyData());

    var cli_res = cr;
    var srv_res = sr;
    while (!cli.done()) {
        cli_res = try cli.run(srv_res.send, &cs_buf);
        srv_res = try srv.run(cli_res.send, &sc_buf);
    }
    try testing.expect(cli.done());
    try testing.expect(srv.done());
}

test "interop: TLS 1.3 cert handshake with OCSP staple" {
    const testing = @import("std").testing;
    const allocator = testing.allocator;
    const ocsp = [_]u8{ 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00 };
    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIBfDCCASOgAwIBAgIUQLqOnCo7H/bJUF1Szr+llCjaUDQwCgYIKoZIzj0EAwIw
        \\FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYwODE2NDI0NVoXDTM2MDYwNTE2
        \\NDI0NVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
        \\AQcDQgAEn33K13S5Q8LcxDFMdsmKOFszNXyW7wOyxZfvDxbpa0k5uuzT9ex4G20Q
        \\q0dJ3jaRBz8MMglQClooPnY3Z3iNJKNTMFEwHQYDVR0OBBYEFKCBVZdchts7bXZB
        \\ZWuL8eNAdz/YMB8GA1UdIwQYMBaAFKCBVZdchts7bXZBZWuL8eNAdz/YMA8GA1Ud
        \\EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgcbi5sqviAW6/cB5IceGx2aBG
        \\mURelDq3gDVCXdGXhuoCIHgffOqfX89M1r8Hax8HY7MACM+wnevA7UDIurNdCUUU
        \\-----END CERTIFICATE-----
    ;
    const key_pem =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MHcCAQEEIKpmzT0Wdz4OucLI2ZaHsBjBsSLW4rqsmjMoDhmegFKdoAoGCCqGSM49
        \\AwEHoUQDQgAEn33K13S5Q8LcxDFMdsmKOFszNXyW7wOyxZfvDxbpa0k5uuzT9ex4
        \\G20Qq0dJ3jaRBz8MMglQClooPnY3Z3iNJA==
        \\-----END EC PRIVATE KEY-----
    ;
    var cert_key = try config.CertKeyPair.fromPem(allocator, cert_pem, key_pem);
    defer cert_key.deinit(allocator);

    const groups = &[_]config.NamedGroup{.x25519};
    const ciphers = &[_]config.CipherSuite{.AES_128_GCM_SHA256};
    const server_opt = config.Server{
        .auth = &cert_key,
        .cipher_suites = ciphers,
        .named_groups = groups,
        .ocsp_response = &ocsp,
        .send_hello_retry_for_preferred_group = false,
        .min_version = .tls_1_3,
        .max_version = .tls_1_3,
    };
    const client_opt = config.Client{
        .host = "localhost",
        .root_ca = .empty,
        .insecure_skip_verify = true,
        .cipher_suites = ciphers,
        .named_groups = groups,
        .request_ocsp = true,
        .server_ecdsa_p256_w7_table = cert_key.ecdsa_p256_w7_table,
        .table_allocator = allocator,
        .min_version = .tls_1_3,
        .max_version = .tls_1_3,
    };

    var cli = nonblock.Client.init(client_opt);
    var srv = nonblock.Server.init(server_opt);
    try pumpNonblockHandshake(&cli, &srv);
    try testing.expect(cli.done());
    try testing.expect(srv.done());
    try testing.expect(cli.cipher() != null);
}

test "nonblock handshake and connection" {
    const testing = @import("std").testing;

    // data from server to the client
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    // data from client to the server
    var cs_buf: [max_ciphertext_record_len]u8 = undefined;

    // client/server handshake produces ciphers
    const cli_cipher, const srv_cipher = brk: {
        var cli = nonblock.Client.init(.{
            .root_ca = .empty,
            .host = &.{},
            .insecure_skip_verify = true,
        });
        var srv = nonblock.Server.init(.{ .auth = null });

        // client flight1; client hello is in buf1
        var cr = try cli.run(&sc_buf, &cs_buf);
        try testing.expectEqual(0, cr.recv_pos);
        try testing.expect(cr.send.len > 0);
        try testing.expect(!cli.done());

        { // short read, partial buffer received
            for (0..cr.send_pos) |i| {
                const sr = try srv.run(cs_buf[0..i], &sc_buf);
                try testing.expectEqual(0, sr.recv_pos);
                try testing.expectEqual(0, sr.send_pos);
            }
        }

        // server flight 1; server parses client hello from buf2 and writes server hello into buf1
        var sr = try srv.run(&cs_buf, &sc_buf);
        try testing.expectEqual(sr.recv_pos, cr.send_pos);
        try testing.expect(sr.send.len > 0);
        try testing.expect(!srv.done());

        { // short read, partial buffer received
            for (0..sr.send_pos) |i| {
                cr = try cli.run(sc_buf[0..i], &cs_buf);
                try testing.expectEqual(0, cr.recv_pos);
                try testing.expectEqual(0, cr.send_pos);
            }
        }

        // client flight 2; client parses server hello from buf1 and writes finished into buf2
        cr = try cli.run(&sc_buf, &cs_buf);
        try testing.expectEqual(sr.send_pos, cr.recv_pos);
        try testing.expect(cr.send.len > 0);
        try testing.expect(cli.done()); // client is done
        try testing.expect(cli.cipher() != null);

        // server parses client finished
        sr = try srv.run(&cs_buf, &sc_buf);
        try testing.expectEqual(sr.recv_pos, cr.send_pos);
        try testing.expectEqual(0, sr.send.len);
        try testing.expect(srv.done()); // server is done
        try testing.expect(srv.cipher() != null);

        break :brk .{ cli.cipher().?, srv.cipher().? };
    };
    { // use ciphers in connection
        var cli = nonblock.Connection.init(cli_cipher);
        var srv = nonblock.Connection.init(srv_cipher);

        const cleartext = "Lorem ipsum dolor sit amet";
        { // client to server
            const e = try cli.encrypt(cleartext, &cs_buf);
            try testing.expectEqual(cleartext.len, e.cleartext_pos);
            try testing.expect(e.ciphertext.len > cleartext.len);
            try testing.expect(e.unused_cleartext.len == 0);

            const d = try srv.decrypt(e.ciphertext, &sc_buf);
            try testing.expectEqualSlices(u8, cleartext, d.cleartext);
            try testing.expectEqual(e.ciphertext.len, d.ciphertext_pos);
            try testing.expectEqual(0, d.unused_ciphertext.len);
        }
        { // server to client
            const e = try srv.encrypt(cleartext, &sc_buf);
            const d = try cli.decrypt(e.ciphertext, &cs_buf);
            try testing.expectEqualSlices(u8, cleartext, d.cleartext);
        }
        { // server sends close
            const close_buf = try srv.close(&sc_buf);
            const d = try cli.decrypt(close_buf, &cs_buf);
            try testing.expectEqual(close_buf.len, d.ciphertext_pos);
            try testing.expectEqual(0, d.unused_ciphertext.len);
            try testing.expect(d.closed);
        }
    }
}

test {
    _ = @import("handshake_common.zig");
    _ = @import("handshake_server.zig");
    _ = @import("handshake_client.zig");

    _ = @import("connection.zig");
    _ = @import("cipher.zig");
    _ = @import("record.zig");
    _ = @import("transcript.zig");
    _ = @import("PrivateKey.zig");
    _ = @import("alpn.zig");
    _ = @import("cipher_names.zig");
    _ = @import("session_ticket.zig");
    _ = @import("ktls_linux.zig");
    _ = @import("ffdhe.zig");
    _ = @import("aes_gcm_cached.zig");
    _ = @import("tls_hkdf.zig");
    _ = @import("crypto/x25519_base.zig");
}
