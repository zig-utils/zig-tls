const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const crypto = std.crypto;
const Certificate = crypto.Certificate;
const Io = std.Io;

const Transcript = @import("transcript.zig").Transcript;
const PrivateKey = @import("PrivateKey.zig");
const record = @import("record.zig");
const rsa = @import("rsa/rsa.zig");
const proto = @import("protocol.zig");

const X25519 = crypto.dh.X25519;
const ecdsa_p256 = @import("crypto/ecdsa_p256.zig");
const nistz_p256 = @import("crypto/p256_nistz.zig");
const EcdsaP256Sha256 = ecdsa_p256.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const MLKem768 = crypto.kem.ml_kem.MLKem768;

pub const supported_signature_algorithms = &[_]proto.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .ed25519,
    .rsa_pkcs1_sha1,
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
};

pub const CertKeyPair = struct {
    /// A chain of one or more certificates, leaf first.
    ///
    /// Each X.509 certificate contains the public key of a key pair, extra
    /// information (the name of the holder, the name of an issuer of the
    /// certificate, validity time spans) and a signature generated using the
    /// private key of the issuer of the certificate.
    ///
    /// All certificates from the bundle are sent to the other side when creating
    /// Certificate tls message.
    ///
    /// Leaf certificate and private key are used to create signature for
    /// CertifyVerify tls message.
    bundle: Certificate.Bundle,

    /// Private key corresponding to the public key in leaf certificate from the
    /// bundle.
    key: PrivateKey,

    /// Ecdsa key pair derived from key. Computed on init and cached because it
    /// is costly operation. Important for server which is creating many
    /// signatures with the same key to not repeat that operation.
    ecdsa_key_pair: ?EcdsaKeyPair = null,

    /// Pre-serialized TLS 1.3 Certificate handshake message (type + len + body).
    tls13_certificate_msg: []const u8 = &.{},

    /// Heap-cached w7 P-256 verify table for the leaf public key (P-256 only).
    ecdsa_p256_w7_table: ?*ecdsa_p256.W7Table = null,

    /// Cached P-256 private scalar for repeated CertificateVerify signing.
    ecdsa_p256_d: ?ecdsa_p256.P256.scalar.Scalar = null,

    fn cacheEcdsaP256SignScalar(c: *CertKeyPair) void {
        const ekp = c.ecdsa_key_pair orelse return;
        c.ecdsa_p256_d = switch (ekp) {
            .ecdsa_secp256r1_sha256 => |kp| ecdsa_p256.P256.scalar.Scalar.fromBytes(kp.secret_key.bytes, .big) catch null,
            else => null,
        };
    }

    pub fn fromFilePath(
        allocator: mem.Allocator,
        io: Io,
        dir: std.Io.Dir,
        cert_path: []const u8,
        key_path: []const u8,
    ) !CertKeyPair {
        var bundle: cert.Bundle = .empty;
        try bundle.addCertsFromFilePath(allocator, dir, cert_path);

        const key_file = try dir.openFile(io, key_path, .{});
        defer key_file.close(io);
        const key = try PrivateKey.fromFile(allocator, key_file);

        var pair: CertKeyPair = .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
        pair.cacheEcdsaP256SignScalar();
        try pair.cacheTls13CertificateMessage(allocator);
        try pair.cacheEcdsaP256W7Table(allocator);
        return pair;
    }

    pub fn fromFilePathAbsolute(
        allocator: mem.Allocator,
        io: Io,
        cert_path: []const u8,
        key_path: []const u8,
    ) !CertKeyPair {
        var bundle: cert.Bundle = .empty;
        const now = try Io.Clock.real.now(io);
        try bundle.addCertsFromFilePathAbsolute(allocator, io, now, cert_path);

        const key_file = try std.Io.Dir.openFileAbsolute(io, key_path, .{});
        defer key_file.close(io);
        const key = try PrivateKey.fromFile(allocator, key_file);

        var pair: CertKeyPair = .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
        pair.cacheEcdsaP256SignScalar();
        try pair.cacheTls13CertificateMessage(allocator);
        try pair.cacheEcdsaP256W7Table(allocator);
        return pair;
    }

    /// Reads certs directly from PEM files (delegates to fromFilePathAbsolute)
    pub fn fromFilePathAbsoluteSync(
        allocator: mem.Allocator,
        cert_path: []const u8,
        key_path: []const u8,
    ) !CertKeyPair {
        // This function is called from contexts that have io_compat initialized.
        // We use the same approach - read cert/key via Io.
        // Callers should use fromFilePathAbsolute directly when they have Io.

        // Read key file using posix fd operations (no Io needed)
        // For cert, manually parse PEM
        var cert_buf: [32768]u8 = undefined;
        var cert_len: usize = 0;

        // Use posix read since we may not have Io
        const cert_path_z = @as([*:0]const u8, @ptrCast(cert_path.ptr));
        const cert_fd = std.c.open(cert_path_z, .{}, @as(std.c.mode_t, 0));
        if (cert_fd < 0) return error.FileNotFound;
        defer std.posix.close(@intCast(cert_fd));

        while (cert_len < cert_buf.len) {
            const n = std.posix.read(@intCast(cert_fd), cert_buf[cert_len..]) catch break;
            if (n == 0) break;
            cert_len += n;
        }

        // Parse PEM certificates manually
        var bundle: cert.Bundle = .empty;
        const pem_data = cert_buf[0..cert_len];

        // Find and decode PEM blocks - add DER bytes directly to bundle
        const base64_decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
        var start: usize = 0;
        while (std.mem.indexOfPos(u8, pem_data, start, "-----BEGIN CERTIFICATE-----")) |begin| {
            const content_start = begin + 27; // Length of "-----BEGIN CERTIFICATE-----"
            if (std.mem.indexOfPos(u8, pem_data, content_start, "-----END CERTIFICATE-----")) |end| {
                const base64_data = pem_data[content_start..end];
                const decoded_start: u32 = @intCast(bundle.bytes.items.len);
                const dest_buf = bundle.bytes.addManyAsSlice(allocator, base64_decoder.calcSizeUpperBound(base64_data.len)) catch {
                    start = end + 25;
                    continue;
                };
                const decoded_len = base64_decoder.decode(dest_buf, base64_data) catch {
                    bundle.bytes.items.len = decoded_start;
                    start = end + 25;
                    continue;
                };
                bundle.bytes.items.len = decoded_start + decoded_len;
                // Parse and add to map
                bundle.parseCert(allocator, decoded_start, 0) catch {
                    bundle.bytes.items.len = decoded_start;
                };
                start = end + 25;
            } else break;
        }

        // Read key file using posix fd
        const key_path_z = @as([*:0]const u8, @ptrCast(key_path.ptr));
        const key_fd = std.c.open(key_path_z, .{}, @as(std.c.mode_t, 0));
        if (key_fd < 0) return error.FileNotFound;
        defer std.posix.close(@intCast(key_fd));

        var key_buf: [8192]u8 = undefined;
        var key_len: usize = 0;
        while (key_len < key_buf.len) {
            const n = std.posix.read(@intCast(key_fd), key_buf[key_len..]) catch break;
            if (n == 0) break;
            key_len += n;
        }
        const key = try PrivateKey.parsePem(key_buf[0..key_len]);

        var pair: CertKeyPair = .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
        pair.cacheEcdsaP256SignScalar();
        try pair.cacheTls13CertificateMessage(allocator);
        try pair.cacheEcdsaP256W7Table(allocator);
        return pair;
    }

    fn addCertsFromPem(bundle: *cert.Bundle, allocator: mem.Allocator, pem: []const u8, now_sec: i64) !void {
        const begin_marker = "-----BEGIN CERTIFICATE-----";
        const end_marker = "-----END CERTIFICATE-----";
        const base64_decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
        var start_index: usize = 0;
        while (mem.indexOfPos(u8, pem, start_index, begin_marker)) |begin_marker_start| {
            const cert_start = begin_marker_start + begin_marker.len;
            const cert_end = mem.indexOfPos(u8, pem, cert_start, end_marker) orelse break;
            start_index = cert_end + end_marker.len;
            const encoded_cert = mem.trim(u8, pem[cert_start..cert_end], " \t\r\n");
            const decoded_start: u32 = @intCast(bundle.bytes.items.len);
            const upper = base64_decoder.calcSizeUpperBound(encoded_cert.len);
            try bundle.bytes.ensureUnusedCapacity(allocator, upper);
            const dest_buf = bundle.bytes.allocatedSlice()[decoded_start..];
            const decoded_len = try base64_decoder.decode(dest_buf[0..upper], encoded_cert);
            bundle.bytes.items.len = decoded_start + decoded_len;
            try bundle.parseCert(allocator, decoded_start, now_sec);
        }
    }

    /// Parse a certificate chain and private key from PEM strings.
    pub fn fromPem(allocator: mem.Allocator, cert_pem: []const u8, key_pem: []const u8) !CertKeyPair {
        var bundle: cert.Bundle = .empty;
        // Bench/test credentials may be expired; use 0 so parseCert does not drop them.
        try addCertsFromPem(&bundle, allocator, cert_pem, 0);
        const key = try PrivateKey.parsePem(key_pem);
        var pair: CertKeyPair = .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
        pair.cacheEcdsaP256SignScalar();
        try pair.cacheTls13CertificateMessage(allocator);
        try pair.cacheEcdsaP256W7Table(allocator);
        return pair;
    }

    fn buildTls13CertificateMessage(allocator: mem.Allocator, bundle: cert.Bundle) ![]u8 {
        const certs = bundle.bytes.items;
        const certs_count = bundle.map.size;
        const extensions = [_]u8{ 0, 0 };
        const certs_len = certs.len + (3 + extensions.len) * certs_count;
        const body_len = 1 + 3 + certs_len;
        const msg = try allocator.alloc(u8, 4 + body_len);
        var w = record.Writer.init(msg);
        try w.handshakeRecordHeader(.certificate, body_len);
        try w.byte(0);
        try w.int(u24, certs_len);
        var index: u32 = 0;
        while (index < certs.len) {
            const e = try Certificate.der.Element.parse(certs, index);
            const crt = certs[index..e.slice.end];
            try w.int(u24, crt.len);
            try w.slice(crt);
            try w.slice(&extensions);
            index = e.slice.end;
        }
        return msg;
    }

    pub fn cacheTls13CertificateMessage(c: *CertKeyPair, allocator: mem.Allocator) !void {
        if (c.bundle.map.size == 0) return;
        c.tls13_certificate_msg = try buildTls13CertificateMessage(allocator, c.bundle);
    }

    pub fn cacheEcdsaP256W7Table(c: *CertKeyPair, allocator: mem.Allocator) !void {
        if (c.ecdsa_p256_w7_table != null) return;
        const kp = c.ecdsa_key_pair orelse return;
        switch (kp) {
            .ecdsa_secp256r1_sha256 => |key_pair| {
                if (!nistz_p256.enabled) return;
                c.ecdsa_p256_w7_table = try ecdsa_p256.W7Table.create(allocator, key_pair.public_key.p);
            },
            else => {},
        }
    }

    pub fn deinit(c: *CertKeyPair, allocator: mem.Allocator) void {
        if (c.tls13_certificate_msg.len != 0) allocator.free(c.tls13_certificate_msg);
        if (c.ecdsa_p256_w7_table) |w7| ecdsa_p256.W7Table.deinit(allocator, w7);
        c.bundle.deinit(allocator);
    }

    const EcdsaKeyPair = union(enum) {
        ecdsa_secp256r1_sha256: EcdsaP256Sha256.KeyPair,
        ecdsa_secp384r1_sha384: EcdsaP384Sha384.KeyPair,

        fn init(pk: PrivateKey) !?EcdsaKeyPair {
            switch (pk.signature_scheme) {
                inline .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384,
                => |comptime_scheme| {
                    const Ecdsa = SchemeEcdsa(comptime_scheme);
                    const key = pk.key.ecdsa;
                    const key_len = Ecdsa.SecretKey.encoded_length;
                    if (key.len < key_len) return error.InvalidEncoding;
                    const secret_key = try Ecdsa.SecretKey.fromBytes(key[0..key_len].*);
                    const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key);
                    return switch (comptime_scheme) {
                        .ecdsa_secp256r1_sha256 => .{ .ecdsa_secp256r1_sha256 = key_pair },
                        .ecdsa_secp384r1_sha384 => .{ .ecdsa_secp384r1_sha384 = key_pair },
                        else => unreachable,
                    };
                },
                else => return null,
            }
        }
    };
};

pub const cert = struct {
    // A chain of one or more certificates.
    //
    // They are used to verify that certificate chain sent by the other side
    // forms valid trust chain.
    pub const Bundle = crypto.Certificate.Bundle;

    pub fn fromFilePath(allocator: mem.Allocator, dir: std.fs.Dir, path: []const u8) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.addCertsFromFilePath(allocator, dir, path);
        return bundle;
    }

    pub fn fromFilePathAbsolute(allocator: mem.Allocator, path: []const u8) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.addCertsFromFilePathAbsolute(allocator, path);
        return bundle;
    }

    pub fn fromSystem(allocator: mem.Allocator) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.rescan(allocator);
        return bundle;
    }
};

pub const CertificateBuilder = struct {
    cert_key_pair: *CertKeyPair,
    transcript: *Transcript,
    tls_version: proto.Version = .tls_1_3,
    side: proto.Side = .client,

    pub fn makeCertificate(h: CertificateBuilder, w: *record.Writer) !void {
        if (h.tls_version == .tls_1_3 and h.cert_key_pair.tls13_certificate_msg.len != 0) {
            try w.slice(h.cert_key_pair.tls13_certificate_msg);
            return;
        }
        const certs = h.cert_key_pair.bundle.bytes.items;
        const certs_count = h.cert_key_pair.bundle.map.size;

        // Differences between tls 1.3 and 1.2
        // TLS 1.3 has request context in header and extensions for each certificate.
        // Here we use empty length for each field.
        // TLS 1.2 don't have these two fields.
        const request_context, const extensions = if (h.tls_version == .tls_1_3)
            .{ &[_]u8{0}, &[_]u8{ 0, 0 } }
        else
            .{ &[_]u8{}, &[_]u8{} };
        const certs_len = certs.len + (3 + extensions.len) * certs_count;

        // Write handshake header
        try w.handshakeRecordHeader(.certificate, certs_len + request_context.len + 3);
        try w.slice(request_context);
        try w.int(u24, certs_len);

        // Write each certificate
        var index: u32 = 0;
        while (index < certs.len) {
            const e = try Certificate.der.Element.parse(certs, index);
            const crt = certs[index..e.slice.end];
            try w.int(u24, crt.len); // certificate length
            try w.slice(crt); // certificate
            try w.slice(extensions); // certificate extensions
            index = e.slice.end;
        }
    }

    pub fn makeCertificateVerify(h: CertificateBuilder, w: *record.Writer) !void {
        // Creates signature for client certificate signature message.
        // Returns signature bytes and signature scheme.
        const signature, const signature_scheme = switch (h.cert_key_pair.key.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| brk: {
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const key_pair = switch (comptime_scheme) {
                    .ecdsa_secp256r1_sha256 => h.cert_key_pair.ecdsa_key_pair.?.ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384 => h.cert_key_pair.ecdsa_key_pair.?.ecdsa_secp384r1_sha384,
                    else => unreachable,
                };
                const signature = switch (h.tls_version) {
                    .tls_1_2 => blk: {
                        var hash_state = h.transcript.hash(switch (comptime_scheme) {
                            .ecdsa_secp256r1_sha256 => crypto.hash.sha2.Sha256,
                            .ecdsa_secp384r1_sha384 => crypto.hash.sha2.Sha384,
                            else => unreachable,
                        });
                        const digest = hash_state.finalResult();
                        break :blk if (comptime_scheme == .ecdsa_secp256r1_sha256)
                            try ecdsa_p256.signPrehashed(key_pair, digest, null, h.cert_key_pair.ecdsa_p256_d)
                        else
                            try key_pair.signPrehashed(digest, null);
                    },
                    .tls_1_3 => blk: {
                        const Hash = switch (comptime_scheme) {
                            .ecdsa_secp256r1_sha256 => crypto.hash.sha2.Sha256,
                            .ecdsa_secp384r1_sha384 => crypto.hash.sha2.Sha384,
                            else => unreachable,
                        };
                        var digest: [Hash.digest_length]u8 = undefined;
                        switch (comptime_scheme) {
                            .ecdsa_secp256r1_sha256 => switch (h.side) {
                                .server => h.transcript.serverCertificateVerifyDigest(&digest),
                                .client => h.transcript.clientCertificateVerifyDigest(&digest),
                            },
                            .ecdsa_secp384r1_sha384 => switch (h.side) {
                                .server => h.transcript.serverCertificateVerifyDigestSha384(&digest),
                                .client => h.transcript.clientCertificateVerifyDigestSha384(&digest),
                            },
                            else => unreachable,
                        }
                        break :blk if (comptime_scheme == .ecdsa_secp256r1_sha256)
                            try ecdsa_p256.signPrehashed(key_pair, digest, null, h.cert_key_pair.ecdsa_p256_d)
                        else
                            try key_pair.signPrehashed(digest, null);
                    },
                    else => unreachable,
                };
                var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                const der_bytes = if (comptime_scheme == .ecdsa_secp256r1_sha256)
                    ecdsa_p256.signatureToDerTls(signature, &buf)
                else
                    signature.toDer(&buf);
                break :brk .{ der_bytes, comptime_scheme };
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| brk: {
                const Hash = SchemeHash(comptime_scheme);
                var signer = try h.cert_key_pair.key.key.rsa.signerOaep(Hash, null);
                h.setSignatureVerifyBytes(&signer);
                var buf: [512]u8 = undefined;
                const signature = try signer.finalize(&buf);
                break :brk .{ signature.bytes, comptime_scheme };
            },
            else => return error.TlsUnknownSignatureScheme,
        };

        try w.handshakeRecordHeader(.certificate_verify, signature.len + 4);
        try w.enumValue(signature_scheme);
        try w.int(u16, signature.len);
        try w.slice(signature);
    }

    fn setSignatureVerifyBytes(h: CertificateBuilder, signer: anytype) void {
        if (h.tls_version == .tls_1_2) {
            // tls 1.2 signature uses current transcript hash value.
            // ref: https://datatracker.ietf.org/doc/html/rfc5246.html#section-7.4.8
            const Hash = @TypeOf(signer.h);
            signer.h = h.transcript.hash(Hash);
        } else {
            // tls 1.3 signature is computed over concatenation of 64 spaces,
            // context, separator and content.
            // ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
            if (h.side == .server) {
                signer.update(h.transcript.serverCertificateVerify());
            } else {
                signer.update(h.transcript.clientCertificateVerify());
            }
        }
    }
};

pub fn SchemeEcdsa(comptime scheme: proto.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => EcdsaP384Sha384,
        else => unreachable,
    };
}

fn checkCertValidity(subject: Certificate.Parsed, now_sec: i64) Certificate.Parsed.VerifyError!void {
    if (now_sec != 0 and now_sec < subject.validity.not_before)
        return error.CertificateNotYetValid;
    if (now_sec != 0 and now_sec > subject.validity.not_after)
        return error.CertificateExpired;
}

fn checkCertValidityCached(h: *const CertificateParser) Certificate.Parsed.VerifyError!void {
    if (h.now_sec != 0 and h.now_sec < h.cached_not_before)
        return error.CertificateNotYetValid;
    if (h.now_sec != 0 and h.now_sec > h.cached_not_after)
        return error.CertificateExpired;
}

fn bundleDerSpan(bundle: Certificate.Bundle, bytes_index: u32) ?[]const u8 {
    const cert_bytes = bundle.bytes.items;
    if (bytes_index >= cert_bytes.len) return null;
    const certificate = Certificate.der.Element.parse(cert_bytes, bytes_index) catch return null;
    return cert_bytes[bytes_index..certificate.slice.end];
}

fn bundleContainsCertDer(bundle: Certificate.Bundle, bytes_index: u32, der: []const u8) bool {
    const cert_bytes = bundle.bytes.items;
    if (bytes_index >= cert_bytes.len) return false;
    const certificate = Certificate.der.Element.parse(cert_bytes, bytes_index) catch return false;
    const bundle_der = cert_bytes[bytes_index..certificate.slice.end];
    return mem.eql(u8, der, bundle_der);
}

const prewarm_trusted_max = 32;

fn findTrustedCertDer(h: *const CertificateParser, der: []const u8, leaf_hash: u64) ?u32 {
    const der_len: u32 = @intCast(der.len);
    if (h.cached_leaf_ready and der_len == h.cached_leaf_der_len and leaf_hash == h.cached_leaf_hash) {
        if (h.cached_trusted_bytes_index) |idx| return idx;
        for (h.prewarmed_trusted.entries[0..h.prewarmed_trusted.count]) |entry| {
            if (entry.der_len == der_len and entry.hash == leaf_hash) return entry.bytes_index;
        }
    }
    for (h.prewarmed_trusted.entries[0..h.prewarmed_trusted.count]) |entry| {
        if (entry.der_len == der_len and entry.hash == leaf_hash and
            bundleContainsCertDer(h.root_ca, entry.bytes_index, der))
        {
            return entry.bytes_index;
        }
    }
    var it = h.root_ca.map.iterator();
    while (it.next()) |entry| {
        const bytes_index = entry.value_ptr.*;
        if (bundleContainsCertDer(h.root_ca, bytes_index, der)) return bytes_index;
    }
    return null;
}

fn parseCertificateSubject(
    bundle: Certificate.Bundle,
    der: []const u8,
    trusted_index: ?u32,
) !Certificate.Parsed {
    if (trusted_index) |bytes_index| {
        const entry: Certificate = .{ .buffer = bundle.bytes.items, .index = bytes_index };
        return entry.parse();
    }
    const entry: Certificate = .{ .buffer = der, .index = 0 };
    return entry.parse();
}

/// Verify chain against root_ca. When the presented cert bytes match a trusted
/// anchor entry exactly, skip re-parsing the issuer and ECDSA/RSA chain verify.
fn verifyTrustedAnchor(
    bundle: Certificate.Bundle,
    subject: Certificate.Parsed,
    der: []const u8,
    now_sec: i64,
) Certificate.Bundle.VerifyError!void {
    const bytes_index = bundle.find(subject.issuer()) orelse return error.CertificateIssuerNotFound;
    if (!bundleContainsCertDer(bundle, bytes_index, der)) {
        return bundle.verify(subject, now_sec);
    }
    try checkCertValidity(subject, now_sec);
}

pub const CertificateParser = struct {
    pub_key_algo: Certificate.Parsed.PubKeyAlgo = undefined,
    pub_key_buf: [1038]u8 = undefined,
    pub_key: []const u8 = undefined,

    signature_scheme: proto.SignatureScheme = @enumFromInt(0),
    signature_buf: [1024]u8 = undefined,
    signature: []const u8 = undefined,

    /// Parsed leaf public keys (avoid re-parsing SEC1/DER on CertificateVerify).
    ecdsa_p256_pk: ?EcdsaP256Sha256.PublicKey = null,
    ecdsa_p256_mul_pc: ?[9]@import("crypto/p256.zig").AffineCoordinates = null,
    borrowed_ecdsa_p256_w7_table: ?*const ecdsa_p256.W7Table = null,
    owned_ecdsa_p256_w7_table: ?*ecdsa_p256.W7Table = null,
    table_allocator: ?mem.Allocator = null,
    ecdsa_p384_pk: ?EcdsaP384Sha384.PublicKey = null,
    ed25519_pk: ?crypto.sign.Ed25519.PublicKey = null,
    rsa_pk: ?rsa.PublicKey = null,

    root_ca: Certificate.Bundle,
    host: []const u8,
    skip_verify: bool = false,
    now_sec: i64 = 0,

    /// Reused across handshakes when the server sends the same leaf certificate.
    cached_leaf_hash: u64 = 0,
    cached_host_ok: bool = false,
    cached_leaf_ready: bool = false,
    cached_not_before: u64 = 0,
    cached_not_after: u64 = 0,
    cached_leaf_der_len: u32 = 0,
    cached_trusted_bytes_index: ?u32 = null,
    prewarmed_trusted: struct {
        count: u8 = 0,
        entries: [prewarm_trusted_max]struct {
            hash: u64,
            der_len: u32,
            bytes_index: u32,
        } = undefined,
    } = .{},

    fn indexPrewarmedTrusted(h: *CertificateParser, bytes_index: u32, der: []const u8) void {
        const der_len: u32 = @intCast(der.len);
        const hash = std.hash.Wyhash.hash(0, der);
        for (h.prewarmed_trusted.entries[0..h.prewarmed_trusted.count]) |entry| {
            if (entry.bytes_index == bytes_index and entry.der_len == der_len and entry.hash == hash) return;
        }
        if (h.prewarmed_trusted.count >= prewarm_trusted_max) return;
        h.prewarmed_trusted.entries[h.prewarmed_trusted.count] = .{
            .hash = hash,
            .der_len = der_len,
            .bytes_index = bytes_index,
        };
        h.prewarmed_trusted.count += 1;
    }

    fn cachePrewarmedLeaf(h: *CertificateParser, bytes_index: u32, der: []const u8, subject: Certificate.Parsed) !void {
        if (h.host.len > 0) {
            try subject.verifyHostName(h.host);
            h.cached_host_ok = true;
        }
        h.pub_key = try dupe(&h.pub_key_buf, subject.pubKey());
        h.pub_key_algo = subject.pub_key_algo;
        try h.cacheParsedPublicKey();
        h.cached_leaf_hash = std.hash.Wyhash.hash(0, der);
        h.cached_leaf_der_len = @intCast(der.len);
        h.cached_not_before = subject.validity.not_before;
        h.cached_not_after = subject.validity.not_after;
        h.indexPrewarmedTrusted(bytes_index, der);
        h.cached_trusted_bytes_index = bytes_index;
        h.cached_leaf_ready = true;
    }

    /// Index trusted root_ca certificates and pre-parse a matching leaf when possible.
    pub fn prewarmTrustedLeaf(h: *CertificateParser) !void {
        if (h.skip_verify or h.cached_leaf_ready) return;

        var it = h.root_ca.map.iterator();
        while (it.next()) |entry| {
            const bytes_index = entry.value_ptr.*;
            const der = bundleDerSpan(h.root_ca, bytes_index) orelse continue;
            h.indexPrewarmedTrusted(bytes_index, der);
        }

        it = h.root_ca.map.iterator();
        while (it.next()) |entry| {
            const bytes_index = entry.value_ptr.*;
            const der = bundleDerSpan(h.root_ca, bytes_index) orelse continue;
            const entry_cert: Certificate = .{ .buffer = h.root_ca.bytes.items, .index = bytes_index };
            const subject = try entry_cert.parse();
            if (h.host.len > 0) {
                subject.verifyHostName(h.host) catch |err| switch (err) {
                    error.CertificateHostMismatch => continue,
                    else => return err,
                };
            }
            try h.cachePrewarmedLeaf(bytes_index, der, subject);
            return;
        }
    }

    pub fn skipCertificate(d: *record.Decoder, tls_version: proto.Version) !void {
        if (tls_version == .tls_1_3) {
            _ = try d.decode(u8);
        }
        const certs_len = try d.decode(u24);
        if (d.idx + certs_len > d.payload.len) return error.TlsDecodeError;
        d.idx += certs_len;
    }

    /// Parse only the leaf certificate public key (no chain or hostname checks).
    /// Used when `skip_verify` but CertificateVerify still must be checked.
    pub fn parseCertificateLeaf(h: *CertificateParser, d: *record.Decoder, tls_version: proto.Version) !void {
        if (tls_version == .tls_1_3) {
            const request_context = try d.decode(u8);
            if (request_context != 0) return error.TlsIllegalParameter;
        }
        const certs_len = try d.decode(u24);
        const start_idx = d.idx;
        if (d.idx - start_idx >= certs_len) return error.TlsDecodeError;

        const crt_len = try d.decode(u24);
        const crt = try d.slice(crt_len);
        if (tls_version == .tls_1_3) {
            try d.skip(try d.decode(u16));
        }
        d.idx = start_idx + certs_len;

        const leaf_hash = std.hash.Wyhash.hash(0, crt);
        if (h.cached_leaf_ready and crt.len == h.cached_leaf_der_len and leaf_hash == h.cached_leaf_hash) {
            return;
        }

        const entry: Certificate = .{ .buffer = crt, .index = 0 };
        const subject = try entry.parse();
        h.pub_key = try dupe(&h.pub_key_buf, subject.pubKey());
        h.pub_key_algo = subject.pub_key_algo;
        try h.cacheParsedPublicKey();
        h.cached_leaf_hash = leaf_hash;
        h.cached_leaf_der_len = @intCast(crt.len);
        h.cached_not_before = subject.validity.not_before;
        h.cached_not_after = subject.validity.not_after;
        h.cached_leaf_ready = true;
    }

    pub fn parseCertificate(h: *CertificateParser, d: *record.Decoder, tls_version: proto.Version) !void {
        if (h.now_sec == 0) {
            var ts: std.c.timespec = undefined;
            if (std.c.clock_gettime(.REALTIME, &ts) == 0) {
                h.now_sec = ts.sec;
            }
        }
        if (tls_version == .tls_1_3) {
            const request_context = try d.decode(u8);
            if (request_context != 0) return error.TlsIllegalParameter;
        }

        var trust_chain_established = false;
        var last_cert: ?Certificate.Parsed = null;
        const certs_len = try d.decode(u24);
        const start_idx = d.idx;
        while (d.idx - start_idx < certs_len) {
            const crt_len = try d.decode(u24);
            const crt = try d.slice(crt_len);
            if (tls_version == .tls_1_3) {
                // certificate extensions present in tls 1.3
                try d.skip(try d.decode(u16));
            }
            if (trust_chain_established)
                continue;

            const leaf_hash = std.hash.Wyhash.hash(0, crt);
            const trusted_index = if (!h.skip_verify) findTrustedCertDer(h, crt, leaf_hash) else null;
            const reuse_leaf = h.cached_leaf_ready and
                crt.len == h.cached_leaf_der_len and
                leaf_hash == h.cached_leaf_hash;

            if (last_cert == null and reuse_leaf and trusted_index != null) {
                if (!h.skip_verify) {
                    try checkCertValidityCached(h);
                    trust_chain_established = true;
                }
                continue;
            }

            const subject = try parseCertificateSubject(h.root_ca, crt, trusted_index);
            if (last_cert) |pc| {
                if (pc.verify(subject, h.now_sec)) {
                    last_cert = subject;
                } else |err| switch (err) {
                    error.CertificateIssuerMismatch => {
                        // skip certificate which is not part of the chain
                        continue;
                    },
                    else => return err,
                }
            } else { // first certificate
                if (!h.skip_verify and h.host.len > 0) {
                    if (!(h.cached_host_ok and leaf_hash == h.cached_leaf_hash)) {
                        try subject.verifyHostName(h.host);
                        h.cached_host_ok = true;
                    }
                }
                if (!reuse_leaf) {
                    h.pub_key = try dupe(&h.pub_key_buf, subject.pubKey());
                    h.pub_key_algo = subject.pub_key_algo;
                    try h.cacheParsedPublicKey();
                    h.cached_leaf_hash = leaf_hash;
                    h.cached_leaf_der_len = @intCast(crt.len);
                    h.cached_not_before = subject.validity.not_before;
                    h.cached_not_after = subject.validity.not_after;
                    if (trusted_index) |idx| {
                        h.indexPrewarmedTrusted(idx, crt);
                        h.cached_trusted_bytes_index = idx;
                    }
                    h.cached_leaf_ready = true;
                }
                last_cert = subject;
            }
            if (!h.skip_verify) {
                if (trusted_index) |_| {
                    try checkCertValidity(last_cert.?, h.now_sec);
                    trust_chain_established = true;
                } else if (verifyTrustedAnchor(h.root_ca, last_cert.?, crt, h.now_sec)) |_| {
                    trust_chain_established = true;
                } else |err| switch (err) {
                    error.CertificateIssuerNotFound => {},
                    else => return err,
                }
            }
        }
        if (!h.skip_verify and !trust_chain_established) {
            return error.CertificateIssuerNotFound;
        }
    }

    pub fn parseCertificateVerify(h: *CertificateParser, d: *record.Decoder) !void {
        h.signature_scheme = try d.decode(proto.SignatureScheme);
        h.signature = try dupe(&h.signature_buf, try d.slice(try d.decode(u16)));
    }

    fn ecdsaP256W7Rows(h: *const CertificateParser) ?*const ecdsa_p256.TableRows {
        if (h.borrowed_ecdsa_p256_w7_table) |t| return t.rowsPtr();
        if (h.owned_ecdsa_p256_w7_table) |t| return t.rowsPtr();
        return null;
    }

    fn cacheEcdsaP256W7Table(h: *CertificateParser) !void {
        if (!nistz_p256.enabled) return;
        const pk = h.ecdsa_p256_pk orelse return;
        if (h.borrowed_ecdsa_p256_w7_table) |borrowed| {
            if (borrowed.matchesPublicKey(pk.p)) return;
        }
        if (h.owned_ecdsa_p256_w7_table) |owned| {
            if (owned.matchesPublicKey(pk.p)) return;
        }
        if (h.table_allocator) |alloc| {
            h.owned_ecdsa_p256_w7_table = try ecdsa_p256.W7Table.create(alloc, pk.p);
        }
    }

    fn cacheParsedPublicKey(h: *CertificateParser) !void {
        switch (h.pub_key_algo) {
            .X9_62_id_ecPublicKey => |curve| switch (curve) {
                .X9_62_prime256v1 => {
                    h.ecdsa_p256_pk = try EcdsaP256Sha256.PublicKey.fromSec1(h.pub_key);
                    h.ecdsa_p256_mul_pc = try ecdsa_p256.P256.precomputeMulPublicAffine(h.ecdsa_p256_pk.?.p);
                    try h.cacheEcdsaP256W7Table();
                },
                .secp384r1 => h.ecdsa_p384_pk = try EcdsaP384Sha384.PublicKey.fromSec1(h.pub_key),
                else => {},
            },
            .curveEd25519 => {
                if (h.pub_key.len != crypto.sign.Ed25519.PublicKey.encoded_length) return error.InvalidEncoding;
                h.ed25519_pk = try crypto.sign.Ed25519.PublicKey.fromBytes(h.pub_key[0..crypto.sign.Ed25519.PublicKey.encoded_length].*);
            },
            .rsaEncryption => h.rsa_pk = try rsa.PublicKey.fromDer(h.pub_key),
            else => {},
        }
    }

    pub const CertificateVerifySide = enum { server, client };

    pub fn verifySignatureTranscript(h: *CertificateParser, transcript: *Transcript, side: CertificateVerifySide) !void {
        switch (h.signature_scheme) {
            .ecdsa_secp256r1_sha256 => {
                if (h.pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;
                if (h.pub_key_algo.X9_62_id_ecPublicKey != .X9_62_prime256v1) return error.TlsUnknownSignatureScheme;
                const key = h.ecdsa_p256_pk orelse try EcdsaP256Sha256.PublicKey.fromSec1(h.pub_key);
                const sig = try ecdsa_p256.signatureFromDerTls(h.signature);
                var digest: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
                switch (side) {
                    .server => transcript.serverCertificateVerifyDigest(&digest),
                    .client => transcript.clientCertificateVerifyDigest(&digest),
                }
                try ecdsa_p256.verifyPrehashed(sig, digest, key, if (h.ecdsa_p256_mul_pc) |*pc| pc else null, h.ecdsaP256W7Rows());
            },
            .ecdsa_secp384r1_sha384 => {
                if (h.pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;
                if (h.pub_key_algo.X9_62_id_ecPublicKey != .secp384r1) return error.TlsUnknownSignatureScheme;
                const key = h.ecdsa_p384_pk orelse try EcdsaP384Sha384.PublicKey.fromSec1(h.pub_key);
                const sig = try EcdsaP384Sha384.Signature.fromDer(h.signature);
                var digest: [crypto.hash.sha2.Sha384.digest_length]u8 = undefined;
                switch (side) {
                    .server => transcript.serverCertificateVerifyDigestSha384(&digest),
                    .client => transcript.clientCertificateVerifyDigestSha384(&digest),
                }
                try sig.verifyPrehashed(digest, key);
            },
            else => {
                const verify_bytes = switch (side) {
                    .server => transcript.serverCertificateVerify(),
                    .client => transcript.clientCertificateVerify(),
                };
                try h.verifySignature(verify_bytes);
            },
        }
    }

    pub fn verifySignature(h: *CertificateParser, verify_bytes: []const u8) !void {
        switch (h.signature_scheme) {
            .ecdsa_secp256r1_sha256 => {
                if (h.pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;
                if (h.pub_key_algo.X9_62_id_ecPublicKey != .X9_62_prime256v1) return error.TlsUnknownSignatureScheme;
                const key = h.ecdsa_p256_pk orelse try EcdsaP256Sha256.PublicKey.fromSec1(h.pub_key);
                const sig = try ecdsa_p256.signatureFromDerTls(h.signature);
                var digest: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
                crypto.hash.sha2.Sha256.hash(verify_bytes, &digest, .{});
                try ecdsa_p256.verifyPrehashed(sig, digest, key, if (h.ecdsa_p256_mul_pc) |*pc| pc else null, h.ecdsaP256W7Rows());
            },
            .ecdsa_secp384r1_sha384 => {
                if (h.pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;
                if (h.pub_key_algo.X9_62_id_ecPublicKey != .secp384r1) return error.TlsUnknownSignatureScheme;
                const key = h.ecdsa_p384_pk orelse try EcdsaP384Sha384.PublicKey.fromSec1(h.pub_key);
                const sig = try EcdsaP384Sha384.Signature.fromDer(h.signature);
                var digest: [crypto.hash.sha2.Sha384.digest_length]u8 = undefined;
                crypto.hash.sha2.Sha384.hash(verify_bytes, &digest, .{});
                try sig.verifyPrehashed(digest, key);
            },
            .ed25519 => {
                if (h.pub_key_algo != .curveEd25519) return error.TlsBadSignatureScheme;
                const Eddsa = crypto.sign.Ed25519;
                if (h.signature.len != Eddsa.Signature.encoded_length) return error.InvalidEncoding;
                const sig = Eddsa.Signature.fromBytes(h.signature[0..Eddsa.Signature.encoded_length].*);
                const key = h.ed25519_pk orelse try Eddsa.PublicKey.fromBytes(h.pub_key[0..Eddsa.PublicKey.encoded_length].*);
                try sig.verify(verify_bytes, key);
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| {
                if (h.pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const pk = h.rsa_pk orelse try rsa.PublicKey.fromDer(h.pub_key);
                const sig = rsa.Pss(Hash).Signature{ .bytes = h.signature };
                try sig.verify(verify_bytes, pk, null);
            },
            inline .rsa_pkcs1_sha1,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            => |comptime_scheme| {
                if (h.pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const pk = h.rsa_pk orelse try rsa.PublicKey.fromDer(h.pub_key);
                const sig = rsa.PKCS1v1_5(Hash).Signature{ .bytes = h.signature };
                try sig.verify(verify_bytes, pk);
            },
            else => return error.TlsUnknownSignatureScheme,
        }
    }

};

pub fn SchemeHash(comptime scheme: proto.SignatureScheme) type {
    const Sha256 = crypto.hash.sha2.Sha256;
    const Sha384 = crypto.hash.sha2.Sha384;
    const Sha512 = crypto.hash.sha2.Sha512;

    return switch (scheme) {
        .rsa_pkcs1_sha1 => crypto.hash.Sha1,
        .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => Sha256,
        .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384 => Sha384,
        .rsa_pss_rsae_sha512, .rsa_pkcs1_sha512 => Sha512,
        else => @compileError("bad scheme"),
    };
}

pub fn dupe(buf: []u8, data: []const u8) ![]u8 {
    if (buf.len < data.len) {
        return error.BufferUndersize;
    }
    @memcpy(buf[0..data.len], data);
    return buf[0..data.len];
}

pub fn dupeMin(buf: []u8, data: []const u8) []u8 {
    const n = @min(data.len, buf.len);
    @memcpy(buf[0..n], data[0..n]);
    return buf[0..n];
}

const Ffdhe2048 = @import("ffdhe.zig").KeyPair;

pub const DhKeyPair = struct {
    x25519_kp: X25519.KeyPair = undefined,
    secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,
    secp384r1_kp: EcdsaP384Sha384.KeyPair = undefined,
    ml_kem768: MLKem768.KeyPair = undefined,
    ffdhe2048_kp: Ffdhe2048 = undefined,

    secp256r1_pk_buf: [EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined, //65 bytes
    secp384r1_pk_buf: [EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined, //97
    ml_kem768_pk_buf: [MLKem768.PublicKey.encoded_length + X25519.public_length]u8 = undefined, // 1216
    shared_key_buf: [256]u8 = undefined,

    pub const seed_len = 32 + 32 + 48 + 64 + 64 + 32;
    pub const x25519_seed_len = X25519.seed_length;

    pub fn initX25519(seed: [x25519_seed_len]u8) !DhKeyPair {
        var kp: DhKeyPair = .{};
        kp.x25519_kp = try X25519.KeyPair.generateDeterministic(seed);
        return kp;
    }

    pub fn init(seed: [seed_len]u8, named_groups: []const proto.NamedGroup) !DhKeyPair {
        if (named_groups.len == 1 and named_groups[0] == .x25519)
            return initX25519(seed[0..x25519_seed_len].*);
        var kp: DhKeyPair = .{};
        for (named_groups) |ng|
            switch (ng) {
                .x25519 => kp.x25519_kp = try X25519.KeyPair.generateDeterministic(seed[0..][0..X25519.seed_length].*),
                .secp256r1 => kp.secp256r1_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed[32..][0..EcdsaP256Sha256.KeyPair.seed_length].*),
                .secp384r1 => kp.secp384r1_kp = try EcdsaP384Sha384.KeyPair.generateDeterministic(seed[32 + 32 ..][0..EcdsaP384Sha384.KeyPair.seed_length].*),
                .x25519_ml_kem768 => kp.ml_kem768 = try MLKem768.KeyPair.generateDeterministic(seed[32 + 32 + 48 + 64 ..][0..MLKem768.seed_length].*),
                .ffdhe2048 => kp.ffdhe2048_kp = try Ffdhe2048.generateDeterministic(seed[32 + 32 + 48 + 64 + 64 ..][0..32].*),
                .x448, .secp521r1 => return error.TlsIllegalParameter,
                else => return error.TlsIllegalParameter,
            };
        return kp;
    }

    // x25519: 32,  secp256r1: 32, secp384r1: 48, x25519_ml_kem768: 64
    pub fn sharedKey(self: *DhKeyPair, named_group: proto.NamedGroup, server_pub_key: []const u8) ![]const u8 {
        return switch (named_group) {
            .x25519 => {
                if (server_pub_key.len != X25519.public_length)
                    return error.TlsIllegalParameter;
                self.shared_key_buf[0..32].* = try X25519.scalarmult(
                    self.x25519_kp.secret_key,
                    server_pub_key[0..X25519.public_length].*,
                );
                return self.shared_key_buf[0..32];
            },
            .secp256r1 => {
                const pk = try EcdsaP256Sha256.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp256r1_kp.secret_key.bytes, .big);
                self.shared_key_buf[0..32].* = mul.affineCoordinates().x.toBytes(.big);
                return self.shared_key_buf[0..32];
            },
            .secp384r1 => {
                const pk = try EcdsaP384Sha384.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp384r1_kp.secret_key.bytes, .big);
                self.shared_key_buf[0..48].* = mul.affineCoordinates().x.toBytes(.big);
                return self.shared_key_buf[0..48];
            },
            .x25519_ml_kem768 => {
                const hksl = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                const xksl = hksl + crypto.dh.X25519.public_length;
                if (server_pub_key.len != xksl) return error.TlsIllegalParameter;

                const hsk = self.ml_kem768.secret_key.decaps(server_pub_key[0..hksl]) catch
                    return error.TlsDecryptFailure;
                const xsk = crypto.dh.X25519.scalarmult(self.x25519_kp.secret_key, server_pub_key[hksl..xksl].*) catch
                    return error.TlsDecryptFailure;
                const shared_len = crypto.kem.ml_kem.MLKem768.shared_length + X25519.public_length;
                self.shared_key_buf[0..shared_len].* = (hsk ++ xsk);
                return self.shared_key_buf[0..shared_len];
            },
            .ffdhe2048 => {
                const secret = try self.ffdhe2048_kp.sharedSecret(server_pub_key);
                @memcpy(self.shared_key_buf[0..secret.len], &secret);
                return self.shared_key_buf[0..secret.len];
            },
            .x448, .secp521r1 => return error.TlsIllegalParameter,
            else => return error.TlsIllegalParameter,
        };
    }

    // Returns 32, 65, 97 or 1216 bytes ml_kem
    pub fn publicKey(self: *DhKeyPair, named_group: proto.NamedGroup) ![]const u8 {
        return switch (named_group) {
            .x25519 => &self.x25519_kp.public_key,
            .secp256r1 => {
                self.secp256r1_pk_buf = self.secp256r1_kp.public_key.toUncompressedSec1();
                return &self.secp256r1_pk_buf;
            },
            .secp384r1 => {
                self.secp384r1_pk_buf = self.secp384r1_kp.public_key.toUncompressedSec1();
                return &self.secp384r1_pk_buf;
            },
            .x25519_ml_kem768 => {
                self.ml_kem768_pk_buf = self.ml_kem768.public_key.toBytes() ++ self.x25519_kp.public_key;
                return &self.ml_kem768_pk_buf;
            },
            .ffdhe2048 => return &self.ffdhe2048_kp.public_key,
            .x448, .secp521r1 => return error.TlsIllegalParameter,
            else => return error.TlsIllegalParameter,
        };
    }
};

/// TLS 1.3 HelloRetryRequest server_random (RFC 8446 §4.1.3).
pub const hello_retry_request_random: [32]u8 = .{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

const testing = std.testing;
const testu = @import("testu.zig");

test "CertKeyPair.fromPem loads P-256 credentials" {
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
    var pair = try CertKeyPair.fromPem(testing.allocator, cert_pem, key_pem);
    defer pair.deinit(testing.allocator);
    try testing.expect(pair.bundle.map.size > 0);
    try testing.expect(pair.bundle.bytes.items.len > 0);
    try testing.expect(pair.tls13_certificate_msg.len > 0);
    try testing.expect(pair.ecdsa_key_pair != null);
    try testing.expectEqual(.ecdsa_secp256r1_sha256, pair.key.signature_scheme);
}

test "DhKeyPair.x25519" {
    var seed: [DhKeyPair.seed_len]u8 = undefined;
    testu.fill(&seed);
    const server_pub_key = &testu.hexToBytes("3303486548531f08d91e675caf666c2dc924ac16f47a861a7f4d05919d143637");
    const expected = &testu.hexToBytes(
        \\ F1 67 FB 4A 49 B2 91 77  08 29 45 A1 F7 08 5A 21
        \\ AF FE 9E 78 C2 03 9B 81  92 40 72 73 74 7A 46 1E
    );
    var kp = try DhKeyPair.init(seed, &.{.x25519});
    try testing.expectEqualSlices(u8, expected, try kp.sharedKey(.x25519, server_pub_key));
}
