# zig-tls

Pure Zig TLS 1.2/1.3 implementation for SMTP and other protocols.

## Features

- TLS 1.3 and TLS 1.2 client and server support
- Zig implementation with optional platform AES-GCM assembly (AArch64/x86_64)
- Non-blocking I/O
- STARTTLS support for protocol upgrades
- Certificate and private key management
- PSK resumption and opt-in 0-RTT early data

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .tls = .{
        .path = "../zig-tls",
    },
},
```

Add to your `build.zig`:

```zig
const tls = b.dependency("tls", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("tls", tls.module("tls"));
```

## Usage

### Server Example

```zig
const tls = @import("tls");

// Load certificate and key
var cert_key = try tls.config.CertKeyPair.fromFilePathAbsolute(
    allocator,
    io,
    "/path/to/cert.pem",
    "/path/to/key.pem",
);
defer cert_key.deinit(allocator);

// Create TLS connection from stream
const tls_conn = try tls.serverFromStream(stream, .{
    .auth = &cert_key,
});

// Read/write through TLS
const n = try tls_conn.read(buffer);
try tls_conn.write(data);
```

### Client Example

```zig
const tls = @import("tls");

// Load the system trust store (or use tls.config.cert.fromFilePathAbsolute
// to pin a specific root CA bundle).
var roots = try tls.config.cert.fromSystem(allocator);
defer roots.deinit(allocator);

// `stream` is any connected stream (e.g. std.net.Stream) over TCP.
var conn = try tls.clientFromStream(stream, .{
    .host = "example.com", // verified against the server certificate (SNI + hostname)
    .root_ca = roots,
});

try conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
var buffer: [4096]u8 = undefined;
const n = try conn.read(&buffer);
_ = n;
```

> Certificate chain and hostname verification are on by default. Setting
> `insecure_skip_verify = true` disables them and must only be used for testing.

### Non-blocking handshake (servers, SMTP STARTTLS, etc.)

```zig
var client = tls.nonblock.Client.init(.{
    .host = "mail.example.com",
    .root_ca = roots,
});
defer client.deinit(); // frees optional P-256 verify table from table_allocator

var send_buf: [tls.output_buffer_len]u8 = undefined;
var recv_buf: [tls.input_buffer_len]u8 = undefined;
var recv_len: usize = 0;

while (!client.done()) {
    const step = try client.run(recv_buf[0..recv_len], &send_buf);
    recv_len -= step.recv_pos;
    // write step.send to the socket; read more ciphertext into recv_buf
    recv_len += try stream.read(recv_buf[recv_len..]);
}
const app_cipher = client.cipher().?;
var conn = tls.nonblock.Connection.init(app_cipher);
```

Reuse `client.reset()` between connections to the same host to keep cached
certificate state (trusted leaf skip-parse, hostname, P-256 verify tables).

### Production defaults

| Setting | Default | Notes |
|---------|---------|-------|
| Cipher suites | `cipher_suites.secure` | TLS 1.3 + TLS 1.2 AEAD (GCM/ChaCha); no CBC |
| Hostname verify | on | Set `insecure_skip_verify = true` only in tests |
| 0-RTT early data | off | `Server.max_early_data_size = 0` |
| TLS versions | 1.2–1.3 | Pin with `min_version` / `max_version` if needed |

For legacy TLS 1.2 CBC clients, pass `cipher_suites = tls.config.cipher_suites.tls12`
(or `.all`) explicitly on both client and server.

See [SECURITY.md](SECURITY.md) and [docs/AUDIT_PREP.md](docs/AUDIT_PREP.md) before
deploying to production.

## Benchmarks

```bash
zig build bench -Doptimize=ReleaseFast -Dcpu=native
./bench/compare.sh
```

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## License

MIT - Based on <https://github.com/ianic/tls.zig>

Record-layer AES-GCM and P-256 field arithmetic assembly is derived from [BoringSSL](https://github.com/google/boringssl) (Apache 2.0); see `src/crypto/*/NOTICE`.
