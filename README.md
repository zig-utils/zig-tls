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

## Benchmarks

```bash
zig build bench -Doptimize=ReleaseFast -Dcpu=native
./bench/compare.sh
```

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## License

MIT - Based on <https://github.com/ianic/tls.zig>

Record-layer AES-GCM and P-256 field arithmetic assembly is derived from [BoringSSL](https://github.com/google/boringssl) (Apache 2.0); see `src/crypto/*/NOTICE`.
