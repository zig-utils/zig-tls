# Third-Party Audit Preparation Checklist

Use this checklist before engaging a security auditor or enabling zig-tls as the
default TLS stack in Bun.

## Scope

- TLS 1.2 and TLS 1.3 client/server handshake
- Record layer encryption/decryption (AEAD and CBC)
- Certificate chain verification
- Session ticket encryption (RFC 5077 / TLS 1.3 NewSessionTicket)
- RSA, ECDSA signing and verification
- Post-quantum hybrid key exchange (ML-KEM-768 + X25519)

Out of scope: `node:crypto` EVP layer, QUIC, DTLS, legacy SSLv3.

## Code Areas for Review

| Area | Path | Notes |
|------|------|-------|
| Handshake state machines | `src/handshake_client.zig`, `src/handshake_server.zig` | Non-blocking + blocking |
| Record parser | `src/record.zig` | Fuzz target available |
| Cipher suites | `src/cipher.zig` | AEAD + CBC |
| Key schedule | `src/transcript.zig` | HKDF labels |
| RSA | `src/rsa/rsa.zig` | Constant-time decrypt |
| Session tickets | `src/session_ticket.zig` | AES-256-GCM encryption |
| ALPN | `src/alpn.zig` | Protocol negotiation |
| Embedding API | `src/embed.zig` | Bun adapter surface |

## Test Evidence to Provide

```bash
zig build test
zig build bench -Doptimize=ReleaseFast
./bench/compare.sh            # zig-tls vs BoringSSL (see docs/BENCHMARKS.md)
zig build -Dfuzz=true fuzz   # fuzz binaries in zig-out/bin/
```

## Interop Evidence

```bash
# Against local test server (see examples/test_server.zig)
testssl.sh --quiet --color 0 localhost:8443
```

## Known Limitations (document for auditor)

- TLS 1.2 static RSA key exchange: server decrypt path implemented; legacy export ciphers still unsupported
- HelloRetryRequest: implemented for preferred-group mismatch; stateless cookie is connection-scoped (16-byte random)
- 0-RTT early data: client send and server decrypt with PSK binder verification; `max_early_data` advertised in EncryptedExtensions
- FFDHE2048: implemented (RFC 7919); x448 and secp521r1 negotiate but require future `std.crypto` curve support

## Bun Integration Surface

The embedding API in `src/embed.zig` exposes:

- `zigt_ctx_*` — secure context (cipher list, ALPN, ticket keys, PQ flag)
- `zigt_conn_*` — per-connection non-blocking handshake
- Error codes mapped to OpenSSL `SSL_ERROR_WANT_READ/WRITE`

Bun-specific half-open TCP semantics remain in the Bun adapter, not zig-tls core.
