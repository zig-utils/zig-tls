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
./scripts/testssl.sh localhost 8443
```

## Known Limitations (document for auditor)

- OCSP stapling: server attaches `Server.ocsp_response` to the leaf Certificate
  `status_request` extension (TLS 1.3); client validates staples when `request_ocsp`
  is set and certificate verification is enabled (DER shape, successful status,
  CertID hash/serial match, thisUpdate/nextUpdate); OCSP responder signature
  verification is not implemented yet
- TLS 1.2 static RSA key exchange: server decrypt path implemented; legacy export ciphers still unsupported
- HelloRetryRequest: implemented for preferred-group mismatch; stateless cookie is connection-scoped (16-byte random)
- 0-RTT early data: client send and server decrypt with PSK binder verification; disabled by default (`Server.max_early_data_size = 0`); set `> 0` to accept early data on PSK resume
- FFDHE2048: implemented (RFC 7919); x448 and secp521r1 are rejected if listed in `named_groups` (awaiting `std.crypto` support)
- Record crypto: optional BoringSSL-derived AES-GCM and P-256 Montgomery assembly on AArch64/x86_64 (`src/crypto/*/NOTICE`)

## Bun Integration Surface

The embedding API in `src/embed.zig` exposes:

- `zigt_ctx_*` — secure context (cipher list, ALPN, ticket keys, PQ flag)
- `zigt_conn_*` — per-connection non-blocking handshake
- Error codes mapped to OpenSSL `SSL_ERROR_WANT_READ/WRITE`

Bun-specific half-open TCP semantics remain in the Bun adapter, not zig-tls core.
