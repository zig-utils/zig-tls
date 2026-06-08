# TLS Benchmark Results

Side-by-side comparison of zig-tls and BoringSSL using the matched in-memory harness in
`bench/`. Run locally:

```bash
export ZIG=~/.local/share/pantry/global/pantry_modules/.bin/zig  # zig 0.17-dev
./bench/compare.sh
```

Build BoringSSL once (Release, with assembly — default):

```bash
git clone --depth=1 https://github.com/google/boringssl.git /tmp/boringssl
cmake -S /tmp/boringssl -B /tmp/boringssl/build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/boringssl/build -j
```

## Latest run (2026-06-08, Apple M3 Pro)

**zig-tls:** zig `0.17.0-dev`, `-Doptimize=ReleaseFast -Dcpu=native`  
**BoringSSL:** `/tmp/boringssl/build` Release (assembly enabled)

| Benchmark | zig-tls | BoringSSL | Ratio (zig / BoringSSL) |
|-----------|---------|-----------|-------------------------|
| Handshake TLS 1.3 (minimal ECDHE) | **~7800 /s** | — | — |
| Handshake TLS 1.3 (ECDHE + cert) | **~6045 /s** | ~6090 /s | **~0.99×** |
| Handshake TLS 1.3 (ECDHE + cert + client verify) | **~2860 /s** | — | — |
| Transfer send AES-128-GCM (16 KiB) | **~8080 MB/s** | ~6770 MB/s | **~1.19×** |
| Transfer recv AES-128-GCM (16 KiB) | **~7630 MB/s** | ~7540 MB/s | **~1.01×** |
| Transfer send AES-256-GCM (16 KiB) | **~7400 MB/s** | ~7050 MB/s | **~1.05×** |
| Transfer recv AES-256-GCM (16 KiB) | **~7190 MB/s** | ~5850 MB/s | **~1.23×** |

Iterations: 10 000 handshakes; 5 000 × 16 384-byte application records per transfer test.

BoringSSL's TLS 1.3 server requires a certificate, so there is no BoringSSL minimal-handshake
row. zig-tls reports both minimal (`auth = null`) and cert handshake rows.

### Summary

| Category | Winner |
|----------|--------|
| Minimal handshake | **zig-tls** (zig-only row) |
| Cert handshake | **Parity** (nistz zero-digit fix) |
| Transfer AES-128 | Parity |
| Transfer AES-256 | Parity |

## Methodology

Categories mirror [rustls perf](https://rustls.dev/perf/):

1. **Handshake** — TLS 1.3, X25519 only, in-memory non-blocking pump (no TCP).
2. **Bulk transfer** — AES-128/256-GCM TLS 1.3 application records after handshake, one
   direction per row (send = encrypt only, recv = decrypt only).

### zig-tls (`bench/main.zig`)

- X25519-only, TLS 1.3-only, HelloRetryRequest disabled.
- Client uses `insecure_skip_verify = true` for the default cert row (matches BoringSSL
  `SSL_VERIFY_NONE`). A separate row enables hostname + chain verification against the
  bench self-signed CA (`localhost`).
- Transfer uses monomorphized `encryptApplication` + in-place `decryptRecordInPlace`.

### BoringSSL (`bench/boringssl_bench.cc`)

- `BIO_new_bio_pair` + `SSL_do_handshake` pump.
- Same P-256 test certificate as zig (`bench/certs.zig`).
- Transfer uses post-handshake traffic secrets → HKDF → `EVP_AEAD` on TLS 1.3 record layout.

## Performance work in this tree

- **Transfer:** stitched AES-GCM assembly (AArch64/x86_64, BoringSSL-derived).
- **Handshake:** single-hash transcript updates after cipher suite selection; TLS 1.3 server
  flight coalesced into one encrypted record; cached TLS 1.3 Certificate message in
  `CertKeyPair`; direct `KeyPair.sign` / `signPrehashed` for CertificateVerify.
- **P-256 ECDSA:** BoringSSL `ecp_nistz256` field/scalar Montgomery kernels on AArch64;
  fiat ADX + ord kernels on x86_64 (`src/crypto/p256_*`, `hw_p256.zig`).
- **Client cert verify:** parsed leaf public keys cached in `CertificateParser` (ECDSA,
  Ed25519, RSA) to avoid re-parsing on `CertificateVerify`; ECDSA verify uses
  `verifyPrehashed` (same digest path as `signPrehashed` on the server).
- **Trusted-anchor fast path:** when a presented cert is byte-identical to an entry in
  `root_ca`, skip issuer re-parse and chain signature verification; parse from bundle
  bytes instead of the TLS message buffer.
- **Client handshake reuse:** `nonblock.Client.reset()` preserves cached leaf cert
  public keys and hostname verification across repeated handshakes with the same server.
- **Trusted leaf skip-parse:** on reset, when the server sends the same trusted-anchor
  cert, skip DER parsing and chain verification entirely.
- **Bedrock coord add/sub** (`p256_coord.zig`): foundation for future nistz point-add
  (OpenSSL/BoringSSL nistz formulas need coord add/sub, not fiat Montgomery add/sub).
- **SHA-256:** Zig `std.crypto` already uses AArch64 SHA2 / x86 SHA-NI+AVX2 when
  `-Dcpu=native`; no extra assembly vendored.
- **nistz base-point table:** Gueron–Krasnov 37×64 affine precompute (`p256/nistz_table.zig`)
  for `k×G` on the signing path. Zero Booth digits skip adds (no spurious doubles).

## Regression tracking

Store `compare.sh` output in CI as a non-gating artifact. Re-run after handshake or
cipher changes; investigate >10% swings on the same host.
