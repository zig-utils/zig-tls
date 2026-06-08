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
| Handshake TLS 1.3 (minimal ECDHE) | **~7700 /s** | — | — |
| Handshake TLS 1.3 (ECDHE + cert) | ~3600 /s | ~6500 /s | ~0.55× |
| Transfer send AES-128-GCM (16 KiB) | **~8300 MB/s** | ~8100 MB/s | **~1.02×** |
| Transfer recv AES-128-GCM (16 KiB) | **~8000 MB/s** | ~7800 MB/s | **~1.02×** |
| Transfer send AES-256-GCM (16 KiB) | ~7400 MB/s | ~7600 MB/s | ~0.97× |
| Transfer recv AES-256-GCM (16 KiB) | ~7150 MB/s | ~7350 MB/s | ~0.97× |

Iterations: 10 000 handshakes; 5 000 × 16 384-byte application records per transfer test.

BoringSSL's TLS 1.3 server requires a certificate, so there is no BoringSSL minimal-handshake
row. zig-tls reports both minimal (`auth = null`) and cert handshake rows.

### Summary

| Category | Winner |
|----------|--------|
| Minimal handshake | **zig-tls** (zig-only row) |
| Cert handshake | BoringSSL (P-256 ECDSA sign; see below) |
| Transfer AES-128 | **zig-tls** (parity / slight lead) |
| Transfer AES-256 | Parity (within ~3%) |

## Methodology

Categories mirror [rustls perf](https://rustls.dev/perf/):

1. **Handshake** — TLS 1.3, X25519 only, in-memory non-blocking pump (no TCP).
2. **Bulk transfer** — AES-128/256-GCM TLS 1.3 application records after handshake, one
   direction per row (send = encrypt only, recv = decrypt only).

### zig-tls (`bench/main.zig`)

- X25519-only, TLS 1.3-only, HelloRetryRequest disabled.
- Client uses `insecure_skip_verify = true` (matches BoringSSL `SSL_VERIFY_NONE`).
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
- **Remaining cert gap:** portable Zig P-256 ECDSA vs BoringSSL assembly (`p256-armv8`).
  Closing this requires vendored P-256 field arithmetic (next perf milestone).

## Regression tracking

Store `compare.sh` output in CI as a non-gating artifact. Re-run after handshake or
cipher changes; investigate >10% swings on the same host.
