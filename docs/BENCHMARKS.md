# TLS Benchmark Results

Side-by-side comparison of zig-tls and BoringSSL using the in-memory harness in
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

Optional pure-C BoringSSL baseline (`OPENSSL_NO_ASM=1`) for crypto-only comparisons:

```bash
cmake -S /tmp/boringssl -B /tmp/boringssl/build-noasm -DCMAKE_BUILD_TYPE=Release -DOPENSSL_NO_ASM=1
cmake --build /tmp/boringssl/build-noasm -j
BORINGSSL_BUILD=/tmp/boringssl/build-noasm ./bench/compare.sh
```

## Latest run (2026-06-08, Apple M3 Pro)

**zig-tls:** zig `0.17.0-dev`, `-Doptimize=ReleaseFast -Dcpu=native`  
**BoringSSL:** `/tmp/boringssl/build` Release (assembly enabled)

| Benchmark | zig-tls | BoringSSL | Ratio (zig / BoringSSL) |
|-----------|---------|-----------|-------------------------|
| Full handshake TLS 1.3 | **~8200 /s** | ~6700 /s | **~1.23×** |
| Transfer TLS 1.3 send (16 KiB records) | ~2360 MB/s | **~3450 MB/s** | ~0.68× |
| Transfer TLS 1.3 recv (16 KiB records) | ~2390 MB/s | **~3460 MB/s** | ~0.69× |

Iterations: 10 000 handshakes; 5 000 × 16 384-byte application records per transfer test.

### vs BoringSSL without assembly (reference)

With `BORINGSSL_BUILD=/tmp/boringssl/build-noasm`, zig-tls leads all categories
(handshake ~3×, transfer ~8×) because zig uses ARM AES instructions while that
build disables BoringSSL’s assembly crypto.

## Methodology

Categories mirror [rustls perf](https://rustls.dev/perf/):

1. **Full handshake** — TLS 1.3, X25519 only, in-memory I/O (no TCP).
2. **Bulk transfer** — AES-128-GCM application data after handshake (send or recv direction).

### zig-tls (`bench/main.zig`)

- X25519-only, TLS 1.3-only, `AES_128_GCM_SHA256`, HelloRetryRequest disabled.
- Optimized in-memory pump (`pumpHandshake`) instead of generic buffer churn.
- Transfer uses monomorphized `encryptApplication` + in-place `decryptRecordInPlace`.
- Server runs with `auth = null` (no Certificate / CertificateVerify flights).
- Client uses `insecure_skip_verify = true`.

### BoringSSL (`bench/boringssl_bench.cc`)

- `BIO_new_bio_pair` + `SSL_do_handshake` pump (same process, no TCP).
- Server uses BoringSSL’s ECDSA P-256 test certificate; client skips verification.
- TLS 1.3 only (`TLS1_3_VERSION` min/max).

Handshake numbers are closer to apples-to-apples after zig-tls bench tuning; BoringSSL
still includes certificate messages. Transfer compares zig’s lean record API against
BoringSSL’s `SSL_write` / `SSL_read` on top of heavily optimized assembly GCM.

## Performance work in this tree

- **Handshake:** release log no-ops, lazy server `DhKeyPair` (reused in TLS 1.3
  `serverFlight`, no duplicate keygen), skip TLS 1.3 RSA premaster generation, bench
  pins X25519-only (avoids ML-KEM-768 keygen per handshake).
- **Transfer:** cached AES-GCM key schedule + GHASH subkey (`aes_gcm_cached.zig`),
  TLS 1.3-specialized GCM (`encryptTls13` / `decryptTls13`), cached GHASH state after
  the fixed 5-byte AD block, incremental sequence nonce updates, `encryptApplication`
  fast path (skip redundant header writes for repeated record sizes), in-place decrypt.
- **Gap vs BoringSSL ASM:** remaining transfer deficit is mostly stitched AArch64
  AES-GCM (CTR + GHASH interleaved in assembly). Pure-Zig record-layer tuning is
  largely exhausted at ~0.68×; closing the gap needs platform GCM kernels.
- **Bench:** `-Dcpu=native`, pinned cipher suite, dedicated pump loop, monomorphized
  AES-128-GCM transfer path.

## Regression tracking

Store `compare.sh` output in CI as a non-gating artifact. Re-run after handshake or
cipher changes; investigate >10% swings on the same host.
