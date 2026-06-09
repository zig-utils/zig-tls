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

## Latest run (2026-06-07, Apple M3 Pro)

**zig-tls:** zig `0.17.0-dev`, `-Doptimize=ReleaseFast -Dcpu=native`  
**BoringSSL:** `/tmp/boringssl/build` Release (assembly enabled)

| Benchmark | zig-tls | BoringSSL | Ratio (zig / BoringSSL) |
|-----------|---------|-----------|-------------------------|
| Handshake TLS 1.3 (minimal ECDHE) | **~8280 /s** | — | — |
| Handshake TLS 1.3 (ECDHE + cert) | **~6210 /s** | ~6900 /s | ~0.90× |
| Handshake TLS 1.3 (ECDHE + cert + client verify) | **~5040 /s** | ~6730 /s | ~0.75× |
| Transfer send AES-128-GCM (16 KiB) | **~8370 MB/s** | ~8320 MB/s | ~1.01× |
| Transfer recv AES-128-GCM (16 KiB) | **~7940 MB/s** | ~8080 MB/s | ~0.98× |
| Transfer send AES-256-GCM (16 KiB) | **~7690 MB/s** | ~7620 MB/s | ~1.01× |
| Transfer recv AES-256-GCM (16 KiB) | **~7380 MB/s** | ~7470 MB/s | ~0.99× |

Iterations: 10 000 handshakes; 5 000 × 16 384-byte application records per transfer test.

### Crypto micro-benchmarks (same `zig build bench` run)

After the handshake rows, the bench prints isolated P-256 verify throughput and an
estimated handshake breakdown:

| Row | Typical M3 Pro rate |
|-----|---------------------|
| `ECDSA P-256 verifyPrehashed` | **~36 000 /s** |
| `P-256 w7 double-base (x only)` | **~47 000 /s** |
| `X25519 ECDHE scalarmult` | **~35 000 /s** |
| `SHA-256 update 2 KiB` | **~1.28 M /s** |
| `AES-128-GCM TLS 1.3 ~2 KiB encrypt` | **~3.8 M /s** |
| `ECDSA P-256 signPrehashed` | **~60 500 /s** |
| `HKDF-Expand-Label key+iv (SHA-256)` | **~5.0 M /s** |

Estimated per-handshake cost (from rates, not timers):

| Component | ~ns |
|-----------|-----|
| ECDSA `verifyPrehashed` | ~27 000 |
| Non-ECDSA (cert row) | ~135 000 |
| Chain/hostname extra (verify row) | ~38 000 |

**ECDSA is ~13% of the verify handshake** on this host; closing the BoringSSL gap
requires faster X25519, transcript hashing, and record crypto — not only double-base
point math.

BoringSSL's TLS 1.3 server requires a certificate, so there is no BoringSSL minimal-handshake
row. zig-tls reports both minimal (`auth = null`) and cert handshake rows.

### Summary

| Category | Winner |
|----------|--------|
| Minimal handshake | **zig-tls** (zig-only row) |
| Cert handshake | BoringSSL (~10%; server ECDSA sign dominates) |
| Cert + verify handshake | BoringSSL (~25%; ECDSA sign + chain verify) |
| Transfer AES-128 send | Parity |
| Transfer AES-128 recv | Parity |
| Transfer AES-256 send | Parity |
| Transfer AES-256 recv | Parity |

## Methodology

Categories mirror [rustls perf](https://rustls.dev/perf/):

1. **Handshake** — TLS 1.3, X25519 only, in-memory non-blocking pump (no TCP).
2. **Bulk transfer** — AES-128/256-GCM TLS 1.3 application records after handshake, one
   direction per row (send = encrypt only, recv = decrypt only).

### zig-tls (`bench/main.zig`)

- X25519-only, TLS 1.3-only, HelloRetryRequest disabled.
- Client uses `insecure_skip_verify = true` for the default cert row (skips chain/hostname
  checks like BoringSSL `SSL_VERIFY_NONE`, but still verifies `CertificateVerify`). A
  separate row enables full chain + hostname verification against the bench self-signed CA
  (`localhost`).
- One warmup handshake before each timed loop (amortizes handshake caches).
- Bench passes `CertKeyPair.ecdsa_p256_w7_table` to the client via
  `server_ecdsa_p256_w7_table` (no runtime table build in timed loops).
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
- **Trusted leaf prewarm:** single-cert `root_ca` bundles are parsed once at client
  init (pubkey, hostname, validity) so the first handshake skips TLS cert DER work too.
- **Trusted root index:** all `root_ca` entries are hash+length indexed at client init
  for O(n) trusted-anchor lookup without repeated `memcmp` over the bundle.
- **P-256 CertificateVerify DER:** `signatureFromDerTls` fast-paths the usual 70–72 byte
  ECDSA SEQUENCE before falling back to the generic DER reader (~3000/s verify handshake).
- **CertificateVerify digest:** `verifySignatureTranscript` hashes the TLS 1.3 padded context
  incrementally (no `serverCertificateVerify` buffer assembly) before ECDSA `verifyPrehashed`.
- **Multi-cert leaf prewarm:** `prewarmTrustedLeaf` scans `root_ca` for a hostname match and
  caches pubkey/validity before the first handshake (not limited to single-cert bundles).
- **ECDSA verify fast path:** `ecdsa_p256.verifyPrehashed` uses `mulDoubleBasePublic`
  (Shamir u1·G + u2·Q) instead of two separate `mulPublic` + `add`; base-point `mulPublic`
  routes through nistz `mulBase`.
- **ECDSA pubkey precompute:** leaf P-256 public keys cache a width-8 mul table in
  `CertificateParser` so repeated `CertificateVerify` skips `precompute(p, 8)`.
- **ECDSA scalar invert (verify):** Brian Smith 292-step addition chain in
  `p256/scalar_invert_chain.zig` replaces generic Fermat `pow` on the verify path.
- **CertificateVerify sign path:** TLS 1.3 ECDSA signing uses incremental
  `serverCertificateVerifyDigest`, `ecdsa_p256.signPrehashed` (nistz `mulBaseVarTime`,
  `addMixedVarTime`, `xCoordVarTime`, scalar `invertVarTime`), and `signatureToDerTls`
  (fixed 72-byte layout).
- **nistz mulBase (sign):** `mulBaseProjectiveVarTime` skips identity `cMov` and
  `rejectIdentity`; Booth negation uses in-place `fiat.opp` on table limbs.
- **P-256 field invert (sign/verify):** `field_invert.zig` uses Brian Smith
  `invSqrMont` chain + multiply (`a^{-1} = a^{-2}·a`); `xCoordVarTime` avoids
  full Fermat `pow` on ECDSA sign.
- **CertificateVerify digest:** incremental `Hash.init` + `update(prefix)` +
  `update(transcript)` (avoids concat buffer on sign/verify).
- **Bench server reuse:** `nonblock.Server.reset()` + client `reset()` in
  `bench/main.zig` avoid reallocating server state each iteration.
- **Bedrock C mul_base (optional):** `-Dbedrock-c-mul-base=true` links vendored
  `p256_point.br.c.inc` + BoringSSL nistz table; field mul/sqr call Zig hw asm
  via `p256_bedrock_exports.zig`. Default off (projective Zig path is faster on
  Apple Silicon today).
- **Bedrock C double-base verify (optional):** same flag links
  `bedrock_double_base_verify.c` (`p256_bedrock_mul_double_base_jacobian`) for
  unified w7 Shamir accumulation in C; Zig path is default.
- **ECDSA verify nistz Shamir:** `mulDoubleBaseVerify` uses unified w7
  `mulDoubleBaseVarTimeFromTables` with Bedrock Jacobian accumulation on AArch64
  (`use_bedrock_verify_accum`); `xCoordVarTime` extracts r without full affine conversion.
- **Heap w7 tables:** `ecdsa_p256.W7Table` is built once per `CertKeyPair` (or client
  `table_allocator` / borrowed `server_ecdsa_p256_w7_table`); no process-global cache.
- **Fast w7 table build:** pubkey rows use Bedrock `doublePoint` + `addMixedAffineOrDouble`
  instead of projective `P256.add` + per-entry `affineCoordinatesVarTime`; batch Montgomery
  `Z⁻¹` per row (`batchInvertFe`) replaces per-entry field inverts.
- **ECDSA verify x-only:** `mulDoubleBaseVarTimeXFromTables` + `jacobianXCoord` skip full
  affine normalization when comparing `r` (verify hot path).
- **w7 Shamir loop:** booth windows precomputed once per scalar; 37-step double-base loop
  fully unrolled at comptime; fused G+Q window accumulate per step.
- **Bench crypto breakdown:** `bench/crypto_bench.zig` micro-benchmarks `verifyPrehashed`,
  X25519 scalarmult, SHA-256 (2 KiB), TLS 1.3 GCM encrypt, and prints estimated ECDSA vs
  chain vs other handshake cost.
- **Transcript single-hash:** when all offered cipher suites share one hash (typical TLS 1.3
  bench config), client `initKeys` and server `readClientHello` call `transcript.use()` before
  `ClientHello` bytes are hashed (skips redundant SHA-384/512 updates).
- **Handshake TLS 1.3 GCM:** encrypted handshake records use `encryptTls13` / `decryptTls13`
  (cached AD GHASH) instead of generic AEAD; client decrypts server flight in-place via
  `decryptRecordInPlace`.
- **X25519-only DH init:** single-group bench configs use `DhKeyPair.initX25519` (32-byte seed)
  and one `rng.fill` for client/server random + ECDHE key material.
- **HKDF empty hash:** `TranscriptT` caches `tls.emptyHash(Hash)` at comptime for `derived`
  labels instead of recomputing per handshake.
- **Client flight 2 coalescing:** TLS 1.3 client encrypted flight packs cert/CV/finished into
  one AEAD record (mirrors server coalesced flight).
- **HKDF fast path:** `tls_hkdf.expandLabelEmpty` uses comptime-built info buffers for empty-
  context labels (cipher key/iv, finished keys); transcript caches `master_secret` after
  `applicationSecret`.
- **Server flight 2 decrypt:** `readClientFlight2` decrypts coalesced client records in-place via
  `decryptRecordInPlace`.
- **BoringSSL micro-benchmarks:** `bench/boringssl_bench.cc` prints the same isolated crypto rows
  as `bench/crypto_bench.zig` for side-by-side primitive comparison.
- **ECDSA sign x-only:** `mulBaseVarTimeX` skips full Jacobian→affine `y` on the `k·G` path used by
  `signPrehashed` (~20% sign throughput gain on Apple Silicon; BoringSSL sign still ~1.2× faster).
- **Cert Wyhash:** `parseCertificate` computes leaf Wyhash once per entry and passes it to
  `findTrustedCertDer`; repeat handshakes skip Wyhash when DER length and a 16-byte prefix
  match the cached leaf.
- **Trusted cert lookup:** `findTrustedCertDer` skips `memcmp` when cached leaf hash/len
  matches a prewarmed trusted entry; `cached_trusted_bytes_index` makes repeat-handshake
  lookup O(1) after prewarm.
- **ECDSA sign scalar cache:** `CertKeyPair.ecdsa_p256_d` avoids re-parsing the P-256
  private key on every CertificateVerify.
- **mulBase w7 unroll:** `mulAffineTableJacobianVarTimeX` precomputes Booth windows and
  unrolls the 37-step accumulation loop (sign `k·G` hot path on AArch64).
- **BoringSSL `point_mul_public` (experimental):** Zig + optional Bedrock C ports of wNAF
  interleaved double-base; **disabled by default** (257 Jacobian/projective doubles lose to
  unified w7 Shamir on Apple Silicon).
- **CertificateVerify always checked:** `insecure_skip_verify` skips chain/hostname only;
  leaf pubkey is parsed via `parseCertificateLeaf` so CV ECDSA is still verified.
- **BoringSSL verify row:** `bench/boringssl_bench.cc` trusts the bench self-signed
  cert (`SSL_CTX_set1_verify_cert_store`, `SSL_VERIFY_PEER`, `SSL_set1_host`).
- **P-256 sliding window:** `dbl4` coalesces four doublings in width-4 mul loops.
- **TLS 1.3 GCM nonce cache:** `CachedAesGcm` reuses the counter=1 tag mask and counter=2
  CTR ivec per record nonce (bench transfer path uses a fixed nonce).
- **Bedrock Jacobian mulBase (optional):** `mulBaseJacobian` uses Bedrock `p256_point_double`
  (`doublePoint`), `coord_halve`, and `addMixedAffineOrDouble`; converts via `field_inv_sqr_chain`.
  Equivalence-tested against projective `mulBase`. **Disabled by default** (`use_bedrock_mul_base =
  false`): current BoringSSL has no `ecp_nistz256_point_add_affine` asm (point math is Bedrock C in
  `p256_point.br.c.inc`); Zig Bedrock coord add is still slower than projective `addMixed` on
  typical Apple Silicon runs.
- **Bedrock coord add/sub** (`p256_coord.zig`): Jacobian `addMixedAffine` / `doublePoint` are
  **not** interchangeable with projective `P256.add` / `addMixed` (different Z semantics).
- **SHA-256:** Zig `std.crypto` already uses AArch64 SHA2 / x86 SHA-NI+AVX2 when
  `-Dcpu=native`; no extra assembly vendored.
- **nistz base-point table:** Gueron–Krasnov 37×64 affine precompute (`p256/nistz_table.zig`)
  for `k×G` on the signing path. Zero Booth digits skip adds (no spurious doubles).

## Regression tracking

Store `compare.sh` output in CI as a non-gating artifact. Re-run after handshake or
cipher changes; investigate >10% swings on the same host.
