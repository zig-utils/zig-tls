# zig-tls Benchmarks

Run benchmarks:

```bash
zig build bench -Doptimize=ReleaseFast
```

Compare against BoringSSL (builds `zig-out/bin/boringssl_bench` from `bench/boringssl_bench.cc`):

```bash
chmod +x bench/compare.sh
./bench/compare.sh
```

Recorded results: [docs/BENCHMARKS.md](../docs/BENCHMARKS.md).

## Methodology

Mirrors the [rustls perf report](https://rustls.dev/perf/) categories:

- **Full handshake** — TLS 1.3 ECDHE client/server via non-blocking API
- **Bulk transfer send/recv** — AES-256-GCM application data after handshake

Results are printed as handshakes/sec and MB/s. Store output in CI as non-gating baselines.

## BoringSSL comparison

Build BoringSSL from the commit Bun pins, then expose a `boringssl_bench` binary
that prints the same categories. Point `bench/compare.sh` at both binaries for
side-by-side numbers.
