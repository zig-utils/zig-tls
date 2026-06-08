#!/usr/bin/env bash
# Compare zig-tls benchmarks against BoringSSL when available.
# Usage: ./bench/compare.sh
set -euo pipefail

echo "=== zig-tls ==="
zig build bench -Doptimize=ReleaseFast

if command -v boringssl_bench &>/dev/null; then
  echo ""
  echo "=== BoringSSL (external boringssl_bench) ==="
  boringssl_bench
else
  echo ""
  echo "Note: Install BoringSSL bench tool as 'boringssl_bench' for side-by-side comparison."
  echo "See bench/README.md for setup instructions."
fi
