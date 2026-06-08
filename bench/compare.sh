#!/usr/bin/env bash
# Compare zig-tls vs BoringSSL using matched benchmark categories.
# Canonical rows use the same abstraction on both sides (see docs/BENCHMARKS.md).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ZIG="${ZIG:-zig}"
if ! command -v "$ZIG" &>/dev/null; then
  ZIG="${HOME}/.local/share/pantry/global/pantry_modules/.bin/zig"
fi

BORINGSSL_DIR="${BORINGSSL_DIR:-/tmp/boringssl}"
BORINGSSL_BUILD="${BORINGSSL_BUILD:-${BORINGSSL_DIR}/build}"
BENCH_OUT="${ROOT}/zig-out/bin"
BORINGSSL_BENCH="${BENCH_OUT}/boringssl_bench"

echo "=== zig-tls (ReleaseFast, -Dcpu=native) ==="
ZIG_CACHE="${ZIG_CACHE:-$ROOT/.zig-cache}"
"$ZIG" build bench -Doptimize=ReleaseFast -Dcpu=native --cache-dir "$ZIG_CACHE" 2>/dev/null | tail -8

if [[ ! -f "${BORINGSSL_BUILD}/libssl.a" ]]; then
  echo ""
  echo "Note: Clone and build BoringSSL, then re-run:"
  echo "  git clone --depth=1 https://github.com/google/boringssl.git /tmp/boringssl"
  echo "  cmake -S /tmp/boringssl -B /tmp/boringssl/build -DCMAKE_BUILD_TYPE=Release"
  echo "  cmake --build /tmp/boringssl/build -j"
  exit 0
fi

mkdir -p "$BENCH_OUT"
if [[ "$(uname -s)" == "Darwin" ]]; then
  CXX="${CXX:-clang++}"
  "$CXX" -O3 -std=c++17 -o "$BORINGSSL_BENCH" bench/boringssl_bench.cc \
    -I"${BORINGSSL_DIR}/include" \
    "${BORINGSSL_BUILD}/libssl.a" \
    "${BORINGSSL_BUILD}/libcrypto.a" \
    -lpthread
else
  CXX="${CXX:-g++}"
  "$CXX" -O3 -std=c++17 -o "$BORINGSSL_BENCH" bench/boringssl_bench.cc \
    -I"${BORINGSSL_DIR}/include" \
    -L"${BORINGSSL_BUILD}" -lssl -lcrypto -lpthread
fi

echo ""
echo "=== BoringSSL (matched TLS 1.3 harness, ${BORINGSSL_BUILD##*/}) ==="
"$BORINGSSL_BENCH"
