#!/usr/bin/env bash
# Compare zig-tls benchmarks against BoringSSL (apples-to-apples TLS 1.3 harness).
# Usage: ./bench/compare.sh
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

echo "=== zig-tls (ReleaseFast, -Dcpu=native) ==="
"$ZIG" build bench -Doptimize=ReleaseFast -Dcpu=native 2>/dev/null | tail -5

BORINGSSL_BENCH="${BENCH_OUT}/boringssl_bench"
if [[ -x "$BORINGSSL_BENCH" ]] || [[ -f "${BORINGSSL_BUILD}/libssl.a" ]]; then
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
  echo "=== BoringSSL (in-memory TLS 1.3, AES-128-GCM, ECDSA test cert) ==="
  "$BORINGSSL_BENCH"
else
  echo ""
  echo "Note: Clone and build BoringSSL, then re-run:"
  echo "  git clone --depth=1 https://github.com/google/boringssl.git /tmp/boringssl"
  echo "  cmake -S /tmp/boringssl -B /tmp/boringssl/build -DCMAKE_BUILD_TYPE=Release"
  echo "  cmake --build /tmp/boringssl/build -j"
  echo "  BORINGSSL_DIR=/tmp/boringssl ./bench/compare.sh"
fi
