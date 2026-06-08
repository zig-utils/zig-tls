#!/usr/bin/env bash
# Audit helper: run testssl.sh against a TLS endpoint (default localhost:8443).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${1:-localhost}"
PORT="${2:-8443}"

if ! command -v testssl.sh &>/dev/null; then
  if [[ -d /tmp/testssl.sh ]]; then
    TESTSSL=/tmp/testssl.sh/testssl.sh
  else
    echo "Install testssl.sh:"
    echo "  git clone --depth=1 https://github.com/drwetter/testssl.sh.git /tmp/testssl.sh"
    exit 1
  fi
else
  TESTSSL=testssl.sh
fi

echo "=== zig-tls test suite (sanity) ==="
cd "$ROOT"
zig build test

echo ""
echo "=== testssl.sh ${HOST}:${PORT} ==="
echo "Start a TLS 1.3 server on ${PORT} first (see docs/AUDIT_PREP.md)."
"$TESTSSL" --quiet --color 0 "${HOST}:${PORT}"
