#!/usr/bin/env python3
"""Generate src/crypto/p256/nistz_table.zig from BoringSSL p256-nistz-table.h."""
import re
import sys
from pathlib import Path

def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/boringssl/crypto/fipsmodule/ec/p256-nistz-table.h")
    out = Path(__file__).resolve().parent.parent / "src/crypto/p256/nistz_table.zig"
    raw = src.read_text()
    raw = re.sub(r"//.*", "", raw)
    nums: list[int] = []
    for m in re.finditer(r"TOBN\((0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)", raw):
        hi = int(m.group(1), 16)
        lo = int(m.group(2), 16)
        nums.append((hi << 32) | lo)
    expected = 37 * 64 * 8
    if len(nums) != expected:
        raise SystemExit(f"expected {expected} limbs, got {len(nums)}")

    lines = [
        "//! BoringSSL ecp_nistz256_precomputed (Apache 2.0, from p256-nistz-table.h).",
        "pub const AffineMont = struct { x: [4]u64, y: [4]u64 };",
        "pub const Row = [64]AffineMont;",
        "pub const ecp_nistz256_precomputed: [37]Row = .{",
    ]
    idx = 0
    for _ in range(37):
        lines.append("    .{")
        for _ in range(64):
            x = nums[idx : idx + 4]
            idx += 4
            y = nums[idx : idx + 4]
            idx += 4
            xs = ", ".join(f"0x{v:x}" for v in x)
            ys = ", ".join(f"0x{v:x}" for v in y)
            lines.append(f"        .{{ .x = .{{ {xs} }}, .y = .{{ {ys} }} }},")
        lines.append("    },")
    lines.append("};")
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes)")

if __name__ == "__main__":
    main()
