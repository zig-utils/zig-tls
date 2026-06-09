const std = @import("std");
const tls = @import("tls");

pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, size: usize) c_int {
    if (size < 4) return 0;
    const input = data[0..size];
    tls.fuzz.parseClientHello(input);
    tls.fuzz.parseServerHello(input);
    return 0;
}

/// Standalone entry for `zig build -Dfuzz=true fuzz` without libFuzzer.
pub fn main(_: std.process.Init) !void {}
