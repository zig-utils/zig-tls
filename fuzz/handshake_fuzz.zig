const std = @import("std");
const tls = @import("tls");

pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, size: usize) c_int {
    if (size < 9) return 0;
    const input = data[0..size];
    var reader = std.Io.Reader.fixed(input);
    var decoder = tls.config.Record.decoder(&reader) catch return 0;
    _ = decoder.decode(tls.config.proto.Handshake) catch return 0;
    return 0;
}

/// Standalone entry for `zig build -Dfuzz=true fuzz` without libFuzzer.
pub fn main(_: std.process.Init) !void {}
