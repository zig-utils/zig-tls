//! Platform stitched AES-GCM dispatch (AArch64 or x86_64).
const builtin = @import("builtin");
const aarch64_gcm = @import("aarch64_gcm.zig");
const x86_64_gcm = @import("x86_64_gcm.zig");

pub const enabled = aarch64_gcm.enabled or x86_64_gcm.enabled;
pub const min_bulk_len: usize = if (aarch64_gcm.enabled) 64 else if (x86_64_gcm.enabled) 16 else 64;

pub const AesKey = extern struct {
    rd_key: [60]u32 align(16),
    rounds: u32,
};

pub const U128 = extern struct {
    hi: u64,
    lo: u64,
};

pub fn initAesKey(comptime key_bits: comptime_int, key: *const [key_bits / 8]u8) AesKey {
    if (aarch64_gcm.enabled) return @bitCast(aarch64_gcm.initAesKey(key_bits, key));
    if (x86_64_gcm.enabled) return @bitCast(x86_64_gcm.initAesKey(key_bits, key));
    _ = .{ key_bits, key };
    @compileError("stitched GCM requires AArch64 or x86_64 with AES");
}

pub fn initHtable(htable: *[16]U128, h: [16]u8) void {
    if (aarch64_gcm.enabled) {
        aarch64_gcm.initHtable(@ptrCast(htable), h);
        return;
    }
    if (x86_64_gcm.enabled) {
        x86_64_gcm.initHtable(@ptrCast(htable), h);
        return;
    }
}

pub fn encryptBulk(
    aes_key: *const AesKey,
    htable: *const [16]U128,
    out: []u8,
    in: []const u8,
    xi: *[16]u8,
    ivec: *[16]u8,
) usize {
    if (aarch64_gcm.enabled) {
        return aarch64_gcm.encryptBulk(@ptrCast(aes_key), @ptrCast(htable), out, in, xi, ivec);
    }
    if (x86_64_gcm.enabled) {
        return x86_64_gcm.encryptBulk(@ptrCast(aes_key), @ptrCast(htable), out, in, xi, ivec);
    }
    return 0;
}

pub fn decryptBulk(
    aes_key: *const AesKey,
    htable: *const [16]U128,
    out: []u8,
    in: []const u8,
    xi: *[16]u8,
    ivec: *[16]u8,
) usize {
    if (aarch64_gcm.enabled) {
        return aarch64_gcm.decryptBulk(@ptrCast(aes_key), @ptrCast(htable), out, in, xi, ivec);
    }
    if (x86_64_gcm.enabled) {
        return x86_64_gcm.decryptBulk(@ptrCast(aes_key), @ptrCast(htable), out, in, xi, ivec);
    }
    return 0;
}

pub fn xiFromAcc(acc: u128) [16]u8 {
    if (aarch64_gcm.enabled) return aarch64_gcm.xiFromAcc(acc);
    if (x86_64_gcm.enabled) return x86_64_gcm.xiFromAcc(acc);
    return .{};
}

pub fn accFromXi(xi: *const [16]u8) u128 {
    if (aarch64_gcm.enabled) return aarch64_gcm.accFromXi(xi);
    if (x86_64_gcm.enabled) return x86_64_gcm.accFromXi(xi);
    return 0;
}

pub fn ctrIvec(npub: [12]u8, counter: u32) [16]u8 {
    if (aarch64_gcm.enabled) return aarch64_gcm.ctrIvec(npub, counter);
    if (x86_64_gcm.enabled) return x86_64_gcm.ctrIvec(npub, counter);
    return .{};
}
