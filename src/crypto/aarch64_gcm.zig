//! AArch64 stitched AES-GCM (BoringSSL aesv8-gcm kernel).
const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;

pub const enabled = builtin.cpu.arch == .aarch64 and
    @import("build_options").hw_crypto_asm and
    builtin.cpu.has(.aarch64, .aes) and
    (builtin.os.tag == .macos or builtin.os.tag == .linux);

pub const use_eor3 = enabled and builtin.cpu.has(.aarch64, .sha3);

pub const AesKey = extern struct {
    rd_key: [60]u32 align(16),
    rounds: u32,
};

pub const U128 = extern struct {
    hi: u64,
    lo: u64,
};

extern "C" fn aes_hw_set_encrypt_key(user_key: *const anyopaque, bits: c_int, key: *AesKey) c_int;
extern "C" fn gcm_init_v8(Htable: *[16]U128, H: *const [2]u64) void;
extern "C" fn aes_gcm_enc_kernel(
    in: [*]const u8,
    in_bits: u64,
    out: *anyopaque,
    Xi: *anyopaque,
    ivec: *[16]u8,
    key: *const AesKey,
    Htable: *const [16]U128,
) void;
extern "C" fn aes_gcm_dec_kernel(
    in: [*]const u8,
    in_bits: u64,
    out: *anyopaque,
    Xi: *anyopaque,
    ivec: *[16]u8,
    key: *const AesKey,
    Htable: *const [16]U128,
) void;
extern "C" fn aes_gcm_enc_kernel_eor3(
    in: [*]const u8,
    in_bits: u64,
    out: *anyopaque,
    Xi: *anyopaque,
    ivec: *[16]u8,
    key: *const AesKey,
    Htable: *const [16]U128,
) void;
extern "C" fn aes_gcm_dec_kernel_eor3(
    in: [*]const u8,
    in_bits: u64,
    out: *anyopaque,
    Xi: *anyopaque,
    ivec: *[16]u8,
    key: *const AesKey,
    Htable: *const [16]U128,
) void;

pub fn initAesKey(comptime key_bits: comptime_int, key: *const [key_bits / 8]u8) AesKey {
    var aes_key: AesKey = undefined;
    const rc = aes_hw_set_encrypt_key(key, @intCast(key_bits), &aes_key);
    if (rc != 0) @panic("aes_hw_set_encrypt_key failed");
    return aes_key;
}

pub fn initHtable(htable: *[16]U128, h: [16]u8) void {
    const H: [2]u64 = .{
        mem.readInt(u64, h[0..8], .big),
        mem.readInt(u64, h[8..16], .big),
    };
    gcm_init_v8(htable, &H);
}

/// Process as many 64-byte blocks as possible. Updates `xi` and `ivec` in place.
pub fn encryptBulk(
    aes_key: *const AesKey,
    htable: *const [16]U128,
    out: []u8,
    in: []const u8,
    xi: *[16]u8,
    ivec: *[16]u8,
) usize {
    const bulk = @min(in.len, out.len) & ~@as(usize, 63);
    if (bulk == 0) return 0;
    const in_ptr = in.ptr;
    const out_ptr = out.ptr;
    if (use_eor3) {
        aes_gcm_enc_kernel_eor3(in_ptr, @as(u64, bulk) * 8, out_ptr, xi, ivec, aes_key, htable);
    } else {
        aes_gcm_enc_kernel(in_ptr, @as(u64, bulk) * 8, out_ptr, xi, ivec, aes_key, htable);
    }
    return bulk;
}

pub fn decryptBulk(
    aes_key: *const AesKey,
    htable: *const [16]U128,
    out: []u8,
    in: []const u8,
    xi: *[16]u8,
    ivec: *[16]u8,
) usize {
    const bulk = @min(in.len, out.len) & ~@as(usize, 63);
    if (bulk == 0) return 0;
    const in_ptr = in.ptr;
    const out_ptr = out.ptr;
    if (use_eor3) {
        aes_gcm_dec_kernel_eor3(in_ptr, @as(u64, bulk) * 8, out_ptr, xi, ivec, aes_key, htable);
    } else {
        aes_gcm_dec_kernel(in_ptr, @as(u64, bulk) * 8, out_ptr, xi, ivec, aes_key, htable);
    }
    return bulk;
}

pub fn xiFromAcc(acc: u128) [16]u8 {
    var xi: [16]u8 = undefined;
    mem.writeInt(u128, &xi, acc, .big);
    return xi;
}

pub fn accFromXi(xi: *const [16]u8) u128 {
    return mem.readInt(u128, xi, .big);
}

pub fn ctrIvec(npub: [12]u8, counter: u32) [16]u8 {
    var ivec: [16]u8 = undefined;
    ivec[0..12].* = npub;
    mem.writeInt(u32, ivec[12..16], counter, .big);
    return ivec;
}
