//! x86_64 stitched AES-GCM (BoringSSL vaes/avx2 update path).
const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;

pub const enabled = builtin.cpu.arch == .x86_64 and
    builtin.cpu.has(.x86, .aes) and
    builtin.cpu.has(.x86, .pclmul) and
    builtin.cpu.has(.x86, .avx2) and
    (builtin.os.tag == .linux or builtin.os.tag == .macos);

pub const AesKey = extern struct {
    rd_key: [60]u32 align(16),
    rounds: u32,
};

pub const U128 = extern struct {
    hi: u64,
    lo: u64,
};

extern "C" fn aes_hw_set_encrypt_key_base(user_key: *const anyopaque, bits: c_int, key: *AesKey) c_int;
extern "C" fn gcm_init_vpclmulqdq_avx2(Htable: *[16]U128, H: *const [2]u64) void;
extern "C" fn aes_gcm_enc_update_vaes_avx2(
    in: [*]const u8,
    out: [*]u8,
    len: usize,
    key: *const AesKey,
    ivec: *const [16]u8,
    Htable: *const [16]U128,
    Xi: *[16]u8,
) void;
extern "C" fn aes_gcm_dec_update_vaes_avx2(
    in: [*]const u8,
    out: [*]u8,
    len: usize,
    key: *const AesKey,
    ivec: *const [16]u8,
    Htable: *const [16]U128,
    Xi: *[16]u8,
) void;

pub fn initAesKey(comptime key_bits: comptime_int, key: *const [key_bits / 8]u8) AesKey {
    var aes_key: AesKey = undefined;
    const rc = aes_hw_set_encrypt_key_base(key, @intCast(key_bits), &aes_key);
    if (rc != 0) @panic("aes_hw_set_encrypt_key_base failed");
    return aes_key;
}

pub fn initHtable(htable: *[16]U128, h: [16]u8) void {
    const H: [2]u64 = .{
        mem.readInt(u64, h[0..8], .big),
        mem.readInt(u64, h[8..16], .big),
    };
    gcm_init_vpclmulqdq_avx2(htable, &H);
}

pub fn encryptBulk(
    aes_key: *const AesKey,
    htable: *const [16]U128,
    out: []u8,
    in: []const u8,
    xi: *[16]u8,
    ivec: *[16]u8,
) usize {
    const bulk = @min(in.len, out.len) & ~@as(usize, 15);
    if (bulk == 0) return 0;
    aes_gcm_enc_update_vaes_avx2(in.ptr, out.ptr, bulk, aes_key, ivec, htable, xi);
    advanceCounter(ivec, bulk);
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
    const bulk = @min(in.len, out.len) & ~@as(usize, 15);
    if (bulk == 0) return 0;
    aes_gcm_dec_update_vaes_avx2(in.ptr, out.ptr, bulk, aes_key, ivec, htable, xi);
    advanceCounter(ivec, bulk);
    return bulk;
}

fn advanceCounter(ivec: *[16]u8, processed_len: usize) void {
    const block_count: u32 = @intCast(processed_len / 16);
    const counter = mem.readInt(u32, ivec[12..16], .big);
    mem.writeInt(u32, ivec[12..16], counter +% block_count, .big);
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

test "advance counter after stitched blocks" {
    var ivec = ctrIvec(@splat(0xaa), 2);
    advanceCounter(&ivec, 16 * 1024);
    try std.testing.expectEqual(@as(u32, 1026), mem.readInt(u32, ivec[12..16], .big));
}
