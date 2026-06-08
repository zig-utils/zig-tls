//! AES-GCM with cached key schedule and GHASH subkey for hot record paths.
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const modes = crypto.core.modes;
const Ghash = crypto.onetimeauth.Ghash;
const AuthenticationError = crypto.errors.AuthenticationError;

pub fn CachedAesGcm(comptime Aes: type) type {
    const dummy_key: [Aes.key_bits / 8]u8 = undefined;
    const AesCtx = @TypeOf(Aes.initEnc(dummy_key));

    return struct {
        pub const tag_length = 16;
        pub const nonce_length = 12;
        pub const key_length = Aes.key_bits / 8;

        aes: AesCtx,
        h: [16]u8,
        /// GHASH state after the padded 5-byte TLS 1.3 AD block (keyed by record payload length).
        tls13_mac_after_ad: Ghash = undefined,
        tls13_payload_len: u16 = 0xffff,

        pub fn fromKey(key: [key_length]u8) @This() {
            var ctx: @This() = .{ .aes = Aes.initEnc(key), .h = undefined };
            ctx.aes.encrypt(&ctx.h, &@splat(0));
            return ctx;
        }

        fn ensureTls13MacAfterAd(ctx: *@This(), ad: *const [5]u8) void {
            const payload_len = mem.readInt(u16, ad[3..5], .big);
            if (ctx.tls13_payload_len == payload_len) return;
            var ad_block: [16]u8 = undefined;
            @memcpy(ad_block[0..5], ad);
            @memset(ad_block[5..], 0);
            const ct_len = payload_len - tag_length;
            const ct_blocks = (ct_len + Ghash.block_length - 1) / Ghash.block_length;
            var mac = Ghash.initForBlockCount(&ctx.h, 1 + ct_blocks + 1);
            mac.update(&ad_block);
            mac.pad();
            ctx.tls13_mac_after_ad = mac;
            ctx.tls13_payload_len = payload_len;
        }

        fn finishTls13Mac(mac: *Ghash, ct_len: usize, tag: *[tag_length]u8, t: *const [16]u8) void {
            var final_block: [16]u8 = undefined;
            mem.writeInt(u64, final_block[0..8], 40, .big);
            mem.writeInt(u64, final_block[8..16], @as(u64, ct_len) * 8, .big);
            mac.update(&final_block);
            mem.writeInt(u128, tag[0..16], mac.acc, .big);
            for (t, 0..) |x, i| tag[i] ^= x;
        }

        inline fn gcmBlockCount(ad_len: usize, c_len: usize) usize {
            return (ad_len + Ghash.block_length - 1) / Ghash.block_length +
                (c_len + Ghash.block_length - 1) / Ghash.block_length + 1;
        }

        pub fn encrypt(
            ctx: *const @This(),
            c: []u8,
            tag: *[tag_length]u8,
            m: []const u8,
            ad: []const u8,
            npub: [nonce_length]u8,
        ) void {
            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            j[0..nonce_length].* = npub;
            mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
            ctx.aes.encrypt(&t, &j);

            var mac = Ghash.initForBlockCount(&ctx.h, gcmBlockCount(ad.len, c.len));
            mac.update(ad);
            mac.pad();

            mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
            modes.ctr(@TypeOf(ctx.aes), ctx.aes, c, m, j, .big);
            mac.update(c[0..m.len]);
            mac.pad();

            var final_block = ctx.h;
            mem.writeInt(u64, final_block[0..8], @as(u64, ad.len) * 8, .big);
            mem.writeInt(u64, final_block[8..16], @as(u64, m.len) * 8, .big);
            mac.update(&final_block);
            mac.final(tag);
            for (t, 0..) |x, i| tag[i] ^= x;
        }

        /// TLS 1.3 record path: AD is always the 5-byte record header.
        pub fn encryptTls13(
            ctx: *@This(),
            c: []u8,
            tag: *[tag_length]u8,
            m: []const u8,
            ad: *const [5]u8,
            npub: [nonce_length]u8,
        ) void {
            ctx.ensureTls13MacAfterAd(ad);

            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            j[0..nonce_length].* = npub;
            mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
            ctx.aes.encrypt(&t, &j);

            mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
            modes.ctr(@TypeOf(ctx.aes), ctx.aes, c, m, j, .big);

            var mac = ctx.tls13_mac_after_ad;
            mac.update(c[0..m.len]);
            mac.pad();
            finishTls13Mac(&mac, m.len, tag, &t);
        }

        pub fn decrypt(
            ctx: *const @This(),
            m: []u8,
            c: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            npub: [nonce_length]u8,
        ) AuthenticationError!void {
            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            j[0..nonce_length].* = npub;
            mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
            ctx.aes.encrypt(&t, &j);

            var mac = Ghash.initForBlockCount(&ctx.h, gcmBlockCount(ad.len, c.len));
            mac.update(ad);
            mac.pad();
            mac.update(c);
            mac.pad();

            var final_block = ctx.h;
            mem.writeInt(u64, final_block[0..8], @as(u64, ad.len) * 8, .big);
            mem.writeInt(u64, final_block[8..16], @as(u64, m.len) * 8, .big);
            mac.update(&final_block);
            var computed_tag: [Ghash.mac_length]u8 = undefined;
            mac.final(&computed_tag);
            for (t, 0..) |x, i| computed_tag[i] ^= x;

            const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
            if (!verify) {
                crypto.secureZero(u8, &computed_tag);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }

            mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
            modes.ctr(@TypeOf(ctx.aes), ctx.aes, m, c, j, .big);
        }

        /// TLS 1.3 record path: AD is always the 5-byte record header.
        pub fn decryptTls13(
            ctx: *@This(),
            m: []u8,
            c: []const u8,
            tag: [tag_length]u8,
            ad: *const [5]u8,
            npub: [nonce_length]u8,
        ) AuthenticationError!void {
            ctx.ensureTls13MacAfterAd(ad);

            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            j[0..nonce_length].* = npub;
            mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
            ctx.aes.encrypt(&t, &j);

            var mac = ctx.tls13_mac_after_ad;
            mac.update(c);
            mac.pad();

            var computed_tag: [tag_length]u8 = undefined;
            finishTls13Mac(&mac, m.len, &computed_tag, &t);

            const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
            if (!verify) {
                crypto.secureZero(u8, &computed_tag);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }

            mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
            modes.ctr(@TypeOf(ctx.aes), ctx.aes, m, c, j, .big);
        }
    };
}

const testing = std.testing;

test "CachedAesGcm matches std" {
    const Std = crypto.aead.aes_gcm.Aes128Gcm;
    const Cached = CachedAesGcm(crypto.core.aes.Aes128);
    var key: [16]u8 = undefined;
    @memset(&key, 0x69);
    var npub: [12]u8 = undefined;
    @memset(&npub, 0x42);
    const m = "Test with message only";
    const ad = "";
    var c_std: [m.len]u8 = undefined;
    var tag_std: [16]u8 = undefined;
    Std.encrypt(&c_std, &tag_std, m, ad, npub, key);
    var ctx = Cached.fromKey(key);
    var c_cached: [m.len]u8 = undefined;
    var tag_cached: [16]u8 = undefined;
    ctx.encrypt(&c_cached, &tag_cached, m, ad, npub);
    try testing.expectEqualSlices(u8, &c_std, &c_cached);
    try testing.expectEqualSlices(u8, &tag_std, &tag_cached);
}

test "CachedAesGcm encryptTls13 reuses AD mac state" {
    const Cached = CachedAesGcm(crypto.core.aes.Aes128);
    var key: [16]u8 = undefined;
    @memset(&key, 0x33);
    var ctx = Cached.fromKey(key);
    var npub: [12]u8 = undefined;
    @memset(&npub, 0x44);
    var ad: [5]u8 = .{ 0x17, 0x03, 0x03, 0x40, 0x11 };
    const m = "repeatable-payload!!";
    var c1: [m.len]u8 = undefined;
    var c2: [m.len]u8 = undefined;
    var tag1: [16]u8 = undefined;
    var tag2: [16]u8 = undefined;
    ctx.encryptTls13(&c1, &tag1, m, &ad, npub);
    npub[11] +%= 1;
    ctx.encryptTls13(&c2, &tag2, m, &ad, npub);
    try testing.expect(!mem.eql(u8, &tag1, &tag2));
    try testing.expectEqual(@as(u16, 0x4011), ctx.tls13_payload_len);
}

test "CachedAesGcm encryptTls13 matches generic" {
    const Cached = CachedAesGcm(crypto.core.aes.Aes128);
    var key: [16]u8 = undefined;
    @memset(&key, 0x55);
    var ctx = Cached.fromKey(key);
    var npub: [12]u8 = undefined;
    @memset(&npub, 0xaa);
    const m = "sixteen bytes!!!";
    var ad: [5]u8 = .{ 0x17, 0x03, 0x03, 0x00, 0x11 };
    var c_tls: [m.len]u8 = undefined;
    var tag_tls: [16]u8 = undefined;
    var c_gen: [m.len]u8 = undefined;
    var tag_gen: [16]u8 = undefined;
    ctx.encryptTls13(&c_tls, &tag_tls, m, &ad, npub);
    ctx.encrypt(&c_gen, &tag_gen, m, &ad, npub);
    try testing.expectEqualSlices(u8, &c_tls, &c_gen);
    try testing.expectEqualSlices(u8, &tag_tls, &tag_gen);
}

test "CachedAesGcm roundtrip" {
    const Cached = CachedAesGcm(crypto.core.aes.Aes128);
    var key: [Cached.key_length]u8 = undefined;
    @memset(&key, 0x11);
    var ctx = Cached.fromKey(key);
    var npub: [12]u8 = undefined;
    @memset(&npub, 0);
    npub[11] = 1;
    const ad = "tls";
    const m = "hello";
    var c: [m.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    ctx.encrypt(&c, &tag, m, ad, npub);
    var out: [m.len]u8 = undefined;
    try ctx.decrypt(&out, &c, tag, ad, npub);
    try testing.expectEqualSlices(u8, m, &out);
}
