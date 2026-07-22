const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const proto = @import("protocol.zig");
const record = @import("record.zig");
const CipherSuite = @import("cipher.zig").CipherSuite;
const rng = @import("random.zig");

fn nowSeconds() i64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(.REALTIME, &ts) != 0) return 0;
    return ts.sec;
}

/// 48-byte ticket keys per Node.js / OpenSSL convention:
/// 16-byte name prefix, 16-byte HMAC key, 16-byte AES key.
pub const TicketKeys = struct {
    name: [16]u8,
    hmac_key: [16]u8,
    aes_key: [16]u8,

    pub fn fromBytes(bytes: *const [48]u8) TicketKeys {
        return .{
            .name = bytes[0..16].*,
            .hmac_key = bytes[16..32].*,
            .aes_key = bytes[32..48].*,
        };
    }

    pub fn random() TicketKeys {
        var keys: [48]u8 = undefined;
        rng.fill(&keys);
        return fromBytes(&keys);
    }
};

/// Thread-safe bounded session-ticket key ring.
///
/// New tickets always use the active key at index zero. Resumption accepts the
/// active key and at most three previous keys. Keep the ring at a stable address
/// for as long as server configurations reference it. Rotation is serialized,
/// does not require a listener restart, and securely clears retired material.
pub const TicketKeyRing = struct {
    pub const capacity = 4;

    mutex: std.atomic.Mutex = .unlocked,
    keys: [capacity]TicketKeys = undefined,
    count: u8 = 1,

    pub fn init(primary: TicketKeys) TicketKeyRing {
        var ring: TicketKeyRing = .{};
        ring.keys[0] = primary;
        return ring;
    }

    pub fn rotate(self: *TicketKeyRing, next: TicketKeys) error{DuplicateKeyName}!void {
        lock(&self.mutex);
        defer self.mutex.unlock();

        for (self.keys[0..self.count]) |existing| {
            if (mem.eql(u8, &existing.name, &next.name)) return error.DuplicateKeyName;
        }

        if (self.count == capacity) secureZeroKeys(&self.keys[capacity - 1]);
        const retained: usize = @min(self.count, capacity - 1);
        var index = retained;
        while (index > 0) : (index -= 1) self.keys[index] = self.keys[index - 1];
        self.keys[0] = next;
        if (self.count < capacity) self.count += 1;
    }

    pub fn active(self: *TicketKeyRing) TicketKeys {
        lock(&self.mutex);
        defer self.mutex.unlock();
        return self.keys[0];
    }

    pub fn decryptTicket(self: *TicketKeyRing, identity: []const u8) ?SessionState {
        if (identity.len < 16) return null;
        var selected: ?TicketKeys = null;
        lock(&self.mutex);
        for (self.keys[0..self.count]) |candidate| {
            if (mem.eql(u8, identity[0..16], &candidate.name)) {
                selected = candidate;
                break;
            }
        }
        self.mutex.unlock();
        return decrypt(identity, selected orelse return null);
    }

    pub fn keyCount(self: *TicketKeyRing) usize {
        lock(&self.mutex);
        defer self.mutex.unlock();
        return self.count;
    }

    pub fn containsKeyName(self: *TicketKeyRing, name: *const [16]u8) bool {
        lock(&self.mutex);
        defer self.mutex.unlock();
        for (self.keys[0..self.count]) |candidate| {
            if (mem.eql(u8, &candidate.name, name)) return true;
        }
        return false;
    }
};

fn lock(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

fn secureZeroKeys(keys: *TicketKeys) void {
    crypto.secureZero(u8, &keys.name);
    crypto.secureZero(u8, &keys.hmac_key);
    crypto.secureZero(u8, &keys.aes_key);
}

/// Serialized session state encrypted into a TLS session ticket.
pub const SessionState = struct {
    tls_version: proto.Version,
    cipher_suite: CipherSuite,
    named_group: proto.NamedGroup,
    master_secret: [48]u8,
    session_timeout_secs: u32 = 300,
    /// TLS 1.3 PSK ticket_nonce (RFC 8446); distinct from the AES-GCM encryption nonce in the identity blob.
    psk_nonce_len: u8 = 0,
    psk_nonce: [Aes128Gcm.nonce_length]u8 = undefined,
};

pub const Ticket = struct {
    identity: []const u8,
    lifetime: u32,
    age_add: u32,
    nonce: []const u8,
    /// Decrypted session state (only set after successful decrypt).
    state: ?SessionState = null,
};

/// Encrypt session state into a ticket identity blob.
pub fn encrypt(
    allocator: mem.Allocator,
    keys: TicketKeys,
    state: SessionState,
    nonce: []const u8,
) ![]u8 {
    var plaintext: [128]u8 = undefined;
    var idx: usize = 0;
    mem.writeInt(u16, plaintext[idx .. idx + 2][0..2], @backingInt(state.tls_version), .big);
    idx += 2;
    mem.writeInt(u16, plaintext[idx .. idx + 2][0..2], @backingInt(state.cipher_suite), .big);
    idx += 2;
    mem.writeInt(u16, plaintext[idx .. idx + 2][0..2], @backingInt(state.named_group), .big);
    idx += 2;
    @memcpy(plaintext[idx .. idx + 48], &state.master_secret);
    idx += 48;
    mem.writeInt(u32, plaintext[idx .. idx + 4][0..4], state.session_timeout_secs, .big);
    idx += 4;
    mem.writeInt(u64, plaintext[idx .. idx + 8][0..8], @intCast(nowSeconds()), .big);
    idx += 8;
    plaintext[idx] = state.psk_nonce_len;
    idx += 1;
    @memcpy(plaintext[idx .. idx + state.psk_nonce_len], state.psk_nonce[0..state.psk_nonce_len]);
    idx += state.psk_nonce_len;

    const aad = keys.name;
    var ciphertext_buf: [128 + Aes128Gcm.tag_length]u8 = undefined;
    const ciphertext = ciphertext_buf[0..idx];
    var auth_tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(
        ciphertext,
        &auth_tag,
        plaintext[0..idx],
        &aad,
        nonce[0..Aes128Gcm.nonce_length].*,
        keys.aes_key,
    );

    const ticket = try allocator.alloc(u8, 17 + nonce.len + idx + Aes128Gcm.tag_length);
    @memcpy(ticket[0..16], &keys.name);
    ticket[16] = @intCast(nonce.len);
    @memcpy(ticket[17 .. 17 + nonce.len], nonce);
    @memcpy(ticket[17 + nonce.len .. 17 + nonce.len + idx], ciphertext);
    @memcpy(ticket[17 + nonce.len + idx .. 17 + nonce.len + idx + auth_tag.len], &auth_tag);
    return ticket;
}

/// Decrypt a ticket identity blob. Returns null if keys don't match or decryption fails.
pub fn decrypt(identity: []const u8, keys: TicketKeys) ?SessionState {
    if (identity.len < 18) return null;
    if (!mem.eql(u8, identity[0..16], &keys.name)) return null;
    const nonce_len = identity[16];
    if (identity.len < 17 + nonce_len + Aes128Gcm.tag_length + 59) return null;
    const nonce = identity[17 .. 17 + nonce_len];
    const ciphertext = identity[17 + nonce_len ..];
    if (nonce.len != Aes128Gcm.nonce_length) return null;

    var plaintext: [128]u8 = undefined;
    const pt_len = ciphertext.len - Aes128Gcm.tag_length;
    Aes128Gcm.decrypt(
        plaintext[0..pt_len],
        ciphertext[0..pt_len],
        ciphertext[pt_len..][0..Aes128Gcm.tag_length].*,
        &keys.name,
        nonce[0..Aes128Gcm.nonce_length].*,
        keys.aes_key,
    ) catch return null;

    var state: SessionState = undefined;
    state.tls_version = @fromBackingInt(@intCast(mem.readInt(u16, plaintext[0..2], .big)));
    state.cipher_suite = @fromBackingInt(@intCast(mem.readInt(u16, plaintext[2..4], .big)));
    state.named_group = @fromBackingInt(@intCast(mem.readInt(u16, plaintext[4..6], .big)));
    @memcpy(&state.master_secret, plaintext[6..54]);
    state.session_timeout_secs = mem.readInt(u32, plaintext[54..58], .big);
    const issued_at = mem.readInt(i64, plaintext[58..66], .big);
    state.psk_nonce_len = plaintext[66];
    if (state.psk_nonce_len > Aes128Gcm.nonce_length) return null;
    @memcpy(state.psk_nonce[0..state.psk_nonce_len], plaintext[67 .. 67 + state.psk_nonce_len]);
    const now = nowSeconds();
    if (now - issued_at > state.session_timeout_secs) return null;
    return state;
}

/// Build a TLS 1.3 NewSessionTicket handshake message body.
pub fn makeNewSessionTicket(
    buf: []u8,
    lifetime: u32,
    age_add: u32,
    nonce: []const u8,
    identity: []const u8,
) ![]const u8 {
    var w = record.Writer.init(buf);
    try w.handshakeRecordHeader(.new_session_ticket, 4 + 4 + 1 + nonce.len + 2 + identity.len);
    try w.int(u32, lifetime);
    try w.int(u32, age_add);
    try w.byte(@intCast(nonce.len));
    try w.slice(nonce);
    try w.int(u16, identity.len);
    try w.slice(identity);
    return w.buffered();
}

/// Called when a new session is established (Node `newSession` callback).
pub const NewSessionCallback = *const fn (
    ctx: ?*anyopaque,
    session_id: []const u8,
    session_data: []const u8,
) void;

/// Called when client offers a ticket (Node `resumeSession` callback).
pub const ResumeSessionCallback = *const fn (
    ctx: ?*anyopaque,
    session_id: []const u8,
    session_data: []const u8,
) bool;

/// Server-side session ticket manager.
pub const Manager = struct {
    keys: TicketKeys,
    key_ring: ?*TicketKeyRing = null,
    session_timeout_secs: u32 = 300,
    ticket_lifetime_secs: u32 = 7200,
    nonce_buf: [Aes128Gcm.nonce_length]u8 = undefined,
    last_enc_nonce: [Aes128Gcm.nonce_length]u8 = undefined,
    last_psk_nonce: [Aes128Gcm.nonce_length]u8 = undefined,
    nonce_counter: u64 = 0,
    new_session_cb: ?NewSessionCallback = null,
    resume_session_cb: ?ResumeSessionCallback = null,
    callback_ctx: ?*anyopaque = null,

    pub fn init(keys: TicketKeys) Manager {
        return .{ .keys = keys };
    }

    pub fn initKeyRing(key_ring: *TicketKeyRing) Manager {
        return .{ .keys = undefined, .key_ring = key_ring };
    }

    pub fn nextNonce(self: *Manager) []const u8 {
        self.nonce_counter +%= 1;
        @memset(&self.nonce_buf, 0);
        mem.writeInt(u64, self.nonce_buf[4..][0..8], self.nonce_counter, .big);
        return &self.nonce_buf;
    }

    pub fn issueTicket(
        self: *Manager,
        allocator: mem.Allocator,
        state_in: SessionState,
    ) !Ticket {
        @memcpy(&self.last_enc_nonce, self.nextNonce());
        @memcpy(&self.last_psk_nonce, self.nextNonce());
        var state = state_in;
        state.psk_nonce_len = Aes128Gcm.nonce_length;
        @memcpy(&state.psk_nonce, &self.last_psk_nonce);
        const active_keys = if (self.key_ring) |key_ring| key_ring.active() else self.keys;
        const identity = try encrypt(allocator, active_keys, state, &self.last_enc_nonce);
        const ticket: Ticket = .{
            .identity = identity,
            .lifetime = self.ticket_lifetime_secs,
            .age_add = rng.csprng.int(u32),
            .nonce = &self.last_psk_nonce,
            .state = state,
        };
        if (self.new_session_cb) |cb| {
            cb(self.callback_ctx, identity, identity);
        }
        return ticket;
    }

    pub fn resumeTicket(self: *Manager, identity: []const u8) ?SessionState {
        if (self.resume_session_cb) |cb| {
            if (!cb(self.callback_ctx, identity, identity)) return null;
        }
        if (self.key_ring) |key_ring| return key_ring.decryptTicket(identity);
        return decrypt(identity, self.keys);
    }
};

const testing = std.testing;

test "issueTicket separates encryption and PSK nonces" {
    const keys = TicketKeys.random();
    var mgr = Manager.init(keys);
    const state: SessionState = .{
        .tls_version = .tls_1_3,
        .cipher_suite = .AES_128_GCM_SHA256,
        .named_group = .x25519,
        .master_secret = @as([48]u8, @splat(0xAB)),
        .session_timeout_secs = 3600,
    };
    const ticket = try mgr.issueTicket(testing.allocator, state);
    defer testing.allocator.free(ticket.identity);
    try testing.expectEqual(Aes128Gcm.nonce_length, ticket.nonce.len);
    const enc_nonce_len = ticket.identity[16];
    const enc_nonce = ticket.identity[17 .. 17 + enc_nonce_len];
    try testing.expect(!mem.eql(u8, enc_nonce, ticket.nonce));
    const recovered = ticket.state.?;
    try testing.expectEqual(Aes128Gcm.nonce_length, recovered.psk_nonce_len);
    try testing.expectEqualSlices(u8, ticket.nonce, recovered.psk_nonce[0..recovered.psk_nonce_len]);
}

test "encrypt decrypt roundtrip" {
    const keys = TicketKeys.random();
    const state: SessionState = .{
        .tls_version = .tls_1_3,
        .cipher_suite = .AES_256_GCM_SHA384,
        .named_group = .x25519,
        .master_secret = @as([48]u8, @splat(42)),
        .session_timeout_secs = 3600,
    };
    const nonce = "123456789012";
    const identity = try encrypt(testing.allocator, keys, state, nonce);
    defer testing.allocator.free(identity);
    const recovered = decrypt(identity, keys).?;
    try testing.expectEqual(state.tls_version, recovered.tls_version);
    try testing.expectEqual(state.cipher_suite, recovered.cipher_suite);
    try testing.expect(mem.eql(u8, &state.master_secret, &recovered.master_secret));
}

test "ticket key ring resumes across rotation and retires bounded keys" {
    const first = TicketKeys.random();
    var ring = TicketKeyRing.init(first);
    var manager = Manager.initKeyRing(&ring);
    const state: SessionState = .{
        .tls_version = .tls_1_3,
        .cipher_suite = .AES_128_GCM_SHA256,
        .named_group = .x25519,
        .master_secret = @as([48]u8, @splat(0x5a)),
        .session_timeout_secs = 3600,
    };

    const old_ticket = try manager.issueTicket(testing.allocator, state);
    defer testing.allocator.free(old_ticket.identity);

    const second = TicketKeys.random();
    try ring.rotate(second);
    const new_ticket = try manager.issueTicket(testing.allocator, state);
    defer testing.allocator.free(new_ticket.identity);

    try testing.expect(manager.resumeTicket(old_ticket.identity) != null);
    try testing.expect(manager.resumeTicket(new_ticket.identity) != null);
    try testing.expectEqual(@as(usize, 2), ring.keyCount());
    try testing.expectError(error.DuplicateKeyName, ring.rotate(second));

    try ring.rotate(TicketKeys.random());
    try ring.rotate(TicketKeys.random());
    try ring.rotate(TicketKeys.random());
    try testing.expectEqual(@as(usize, TicketKeyRing.capacity), ring.keyCount());
    try testing.expect(!ring.containsKeyName(&first.name));
    try testing.expect(manager.resumeTicket(old_ticket.identity) == null);
    try testing.expect(manager.resumeTicket(new_ticket.identity) != null);
}
