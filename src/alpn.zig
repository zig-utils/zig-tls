const std = @import("std");
const mem = std.mem;
const record = @import("record.zig");

pub const Protocol = []const u8;
pub const ProtocolList = []const Protocol;

/// Select the first client protocol that appears in the server list (RFC 7301).
pub fn negotiate(client_protocols: ProtocolList, server_protocols: ProtocolList) ?Protocol {
    for (client_protocols) |client_proto| {
        for (server_protocols) |server_proto| {
            if (mem.eql(u8, client_proto, server_proto)) return client_proto;
        }
    }
    return null;
}

/// Per-connection ALPN picker (Node `ALPNCallback` semantics).
pub const Callback = *const fn (
    ctx: ?*anyopaque,
    server_name: []const u8,
    client_protocols: ProtocolList,
) ?Protocol;

pub fn negotiateWithCallback(
    callback: ?Callback,
    ctx: ?*anyopaque,
    server_name: []const u8,
    client_protocols: ProtocolList,
    server_protocols: ProtocolList,
) ?Protocol {
    if (callback) |cb| return cb(ctx, server_name, client_protocols);
    return negotiate(client_protocols, server_protocols);
}

/// Parse ALPN extension payload into caller-provided protocol pointer array.
/// Protocol name bytes are views into `payload`.
pub fn parseProtocolListFixed(
    payload: []const u8,
    out: []Protocol,
) ![]Protocol {
    if (payload.len < 2) return error.TlsDecodeError;
    const list_len = mem.readInt(u16, payload[0..2], .big);
    if (list_len + 2 > payload.len) return error.TlsDecodeError;

    var count: usize = 0;
    var idx: usize = 2;
    const end = 2 + list_len;
    while (idx < end) : (count += 1) {
        if (count >= out.len) return error.TlsDecodeError;
        const name_len = payload[idx];
        idx += 1;
        if (idx + name_len > end) return error.TlsDecodeError;
        out[count] = payload[idx .. idx + name_len];
        idx += name_len;
    }
    return out[0..count];
}

/// Parse ALPN extension payload into a slice of protocol name views.
pub fn parseProtocolList(allocator: mem.Allocator, payload: []const u8) ![]const Protocol {
    if (payload.len < 2) return error.TlsDecodeError;
    const list_len = mem.readInt(u16, payload[0..2], .big);
    if (list_len + 2 > payload.len) return error.TlsDecodeError;

    var protocols: std.ArrayListUnmanaged(Protocol) = .empty;
    errdefer protocols.deinit(allocator);

    var idx: usize = 2;
    const end = 2 + list_len;
    while (idx < end) {
        const name_len = payload[idx];
        idx += 1;
        if (idx + name_len > end) return error.TlsDecodeError;
        try protocols.append(allocator, payload[idx .. idx + name_len]);
        idx += name_len;
    }
    return try protocols.toOwnedSlice(allocator);
}

/// Write ALPN extension to a record Writer.
pub fn writeExtension(w: *record.Writer, protocols: ProtocolList) !void {
    if (protocols.len == 0) return;
    var list_len: usize = 0;
    for (protocols) |p| list_len += 1 + p.len;
    try w.enumValue(@import("protocol.zig").Extension.application_layer_protocol_negotiation);
    try w.int(u16, list_len + 2);
    try w.int(u16, list_len);
    for (protocols) |p| {
        if (p.len > 255) return error.TlsIllegalParameter;
        try w.byte(@intCast(p.len));
        try w.slice(p);
    }
}

/// Build encrypted_extensions body with optional ALPN selected protocol.
pub fn makeEncryptedExtensionsBody(buf: []u8, selected: ?Protocol) ![]const u8 {
    var w = record.Writer.init(buf);
    const ext_bytes: usize = if (selected) |p| 4 + 1 + p.len else 0;
    try w.int(u16, ext_bytes);
    if (selected) |p| {
        try w.enumValue(@import("protocol.zig").Extension.application_layer_protocol_negotiation);
        try w.int(u16, 1 + p.len);
        try w.byte(@intCast(p.len));
        try w.slice(p);
    }
    return w.buffered();
}

const testing = std.testing;

test "negotiate" {
    const client = [_]Protocol{ "h2", "http/1.1" };
    const server = [_]Protocol{ "http/1.1", "h2" };
    try testing.expectEqualStrings("h2", negotiate(&client, &server).?);
}

test "parseProtocolList" {
    const payload = [_]u8{ 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    const list = try parseProtocolList(testing.allocator, &payload);
    defer testing.allocator.free(list);
    try testing.expectEqual(2, list.len);
    try testing.expectEqualStrings("h2", list[0]);
    try testing.expectEqualStrings("http/1.1", list[1]);
}
