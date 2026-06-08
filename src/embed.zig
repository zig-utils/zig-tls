//! C-compatible embedding API for Bun uSockets integration.
const std = @import("std");
const tls = @import("root.zig");

pub const Error = enum(c_int) {
    ok = 0,
    ssl = 1,
    want_read = 2,
    want_write = 3,
    syscall = 5,
    zero_return = 6,
};

pub const Mode = enum(c_int) {
    client = 0,
    server = 1,
};

pub const Context = struct {
    mode: Mode,
    client_opt: tls.config.Client,
    server_opt: tls.config.Server,
    allocator: std.mem.Allocator,
    cipher_list_owned: ?[]tls.config.CipherSuite = null,
};

pub const Connection = struct {
    ctx: *Context,
    client: ?tls.nonblock.Client = null,
    server: ?tls.nonblock.Server = null,
    conn: ?tls.nonblock.Connection = null,
    handshake_done: bool = false,
    alpn_protocol: ?[]const u8 = null,
    last_error: ?anyerror = null,
    send_len: usize = 0,
};

export fn zigt_ctx_create(mode: Mode) ?*Context {
    const alloc = std.heap.c_allocator;
    const ctx = alloc.create(Context) catch return null;
    ctx.* = .{
        .mode = mode,
        .client_opt = .{
            .host = "",
            .root_ca = .empty,
            .insecure_skip_verify = true,
        },
        .server_opt = .{ .auth = null },
        .allocator = alloc,
        .cipher_list_owned = null,
    };
    return ctx;
}

export fn zigt_ctx_destroy(ctx: ?*Context) void {
    if (ctx) |c| {
        if (c.cipher_list_owned) |list| c.allocator.free(list);
        c.allocator.destroy(c);
    }
}

export fn zigt_ctx_set_host(ctx: ?*Context, host: [*:0]const u8) void {
    if (ctx) |c| c.client_opt.host = std.mem.span(host);
}

export fn zigt_ctx_set_post_quantum(ctx: ?*Context, enabled: bool) void {
    if (ctx) |c| c.server_opt.enable_post_quantum = enabled;
}

export fn zigt_ctx_set_ticket_keys(ctx: ?*Context, keys: *const [48]u8) void {
    if (ctx) |c| {
        c.server_opt.session_tickets = .{
            .keys = tls.config.session_ticket.TicketKeys.fromBytes(keys),
        };
    }
}

export fn zigt_conn_create(ctx: ?*Context) ?*Connection {
    if (ctx) |c| {
        const conn = c.allocator.create(Connection) catch return null;
        conn.* = .{
            .ctx = c,
        };
        switch (c.mode) {
            .client => conn.client = tls.nonblock.Client.init(c.client_opt),
            .server => conn.server = tls.nonblock.Server.init(c.server_opt),
        }
        return conn;
    }
    return null;
}

export fn zigt_conn_destroy(conn: ?*Connection) void {
    if (conn) |c| c.ctx.allocator.destroy(c);
}

export fn zigt_conn_handshake_done(conn: ?*Connection) bool {
    if (conn) |c| return c.handshake_done;
    return false;
}

export fn zigt_conn_get_alpn(conn: ?*Connection) ?[*:0]const u8 {
    if (conn) |c| {
        if (c.alpn_protocol) |p| return @ptrCast(p.ptr);
    }
    return null;
}

export fn zigt_conn_do_handshake(
    conn: ?*Connection,
    recv_data: [*]const u8,
    recv_len: usize,
    send_buf: [*]u8,
    send_buf_len: usize,
) Error {
    if (conn) |c| {
        const data = recv_data[0..recv_len];
        const out = send_buf[0..send_buf_len];

        if (c.client) |*cli| {
            const result = cli.run(data, out) catch |err| {
                c.last_error = err;
                return mapError(err);
            };
            c.send_len = result.send_pos;
            if (cli.done()) {
                c.handshake_done = true;
                c.conn = tls.nonblock.Connection.init(cli.cipher().?);
                c.alpn_protocol = cli.selectedAlpn();
            }
        } else if (c.server) |*srv| {
            const result = srv.run(data, out) catch |err| {
                c.last_error = err;
                return mapError(err);
            };
            c.send_len = result.send_pos;
            if (srv.done()) {
                c.handshake_done = true;
                c.conn = tls.nonblock.Connection.init(srv.cipher().?);
                c.alpn_protocol = srv.selectedAlpn();
            }
        } else return .ssl;

        return .ok;
    }
    return .ssl;
}

export fn zigt_conn_get_send_len(conn: ?*Connection) usize {
    if (conn) |c| return c.send_len;
    return 0;
}

fn mapError(err: anyerror) Error {
    return switch (err) {
        error.EndOfStream, error.InputBufferUndersize => .want_read,
        error.OutputBufferUndersize => .want_write,
        else => .ssl,
    };
}
