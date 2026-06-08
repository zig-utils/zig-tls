# Bun uSockets Adapter Specification

zig-tls exposes a thin C embedding API (`src/embed.zig`) designed to replace
BoringSSL in Bun's `node:tls` path behind a `BUN_ZIGTLS=1` flag.

## Architecture

```
node:tls (JS) → bun-usockets → zigtls.c shim → embed.zig exports
```

Bun-specific concerns (half-open sockets, TLSSocket lifecycle, OpenSSL error
string shapes) stay in `packages/bun-usockets/src/crypto/zigtls.c`.

## Required SSL API Mapping

| BoringSSL / OpenSSL | zig-tls embed export |
|---------------------|----------------------|
| `SSL_CTX_new` | `zigt_ctx_create` |
| `SSL_CTX_free` | `zigt_ctx_destroy` |
| `SSL_new` | `zigt_conn_create` |
| `SSL_free` | `zigt_conn_destroy` |
| `SSL_do_handshake` | `zigt_conn_do_handshake` |
| `SSL_read` / `SSL_write` | `zigt_conn_read` / `zigt_conn_write` (post-handshake) |
| `SSL_get_error` | Return value of `zigt_conn_do_handshake` |
| `SSL_set_alpn_protos` | `zigt_ctx_set_alpn_protos` |
| `SSL_CTX_set_cipher_list` | `zigt_ctx_set_cipher_list` |
| `SSL_CTX_set_session_ticket_keys` | `zigt_ctx_set_ticket_keys` |
| `SSL_CTX_set_keylog_callback` | via `key_log_callback` in Options |
| `SSL_get0_alpn_selected` | `zigt_conn_get_alpn` |

## Error Code Mapping

| embed `Error` | OpenSSL equivalent |
|---------------|-------------------|
| `want_read` (2) | `SSL_ERROR_WANT_READ` |
| `want_write` (3) | `SSL_ERROR_WANT_WRITE` |
| `zero_return` (6) | `SSL_ERROR_ZERO_RETURN` |
| `ssl` (1) | `SSL_ERROR_SSL` |

## Rollout

1. `BUN_ZIGTLS=1` — run `node:tls` test suite
2. Canary internal `fetch` / `tls.connect` traffic
3. Default-on after audit + parity tests pass
4. Keep BoringSSL for `node:crypto` until separate migration

## Memory

- Handshake state: ~19 KB per connection (`NonBlock` client)
- ML-KEM buffers: lazy-allocated only when PQ group negotiated
- Align with Bun's SHA-256 memoized `SSL_CTX` cache for cert contexts
