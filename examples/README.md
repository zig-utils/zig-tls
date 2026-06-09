# Examples

Full client and server patterns live in the repository [README](../README.md).

## Quick reference

| Goal | API |
|------|-----|
| Blocking client | `tls.clientFromStream(stream, .{ .host, .root_ca })` |
| Blocking server | `tls.serverFromStream(stream, .{ .auth = &cert_key })` |
| Non-blocking handshake | `tls.nonblock.Client` / `tls.nonblock.Server` + `run()` pump |
| Post-handshake I/O | `tls.Connection` or `tls.nonblock.Connection` |
| OCSP stapling (server) | `Server.ocsp_response = ocsp_der_bytes` |
| Session resumption | `Client.session_resumption` + `SessionResumption` |
| Bun embed | `src/embed.zig` C API |

## Local interop check

```bash
zig build test   # includes in-memory interop + OCSP staple tests
./scripts/testssl.sh localhost 8443   # against a deployed server
```

Bench credentials for local experiments: `bench/certs.zig`.
