# Session-ticket key rotation

`session_ticket.TicketKeyRing` provides live bounded rotation for TLS 1.2 and
TLS 1.3 ticket encryption. The active key encrypts new tickets; the active key
and up to three previous keys decrypt resumptions.

Keep the ring at a stable address for the lifetime of every server option that
references it:

```zig
var ring = tls.session_ticket.TicketKeyRing.init(initial_keys);
const options: tls.config.Server = .{
    // certificate and protocol settings omitted
    .session_tickets = .{ .key_ring = &ring },
};

try ring.rotate(next_keys);
```

Rotation rejects duplicate 16-byte key names, securely clears material when a
key leaves the bounded ring, and requires no listener restart. Coordinate key
distribution externally for multi-node deployments and rotate no faster than
the desired resumption overlap. The ring is internally synchronized; copying a
ring after it is referenced is unsupported.
