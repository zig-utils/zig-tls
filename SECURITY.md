# Security Policy

## Reporting a Vulnerability

Report security issues privately to the maintainers via GitHub Security Advisories
or email. Do not open public issues for undisclosed vulnerabilities.

We aim to acknowledge reports within 48 hours and provide a fix or mitigation
timeline within 7 days for critical issues.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Security Properties

zig-tls is a Zig TLS 1.2/1.3 implementation with:

- No C code in the TLS protocol core; optional vendored AES-GCM assembly on AArch64/x86_64 (Apache 2.0, see `src/crypto/*/NOTICE`)
- 0-RTT early data disabled by default (`Server.max_early_data_size = 0`); enable explicitly when needed
- Bounded record buffers (max 16 KiB cleartext per RFC 8446)
- Constant-time RSA decryption paths (see `src/rsa/rsa.zig`)
- No TLS renegotiation (aligned with BoringSSL policy)
- Fuzz targets for record and handshake parsers (`zig build -Dfuzz=true fuzz`)

## Audit Preparation

Before production deployment (e.g. Bun `node:tls` default-on):

1. Third-party cryptographic audit (Trail of Bits / NCC recommended)
2. Continuous fuzzing via OSS-Fuzz
3. testssl.sh interop grade A+ on default server configuration
4. Full `node:tls` compatibility test suite with `BUN_ZIGTLS=1`

See [docs/AUDIT_PREP.md](docs/AUDIT_PREP.md) for the audit checklist.

## Disclosure

Security advisories are published on GitHub with CVE assignment when applicable.
Patches are released as semver patch versions with conventional commit messages.
