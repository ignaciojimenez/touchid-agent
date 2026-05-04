# Building

## Prerequisites

- macOS 11 or later (CryptoKit's `SecureEnclave.P256` API)
- Xcode Command Line Tools (provides `swiftc`)
- Go 1.21 or later

## Build variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CODESIGN_IDENTITY` | `-` (ad-hoc) | Code signing identity. Set to a Developer ID for production. |
| `PREFIX` | `/usr/local` | Install prefix for `make install`. |
| `VERSION` | `git describe` | Version string embedded in the binary. |

## Targets

```bash
make build          # compile libsecureenclave.a (Swift) then the Go binary
make sign           # build + code sign
make install        # build + sign + install to PREFIX/bin
make test           # run tests with race detector
make test-cover     # run tests with coverage report
make clean          # remove build artifacts
```

`make build` invokes `swiftc -emit-library -static` first to produce
`libsecureenclave.a`, then `go build` links against it via cgo. The
resulting binary is a flat Mach-O that depends on the system Swift
runtime at `/usr/lib/swift/` (no Swift dylibs need to be bundled).

## Code signing

Ad-hoc signing (the default) produces a binary suitable for development
and running tests. Secure Enclave key creation requires a Developer
ID-signed binary because the hardened runtime + secure timestamp
combination is what lets AMFI run the binary at all. **No entitlements**
are claimed; the SEP is reached via CryptoKit, which bypasses the
data-protection keychain entirely.

```bash
make install CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
```

List available signing identities:

```bash
security find-identity -v -p codesigning
```
