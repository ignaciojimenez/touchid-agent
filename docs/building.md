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

Ad-hoc signing (the default) produces a binary that supports software-
backed keys. This is sufficient for development and testing; software
keys do not require any Apple-issued identity.

Secure Enclave key creation requires a Developer ID-signed binary
because the hardened runtime + secure timestamp combination is what
lets AMFI run the binary at all. **No entitlements** are claimed; the
SEP is reached via CryptoKit, which bypasses the data-protection
keychain entirely.

```bash
make install CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
```

List available signing identities:

```bash
security find-identity -v -p codesigning
```

## Feature availability by signing mode

| Feature | Ad-hoc (`-`) | Developer ID |
|---------|:------------:|:------------:|
| Software key (`-software -no-touch`) | yes | yes |
| Secure Enclave key, no Touch ID (`-no-touch`) | no | yes |
| Secure Enclave key, Touch ID (default) | no | yes |

`-software` requires `-no-touch`. Software-backed keys with Touch ID
are not supported: enforcing biometry on a key whose private material
sits on disk would require a custom encryption-with-LAContext scheme
whose security gain is questionable. Users wanting biometry should use
the SE-backed default (which is strictly better than software+biometry
in every dimension).
