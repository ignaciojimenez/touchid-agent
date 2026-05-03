# Building

## Build variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CODESIGN_IDENTITY` | `-` (ad-hoc) | Code signing identity. Set to a Developer ID for production. |
| `PREFIX` | `/usr/local` | Install prefix for `make install`. |
| `VERSION` | `git describe` | Version string embedded in the binary. |

## Targets

```bash
make build          # compile the binary
make sign           # build + code sign
make install        # build + sign + install to PREFIX/bin
make test           # run tests with race detector
make test-cover     # run tests with coverage report
make clean          # remove build artifacts
```

## Code signing

Ad-hoc signing (the default) produces a binary that supports software-backed
keys without Touch ID. This is sufficient for development and testing.

Secure Enclave key creation requires a Developer ID-signed binary. The
current Security.framework-based implementation hits an AMFI restriction
on flat Mach-O CLI binaries: see
[`docs/cryptokit-migration.md`](cryptokit-migration.md) for the planned
move to CryptoKit, which restores SE access without the entitlement /
provisioning-profile dependency.

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
| Software key, no Touch ID (`-software -no-touch`) | yes | yes |
| Software key, Touch ID (`-software`) | no | yes |
| Secure Enclave key (default) | no | yes |
