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

For production, sign with a Developer ID to embed the
`touchid-agent.entitlements` file, which grants the `keychain-access-groups`
entitlement required for Secure Enclave access and Touch ID enforcement on
software keys:

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
