# Migration Spec: Security.framework → CryptoKit (Path B)

**Status:** ready for implementation
**Audience:** an autonomous coding agent executing this migration end-to-end
**Owner:** project maintainer
**Estimated scope:** 1–2 focused sessions; ~400–600 net LOC change

---

## 1. Executive summary

`touchid-agent` currently creates Secure Enclave keys via Apple's
**Security.framework** (`SecKeyCreateRandomKey` with
`kSecAttrTokenIDSecureEnclave`) called from Objective-C through cgo. This API
inserts the key into the *data-protection keychain*, which on macOS 14
(Sonoma), 15 (Sequoia), and 26 (Tahoe) requires the binary to claim the
`keychain-access-groups` entitlement, which in turn requires an embedded
provisioning profile (per Apple TN3125, AMFI's restricted-entitlement list).
**A flat Mach-O has no supported location for `embedded.provisionprofile`** —
that location only exists inside `.app/Contents/`. Result: a Developer
ID-signed CLI binary cannot legally use this API path. Symptoms confirmed
empirically on macOS 26.4.1:

- With `keychain-access-groups: K7CDW3K37X.touchid-agent` entitlement: AMFI
  kills the binary at exec with `-413 "No matching profile found"`.
- Without the entitlement: `SecKeyCreateRandomKey` returns
  `errSecMissingEntitlement` (-34018) on the SE token.

**Resolution:** migrate Secure Enclave operations from Security.framework to
**CryptoKit's `SecureEnclave.P256.Signing.PrivateKey`** API. CryptoKit talks
to the Secure Enclave Processor directly; it does **not** insert anything
into the data-protection keychain, requires **no entitlements**, and
therefore needs **no provisioning profile**. The binary stays a flat
Mach-O signed with Developer ID + hardened runtime + secure timestamp,
notarization-ready, Homebrew-distributable.

Cryptographic guarantees are unchanged: same SEP, same non-extractable
private key, same Touch ID enforcement (`SecAccessControl` with
`.privateKeyUsage` + `.biometryAny`). Persistence moves from Keychain to
files in `~/.touchid-agent/keys/`. Each file holds the opaque
`dataRepresentation` blob (a SEP-wrapped token; the key material itself
never leaves the SEP) plus minimal metadata.

This is the same architectural choice as `remko/age-plugin-se` (the
recommended OSS Secure Enclave tool, endorsed in Filo Sottile's
awesome-age list). See `Documentation/Design.md` in that project for the
prior art.

---

## 2. Background and constraints

### 2.1 What we cannot do

- **Cannot embed a provisioning profile in a flat Mach-O.** The only
  supported location is `<app>.app/Contents/embedded.provisionprofile`.
  There is no equivalent for a single-file CLI executable.
- **Cannot claim `keychain-access-groups` without a profile.** AMFI hard-
  kills the binary at exec time. This is a SIGKILL before `main` runs;
  there is no recovery and no diagnostic beyond the AMFI log message.
- **Cannot wrap as `.app` bundle.** Considered and rejected. Reasons:
  ergonomically wrong for a CLI tool, awkward for Homebrew, ties releases
  to manual Apple Developer portal steps for App ID + profile, increases
  trust assertions the binary makes (more entitlements = more reviewer
  scrutiny, not less). Path A is documented for completeness in §11 but
  is not the chosen path.

### 2.2 What we do want

- **Flat single-file Mach-O**, Developer ID signed + hardened runtime +
  notarized. No entitlements. Distributable via Homebrew with a standard
  Go formula.
- **Same security properties as today.** Hardware-isolated keys, per-
  operation Touch ID, no key extractability, no iCloud sync.
- **Same external CLI surface** (`-create`, `-list`, `-delete`,
  `-delete-all`, `-no-touch`, `-software`, `-post-hook`, `-l`).
- **Test suite stays green** with the existing mock-store strategy.

### 2.3 Why CryptoKit

| Property | Security.framework (current) | CryptoKit (proposed) |
|---|---|---|
| SE key generation | `SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave` | `SecureEnclave.P256.Signing.PrivateKey(accessControl:)` |
| Goes through data-protection keychain | **Yes** → requires entitlement → requires profile | **No** → no entitlement, no profile |
| Persistence model | Keychain item (system-managed) | Opaque `Data` blob (we manage) |
| Touch ID enforcement | `SecAccessControl` flags on Keychain item | `SecAccessControl` flags on key creation |
| Key non-extractability | SEP hardware | SEP hardware (identical) |
| Language | Objective-C | Swift |
| Available since | macOS 10.12.1 | macOS 10.15 |

The two APIs hit the same SEP with identical cryptographic guarantees. The
difference is purely the persistence layer: Keychain-managed (which drags
in the entitlement requirement) vs. application-managed (which doesn't).

### 2.4 Reference: how `age-plugin-se` does it

[`remko/age-plugin-se`](https://github.com/remko/age-plugin-se) is the
canonical OSS Secure Enclave CLI tool for macOS. It ships unsigned/signed
Mach-O binaries via Homebrew core, no app bundle, no entitlements, no
profile. Its `Documentation/Design.md` explains the choice explicitly.
Read that document before starting; it is short and answers most "why
this and not that" questions.

---

## 3. Target architecture

### 3.1 File layout after migration

```
agent.go                       (unchanged behavior — depends only on KeyStore)
agent_test.go                  (unchanged)
agent_integration_test.go      (unchanged)
cli_test.go                    (unchanged)
hook.go                        (unchanged)
hook_test.go                   (unchanged)
notify_darwin.go               (unchanged)
notify_test.go                 (unchanged)
debug_test.go                  (unchanged)
keychain_errors_test.go        (DELETED — Keychain error classification no longer applies)
keystore.go                    (interface unchanged; impl moves to keystore_fs.go)
keystore_mock_test.go          (unchanged)
main.go                        (small changes: drop -software+touch combo)

secureenclave.swift            (NEW — replaces secureenclave.m + .h)
secureenclave_bridge.h         (NEW — minimal C header for cgo)
secureenclave_darwin.go        (REWRITTEN — thin cgo wrapper around Swift)
secureenclave_test.go          (REWRITTEN — drop tag tests; keep parseECPublicKey)

keystore_fs.go                 (NEW — file-based KeyStore implementation)
keystore_fs_test.go            (NEW — tests for file storage)

Makefile                       (updated — Swift build step, swiftc invocation)
THREAT_MODEL.md                (updated — replace the entitlement paragraph)
docs/architecture.md           (updated — new file inventory)
docs/building.md               (updated — Swift toolchain requirement)
docs/decisions.md              (CREATED if absent — log this decision)
docs/migration.md              (updated — re-create keys after upgrade)
CONTRIBUTING.md                (updated — Swift constraint, build step)
README.md                      (review — update if it references the SE backend)
```

Files to delete: `secureenclave.m`, `secureenclave.h`, `keychain_errors_test.go`.

### 3.2 Storage layout

```
~/.touchid-agent/                     (mode 0700)
└── keys/                             (mode 0700)
    ├── ssh.json                      (mode 0600)
    ├── git.json
    └── ...
```

Each `<label>.json` file:

```json
{
  "version": 1,
  "label": "ssh",
  "backend": "secure-enclave",
  "require_touch": true,
  "created_at": "2026-05-03T14:00:00Z",
  "key_data": "<base64-encoded SEP-wrapped blob>",
  "public_key": "<base64-encoded uncompressed EC point, 65 bytes>"
}
```

Field semantics:
- `version`: schema version (1 for now). Used to gate future changes.
- `label`: human-readable name. Must equal the filename minus `.json`.
- `backend`: `"secure-enclave"` or `"software"`. Determines which API
  the agent uses to load and sign.
- `require_touch`: whether biometry is required per signing operation.
- `created_at`: RFC3339 timestamp.
- `key_data`: for SE keys, the `dataRepresentation` of
  `SecureEnclave.P256.Signing.PrivateKey` (an opaque SEP-wrapped token,
  unusable on any other device or by any other user). For software keys,
  the raw 32-byte private key (`P256.Signing.PrivateKey.rawRepresentation`).
- `public_key`: cached uncompressed EC point (`0x04 || X || Y`, 65 bytes).
  Cached so `-list` doesn't need to load every key (which on SE keys
  requires the SEP and on biometry-gated keys would fire prompts).

### 3.3 Swift module surface (`secureenclave.swift`)

The Swift module exposes pure cryptographic primitives via `@_cdecl`. All
persistence stays in Go. The bridge is intentionally minimal — no Swift-
side state, no Swift-side filesystem access.

C-callable functions (declared in `secureenclave_bridge.h`, implemented in
`secureenclave.swift` with `@_cdecl`):

```c
// All functions return 0 on success, non-zero on error.
// On error, *error_out is set to a malloc'd UTF-8 string the caller must free.
// All output buffers (key_data_out, sig_out, pubkey_out) are malloc'd; caller frees.

// Generate a new SE-backed P-256 key.
// require_touch: 1 = .biometryAny enforced, 0 = no biometry
// Outputs: opaque SEP-wrapped blob and uncompressed EC public point (65 bytes).
int se_generate(
    int require_touch,
    uint8_t **key_data_out, size_t *key_data_len,
    uint8_t **pubkey_out,   size_t *pubkey_len,
    char **error_out
);

// Sign a 32-byte SHA-256 digest using a previously-generated SE key.
// key_data: the blob from se_generate (or a previously-persisted blob).
// digest_len must be 32.
// Outputs: DER-encoded ECDSA signature (X9.62).
int se_sign(
    const uint8_t *key_data, size_t key_data_len,
    const uint8_t *digest,   size_t digest_len,
    uint8_t **sig_out,       size_t *sig_len,
    char **error_out
);

// Recover the uncompressed EC public point (65 bytes) from a key blob.
// Used by `-list` only as a self-check — public_key is normally cached
// in the JSON file. May fire a Touch ID prompt for biometry-gated keys
// on some macOS versions; prefer the cached public_key when listing.
int se_public_key(
    const uint8_t *key_data, size_t key_data_len,
    uint8_t **pubkey_out,    size_t *pubkey_len,
    char **error_out
);

// Software P-256 key generation (no SE, no biometry — for testing and
// machines without a code signing identity).
// key_data_out is the 32-byte raw private scalar; pubkey_out is the
// uncompressed EC point.
int sw_generate(
    uint8_t **key_data_out, size_t *key_data_len,
    uint8_t **pubkey_out,   size_t *pubkey_len,
    char **error_out
);

// Sign with a software P-256 key.
int sw_sign(
    const uint8_t *key_data, size_t key_data_len,
    const uint8_t *digest,   size_t digest_len,
    uint8_t **sig_out,       size_t *sig_len,
    char **error_out
);
```

Swift implementation sketch (`secureenclave.swift`):

```swift
import Foundation
import CryptoKit
import LocalAuthentication
import Security

// MARK: - Helpers

private func writeBytes(_ data: Data, _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
                        _ outLen: UnsafeMutablePointer<Int>) {
    let count = data.count
    let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
    data.copyBytes(to: buf, count: count)
    outPtr.pointee = buf
    outLen.pointee = count
}

private func writeError(_ message: String, _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) {
    outPtr.pointee = strdup(message)
}

// MARK: - Secure Enclave

@_cdecl("se_generate")
public func se_generate(
    require_touch: Int32,
    key_data_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    key_data_len: UnsafeMutablePointer<Int>,
    pubkey_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    pubkey_len: UnsafeMutablePointer<Int>,
    error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if require_touch != 0 { flags.insert(.biometryAny) }
        var cfErr: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &cfErr
        ) else {
            let msg = (cfErr?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String? ?? "unknown" } ?? "SecAccessControlCreateWithFlags failed"
            writeError(msg, error_out); return -1
        }

        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let blob = key.dataRepresentation
        let pub = key.publicKey.x963Representation  // 0x04 || X || Y, 65 bytes

        writeBytes(blob, key_data_out, key_data_len)
        writeBytes(pub,  pubkey_out,   pubkey_len)
        return 0
    } catch {
        writeError("\(error)", error_out)
        return -1
    }
}

@_cdecl("se_sign")
public func se_sign(
    key_data: UnsafePointer<UInt8>, key_data_len: Int,
    digest:   UnsafePointer<UInt8>, digest_len:   Int,
    sig_out:  UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    sig_len:  UnsafeMutablePointer<Int>,
    error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        let blob = Data(bytes: key_data, count: key_data_len)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        let dig = Data(bytes: digest, count: digest_len)
        let sig = try key.signature(for: dig)              // input is pre-hashed digest
        writeBytes(sig.derRepresentation, sig_out, sig_len)
        return 0
    } catch {
        writeError("\(error)", error_out)
        return -1
    }
}

@_cdecl("se_public_key")
public func se_public_key(
    key_data: UnsafePointer<UInt8>, key_data_len: Int,
    pubkey_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    pubkey_len: UnsafeMutablePointer<Int>,
    error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        let blob = Data(bytes: key_data, count: key_data_len)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        writeBytes(key.publicKey.x963Representation, pubkey_out, pubkey_len)
        return 0
    } catch {
        writeError("\(error)", error_out)
        return -1
    }
}

// Software P-256 — analogous, using P256.Signing.PrivateKey.
// Implementations omitted for brevity; follow the same pattern.
```

Caveats the implementing agent must verify:

- `key.signature(for: digest)` accepts a `Data` representing a 32-byte
  SHA-256 digest. CryptoKit accepts `D: Digest` types or `D: DataProtocol`;
  for a pre-computed digest from the SSH agent layer, pass the raw 32 bytes
  as `Data`. **Confirm against current Apple docs** — the API may require
  wrapping in `SHA256Digest` via `unsafeBitCast` or accept `Data` directly
  via the `DataProtocol`-bound overload. Spike this in step 4.1 (§5.1).
- `signature.derRepresentation` produces the X9.62 DER ECDSA encoding
  expected by SSH. Verify byte-equivalence with current output before
  swapping in.

### 3.4 Cgo bridge (`secureenclave_darwin.go`)

Replace the current ~250-line file with a thin wrapper of ~150 lines.
Key shape:

```go
//go:build darwin

package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lsecureenclave -framework CryptoKit -framework LocalAuthentication -framework Security -framework CoreFoundation -framework Foundation
#include "secureenclave_bridge.h"
#include <stdlib.h>
*/
import "C"

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "fmt"
    "io"
    "math/big"
    "unsafe"
)

type Backend int

const (
    BackendSecureEnclave Backend = iota
    BackendSoftware
)

// PrivateKey is the in-memory representation of a key the agent has loaded.
// The underlying secret never leaves the SEP for SE keys.
type PrivateKey struct {
    Label        string
    Backend      Backend
    RequireTouch bool
    PublicKey    *ecdsa.PublicKey
    keyData      []byte // opaque blob; do not log
}

func (k *PrivateKey) Public() crypto.PublicKey { return k.PublicKey }

func (k *PrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
    if len(digest) != 32 {
        return nil, fmt.Errorf("digest must be 32 bytes (SHA-256), got %d", len(digest))
    }
    switch k.Backend {
    case BackendSecureEnclave:
        return cgoSign("se_sign", k.keyData, digest)
    case BackendSoftware:
        return cgoSign("sw_sign", k.keyData, digest)
    default:
        return nil, fmt.Errorf("unknown backend %d", k.Backend)
    }
}

// Generate, sign, public-key recovery: thin wrappers that translate
// Go []byte ↔ C buffers and propagate Swift error strings as Go errors.
// Implementation pattern matches the current secureenclave_darwin.go;
// the agent should preserve the same defensive C string handling.

func parseECPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
    // Unchanged — keep the existing implementation and tests.
}
```

The cgo helper should classify common errors into actionable messages,
similar to the current `classifyKeychainError`, but adapted for CryptoKit
errors. Notable patterns:
- `LAError.userCancel` / "User canceled" → "Touch ID prompt cancelled"
- `LAError.biometryNotAvailable` → "biometry unavailable on this device"
- `CryptoKitError` (generic) → wrap with the underlying message
- The misleading `errSecMissingEntitlement` (-34018) should not occur with
  CryptoKit; if it does, surface as-is — it likely means a regression.

### 3.5 KeyStore implementation (`keystore_fs.go`)

The `KeyStore` interface in `keystore.go` stays exactly as today:

```go
type KeyStore interface {
    List() ([]*SEKey, error)
    Generate(label string, requireTouch bool, useSE bool) (*SEKey, error)
    Delete(label string) error
    DeleteAll() error
}
```

A note on naming: the type is currently called `SEKey` and the receiver
methods reference SE specifically. Rename to `ManagedKey` (or keep
`SEKey` as a backward-compatible alias) — your call. The implementing
agent should pick one and apply it consistently. If unsure, **keep
`SEKey`** to minimize the diff; the type still represents an SE-backed
or software-backed key and the type name is internal.

The new `keystore_fs.go` implements `KeyStore` against the filesystem:

```go
type FilesystemKeyStore struct {
    Dir string // typically ~/.touchid-agent/keys
}

func DefaultKeyStore() (*FilesystemKeyStore, error) {
    home, err := os.UserHomeDir()
    if err != nil { return nil, err }
    dir := filepath.Join(home, ".touchid-agent", "keys")
    if err := os.MkdirAll(dir, 0o700); err != nil { return nil, err }
    // Defensive: enforce 0700 even if the dir pre-existed with looser perms.
    _ = os.Chmod(dir, 0o700)
    _ = os.Chmod(filepath.Dir(dir), 0o700)
    return &FilesystemKeyStore{Dir: dir}, nil
}

func (s *FilesystemKeyStore) Generate(label string, requireTouch bool, useSE bool) (*SEKey, error) {
    // 1. Validate label (already done by main.go's validateLabel; re-validate defensively).
    // 2. Refuse if <label>.json exists (mirrors current "key already exists" check).
    // 3. Call cgo se_generate or sw_generate.
    // 4. Marshal to keyfile struct, write to <Dir>/<label>.json with O_CREATE|O_EXCL, mode 0600.
    // 5. Construct and return *SEKey.
}

func (s *FilesystemKeyStore) List() ([]*SEKey, error) {
    // Read directory. For each *.json:
    //   - parse keyfile
    //   - decode cached public_key (no SEP call needed → no Touch ID prompts)
    //   - construct *SEKey
}

func (s *FilesystemKeyStore) Delete(label string) error {
    path := filepath.Join(s.Dir, label+".json")
    err := os.Remove(path)
    if errors.Is(err, fs.ErrNotExist) { return nil } // idempotent
    return err
}

func (s *FilesystemKeyStore) DeleteAll() error {
    // Read dir, remove every *.json. Do not remove the dir itself.
}
```

Wire into `main.go`:

```go
// in cmdRun and cmdCreate / cmdList / cmdDelete / cmdDeleteAll:
store, err := DefaultKeyStore()
if err != nil { log.Fatalf("init keystore: %v", err) }
// pass store into Agent or call store methods directly
```

This replaces every direct call to `GenerateSEKey`, `ListSEKeys`,
`DeleteSEKey`, `DeleteAllSEKeys` in `main.go` and `agent.go`. The agent
already accepts a `KeyStore` via `Agent.store`; just construct the
filesystem store instead of `&RealKeyStore{}` in `cmdRun`. The CLI
sub-commands in `main.go` should also go through the store rather than
the package-level functions, for consistency.

### 3.6 Decision: drop software-keys-with-Touch-ID

The current code supports four matrix cells: {SE, Software} × {Touch, no
Touch}. Software-with-Touch-ID required a Keychain item with biometry
ACL, which inherits the entitlement problem (different mechanism, same
restricted-entitlement family).

**Drop software+Touch-ID.** New matrix:

| Backend | Touch ID | Flag combination |
|---|---|---|
| Secure Enclave (default) | Yes | `-create NAME` (default) |
| Secure Enclave | No | `-create NAME -no-touch` |
| Software | No | `-create NAME -software` (Touch ID flag is ignored / rejected) |
| ~~Software + Touch ID~~ | ~~removed~~ | reject `-software` without `-no-touch` |

Rationale:
- Software keys are documented as "convenience, not hardware-grade
  security." Adding biometry to them would require a custom file-
  encryption-with-LAContext scheme (complex; questionable security gain
  since key material is on disk regardless).
- This shrinks the test matrix and the threat-model surface.
- Users who want Touch ID get SE-backed keys, which are strictly better
  in every dimension. Users who specifically need software keys are
  doing so because SE is unavailable (rare on supported hardware) or for
  testing without Developer ID.

**CLI behavior:** if the user passes `-software` without `-no-touch`,
print a clear error and exit non-zero:

```
error: -software requires -no-touch (Touch ID is not supported on
       software-backed keys; use the default -create for an SE key
       with Touch ID enforced by the Secure Enclave Processor).
```

Update shell completions (`contrib/completions/touchid-agent.{bash,zsh}`)
and `docs/building.md`'s feature matrix accordingly.

---

## 4. Build system

### 4.1 Toolchain prerequisites

- macOS 11+ (for CryptoKit `SecureEnclave.P256` API stability — it landed
  in 10.15 but had bugs through 10.15.x; 11+ is the safe floor)
- Xcode Command Line Tools (provides `swiftc`)
- Go 1.21+ (no change from current)

### 4.2 Makefile changes

Replace the current `build` and `clean` targets with:

```make
SWIFT_LIB        := libsecureenclave.a
SWIFT_MODULE     := SecureEnclaveBridge
SWIFT_SOURCES    := secureenclave.swift

# Build flags: optimize, static lib, target macOS 11+, deterministic.
SWIFT_FLAGS := -O -whole-module-optimization \
               -emit-library -static \
               -emit-module -module-name $(SWIFT_MODULE) \
               -parse-as-library \
               -target x86_64-apple-macos11

$(SWIFT_LIB): $(SWIFT_SOURCES)
	swiftc $(SWIFT_FLAGS) -o $(SWIFT_LIB) $(SWIFT_SOURCES)

build: $(SWIFT_LIB)
	go build -ldflags "-X main.Version=$(VERSION)" -o touchid-agent .

clean:
	rm -f touchid-agent \
	      $(SWIFT_LIB) \
	      $(SWIFT_MODULE).swiftmodule $(SWIFT_MODULE).swiftdoc \
	      $(SWIFT_MODULE).swiftsourceinfo $(SWIFT_MODULE).abi.json \
	      coverage.out coverage.html
```

**Universal binary follow-up:** the `-target x86_64-apple-macos11` line
above is single-arch. The current Go build is also single-arch (matches
host). Producing a universal binary (x86_64 + arm64) is a separate
concern, addressed in §10 (post-migration follow-ups). The migration
itself should match the host architecture, same as today.

The Go cgo block in `secureenclave_darwin.go`:

```go
/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lsecureenclave
#cgo LDFLAGS: -framework CryptoKit -framework LocalAuthentication
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework Foundation
#include "secureenclave_bridge.h"
*/
import "C"
```

Verify after first successful link that no Swift runtime libs need to be
explicitly linked. On macOS 10.14.4+ the Swift runtime is in `/usr/lib/swift/`
and resolves dynamically; the resulting binary should run on any macOS 11+
host without bundling Swift dylibs.

### 4.3 Sign target (no change)

The `sign` target stays as-is from the current Makefile:

```make
sign: build
ifeq ($(CODESIGN_IDENTITY),-)
	codesign -s "-" -f touchid-agent
else
	codesign -s "$(CODESIGN_IDENTITY)" --options runtime --timestamp -f touchid-agent
endif
```

No entitlements file. Hardened runtime + secure timestamp.

---

## 5. Implementation plan

Execute in this order. Each phase ends with a working state — the agent
should commit at each green milestone (subject to the user's commit
discipline; see §9 on commits).

### 5.1 Phase 1 — Swift spike (smallest viable proof)

Goal: prove that Go cgo can call into a Swift static library that uses
CryptoKit, on this machine, end-to-end.

1. Write a minimal `secureenclave.swift` exporting only `se_generate` and
   `se_public_key` (skip sign for now).
2. Write a minimal `secureenclave_bridge.h` with the two function
   declarations.
3. Update the Makefile to build `libsecureenclave.a`.
4. Update `secureenclave_darwin.go` to call only those two functions and
   print the resulting public key.
5. Replace `main.go`'s `cmdCreate` temporarily with a smoke-test path
   that calls `Generate` and prints the public key. (Stash the real
   logic; restore it in Phase 3.)
6. `make install CODESIGN_IDENTITY="..."` and run with `-create test`.
   Confirm: Touch ID prompt appears, key is created, public key prints,
   exit 0.
7. Run again. Confirm second key is independent (different public key).

**Gate:** Phase 1 is complete when a Touch ID prompt successfully
generates an SE-backed key from a flat Developer-ID-signed binary with
no entitlements. If this fails, **stop and surface the failure** —
Path B is unworkable on this version of macOS and Path A (§11) becomes
the fallback.

### 5.2 Phase 2 — Sign + round-trip

1. Add `se_sign` to `secureenclave.swift` and `_bridge.h`.
2. Add a sign() smoke path in Go: generate a key, sign a fixed 32-byte
   digest, verify the signature with `crypto/ecdsa.VerifyASN1` against
   the public key. This must succeed locally before continuing.
3. Test that the same blob can be loaded later (re-init from
   `dataRepresentation`) and produce a verifiable signature for a
   different digest. Confirms persistence round-trip works.

**Gate:** can generate, persist, reload, sign, and verify.

### 5.3 Phase 3 — File-backed KeyStore

1. Implement `keystore_fs.go` per §3.5.
2. Implement `keystore_fs_test.go`. Table-driven tests for: empty dir,
   single key, multiple keys, delete, delete-all, idempotent delete of
   missing key, refusal to overwrite existing key, parse errors on
   corrupt JSON. Use a temp dir per test (`t.TempDir()`).
3. Wire into `main.go`'s CLI command handlers and `agent.go`'s daemon path.
4. Restore `cmdCreate`'s real behavior (the post-hook flow, public key
   file writing, etc. — all unchanged from current `main.go`).

**Gate:** existing CLI behaviour reproduced. Manual test:
- `touchid-agent -create demo` → Touch ID, success message, file at
  `~/.touchid-agent/keys/demo.json` with mode 0600.
- `touchid-agent -list` → shows demo, no Touch ID prompt (uses cached
  public key).
- `touchid-agent -delete demo` → file removed.
- `touchid-agent -create demo -no-touch` → no Touch ID, key created.

### 5.4 Phase 4 — Software keys

1. Add `sw_generate` and `sw_sign` to Swift module.
2. Wire `-software -no-touch` through. Storage uses the same
   `keystore_fs` with `backend: "software"`.
3. Add validation: `-software` without `-no-touch` must error per §3.6.
4. Update CLI tests for the new error message.

**Gate:** ad-hoc-signed build can run `-software -no-touch` end-to-end,
including SSH-agent path.

### 5.5 Phase 5 — Full agent integration

1. Run the SSH agent: `touchid-agent -l /tmp/.touchid-agent.sock &`,
   `export SSH_AUTH_SOCK=/tmp/.touchid-agent.sock`, `ssh-add -L`.
   Confirm the public key is listed.
2. Set up a local test sshd or use a remote host you control. Add the
   agent's public key to `~/.ssh/authorized_keys`. Connect:
   `ssh -v <host>`. Confirm a Touch ID prompt appears for biometry-gated
   keys, no prompt for `-no-touch` keys, and the connection succeeds.
3. Test post-create hook: `-create test -post-hook 'echo $TOUCHID_AGENT_PUBKEY'`.

**Gate:** real-world SSH round-trip works against an actual sshd.

### 5.6 Phase 6 — Test suite + docs

1. Run `make test`. Fix any breakage in: `agent_test.go`,
   `agent_integration_test.go`, `cli_test.go`, `keystore_mock_test.go`.
   Most should not need changes — the mock store is independent of the
   real store implementation.
2. Delete `keychain_errors_test.go` and the `classifyKeychainError`
   function (replace its callers with simple `fmt.Errorf` wrapping; the
   CryptoKit error messages are already actionable).
3. Update `secureenclave_test.go`: drop `makeTag`/`parseTag` tests (the
   tag scheme goes away with Keychain). Keep `parseECPublicKey` tests.
4. Add new tests in `keystore_fs_test.go`.
5. Update documentation per §6.
6. Run `make test-cover` and confirm coverage is comparable (~current
   level or better; the migration removes some code, adds some, net
   should be near-neutral).

**Gate:** `make test` green, manual smoke pass, docs updated.

---

## 6. Documentation updates

### 6.1 `THREAT_MODEL.md`

The "Code signing posture" subsection (added during the prior
investigation) was written with incomplete information and contains an
overstatement. Replace it with this corrected version:

> ### Code signing and runtime entitlements
>
> Production builds are signed with Developer ID, hardened runtime
> (`--options runtime`), and a secure timestamp (`--timestamp`). The
> binary embeds **no entitlements** and contains no provisioning profile.
>
> Secure Enclave access is obtained via Apple's **CryptoKit**
> `SecureEnclave.P256.Signing.PrivateKey` API. Unlike the lower-level
> `SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave` path,
> CryptoKit talks to the SEP directly without inserting items into the
> data-protection keychain. This is what lets the binary ship as a flat
> Mach-O without a provisioning profile while still using the Secure
> Enclave for hardware-backed keys.
>
> Security-relevant consequences:
>
> - **Key non-extractability** is unchanged. The private key is generated
>   inside the SEP and never exposed in plaintext. The
>   `dataRepresentation` blob persisted to disk is a SEP-wrapped token
>   that is unusable without the same SEP on the same device.
> - **Touch ID enforcement** is unchanged. `SecAccessControl` flags
>   `.privateKeyUsage | .biometryAny` are applied at key-creation time
>   and enforced by the SEP at every signing operation.
> - **Persistence security** is now the responsibility of the
>   filesystem: key files are stored in `~/.touchid-agent/keys/` with
>   directory mode 0700 and file mode 0600. A user-level attacker who
>   reads a key file gets only the wrapped blob, which they cannot
>   unwrap on any device other than the originating Mac (and even on
>   that Mac, signing requires Touch ID for biometry-gated keys).

### 6.2 `docs/architecture.md`

Add a short "Why CryptoKit" subsection capturing the rationale (mirror
of §2.3 of this spec, condensed). The current `architecture.md`
references Security.framework directly — update those mentions to
CryptoKit and revise the file inventory.

### 6.3 `docs/building.md`

- Add Swift toolchain prerequisite (Xcode Command Line Tools / `swiftc`).
- Update the feature matrix:

  | Feature | Ad-hoc (`-`) | Developer ID |
  |---------|:------------:|:------------:|
  | Software key (`-software -no-touch`) | yes | yes |
  | Secure Enclave key, no Touch ID (`-no-touch`) | no | yes |
  | Secure Enclave key, Touch ID (default) | no | yes |

- Note that `make build` now invokes `swiftc` first, then `go build`.

### 6.4 `docs/migration.md`

Add a section for users upgrading from a pre-CryptoKit version:

```markdown
## Upgrading from versions prior to CryptoKit migration

The storage backend changed from the macOS Keychain to per-key JSON files
in `~/.touchid-agent/keys/`. Keys created before the upgrade remain in
the Keychain but are not visible to the new agent.

To migrate:

1. Note the labels of any keys you want to keep (`/usr/local/bin/touchid-agent
   -list` against the old binary).
2. Re-create each key after upgrading: `touchid-agent -create LABEL`. You
   will get a new public key; update any `authorized_keys` files,
   GitHub/GitLab/Bitbucket SSH key entries, etc.
3. Optional: delete the orphaned old Keychain items with the old binary
   before removing it.

Existing key blobs cannot be transferred between the two storage models
because they use different SE token formats. This is a one-time
re-creation.
```

### 6.5 `CONTRIBUTING.md`

- Update "Key constraints" to note Swift is required (in addition to Go and CGo).
- Update the architecture file list.
- Note the `swiftc` invocation that runs as part of `make build`.

### 6.6 `README.md`

Review for any references to "Security.framework" or "Objective-C" or
"Keychain-stored" — update if present. The README is intentionally
minimal; most likely no changes are needed beyond a possible mention
of the storage location (`~/.touchid-agent/keys/`) if it currently
mentions Keychain.

---

## 7. Test plan

### 7.1 Automated (CI-friendly)

`make test` runs all of these. None of them touch the real Keychain or SEP
— they use the mock `KeyStore`.

- `agent_test.go`, `agent_integration_test.go` — unchanged. Verify no
  regressions.
- `cli_test.go` — update expected error message for `-software` without
  `-no-touch`.
- `hook_test.go`, `notify_test.go`, `debug_test.go` — unchanged.
- `keystore_mock_test.go` — unchanged.
- `keystore_fs_test.go` — new. Table-driven tests for filesystem
  operations using `t.TempDir()`. Cover: create, list, delete, delete-all,
  permission enforcement (verify file mode is 0600 after creation),
  refuse-overwrite, empty-dir listing, malformed-JSON listing
  (skip with logged warning, not crash), idempotent delete.
- `secureenclave_test.go` — keep `parseECPublicKey` tests, drop tag
  tests.

### 7.2 Manual (requires hardware)

The implementing agent should run these and report back:

1. **SE key with Touch ID** — `touchid-agent -create m1`. Touch ID
   prompts. File created at `~/.touchid-agent/keys/m1.json`, mode 0600.
2. **SE key without Touch ID** — `touchid-agent -create m2 -no-touch`.
   No prompt.
3. **Software key** — `touchid-agent -create m3 -software -no-touch`.
   No prompt. Works on ad-hoc-signed builds.
4. **Software with Touch ID rejected** — `touchid-agent -create m4 -software`
   should error and exit non-zero.
5. **List with cached public keys** — `touchid-agent -list`. No Touch ID
   prompts (proves the cached `public_key` field is being used).
6. **Sign through SSH agent** — start the agent, set `SSH_AUTH_SOCK`,
   `ssh-add -L` (no Touch ID — listing only). Then SSH to a host with
   the key authorized: Touch ID prompts (m1), connection succeeds.
7. **Delete and delete-all** — `touchid-agent -delete m1`, then
   `touchid-agent -delete-all`. Files removed.
8. **Post-create hook** — `touchid-agent -create m5 -post-hook 'env | grep TOUCHID_AGENT'`.
   Hook runs, env vars present.

### 7.3 Performance / regression

- `-list` time with 0 keys: < 50ms (no SEP calls).
- `-list` time with 10 keys: < 100ms (still no SEP calls; cached public keys).
- `sign` latency: dominated by Touch ID prompt; software keys should be
  sub-10ms.

---

## 8. Risks and known sharp edges

### 8.1 CryptoKit signature input shape

`SecureEnclave.P256.Signing.PrivateKey.signature(for:)` has overloads for
both `Digest` types and arbitrary `DataProtocol`. The SSH agent layer
(`agent.go`) passes a pre-computed digest from
`golang.org/x/crypto/ssh`. Confirm in the spike (Phase 1) that:

- Passing the raw 32-byte digest as `Data` produces a valid X9.62
  ECDSA-SHA256 signature byte-equivalent to the current implementation.
- If CryptoKit insists on `SHA256Digest` (a fixed-size struct), adapt
  via `withUnsafeBytes` + `unsafeBitCast`, or compute the digest in
  Swift after passing the unhashed payload — choose whichever is
  cleaner. The current Go path passes the digest, not the payload, and
  changing that contract requires touching `agent.go`'s `Sign`
  invocation. **Prefer not to change the Go contract.**

### 8.2 Swift static linking on macOS

Static-linking Swift code that depends on the standard library has had
historical sharp edges (`-static-stdlib` interactions, missing symbols
on older toolchains). On modern Xcode (14+) with macOS 11+ deployment
target, the Swift standard library lives at `/usr/lib/swift/` and
resolves dynamically; `-static` on the lib means our Swift code is in
the static archive but still calls into the system Swift runtime.
This works in practice for projects like `age-plugin-se`. If linking
fails with undefined symbols on first attempt, check:

- `swiftc -emit-library -static` should emit `.a`, not `.o`. Confirm
  with `file libsecureenclave.a` (expect "current ar archive").
- Go cgo LDFLAGS must include both `-L.` and `-lsecureenclave`.
- All used frameworks are listed: `-framework CryptoKit -framework
  LocalAuthentication -framework Foundation -framework CoreFoundation
  -framework Security` (Security only if any compatibility shim
  references it).

### 8.3 Touch ID prompt coalescing

CryptoKit's prompts may behave differently from Security.framework's:

- Multiple rapid `signature(for:)` calls may each prompt, vs.
  Security.framework's tendency to coalesce within an `LAContext`. The
  agent layer already serializes signing via `Agent.mu`, so this should
  not be an issue, but verify in Phase 5 with a real SSH session.
- The notification message ("Waiting for Touch ID authentication...")
  in `notify_darwin.go` is timer-based, not Touch-ID-API-based. No
  changes needed.

### 8.4 Filesystem race conditions

`Generate` reads-then-writes (check-not-exists, then create). Use
`os.OpenFile(path, O_WRONLY|O_CREATE|O_EXCL, 0o600)` to make this
atomic. Do not use a check-then-create sequence with separate calls.

### 8.5 Universal binary for distribution

Homebrew users on Apple Silicon will need an arm64 build. The Makefile
sketch in §4.2 produces a single-arch binary. For a universal binary:

1. Build `libsecureenclave.a` for both `x86_64-apple-macos11` and
   `arm64-apple-macos11` separately.
2. `lipo -create -output libsecureenclave.a libse_x86_64.a libse_arm64.a`
3. Build the Go binary twice with `GOARCH=amd64` then `GOARCH=arm64`,
   each linking against the universal `.a`.
4. `lipo -create -output touchid-agent touchid-agent.amd64 touchid-agent.arm64`

This is a follow-up after the migration lands. Track in `TODO.md`. Do
not block the migration on it.

### 8.6 Existing keys are stranded

Per §6.5, keys created with the old code stay in the Keychain. The new
binary cannot see them. This is expected and documented. The user has
been informed in this conversation.

---

## 9. Commit discipline

Per project conventions (`CLAUDE.md` → user's global preferences):

- **No `--no-gpg-sign`** in commits. The user's `git commit` config
  already handles signing via Secure Enclave-backed SSH keys (Secretive
  + Touch ID). Honor that — do not add `--no-gpg-sign` to commit
  commands.
- **One feature branch.** Create `feat/cryptokit-migration` (or similar)
  off `main`. Land as a single PR when complete, or split by phase if
  the diff is unwieldy.
- **Commit at each phase gate.** Phase 1 commit: "Swift SE bridge spike."
  Phase 2: "SE round-trip via CryptoKit." Etc. Subject line ≤ 72 chars,
  body explains *why* not *what*.
- **Do not commit out-of-scope changes.** Only files listed in §3.1 plus
  test/docs files touched. If unrelated cleanup is tempting, defer to a
  separate PR.
- **Co-author trailer.** Per repo convention, use the standard
  `Co-Authored-By: Claude ...` trailer if running as a Claude Code
  agent. If running as a different agent, follow that agent's
  conventions.

---

## 10. Post-migration follow-ups (out of scope for this spec)

These are *not* part of the migration but should be tracked in `TODO.md`
once the migration lands:

1. **Notarization** — the binary is now notarization-ready. Set up
   `notarytool` invocation in a release script or GitHub Actions.
   Stapling not applicable to standalone Mach-O (only to bundles, DMGs,
   and PKGs); for a Homebrew bottle, ship the notarized binary inside a
   `.tar.gz` and let Homebrew unpack.
2. **Universal binary** — see §8.5.
3. **Homebrew formula** — TODO #3 from `TODO.md`. Standard Go formula
   plus a `post_install` codesign step is no longer needed once we ship
   a notarized signed binary; the formula just installs the bottle.
4. **Migration tool from old Keychain keys** — optional. A one-shot
   `touchid-agent -migrate-keychain` could read the old Keychain items
   via legacy code and write JSON files. Decision deferred; users have
   been told to re-create.

---

## 11. Path A (rejected) — for future reference only

If, during Phase 1, the implementing agent finds that CryptoKit's SE API
does not work on this version of macOS (e.g., a regression in macOS 27
or an undocumented restriction), Path A is the documented fallback. Do
not implement Path A speculatively — only if Path B is empirically
proven unworkable.

Path A in brief:

1. Register an explicit App ID in Apple Developer portal:
   `K7CDW3K37X.com.ignaciojimenez.touchid-agent`.
2. Generate a Developer ID provisioning profile authorizing
   `keychain-access-groups`, `application-identifier`,
   `team-identifier`. Download as `embedded.provisionprofile`.
3. Build app bundle structure:
   ```
   touchid-agent.app/Contents/
     Info.plist
     MacOS/touchid-agent
     embedded.provisionprofile
     _CodeSignature/
   ```
4. `codesign -s "Developer ID Application: ..." --options runtime
   --timestamp --entitlements ent.plist touchid-agent.app`
5. Notarize the `.app`, staple, ship.
6. Symlink `/usr/local/bin/touchid-agent` to
   `<install-prefix>/touchid-agent.app/Contents/MacOS/touchid-agent`.

Apple's reference doc:
[Signing a daemon with a restricted entitlement](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement).

The keychain-Storage code from before the migration would be reusable
under Path A; Phase 1 does not need to delete `secureenclave.{m,h}`
until Phase 1's success gate is met.

---

## 12. References

- [Apple Forums 728150 — -34018 when using Secure Enclave](https://developer.apple.com/forums/thread/728150)
- [Apple Forums 125510 — macOS CLI tool to interact with Secure Enclave](https://developer.apple.com/forums/thread/125510)
- [Apple Forums 745017 — codesign CLI tool with restricted entitlement](https://developer.apple.com/forums/thread/745017)
- [Apple Forums 129596 — Packaging a Daemon with a Provisioning Profile](https://developer.apple.com/forums/thread/129596)
- [Apple — Signing a daemon with a restricted entitlement](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement)
- [Apple TN3125 — Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
- [`remko/age-plugin-se` Design.md](https://github.com/remko/age-plugin-se/blob/main/Documentation/Design.md)
- [Apple — `SecureEnclave.P256.Signing.PrivateKey`](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
- [Apple — `SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)
- Original yubikey-agent (`FiloSottile/yubikey-agent`) — architectural
  prior art, but the YubiKey backend means it does not face this
  entitlement issue.
