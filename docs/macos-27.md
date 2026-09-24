# macOS 27 (Golden Gate) — hardening evaluation

Status: **proposal**, 2026-09-24. macOS 27 shipped 2026-09-14; 27.2 is in
public beta. Everything below marked *verified* was read from Apple's own
docs or WWDC26 session transcripts; anything else is flagged.

## What macOS 27 changes for this project

| Change | Source | Relevance |
|---|---|---|
| **App Attest on macOS** — `DCAppAttestService.isSupported` is now true on macOS 27+ (previously unsupported). | WWDC26 session 201 (*verified*) | **High.** First Apple-signed attestation available to a Mac process. Closes the gap in [THREAT_MODEL.md § Attestation](THREAT_MODEL.md#attestation). |
| **ACL Blob OID** (`1.2.840.113635.100.8.6`) in the App Attest leaf cert: proves the key's SEP policy required **SIP + Full Security** at attestation time. One constant value to compare; Apple says it never changes. | *Validating apps that connect to your server* (*verified*) | **High.** Remote proof of boot/OS integrity posture, not just "genuine Apple hardware". |
| **Launch validation category** in authenticator data — `6` = Developer ID, `3` = development, `10` = other. On macOS the RP ID is derived from the **code-signing requirement**, not a bundle ID. | Same doc (*verified*) | **High.** A verifier can reject re-signed or ad-hoc builds of the agent. |
| `launchd` refuses plists carrying the quarantine xattr. | macOS 27 release notes (*verified*) | Low. `-install-plist` writes fresh files (no xattr); a user hand-copying `contrib/plist/` out of a downloaded archive will get a silent load failure. Runbook note. |
| SIP denies access to other teams' app containers by default; XProtect may restrict access to "app data commonly targeted by malware". | Release notes (*verified*) | Low / watch. Keys are SEP-wrapped (useless off-device) and live outside any container. Needs a smoke test that nothing we touch (`~/.ssh/*.pub`, audit log) gets newly blocked. |
| MDM binary allow/deny lists via Endpoint Security; declarative app config with hardware-bound keys. | Jamf / vendor write-ups (*not verified against Apple* — Apple's `ManagedApp` docs still list iOS/iPadOS/visionOS only) | Medium, fleet docs only. Admins can allow `touchid-agent` by Team ID and deny unapproved SSH clients. |
| Enhanced Security / MIE / `arm64e.x1` (M5+/M6+). | Release notes, Xcode docs (*verified*) | **Not adopting.** Needs `hardened-process` entitlements (we ship none by design); Go emits `arm64`, not `arm64e`, and its heap isn't the system allocator, so tagging/PAC would cover only the small Swift shim. |
| SEP ML-DSA / ML-KEM. | CryptoKit docs — **macOS 26**, not 27 (*verified*) | Watch. OpenSSH has no ML-DSA user-auth key type yet; nothing an SSH server could verify. |

## The one honest limitation

App Attest does **not** attest arbitrary SEP keys. It creates its *own*
SEP key, bound to the calling app's code identity; its signatures use
WebAuthn-style authenticator data, not raw ECDSA, so an SSH server can't
consume them. There is still no `SecKeyCreateAttestation` on macOS.

So the attestation is **transitive**: Apple attests *"a genuine,
Developer-ID-signed touchid-agent (our Team ID) on genuine Apple
hardware with SIP + Full Security vouched for this SSH public key"*. The
SSH key's SEP residency follows because that exact binary can only create
SEP keys. That is materially stronger than today (nothing), but it trusts
the agent's code path — say so in the threat model rather than oversell.

## Proposal

### 1. Spike first — go/no-go (≈1 h, needs a macOS 27 Mac)

Unverified and blocking: can a **flat, entitlement-free, Developer-ID
Mach-O** (our shape) call App Attest, and does it work from a launchd
user agent? Apple's docs mention "Action and SSO extensions" as supported
extension types but say nothing explicit about CLI tools; the macOS RP-ID
and validation-category-6 wording suggests yes. If it needs an app bundle
+ provisioning profile, we'd have to revisit the flat-Mach-O decision —
that is its own call, not something to slip in.

### 2. Key attestation (if the spike passes) — v0.10.0

- `touchid-agent -attest LABEL -challenge B64` → JSON bundle on stdout:
  App Attest attestation object + key ID, SSH pubkey, touch policy,
  agent version, and an **SSH-key signature over the same challenge**
  (proof of possession). `clientDataHash = SHA-256(challenge ‖ pubkey ‖
  policy)` binds all of it.
- Post-create hook gains `TOUCHID_AGENT_ATTESTATION_FILE` when the
  hook/enroll flow supplies a challenge — this is Track #3 `enroll`
  step 3, not a parallel mechanism.
- Ship a small Go verifier package + `-verify-attestation` so a server
  can check: Apple App Attest root → leaf, nonce, **ACL blob constant**,
  RP ID = our Team ID requirement, category `6`, `aaguid` production,
  PoP signature. Verifier is what makes this real; without it the bundle
  is decoration.
- One App Attest key per agent install, stored alongside keyfiles by key
  ID (the service can't list them).

### 3. Signed audit checkpoints — v0.11.0

Periodically sign the audit-log hash-chain head with an App Attest
**assertion**. An off-host receiver then verifies the log came from a
genuine, un-re-signed agent instance on a SIP-on Mac — the missing half
of #19's tamper-resistance story.

### 4. Docs-only

- Threat model: new *Attestation* section (transitive, point-in-time —
  SIP could be disabled *after* attestation; assertions narrow that).
- Runbook: quarantined-plist failure mode.
- Fleet (Track #2 §4): binary allow-list by Team ID, once Apple's own
  docs confirm the macOS semantics.

### Compatibility: one binary, runtime-gated — not separate releases

- The `DCAppAttestService` symbols exist in SDKs since macOS 11, so the
  current CI (`macos-14`) can build it; gate calls with
  `if #available(macOS 27, *)` **and** `isSupported`. Deployment target
  stays macOS 11. One universal artefact for brew and `.pkg`.
- On macOS < 27 (or Intel Macs without a T2 — to verify in the spike)
  attestation is simply unavailable; everything else behaves as today.
- **Fail closed where policy asks for it:** a `require_attestation`
  Managed Preference makes `-create` refuse to produce a key it can't
  attest. Default off, so older fleets aren't broken.
- Separate release lines would double the release/notarization matrix
  for no security gain; the risk they'd guard against (a symbol missing
  at load time) is handled by weak-linking via `#available`.

## Not macOS 27, but worth doing alongside

`.biometryAny` → `.biometryCurrentSet` (opt-in `-bind-fingerprints`,
default for new keys in a later major). Today anyone who knows the login
password can enrol a new finger and satisfy Touch ID for existing keys;
`biometryCurrentSet` invalidates the key when the enrolled set changes.
Trade-off: re-enrolling a finger forces key re-creation + re-registration.
