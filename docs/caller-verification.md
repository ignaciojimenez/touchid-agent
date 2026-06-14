# Caller verification

touchid-agent verifies which process is asking it to sign. This is on by
default; the security rationale is in [THREAT_MODEL.md](THREAT_MODEL.md) —
this page is the how-to.

## Default

Out of the box, only genuine Apple OS SSH tools may use the agent: a caller
must validate against `anchor apple` **and** have a Signing ID of
`com.apple.ssh`, `com.apple.scp`, `com.apple.sftp`, or `com.apple.ssh-keygen`
(git commit/tag signing connects as `ssh-keygen`). Identity is resolved
race-free from the connection's audit token, not the PID. Nothing else is
allowed unless you add a rule.

Disable verification entirely (not recommended) with `-no-peer-check`.

## Adding callers

Point `-allowed-callers` at a file of rules, one per line:

```
team-id:ABCDE12345          # any binary signed by this Apple Developer Team ID
signing-id:org.example.ssh  # a specific code signing identifier
cdhash:9f86d081…            # one exact binary, by code directory hash
path:/opt/homebrew/bin/ssh  # by path (escape hatch for unsigned/ad-hoc binaries)
```

- `team-id:` and `signing-id:` are honored **only** for Apple-anchored
  signatures, so a self-signed binary cannot claim them. A Team ID rule is
  the best way to allow in-house or vendor tooling — it survives version
  updates. (`/opt/homebrew/bin/ssh` is usually ad-hoc-signed with no Team
  ID; allow it by `cdhash:` or `path:`.)
- `cdhash:` pins one exact build (changes on every upgrade).
- `path:` works for unsigned/ad-hoc callers but a user-writable path can be
  replaced, so the agent logs a warning when path rules are configured.

**Anchor the rules file above the caller's privilege.** A rule only resists
tampering if the binary it authorizes cannot rewrite it — use a root-owned
path (e.g. `/etc/touchid-agent/allowed-callers`, `root:wheel` `0644`) or
deliver it through a Managed Preferences / MDM profile. See
[`contrib/allowed-callers.example`](../contrib/allowed-callers.example).

## Finding a binary's identity

```bash
codesign -dv --verbose=4 /path/to/binary 2>&1 | grep -E 'Identifier|TeamIdentifier'
codesign --verify -R='anchor apple' /path/to/binary   # is it a genuine Apple OS binary?
```

## Extra hardening

- **`-require-hardened-callers`** — additionally require callers to run with
  the hardened runtime, so a same-UID process cannot inject into them
  without root. The Apple SSH tools are already hardened.
- **Per-key binding** — restrict a single key to specific callers at
  creation: `touchid-agent -create git-signing -key-callers
  signing-id:com.apple.ssh-keygen`. A caller must then satisfy both the
  global policy and the key's own rules.

## Fleet deployment

The same flags map to Managed Preferences keys (`peer_check`,
`allowed_callers`, `require_hardened_callers`) in the shipped
`.mobileconfig`, so the policy can be pinned fleet-wide via MDM.
