# Enterprise deployment

Guide for distributing touchid-agent across a managed Mac fleet via
MDM (Munki, Jamf, Mosyle, or similar).

## Prerequisites

- **Developer ID signing is mandatory.** Ad-hoc signed binaries cannot
  access the Secure Enclave. Confirm your signing identity before
  anything else: `security find-identity -v -p codesigning`.
- macOS 11+ on all target machines.
- A key registration API or workflow to provision SSH public keys on
  servers (the setup script template calls one via curl).

## Build

```bash
make universal
make sign CODESIGN_IDENTITY="Developer ID Application: Your Org (TEAMID)"
make notarize NOTARY_PROFILE=your-profile   # recommended for Gatekeeper
```

See `docs/release.md` for notarization details.

## Package contents

| Path | Description |
|------|-------------|
| `/usr/local/bin/touchid-agent` | Signed universal binary |
| `/usr/local/bin/enterprise-touchid-setup` | Customized copy of `contrib/enterprise/setup.sh` |
| `/usr/local/bin/enterprise-touchid-reset` | Customized copy of `contrib/enterprise/reset.sh` |
| `/usr/local/share/touchid-agent/touchid-agent.plist` | Customized copy of `contrib/enterprise/touchid-agent.plist` |

Adjust install paths to match your organization's conventions.

## Customizing the templates

### Setup script (`contrib/enterprise/setup.sh`)

The setup script orchestrates the full provisioning flow: authenticate
user, create keys, register with your API, configure launchd. Edit the
configuration block at the top:

- `KEY_REGISTRATION_URL` / `APISERVER`: your key registration endpoint.
- `USERNAME` detection: adjust to your MDM's method (file, console user, etc.).
- `AUTH_ENDPOINT` / `REGISTER_ENDPOINT`: your identity and registration API paths.
- API payload format in step 6: match your registration API's expected schema.

### Enterprise plist (`contrib/enterprise/touchid-agent.plist`)

Pre-configured with `-peer-check` and `-audit-log`. Peer verification
restricts which binaries can use no-touch keys.
The audit log writes JSON-lines records per signing event.

Optional flags to add to `ProgramArguments`:

| Flag | Effect |
|------|--------|
| `-rate-limit 30` | Cap signing to 30 operations/min per key (ceiling: 120) |
| `-allowed-callers /path/to/list` | Extend the default caller allowlist with org-specific binaries |

### Reset script (`contrib/enterprise/reset.sh`)

Deletes all keys and re-runs setup. Update the `SETUP_SCRIPT` path to
match where your MDM installs the setup script.

## Deployment model

Two options:

**Self-service**: publish the package to your software catalog. Employees
install it and run the setup script themselves. Lower risk, slower adoption.

**Push binary, self-service setup**: push the package to all Macs silently.
Employees run the setup script when ready. The setup script requires
interactive authentication (password prompt, Touch ID for key self-test),
so it cannot run unattended as a postinstall hook.

Auto-provisioning (no employee interaction) is not recommended because:
- The ssh key self-test requires Touch ID confirmation.
- Authentication requires the employee's password.
- Skipping both weakens the security model (no biometric gate, no identity verification).

## Coexistence

touchid-agent coexists safely with yubikey-agent or any other SSH agent.
Different sockets, different key storage, zero shared state. Employees can
migrate at their own pace by switching `SSH_AUTH_SOCK`.

## Audit log format

When `-audit-log` is enabled, each signing event produces a JSON record:

```json
{"ts":"2025-05-06T12:00:00.000Z","event":"sign","label":"ssh","success":true,"peer_pid":1234,"peer_uid":501,"peer_path":"/usr/bin/ssh"}
```

Fields: `ts`, `event`, `label`, `success`, `error` (on failure),
`peer_pid`, `peer_uid`, `peer_path`.
