# Distribution & deployment roadmap

This is a maintainer-facing planning document. It captures the larger
arc behind a series of changes that started with one user manually
rewriting their launchd plist after a `brew upgrade`. It exists so a
future session can pick up the in-flight tracks without re-doing the
discovery — read this end-to-end before starting Track #2 or #3.

For user-facing fleet deployment guidance see `docs/enterprise.md`
(which assumes the maintainer has already done Track #2's work).

## Why this exists

`touchid-agent` began as a personal tool. Adoption beyond a single
maintainer surfaced a gap that nobody planned for: **the upgrade
path**. v0.1.x → v0.2.0 changed the launchd model from
`-l PATH + RunAtLoad + KeepAlive` to socket activation. There was no
migration tooling — a user who ran `brew upgrade` was left with a
stale plist pointing at an obsolete invocation, with no guidance.

The maintainer hit this themselves on 2026-05-10. The manual fix took
a careful read of three doc pages, a hand-edited XML plist, two
launchctl invocations, and a `-status` verification — for a single
user who happened to also be the project author. Anyone else would
have given up.

That experience seeded a broader question: **if this tool is going to
deploy at the maintainer's company, what does the distribution and
deployment story need to look like?** Today's honest answer is "ask
everyone to `brew install`," which IT will veto.

This roadmap breaks the gap into three tracks of increasing scope.
Track #1 is done; #2 and #3 are sketched in enough detail to be picked
up cold.

## Tracks at a glance

| # | Track | Audience | Status |
|---|---|---|---|
| 1 | Self-healing brew/individual upgrade | Individuals via brew | **Done (v0.3.0)** |
| 2 | Signed `.pkg` for fleet deployment | IT pushing via MDM/Munki/Jamf | Not started |
| 3 | Org-scale enrollment + inventory | Org operating at scale | Discovery |

---

## Track #1 — Self-healing brew/individual upgrade — DONE

Shipped in v0.3.0. The brew upgrade story is now: `brew upgrade
touchid-agent` → `touchid-agent -migrate-plist`. Two commands, both
idempotent.

What landed:

- `touchid-agent -install-plist [-audit-log PATH] [-no-reload]` —
  fresh install: writes a socket-activation plist and loads it.
- `touchid-agent -migrate-plist [-dry-run] [-no-reload]` — upgrade in
  place; preserves `-audit-log`, `-peer-check`, `-rate-limit`,
  `-allowed-callers`, `-v`.
- `cmdStatus` warns when a stale `-l`-mode `touchid-agent` process is
  still running on the same socket.
- Brew formula caveats and `docs/launchd.md` updated to point at the
  new commands. The prior sed-and-edit migration recipe is gone.

Implementation in `plist_darwin.go`. Plist parsing via
`/usr/bin/plutil -convert json` (no new Go deps); rendering is a
deterministic XML template. Plist subcommands skip key store init
since they don't need it.

**Why a sibling subcommand instead of a brew `service do` block.**
Homebrew's service DSL only supports TCP/UDP socket activation —
`SOCKET_STRING_REGEX` in `Library/Homebrew/service.rb` rejects Unix
sockets. A `service do` block would force users back to KeepAlive +
`-l`, defeating the v0.2.0 socket-activation upgrade. The decision
was to keep socket activation and ship the install/upgrade tooling in
the binary itself.

References: touchid-agent#7 (v0.3.0 release); homebrew-tap caveats
sync merged directly to tap `main` on 2026-05-10.

---

## Track #2 — Signed `.pkg` for fleet deployment

### Goal

Produce a signed, notarized `.pkg` installer alongside each `vX.Y.Z`
release so MDM (Munki, Jamf, Mosyle, Kandji) can deploy `touchid-agent`
to a managed fleet without anyone running `brew`.

### Why brew is not enough

- `brew` is per-user, requires the user to manage taps and updates,
  and IT cannot pin/audit/rollback versions cleanly.
- IT tooling (Munki, Jamf, MDM) all expect a `.pkg`, not a brew tap.
- A `.pkg` is the difference between "ask everyone to install
  something" and "IT pushes it silently."

### Scope (recommended chunk to ship together)

#### 1. CI pkg build alongside the brew tarball

Extend `.github/workflows/release.yml` to also build, sign, notarize,
and upload a `.pkg` artifact on every `vX.Y.Z` tag. Steps:

- `pkgbuild` over a payload containing:
  - `usr/local/bin/touchid-agent` (the same notarized universal
    binary brew already ships)
  - `Library/LaunchAgents/touchid-agent.plist` (system-wide variant —
    see #2)
  - `Library/Application Support/touchid-agent/postinstall` (post-
    install script)
- `productbuild` to wrap it. Use a `distribution.xml` to enforce
  `min-os = 13.0` (Ventura) and reject installs on older macOS.
  macOS 11 / 12 no longer receive Apple security updates, so they
  are not a floor a security tool should support.
- `productsign` with the **Developer ID Installer** certificate.
  This is a *different cert* from the Developer ID Application cert
  the binary signing uses today (`docs/release.md` covers the
  Application cert). You'll need to provision the Installer cert
  separately at <https://developer.apple.com/account/resources/certificates>.
- `xcrun notarytool submit … --wait` (the existing `notarytool`
  credentials work for pkg notarization too)
- `xcrun stapler staple touchid-agent-vX.Y.Z.pkg`
- Upload `touchid-agent-vX.Y.Z.pkg` and `touchid-agent-vX.Y.Z.pkg.sha256`
  as release artifacts.

Everything new lives in `.github/workflows/release.yml` and a small
`scripts/build-pkg.sh`. No changes to the Go code.

#### 2. Per-user activation from a system-wide pkg

Today's plist (per-user) lives at
`~/Library/LaunchAgents/touchid-agent.plist` and is loaded only for
the user who installs it. A pkg cannot run as a specific user during
install — it runs as root.

**Constraint discovered 2026-05-10:** `launchd` does not perform any
variable substitution (`$HOME`, `~`, etc.) in plist string values —
confirmed against Apple's developer docs, TN2083, and `man 5
launchd.plist`. So a single `/Library/LaunchAgents/touchid-agent.plist`
with `$HOME/...` in `SockPathName` would create one shared socket at
the literal path, not per-user sockets. Per-user paths must be either
hardcoded per user or constructed at runtime.

**Adopted design — bootstrap LaunchAgent:**

- Pkg installs `/Library/LaunchAgents/touchid-agent-bootstrap.plist`,
  owned `root:wheel`, mode 644. This is a system-wide LaunchAgent
  with `LimitLoadToSessionType=Aqua` and `RunAtLoad=true`, so launchd
  runs it once per user GUI session.
- The bootstrap plist invokes a new `touchid-agent -ensure-user-plist`
  subcommand. That subcommand:
  - Resolves the running user's `$HOME` at runtime (the agent already
    knows how to do this).
  - If `~/Library/LaunchAgents/touchid-agent.plist` is already present
    and socket-activated, exits 0 immediately.
  - Otherwise runs the same logic as `-install-plist`, writing the
    per-user socket-activated plist into the user's `LaunchAgents`
    directory and loading it.
- The agent's keystore at `~/.touchid-agent/keys/` is per-user
  already, so each user gets independent keys.

Pkg postinstall script just drops the binary and the bootstrap plist.
It does **not** `launchctl load` anything — launchd picks up the
bootstrap plist on next session start.

This works for users that exist at install time *and* users created
later (their first GUI login activates the bootstrap). It also no-ops
cleanly on users who already installed via brew + `-install-plist`.

#### 3. Configuration profile (`.mobileconfig`)

A signed configuration profile that pins runtime flags via Managed
Preferences so IT can enforce policy across the fleet:

- Bundle ID `com.ignaciojimenez.touchid-agent` (matches the launchd
  label).
- Managed keys: `audit_log_path`, `peer_check`, `rate_limit`,
  `allowed_callers`. The agent reads these via
  `CFPreferencesCopyAppValue` and treats Managed values as overrides
  for any CLI flag of the same name.
- Signed with the **Developer ID Installer** cert (same one used for
  the `.pkg`).
- Shipped as a separate artifact (`touchid-agent-vX.Y.Z.mobileconfig`)
  alongside the `.pkg` so Munki can deploy it as a `configuration_profile`
  pkginfo type — no install order coupling with the binary pkg.

Without this, IT can deploy the agent but cannot enforce the security
flags that justify deploying it. SOC 2 reviewers will flag the gap.

#### 4. `docs/deployment.md`

A one-page guide with three sections:

- **Individual** — `brew install ignaciojimenez/tap/touchid-agent`,
  then `touchid-agent -install-plist`. Already documented in README.
- **Team** — same as Individual plus a shared `~/.ssh/config` snippet
  for `IdentityAgent`.
- **Fleet** — download the `.pkg` + `.mobileconfig`, with **Munki as
  the primary worked example** (`munkiimport touchid-agent-vX.Y.Z.pkg`,
  pkginfo for the configuration profile, recommended `installs` array
  for version detection). Jamf / Mosyle / Kandji as a "same idea,
  different tool" appendix.

This is the artifact that lets the maintainer pitch `touchid-agent`
internally without IT bouncing the conversation.

### Effort estimate

- CI pkg build: ~1 day. Mostly figuring out Developer ID Installer
  cert provisioning + notarytool args. Code is small.
- Bootstrap LaunchAgent + `-ensure-user-plist` subcommand: ~1 day.
  The subcommand is a thin wrapper around the existing
  `cmdInstallPlist`; the bootstrap plist is small. Most of the time
  goes to multi-user testing (existing brew users, fresh users,
  newly created users post-install).
- Configuration profile + Managed Preferences read path in the agent:
  ~1 day. Profile authoring is mechanical; the agent-side change is a
  small `CFPreferencesCopyAppValue` lookup that overrides flag values.
- `docs/deployment.md` (Munki-first): ~3 hours.
- **Total: ~3 days of focused work.**

### Deferred (do later if there's actual demand)

- **Audit-log shipper recipe** (`docs/audit-shipping.md`) with a
  Vector / FluentBit example reading
  `/var/log/touchid-agent/audit.log` → SIEM. Not code, just a recipe.
  Defer until the Munki pilot asks for centralized logs.

### Things explicitly NOT to build under Track #2

- A self-update mechanism. `brew` handles individual updates; MDM
  handles fleet updates. A homegrown self-updater is duplicative
  attack surface.
- A first-run wizard. The two `-install-plist` / `-migrate-plist`
  subcommands from Track #1 are already that wizard, in CLI form.
- Submission to homebrew-core. Their CI cannot sign with the
  maintainer's Developer ID, so the binary they build cannot access
  the SEP. The personal tap is the right home indefinitely.

---

## Track #3 — Org-scale enrollment + inventory

### Goal

Make `touchid-agent` solve the parts of corporate SSH key management
that hurt at scale: **onboarding, offboarding, rotation, attestation**.
Today these are all manual rituals. Track #3 turns them into one CLI
subcommand on the user side and one row in a registry on the IT side.

### Why this matters more than it looks

Even a well-deployed Track #2 fleet still has these holes:

- **Onboarding.** A new employee gets a managed Mac. They need an SSH
  key tied to their identity registered with GitHub Enterprise (or
  Bitbucket / Vault / etc.) so they can clone repos. Today: create
  key, copy pubkey, paste it somewhere, update `~/.ssh/config`.
  Manual every time.
- **Offboarding.** A person leaves. There is no central record of
  what keys were on their laptop. Hope they handed back the device.
  Hope they didn't email themselves the pubkey. There's no mechanism
  to revoke at the source.
- **Rotation.** Annual key rotation or response to a compromise has
  no orchestration — IT cannot answer "how many of our employees
  still hold pre-2025 keys?"
- **Attestation.** When SOC asks "did this signature come from a
  SEP-backed device on a managed laptop?" — there is no answer
  because no one tracks the mapping.

Track #3 closes all four with a small enrollment + inventory loop.

### User stories

```
As a new employee:
  I run `touchid-agent enroll` once and my SSH key is created and
  registered with the company's identity infrastructure. I do not
  paste pubkeys anywhere. ~5 seconds plus one TouchID prompt.

As IT:
  I have a registry showing every active touchid-agent key, mapped
  to (user, device, fingerprint, creation date, touch policy).
  Offboarding is "delete row → revoke at source."

As a security auditor:
  I can answer "did this signature come from a managed device?" by
  looking up the public key fingerprint in the registry.
```

### Components

#### `touchid-agent enroll`

CLI subcommand that:

1. Authenticates the user against an IdP (OAuth device-authorization
   flow — works in CLI without a browser pop-up dependency).
2. Creates a key (or reuses an existing labeled one).
3. Posts `{device_id, user_id, pubkey, label, key_attributes}` to a
   configurable registry URL using a bearer token.
4. Stores an enrollment receipt locally at
   `~/.touchid-agent/enrollment.json` for later inventory queries.

#### `touchid-agent inventory`

CLI subcommand that:

1. Reads the local keystore + enrollment receipts.
2. Posts the current state to the registry (`POST /devices/<id>/keys`
   with the full set, treated as authoritative for that device).
3. Designed to be run periodically — e.g. once a day via a launchd
   `StartInterval` plist, or on every `touchid-agent -create` /
   `-delete`.

#### Registry server (or contract)

The piece that gets hand-waved most: where do enrollment payloads go?

The maintainer's company already runs an LDAP-backed SSH keyserver,
and `contrib/hooks/custom-api-upload.sh` is the existing hook shape
(POST `{label, public_key}` with HTTP basic auth). That gives Track #3
a concrete target: the v1 deliverable is the **webhook contract +
LDAP-keyserver adapter**, not a greenfield registry.

Two paths, with a strong recommendation to keep both viable:

- **Integrate with the existing LDAP keyserver** (primary path). The
  hook in `contrib/hooks/` is the seed; the v1 enroll/inventory
  endpoints should be designed so that adapter is a thin wrapper.
- **Reference Cloudflare Worker registry** (exploration only). Useful
  as a public proof-of-concept for solo / homelab users who don't have
  an LDAP keyserver. Deprioritized — build only if there's a
  non-internal user who actually needs it.

**Recommendation.** Design the enroll API as a pluggable HTTP webhook
with bearer auth. Lock the contract against the LDAP keyserver
integration first; treat the Cloudflare Worker as optional reference.

### Design decisions to make (with recommendations)

#### 1. Build a registry vs. integrate with existing systems

See above — pluggable webhook, with the LDAP keyserver adapter as
the load-bearing v1 integration. Cloudflare Worker reference impl
is exploratory only.

#### 2. How does the agent find the registry URL

- Environment variables (`TOUCHID_AGENT_ENROLL_URL`,
  `TOUCHID_AGENT_BEARER_TOKEN_CMD`) for dev / CI.
- Config file at `~/.touchid-agent/config.json` for individual users
  who want to set it themselves.
- **A configuration profile pinned by MDM** (a Track #2 dependency)
  for managed devices — IT writes the URL once, every laptop gets it,
  user cannot change it.

**Recommendation.** Implement env vars + config file in v1. Document
how a config profile would override them, but that needs Track #2's
configuration profile work first.

#### 3. How does the agent prove who it is to the registry

- **v1: bearer token issued by IT** (manually rotated quarterly). The
  CLI fetches the token via a small shell command stored in config
  (`bearer_token_command: "security find-generic-password -s
  touchid-agent-enroll -w"`). Keeps the token out of files.
- **v2: device-bound mTLS using a SE-backed key.** Bootstrapped off
  the platform we're building. Cleaner, but more work.

**Recommendation.** Bearer for v1. mTLS as an optional v2 once the
shape of v1 is proven.

#### 4. Attestation — proving "this pubkey came from a real SEP"

- Apple's `DeviceCheck` / `App Attest` framework offers true device
  attestation. CryptoKit's `SecureEnclave` does not expose
  attestation directly.
- Self-attestation via signing the enrollment payload with the key
  being enrolled at least proves possession of the private key.
- True hardware attestation requires App Attest — significant scope.

**Recommendation.** v1 = self-attestation via enrollment payload
signature ("I own this private key"). v2 = App Attest if regulated
industries demand it.

#### 5. Privacy boundary — what the registry receives

- **Always:** pubkey, fingerprint, user identifier, creation
  timestamp, touch policy, label.
- **Optional, opt-in via flag:** device hostname / serial. Useful for
  inventory but controversial.
- **Never:** process trees, audit log content, any signing-time data.

**Recommendation.** Default to the conservative set. Hostname /
serial behind `--include-device-info`, off by default.

### API contract sketch (v1)

```http
POST /enroll
Authorization: Bearer <token>
Content-Type: application/json

{
  "device_id": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
  "user_id":   "alice@example.com",
  "key": {
    "label":           "ssh",
    "fingerprint":     "SHA256:…",
    "pubkey":          "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI…",
    "touch_required":  true,
    "created_at":      "2026-05-10T12:34:56Z"
  },
  "self_attestation":  "<signature of canonical payload by the key>"
}
→ 201 { "enrollment_id": "…" }
```

`POST /devices/<id>/keys` is the inventory endpoint — same key shape,
sent as a list, treated as the authoritative current state for that
device (registry deletes any keys not in the list).

### Effort estimate

- Agent CLI (`enroll`, `inventory`, config loading, OAuth device
  flow): ~1 week.
- Reference Cloudflare Worker registry (D1 schema, 4 endpoints, basic
  bearer auth): ~3 days.
- Documentation (`docs/enrollment.md`, API contract, integration
  guide for a custom backend): ~1 day.
- **v1 total: 1.5–2 weeks of focused work.**

mTLS + App Attest (v2) would roughly double that.

### v1 / v2 split

- **v1**: enroll subcommand, inventory subcommand, bearer auth, self-
  attestation, env-var/config-file URL, **LDAP-keyserver adapter**
  modeled on `contrib/hooks/custom-api-upload.sh`. Enough to
  demonstrate end-to-end and pilot at one team.
- **v2**: mTLS, App Attest, GitHub Enterprise Org Keys API
  integration as a second registry backend, optional Cloudflare
  Worker reference impl for non-internal users.

Note: the MDM-pushed config profile is no longer in v2 — it moved
into Track #2 once the Munki pilot was confirmed.

### Things explicitly NOT to build under Track #3

- A user-facing key-rotation prompt. Rotation is an org policy
  decision; the agent's job is to expose primitives, not to
  proactively rotate.
- Local user enrollment without a registry. If there's no registry,
  there's no enrollment — `touchid-agent -create` already does that.
- A web UI for the registry. CLI / API only in v1; UI is the IT
  team's problem if they want one.

---

## Resolved as of 2026-05-10

These were open when this roadmap was first written; the maintainer
answered them before Track #2 work started. Recorded here so future
sessions don't re-litigate.

- **Pilot at the maintainer's company: confirmed, distributing via
  Munki.** Configuration profile work is therefore in Track #2 scope,
  not deferred — see `#3 Configuration profile` above. `docs/deployment.md`
  uses Munki as the primary worked example.
- **Existing key registry: yes — an LDAP-backed SSH keyserver.** The
  hook in `contrib/hooks/custom-api-upload.sh` is the seed shape for
  the integration. Track #3's v1 deliverable is the webhook contract
  + LDAP adapter; the Cloudflare Worker reference registry is
  exploratory only.
- **macOS version floor: raise to macOS 13 (Ventura).** macOS 11 / 12
  no longer receive Apple security updates as of 2024 — keeping them
  as a floor for a security tool is self-contradictory. macOS 13 still
  covers any Mac Apple has shipped in roughly the last five years,
  which matches the pilot fleet's hardware profile. Applies to:
  - Track #2 `distribution.xml` `min-os = 13.0`
  - Brew formula `depends_on macos: ">= :ventura"`
  - Any new code that wants APIs newer than `SecureEnclave.P256`
