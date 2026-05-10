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
  `min-os = 11.0` and reject installs on older macOS.
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

#### 2. System-wide LaunchAgent variant

Today's plist (per-user) lives at
`~/Library/LaunchAgents/touchid-agent.plist` and is loaded only for
the user who installs it. A pkg cannot run as a specific user during
install — it runs as root. The system-wide LaunchAgent pattern:

- Plist installed to `/Library/LaunchAgents/touchid-agent.plist`,
  owned `root:wheel`, mode 644.
- launchd loads it for *every* user who logs in.
- `SockPathName` uses launchd's `$HOME` substitution so each user
  gets their own socket: `$HOME/Library/Caches/touchid-agent/agent.sock`.
- The agent's keystore at `~/.touchid-agent/keys/` is per-user already,
  so each user gets independent keys with no further changes.

Pkg post-install script:
1. Drop the plist at `/Library/LaunchAgents/touchid-agent.plist`,
   `chown root:wheel`, `chmod 644`.
2. Do **not** `launchctl load` from postinstall. Let it activate on
   next user login. This avoids `launchctl bootstrap` complications
   when running as root over a target user session.
3. If a user-installed plist exists at
   `~/Library/LaunchAgents/touchid-agent.plist` for any user, leave
   it alone — log a warning. The system-wide plist takes effect for
   users who don't have a per-user one.

#### 3. `docs/deployment.md`

A one-page guide with three sections:

- **Individual** — `brew install ignaciojimenez/tap/touchid-agent`,
  then `touchid-agent -install-plist`. Already documented in README.
- **Team** — same as Individual plus a shared `~/.ssh/config` snippet
  for `IdentityAgent`.
- **Fleet** — download the `.pkg`, MDM importer commands for Munki
  and Jamf as concrete examples (e.g. `munkiimport
  touchid-agent-vX.Y.Z.pkg`).

This is the artifact that lets the maintainer pitch `touchid-agent`
internally without IT bouncing the conversation.

### Effort estimate

- CI pkg build: ~1 day. Mostly figuring out Developer ID Installer
  cert provisioning + notarytool args. Code is small.
- System-wide plist variant: ~half day. Mostly testing per-user `$HOME`
  resolution and confirming the agent picks up the right keystore
  directory under multiple-user scenarios.
- `docs/deployment.md`: ~2 hours.
- **Total: ~2 days of focused work.**

### Deferred (do later if there's actual demand)

- **Configuration profile (`.mobileconfig`)** to let IT pin
  `-audit-log`, `-peer-check`, `-rate-limit`, `-allowed-callers` via
  Managed Preferences. Without this, technical capability exists but
  not enforcement; SOC 2 reviewers will eventually flag that. Defer
  until a concrete pilot at the maintainer's company asks for it —
  config profiles need an MDM in the loop to test.
- **Audit-log shipper recipe** (`docs/audit-shipping.md`) with a
  Vector / FluentBit example reading
  `/var/log/touchid-agent/audit.log` → SIEM. Not code, just a recipe.
  Defer until the same pilot needs centralized logs.

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
Two paths, with a strong recommendation to keep both viable.

- **Build a reference registry.** A Cloudflare Worker + D1 is enough.
  Endpoints: `POST /enroll`, `POST /devices/<id>/keys`,
  `GET /keys?user=…`, `DELETE /keys/<fingerprint>`. ~200 LOC of
  TypeScript. Good for solo / homelab / proof-of-concept.
- **Integrate with whatever the company already has.** Most orgs
  have Okta, Workspace, or a homegrown access database. Writing the
  same enrollment payload to those systems is a per-company
  integration job.

**Recommendation.** Design the enroll API as a pluggable HTTP
webhook with bearer auth. Ship a reference Cloudflare Worker
implementation. Document the API contract precisely so IT can swap
in their own backend that speaks the same shape.

### Design decisions to make (with recommendations)

#### 1. Build a registry vs. integrate with existing systems

See above — pluggable webhook with reference impl. Don't pick one or
the other; design for both.

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
  attestation, env-var/config-file URL, reference Cloudflare Worker
  registry. Enough to demonstrate end-to-end and pilot at one team.
- **v2**: mTLS, App Attest, MDM-pushed config profile, GitHub
  Enterprise Org Keys API integration as a registry backend.

### Things explicitly NOT to build under Track #3

- A user-facing key-rotation prompt. Rotation is an org policy
  decision; the agent's job is to expose primitives, not to
  proactively rotate.
- Local user enrollment without a registry. If there's no registry,
  there's no enrollment — `touchid-agent -create` already does that.
- A web UI for the registry. CLI / API only in v1; UI is the IT
  team's problem if they want one.

---

## Open questions to revisit when starting Track #2 or #3

- Is there a concrete pilot inside the maintainer's company that
  would consume Track #2's pkg? If yes, prioritize the
  configuration-profile work that's currently deferred — the pilot
  will need it for SOC 2.
- Does the company already have an SSH key registry / inventory
  system? If yes, Track #3's "build a reference registry" piece is
  unnecessary; jump straight to defining the webhook API and writing
  the integration adapter.
- macOS version floor. Today: macOS 11+ (CryptoKit's `SecureEnclave.P256`).
  Track #2's `min-os` enforcement should match. App Attest in v2
  needs macOS 11+ already, so no new floor.
