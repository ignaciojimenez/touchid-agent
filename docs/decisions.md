# Decisions

One-line architecture and strategy calls, newest first.

- **2026-10-12** — The audit log stays tamper-*evident* locally; tamper-*resistance* comes from shipping it off-host ([audit-shipping.md](audit-shipping.md)). Forward-secure sealing (#19 Phase 2) is deferred, since shipping gives the same property more simply. The macOS unified log is rejected as an audit store: it is lossy, rate-limited diagnostics.
- **2026-10-02** — macOS runners pinned to `macos-26` (was `macos-14`, retired 2026-11-02 per [actions/runner-images#13518](https://github.com/actions/runner-images/issues/13518)). Skipped `macos-15`: next in line for retirement. Exact pin kept over `macos-latest` so toolchain and signing never change silently.
