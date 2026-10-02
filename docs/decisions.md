# Decisions

One-line architecture and strategy calls, newest first.

- **2026-10-02** — macOS runners pinned to `macos-26` (was `macos-14`, retired 2026-11-02 per [actions/runner-images#13518](https://github.com/actions/runner-images/issues/13518)). Skipped `macos-15`: next in line for retirement. Exact pin kept over `macos-latest` so toolchain and signing never change silently.
