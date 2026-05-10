# typed: false
# frozen_string_literal: true
#
# Homebrew formula for touchid-agent.
#
# This formula installs a pre-built, Developer-ID-signed and notarized
# binary published as a GitHub release artifact. It does NOT build from
# source: ad-hoc signed binaries cannot access the Secure Enclave on
# macOS, and Homebrew (whether on a user's machine or in the
# homebrew-core CI fleet) has no Developer ID identity to sign with.
# Distribution is therefore via a personal tap that vendors the
# already-notarized binary — same end-user experience as homebrew-core
# (`brew install touchid-agent`), just from a private tap.
#
# Maintainer release flow:
#   1. Push a `vX.Y.Z` tag; GitHub Actions builds, signs, notarizes,
#      and uploads the release artifacts.
#   2. Update `version`, `url`, and `sha256` below to match the new
#      release. The SHA-256 is in the published `.tar.gz.sha256` sidecar.
#   3. Open a PR against the tap repo.

class TouchidAgent < Formula
  desc "macOS SSH agent backed by the Secure Enclave and Touch ID"
  homepage "https://github.com/ignaciojimenez/touchid-agent"
  version "0.1.0"
  url "https://github.com/ignaciojimenez/touchid-agent/releases/download/v#{version}/touchid-agent-v#{version}-darwin-universal.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"

  depends_on :macos
  depends_on macos: :big_sur # CryptoKit's SecureEnclave.P256 requires macOS 11+.

  def install
    bin.install "touchid-agent"
    bash_completion.install "contrib/completions/touchid-agent.bash" => "touchid-agent"
    zsh_completion.install  "contrib/completions/touchid-agent.zsh"  => "_touchid-agent"
    pkgshare.install "contrib/plist/touchid-agent.plist"
    pkgshare.install "contrib/hooks"
    doc.install "README.md", "LICENSE"
  end

  def caveats
    socket = "#{Dir.home}/Library/Caches/touchid-agent/agent.sock"
    <<~EOS
      To use touchid-agent as your SSH agent, point SSH at the agent socket:

          # ~/.ssh/config
          Host *
              IdentityAgent #{socket}

      First-time install — write a launchd plist (socket activation) and load it:

          touchid-agent -install-plist

      Upgrading from a previous version with a hand-installed -l-mode plist?
      Rewrite it to socket activation in place (preserves -audit-log etc.):

          touchid-agent -migrate-plist

      Create your first key:

          touchid-agent -create ssh

      The Secure Enclave requires a Developer-ID-signed binary; this
      formula ships a notarized release built from the source repository.
    EOS
  end

  test do
    # `-version` does not touch the Secure Enclave, so it works in CI.
    assert_match "touchid-agent", shell_output("#{bin}/touchid-agent -version")
  end
end
