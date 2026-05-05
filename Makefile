PREFIX ?= /usr/local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# CODESIGN_IDENTITY controls code signing.
#
#   Ad-hoc (default, CODESIGN_IDENTITY=-):
#     Good for local development and testing.
#     NOTE: ad-hoc-signed binaries CANNOT access the Secure Enclave.
#
#   Developer ID (CODESIGN_IDENTITY="Developer ID Application: ..."):
#     Required for Secure Enclave + Touch ID.
#     Signed with hardened runtime + secure timestamp (notarization-ready).
#
# List available signing identities:
#   security find-identity -v -p codesigning
CODESIGN_IDENTITY ?= -

# Notarization is opt-in: provide either NOTARY_PROFILE (a keychain profile
# stored via `xcrun notarytool store-credentials`) or all three of
# APPLE_ID / APPLE_TEAM_ID / APPLE_PASSWORD. See docs/release.md.
NOTARY_PROFILE ?=

SWIFT_LIB     := libsecureenclave.a
SWIFT_MODULE  := SecureEnclaveBridge
SWIFT_SOURCES := secureenclave.swift

ARCH := $(shell uname -m)
ifeq ($(ARCH),arm64)
SWIFT_TARGET := arm64-apple-macos11
else
SWIFT_TARGET := x86_64-apple-macos11
endif

SWIFT_FLAGS := -O -whole-module-optimization \
               -emit-library -static \
               -emit-module -module-name $(SWIFT_MODULE) \
               -parse-as-library \
               -runtime-compatibility-version none \
               -target $(SWIFT_TARGET)

DIST_DIR     := dist
RELEASE_NAME := touchid-agent-$(VERSION)-darwin-universal
RELEASE_ZIP  := $(DIST_DIR)/$(RELEASE_NAME).zip
RELEASE_TGZ  := $(DIST_DIR)/$(RELEASE_NAME).tar.gz

.PHONY: build sign install install-completions install-launchd \
        universal package notarize release release-notes \
        clean clean-dist test test-cover vuln

$(SWIFT_LIB): $(SWIFT_SOURCES)
	swiftc $(SWIFT_FLAGS) -o $(SWIFT_LIB) $(SWIFT_SOURCES)

build: $(SWIFT_LIB)
	go build -ldflags "-X main.Version=$(VERSION)" -o touchid-agent .

sign: build
ifeq ($(CODESIGN_IDENTITY),-)
	codesign -s "-" -f touchid-agent
else
	codesign -s "$(CODESIGN_IDENTITY)" --options runtime --timestamp -f touchid-agent
endif

install: build sign
	install -d $(PREFIX)/bin
	install -m 755 touchid-agent $(PREFIX)/bin/touchid-agent

install-completions:
	install -d $(PREFIX)/etc/bash_completion.d
	install -m 644 contrib/completions/touchid-agent.bash $(PREFIX)/etc/bash_completion.d/touchid-agent
	install -d $(PREFIX)/share/zsh/site-functions
	install -m 644 contrib/completions/touchid-agent.zsh $(PREFIX)/share/zsh/site-functions/_touchid-agent

SOCKET_DIR  = $(HOME)/Library/Caches/touchid-agent
SOCKET_PATH = $(SOCKET_DIR)/agent.sock
PLIST_SRC   = contrib/plist/touchid-agent.plist
PLIST_DST   = $(HOME)/Library/LaunchAgents/touchid-agent.plist
BINARY_PATH = $(realpath touchid-agent)

install-launchd: build sign
	@if [ -z "$(BINARY_PATH)" ]; then echo "error: build touchid-agent first" >&2; exit 1; fi
	mkdir -p "$(SOCKET_DIR)"
	mkdir -p "$(HOME)/Library/LaunchAgents"
	mkdir -p "$(HOME)/Library/Logs"
	sed -e 's|__BINARY__|$(PREFIX)/bin/touchid-agent|g' \
	    -e 's|__HOME__|$(HOME)|g' \
	    $(PLIST_SRC) > $(PLIST_DST)
	@echo "Plist written to $(PLIST_DST)"
	@echo "Load with: launchctl load $(PLIST_DST)"
	@echo "Socket:    $(SOCKET_PATH)"

universal:
	swiftc $(subst $(SWIFT_TARGET),arm64-apple-macos11,$(SWIFT_FLAGS)) -o libsecureenclave-arm64.a $(SWIFT_SOURCES)
	swiftc $(subst $(SWIFT_TARGET),x86_64-apple-macos11,$(SWIFT_FLAGS)) -o libsecureenclave-x86_64.a $(SWIFT_SOURCES)
	lipo -create libsecureenclave-arm64.a libsecureenclave-x86_64.a -output $(SWIFT_LIB)
	CGO_ENABLED=1 GOARCH=arm64 go build -ldflags "-X main.Version=$(VERSION)" -o touchid-agent-arm64 .
	CGO_ENABLED=1 GOARCH=amd64 go build -ldflags "-X main.Version=$(VERSION)" -o touchid-agent-amd64 .
	lipo -create touchid-agent-arm64 touchid-agent-amd64 -output touchid-agent
	rm -f libsecureenclave-arm64.a libsecureenclave-x86_64.a touchid-agent-arm64 touchid-agent-amd64

# Package the (already built and signed) binary into a release archive.
# Run `make universal sign CODESIGN_IDENTITY="Developer ID Application: ..."` first.
# Produces:
#   - .zip with just the binary (submitted to Apple's notary service)
#   - .tar.gz with binary + completions + plist + hooks + LICENSE + README
#     (distributed to users; consumed by the Homebrew formula)
package:
	@if [ ! -f touchid-agent ]; then \
	  echo "error: touchid-agent binary not found; run 'make universal sign' first" >&2; \
	  exit 1; \
	fi
	@if codesign -dv touchid-agent 2>&1 | grep -q "adhoc"; then \
	  echo "error: binary is ad-hoc signed; notarization will reject it. Re-sign with Developer ID." >&2; \
	  exit 1; \
	fi
	rm -rf $(DIST_DIR)/$(RELEASE_NAME)
	mkdir -p $(DIST_DIR)/$(RELEASE_NAME)
	cp touchid-agent $(DIST_DIR)/$(RELEASE_NAME)/
	cp -R contrib    $(DIST_DIR)/$(RELEASE_NAME)/
	cp LICENSE README.md $(DIST_DIR)/$(RELEASE_NAME)/
	ditto -c -k --keepParent touchid-agent $(RELEASE_ZIP)
	tar -C $(DIST_DIR) -czf $(RELEASE_TGZ) $(RELEASE_NAME)
	cd $(DIST_DIR) && shasum -a 256 $(RELEASE_NAME).tar.gz > $(RELEASE_NAME).tar.gz.sha256
	cd $(DIST_DIR) && shasum -a 256 $(RELEASE_NAME).zip    > $(RELEASE_NAME).zip.sha256
	@echo
	@echo "Release artifacts:"
	@ls -lh $(DIST_DIR)/$(RELEASE_NAME).*
	@echo
	@echo "SHA-256 (tar.gz, for Homebrew formula):"
	@cat $(DIST_DIR)/$(RELEASE_NAME).tar.gz.sha256

# Submit the .zip to Apple's Notary service. Requires `make package` first
# and either NOTARY_PROFILE=<profile> or APPLE_ID + APPLE_TEAM_ID + APPLE_PASSWORD.
# Stapling is not supported for flat Mach-O CLI binaries; Gatekeeper checks
# the notarization ticket online on first launch.
notarize:
	@if [ ! -f $(RELEASE_ZIP) ]; then \
	  echo "error: $(RELEASE_ZIP) not found; run 'make package' first" >&2; \
	  exit 1; \
	fi
ifneq ($(NOTARY_PROFILE),)
	xcrun notarytool submit $(RELEASE_ZIP) \
	  --keychain-profile "$(NOTARY_PROFILE)" \
	  --wait
else
	@if [ -z "$(APPLE_ID)" ] || [ -z "$(APPLE_TEAM_ID)" ] || [ -z "$(APPLE_PASSWORD)" ]; then \
	  echo "error: set NOTARY_PROFILE=<keychain-profile> or APPLE_ID, APPLE_TEAM_ID, APPLE_PASSWORD" >&2; \
	  exit 1; \
	fi
	xcrun notarytool submit $(RELEASE_ZIP) \
	  --apple-id "$(APPLE_ID)" \
	  --team-id "$(APPLE_TEAM_ID)" \
	  --password "$(APPLE_PASSWORD)" \
	  --wait
endif
	@echo
	@echo "Notarization complete. The .tar.gz at $(RELEASE_TGZ) is ready to publish."
	@echo "Note: flat Mach-O cannot be stapled; Gatekeeper validates online on first launch."

# End-to-end release pipeline: build universal, sign, package, notarize.
# Requires CODESIGN_IDENTITY and notarization credentials.
release: clean-dist universal sign package notarize

# Render a release-notes draft to stdout from git log since the previous tag.
release-notes:
	@./scripts/release-notes.sh $(VERSION)

test: $(SWIFT_LIB)
	go test -v -race -count=1 ./...

test-cover: $(SWIFT_LIB)
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Scan for known-vulnerable dependencies. Mirrors what CI runs.
vuln:
	@GOBIN="$$(go env GOPATH)/bin"; \
	if [ ! -x "$$GOBIN/govulncheck" ]; then \
	  go install golang.org/x/vuln/cmd/govulncheck@v1.1.4; \
	fi; \
	"$$GOBIN/govulncheck" ./...

clean-dist:
	rm -rf $(DIST_DIR)

clean: clean-dist
	rm -f touchid-agent \
	      $(SWIFT_LIB) \
	      $(SWIFT_MODULE).swiftmodule $(SWIFT_MODULE).swiftdoc \
	      $(SWIFT_MODULE).swiftsourceinfo $(SWIFT_MODULE).abi.json \
	      coverage.out coverage.html
