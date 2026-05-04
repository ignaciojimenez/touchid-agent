PREFIX ?= /usr/local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# CODESIGN_IDENTITY controls code signing and determines feature availability.
#
#   Ad-hoc (default, CODESIGN_IDENTITY=-):
#     Supports: software keys without Touch ID (-software -no-touch).
#     Good for local development and testing.
#
#   Developer ID (CODESIGN_IDENTITY="Developer ID Application: ..."):
#     Supports: all features (Secure Enclave, Touch ID, software keys).
#     Signed with hardened runtime + secure timestamp (notarization-ready).
#     No entitlements: CryptoKit's SecureEnclave API talks to the SEP
#     directly without inserting items into the data-protection keychain,
#     so no provisioning profile is required.
#     Required for production builds.
#
# List available signing identities:
#   security find-identity -v -p codesigning
CODESIGN_IDENTITY ?= -

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

.PHONY: build sign install install-completions install-launchd universal clean test test-cover

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

test: $(SWIFT_LIB)
	go test -v -race -count=1 ./...

test-cover: $(SWIFT_LIB)
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -f touchid-agent \
	      $(SWIFT_LIB) \
	      $(SWIFT_MODULE).swiftmodule $(SWIFT_MODULE).swiftdoc \
	      $(SWIFT_MODULE).swiftsourceinfo $(SWIFT_MODULE).abi.json \
	      coverage.out coverage.html
