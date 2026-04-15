PREFIX ?= /usr/local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# For Secure Enclave support, set CODESIGN_IDENTITY to a valid signing identity.
# Use `security find-identity -v -p codesigning` to list available identities.
# Software-backed keys (-software flag) work with ad-hoc signing.
CODESIGN_IDENTITY ?= -

.PHONY: build sign install clean

build:
	go build -ldflags "-X main.Version=$(VERSION)" -o touchid-agent .

sign: build
	codesign -s "$(CODESIGN_IDENTITY)" -f touchid-agent

install: build sign
	install -d $(PREFIX)/bin
	install -m 755 touchid-agent $(PREFIX)/bin/touchid-agent

clean:
	rm -f touchid-agent
