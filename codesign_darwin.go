//go:build darwin

package main

/*
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

// cfStringToBuf copies a CFString into a UTF-8 C buffer (empty if NULL).
static void cfStringToBuf(CFStringRef s, char *out, size_t out_len) {
	if (out_len == 0) {
		return;
	}
	out[0] = '\0';
	if (s != NULL) {
		CFStringGetCString(s, out, (CFIndex)out_len, kCFStringEncodingUTF8);
	}
}

// peerCodeIdentity resolves the code-signing identity of the process on the
// other end of unix socket fd, race-free, via its audit token. Returns 0 if a
// SecCode was obtained (team_id/signing_id/cdhash_hex may still be empty for
// unsigned binaries), non-zero otherwise. *valid is set to 1 only when the
// running code's signature validates.
static int peerCodeIdentity(int fd,
		char *path, size_t path_len,
		char *team_id, size_t team_len,
		char *signing_id, size_t signing_len,
		char *cdhash_hex, size_t cdhash_len,
		int *valid) {
	*valid = 0;
	if (path_len) path[0] = '\0';
	if (team_len) team_id[0] = '\0';
	if (signing_len) signing_id[0] = '\0';
	if (cdhash_len) cdhash_hex[0] = '\0';

	audit_token_t token;
	socklen_t len = sizeof(token);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0) {
		return 1;
	}

	CFDataRef tokenData = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
	if (tokenData == NULL) {
		return 2;
	}
	CFStringRef key = kSecGuestAttributeAudit;
	CFDictionaryRef attrs = CFDictionaryCreate(NULL,
		(const void **)&key, (const void **)&tokenData, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(tokenData);
	if (attrs == NULL) {
		return 2;
	}

	SecCodeRef code = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs);
	if (st != errSecSuccess || code == NULL) {
		return 3;
	}

	// Dynamic validity of the running code's signature.
	*valid = (SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL) == errSecSuccess) ? 1 : 0;

	CFDictionaryRef info = NULL;
	if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess && info != NULL) {
		cfStringToBuf((CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), team_id, team_len);
		cfStringToBuf((CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoIdentifier), signing_id, signing_len);

		CFURLRef url = (CFURLRef)CFDictionaryGetValue(info, kSecCodeInfoMainExecutable);
		if (url != NULL && path_len > 0) {
			CFURLGetFileSystemRepresentation(url, true, (UInt8 *)path, (CFIndex)path_len);
		}

		CFDataRef cdhash = (CFDataRef)CFDictionaryGetValue(info, kSecCodeInfoUnique);
		if (cdhash != NULL && cdhash_len > 0) {
			const UInt8 *b = CFDataGetBytePtr(cdhash);
			CFIndex n = CFDataGetLength(cdhash);
			static const char hexd[] = "0123456789abcdef";
			if ((size_t)(n * 2 + 1) <= cdhash_len) {
				for (CFIndex i = 0; i < n; i++) {
					cdhash_hex[i*2] = hexd[(b[i] >> 4) & 0xF];
					cdhash_hex[i*2+1] = hexd[b[i] & 0xF];
				}
				cdhash_hex[n*2] = '\0';
			}
		}
		CFRelease(info);
	}

	CFRelease(code);
	return 0;
}
*/
import "C"

// CallerIdentity is the code-signing identity of a connecting peer, resolved
// race-free from the connection's audit token. Zero values are safe; an
// unsigned caller yields empty identity fields and Signed == false.
type CallerIdentity struct {
	Path      string // main executable path (from the audit token, not proc_pidpath)
	TeamID    string // Apple Developer Team ID, e.g. "" for platform binaries
	SigningID string // code signing identifier, e.g. "com.apple.ssh-keygen"
	CDHash    string // lowercase hex of the code directory hash
	Signed    bool   // the running code's signature validates
}

// resolveCallerIdentity returns the code-signing identity of the process on the
// other end of the unix socket fd. ok is false if the audit token or SecCode
// could not be obtained (e.g. the peer is not a local process).
func resolveCallerIdentity(fd uintptr) (CallerIdentity, bool) {
	var (
		path      [4096]C.char
		teamID    [128]C.char
		signingID [256]C.char
		cdhash    [128]C.char
		valid     C.int
	)
	rc := C.peerCodeIdentity(C.int(fd),
		&path[0], C.size_t(len(path)),
		&teamID[0], C.size_t(len(teamID)),
		&signingID[0], C.size_t(len(signingID)),
		&cdhash[0], C.size_t(len(cdhash)),
		&valid)
	if rc != 0 {
		return CallerIdentity{}, false
	}
	return CallerIdentity{
		Path:      C.GoString(&path[0]),
		TeamID:    C.GoString(&teamID[0]),
		SigningID: C.GoString(&signingID[0]),
		CDHash:    C.GoString(&cdhash[0]),
		Signed:    valid == 1,
	}, true
}
