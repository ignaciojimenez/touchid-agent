//go:build darwin

package main

/*
#include <CoreFoundation/CoreFoundation.h>

// cfPrefCopyAppValue wraps CFPreferencesCopyAppValue, returning NULL
// when the key is absent. The caller must CFRelease a non-NULL result.
static CFPropertyListRef cfPrefCopyAppValue(const char *key, const char *appID) {
	CFStringRef cfKey = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
	CFStringRef cfApp = CFStringCreateWithCString(kCFAllocatorDefault, appID, kCFStringEncodingUTF8);
	CFPropertyListRef val = CFPreferencesCopyAppValue(cfKey, cfApp);
	CFRelease(cfKey);
	CFRelease(cfApp);
	return val;
}

// cfPrefSetAppValue wraps CFPreferencesSetAppValue (used only in tests
// to inject values into the user domain).
static void cfPrefSetAppValue(const char *key, CFPropertyListRef value, const char *appID) {
	CFStringRef cfKey = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
	CFStringRef cfApp = CFStringCreateWithCString(kCFAllocatorDefault, appID, kCFStringEncodingUTF8);
	CFPreferencesSetAppValue(cfKey, value, cfApp);
	CFRelease(cfKey);
	CFRelease(cfApp);
}

// cfPrefAppSync flushes writes made via cfPrefSetAppValue.
static Boolean cfPrefAppSync(const char *appID) {
	CFStringRef cfApp = CFStringCreateWithCString(kCFAllocatorDefault, appID, kCFStringEncodingUTF8);
	Boolean ok = CFPreferencesAppSynchronize(cfApp);
	CFRelease(cfApp);
	return ok;
}
*/
import "C"

import (
	"log"
	"unsafe"
)

var managedBundleID = "com.ignaciojimenez.touchid-agent"

// Managed preference keys. These match the PayloadContent keys in the
// .mobileconfig profile shipped alongside the .pkg.
const (
	managedKeyAuditLogPath    = "audit_log_path"
	managedKeyPeerCheck       = "peer_check"
	managedKeyRateLimit       = "rate_limit"
	managedKeyAllowedCallers  = "allowed_callers"
)

// readManagedString, readManagedBool, readManagedInt are the lookup
// functions used at runtime. Tests override them via the exported
// setManagedReaders helper to avoid hitting CoreFoundation.
var (
	readManagedString = cfPrefString
	readManagedBool   = cfPrefBool
	readManagedInt    = cfPrefInt
)

// cfPrefString reads a string-typed managed preference. Returns ("", false)
// when the key is absent or not a CFString.
func cfPrefString(key string) (string, bool) {
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	cApp := C.CString(managedBundleID)
	defer C.free(unsafe.Pointer(cApp))

	val := C.cfPrefCopyAppValue(cKey, cApp)
	if uintptr(unsafe.Pointer(val)) == 0 {
		return "", false
	}
	defer C.CFRelease(val)

	if C.CFGetTypeID(val) != C.CFStringGetTypeID() {
		return "", false
	}

	cfStr := C.CFStringRef(val)
	length := C.CFStringGetLength(cfStr)
	maxSize := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8) + 1
	buf := C.malloc(C.size_t(maxSize))
	defer C.free(buf)

	if C.CFStringGetCString(cfStr, (*C.char)(buf), maxSize, C.kCFStringEncodingUTF8) == 0 {
		return "", false
	}
	return C.GoString((*C.char)(buf)), true
}

// cfPrefBool reads a boolean-typed managed preference. Returns (false, false)
// when the key is absent or not a CFBoolean.
func cfPrefBool(key string) (bool, bool) {
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	cApp := C.CString(managedBundleID)
	defer C.free(unsafe.Pointer(cApp))

	val := C.cfPrefCopyAppValue(cKey, cApp)
	if uintptr(unsafe.Pointer(val)) == 0 {
		return false, false
	}
	defer C.CFRelease(val)

	if C.CFGetTypeID(val) != C.CFBooleanGetTypeID() {
		return false, false
	}
	return C.CFBooleanGetValue(C.CFBooleanRef(val)) != 0, true
}

// cfPrefInt reads an integer-typed managed preference. Returns (0, false)
// when the key is absent or not a CFNumber.
func cfPrefInt(key string) (int, bool) {
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	cApp := C.CString(managedBundleID)
	defer C.free(unsafe.Pointer(cApp))

	val := C.cfPrefCopyAppValue(cKey, cApp)
	if uintptr(unsafe.Pointer(val)) == 0 {
		return 0, false
	}
	defer C.CFRelease(val)

	if C.CFGetTypeID(val) != C.CFNumberGetTypeID() {
		return 0, false
	}
	var n C.long
	if C.CFNumberGetValue(C.CFNumberRef(val), C.kCFNumberLongType, unsafe.Pointer(&n)) == 0 {
		return 0, false
	}
	return int(n), true
}

// applyManagedOverrides reads managed preferences for the four policy
// flags and overwrites the pointed-to values when a managed key is
// present. Each override is logged to stderr so IT has visibility in
// ~/Library/Logs/touchid-agent.log.
func applyManagedOverrides(auditLogPath *string, peerCheck *bool, rateLimit *int, allowedCallersFile *string) {
	if v, ok := readManagedString(managedKeyAuditLogPath); ok {
		*auditLogPath = v
		log.Printf("Managed preference active: %s=%q", managedKeyAuditLogPath, v)
	}
	if v, ok := readManagedBool(managedKeyPeerCheck); ok {
		*peerCheck = v
		log.Printf("Managed preference active: %s=%v", managedKeyPeerCheck, v)
	}
	if v, ok := readManagedInt(managedKeyRateLimit); ok {
		*rateLimit = v
		log.Printf("Managed preference active: %s=%d", managedKeyRateLimit, v)
	}
	if v, ok := readManagedString(managedKeyAllowedCallers); ok {
		*allowedCallersFile = v
		log.Printf("Managed preference active: %s=%q", managedKeyAllowedCallers, v)
	}
}
