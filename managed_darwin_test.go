//go:build darwin

package main

import (
	"os/exec"
	"testing"
)

// testBundleID isolates test writes from the real agent preferences.
const testBundleID = "com.ignaciojimenez.touchid-agent.test"

// --- defaults(1) helpers for CFPreferences integration tests ---
//
// `defaults write` writes to the user domain, which
// CFPreferencesCopyAppValue merges into its lookup. This avoids
// needing cgo in the test file.

func defaultsWriteString(t *testing.T, domain, key, val string) {
	t.Helper()
	if out, err := exec.Command("defaults", "write", domain, key, "-string", val).CombinedOutput(); err != nil {
		t.Fatalf("defaults write %s %s -string %s: %v (%s)", domain, key, val, err, out)
	}
}

func defaultsWriteBool(t *testing.T, domain, key string, val bool) {
	t.Helper()
	boolStr := "false"
	if val {
		boolStr = "true"
	}
	if out, err := exec.Command("defaults", "write", domain, key, "-bool", boolStr).CombinedOutput(); err != nil {
		t.Fatalf("defaults write %s %s -bool %s: %v (%s)", domain, key, boolStr, err, out)
	}
}

func defaultsWriteInt(t *testing.T, domain, key string, val int) {
	t.Helper()
	if out, err := exec.Command("defaults", "write", domain, key, "-int",
		intToStr(val)).CombinedOutput(); err != nil {
		t.Fatalf("defaults write %s %s -int %d: %v (%s)", domain, key, val, err, out)
	}
}

func defaultsDelete(t *testing.T, domain, key string) {
	t.Helper()
	exec.Command("defaults", "delete", domain, key).Run() // ignore error on missing key
}

func defaultsDeleteDomain(t *testing.T, domain string) {
	t.Helper()
	exec.Command("defaults", "delete", domain).Run()
}

func intToStr(n int) string {
	buf := make([]byte, 0, 12)
	if n < 0 {
		buf = append(buf, '-')
		n = -n
	}
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	for i := len(digits) - 1; i >= 0; i-- {
		buf = append(buf, digits[i])
	}
	return string(buf)
}

// --- CFPreferences integration tests (exercise the real cgo path) ---

func TestCFPrefString_RoundTrip(t *testing.T) {
	old := managedBundleID
	managedBundleID = testBundleID
	defer func() { managedBundleID = old }()

	key := "test_string_key"
	defaultsWriteString(t, testBundleID, key, "/var/log/test.log")
	t.Cleanup(func() {
		defaultsDelete(t, testBundleID, key)
	})

	val, ok := cfPrefString(key)
	if !ok {
		t.Fatal("cfPrefString returned ok=false for a key we just set")
	}
	if val != "/var/log/test.log" {
		t.Errorf("cfPrefString = %q, want %q", val, "/var/log/test.log")
	}
}

func TestCFPrefString_Missing(t *testing.T) {
	old := managedBundleID
	managedBundleID = testBundleID
	defer func() { managedBundleID = old }()

	_, ok := cfPrefString("nonexistent_key_string_12345")
	if ok {
		t.Error("cfPrefString returned ok=true for a missing key")
	}
}

func TestCFPrefBool_RoundTrip(t *testing.T) {
	old := managedBundleID
	managedBundleID = testBundleID
	defer func() { managedBundleID = old }()

	key := "test_bool_key"
	defaultsWriteBool(t, testBundleID, key, true)
	t.Cleanup(func() {
		defaultsDelete(t, testBundleID, key)
	})

	val, ok := cfPrefBool(key)
	if !ok {
		t.Fatal("cfPrefBool returned ok=false for a key we just set")
	}
	if !val {
		t.Error("cfPrefBool = false, want true")
	}
}

func TestCFPrefBool_Missing(t *testing.T) {
	old := managedBundleID
	managedBundleID = testBundleID
	defer func() { managedBundleID = old }()

	_, ok := cfPrefBool("nonexistent_key_bool_12345")
	if ok {
		t.Error("cfPrefBool returned ok=true for a missing key")
	}
}

func TestCFPrefInt_RoundTrip(t *testing.T) {
	old := managedBundleID
	managedBundleID = testBundleID
	defer func() { managedBundleID = old }()

	key := "test_int_key"
	defaultsWriteInt(t, testBundleID, key, 42)
	t.Cleanup(func() {
		defaultsDelete(t, testBundleID, key)
	})

	val, ok := cfPrefInt(key)
	if !ok {
		t.Fatal("cfPrefInt returned ok=false for a key we just set")
	}
	if val != 42 {
		t.Errorf("cfPrefInt = %d, want 42", val)
	}
}

func TestCFPrefInt_Missing(t *testing.T) {
	old := managedBundleID
	managedBundleID = testBundleID
	defer func() { managedBundleID = old }()

	_, ok := cfPrefInt("nonexistent_key_int_12345")
	if ok {
		t.Error("cfPrefInt returned ok=true for a missing key")
	}
}

func TestCFPrefString_WrongType(t *testing.T) {
	old := managedBundleID
	managedBundleID = testBundleID
	defer func() { managedBundleID = old }()

	key := "test_wrong_type_for_string"
	defaultsWriteInt(t, testBundleID, key, 99)
	t.Cleanup(func() {
		defaultsDelete(t, testBundleID, key)
	})

	_, ok := cfPrefString(key)
	if ok {
		t.Error("cfPrefString should return ok=false when value is an integer")
	}
}

func TestCFPrefBool_WrongType(t *testing.T) {
	old := managedBundleID
	managedBundleID = testBundleID
	defer func() { managedBundleID = old }()

	key := "test_wrong_type_for_bool"
	defaultsWriteString(t, testBundleID, key, "not-a-bool")
	t.Cleanup(func() {
		defaultsDelete(t, testBundleID, key)
	})

	_, ok := cfPrefBool(key)
	if ok {
		t.Error("cfPrefBool should return ok=false when value is a string")
	}
}

func TestCFPrefInt_WrongType(t *testing.T) {
	old := managedBundleID
	managedBundleID = testBundleID
	defer func() { managedBundleID = old }()

	key := "test_wrong_type_for_int"
	defaultsWriteString(t, testBundleID, key, "not-a-number")
	t.Cleanup(func() {
		defaultsDelete(t, testBundleID, key)
	})

	_, ok := cfPrefInt(key)
	if ok {
		t.Error("cfPrefInt should return ok=false when value is a string")
	}
}

// --- Pure-Go unit tests for applyManagedOverrides logic ---

func TestApplyManagedOverrides_AllSet(t *testing.T) {
	restore := setManagedReadersForTest(
		func(key string) (string, bool) {
			switch key {
			case managedKeyAuditLogPath:
				return "/managed/audit.log", true
			case managedKeyAllowedCallers:
				return "/managed/callers.txt", true
			}
			return "", false
		},
		func(key string) (bool, bool) {
			if key == managedKeyPeerCheck {
				return true, true
			}
			return false, false
		},
		func(key string) (int, bool) {
			if key == managedKeyRateLimit {
				return 60, true
			}
			return 0, false
		},
	)
	defer restore()

	auditLog := ""
	peerCheck := false
	rateLimit := 0
	allowedCallers := ""

	applyManagedOverrides(&auditLog, &peerCheck, &rateLimit, &allowedCallers)

	if auditLog != "/managed/audit.log" {
		t.Errorf("auditLog = %q, want /managed/audit.log", auditLog)
	}
	if !peerCheck {
		t.Error("peerCheck = false, want true")
	}
	if rateLimit != 60 {
		t.Errorf("rateLimit = %d, want 60", rateLimit)
	}
	if allowedCallers != "/managed/callers.txt" {
		t.Errorf("allowedCallers = %q, want /managed/callers.txt", allowedCallers)
	}
}

func TestApplyManagedOverrides_NoneSet(t *testing.T) {
	restore := setManagedReadersForTest(
		func(string) (string, bool) { return "", false },
		func(string) (bool, bool) { return false, false },
		func(string) (int, bool) { return 0, false },
	)
	defer restore()

	auditLog := "/cli/audit.log"
	peerCheck := true
	rateLimit := 10
	allowedCallers := "/cli/callers.txt"

	applyManagedOverrides(&auditLog, &peerCheck, &rateLimit, &allowedCallers)

	if auditLog != "/cli/audit.log" {
		t.Errorf("auditLog changed to %q, should be untouched", auditLog)
	}
	if !peerCheck {
		t.Error("peerCheck changed, should be untouched")
	}
	if rateLimit != 10 {
		t.Errorf("rateLimit changed to %d, should be untouched", rateLimit)
	}
	if allowedCallers != "/cli/callers.txt" {
		t.Errorf("allowedCallers changed to %q, should be untouched", allowedCallers)
	}
}

func TestApplyManagedOverrides_PartialOverride(t *testing.T) {
	restore := setManagedReadersForTest(
		func(key string) (string, bool) {
			if key == managedKeyAuditLogPath {
				return "/managed/audit.log", true
			}
			return "", false
		},
		func(string) (bool, bool) { return false, false },
		func(string) (int, bool) { return 0, false },
	)
	defer restore()

	auditLog := "/cli/audit.log"
	peerCheck := false
	rateLimit := 5
	allowedCallers := ""

	applyManagedOverrides(&auditLog, &peerCheck, &rateLimit, &allowedCallers)

	if auditLog != "/managed/audit.log" {
		t.Errorf("auditLog = %q, want /managed/audit.log", auditLog)
	}
	if peerCheck {
		t.Error("peerCheck should remain false")
	}
	if rateLimit != 5 {
		t.Errorf("rateLimit should remain 5, got %d", rateLimit)
	}
}

func TestApplyManagedOverrides_OverridesCLIValues(t *testing.T) {
	restore := setManagedReadersForTest(
		func(key string) (string, bool) {
			if key == managedKeyAuditLogPath {
				return "/managed/override.log", true
			}
			return "", false
		},
		func(key string) (bool, bool) {
			if key == managedKeyPeerCheck {
				return false, true
			}
			return false, false
		},
		func(string) (int, bool) { return 0, false },
	)
	defer restore()

	auditLog := "/user/chose/this.log"
	peerCheck := true
	rateLimit := 30
	allowedCallers := "/user/callers.txt"

	applyManagedOverrides(&auditLog, &peerCheck, &rateLimit, &allowedCallers)

	if auditLog != "/managed/override.log" {
		t.Errorf("managed audit_log_path should override CLI value, got %q", auditLog)
	}
	if peerCheck {
		t.Error("managed peer_check=false should override CLI peer_check=true")
	}
	if rateLimit != 30 {
		t.Errorf("rateLimit should be untouched (no managed value), got %d", rateLimit)
	}
	if allowedCallers != "/user/callers.txt" {
		t.Errorf("allowedCallers should be untouched (no managed value), got %q", allowedCallers)
	}
}

// --- Test helpers ---

// setManagedReadersForTest replaces the managed-pref reader functions
// with fakes and returns a restore function.
func setManagedReadersForTest(
	strFn func(string) (string, bool),
	boolFn func(string) (bool, bool),
	intFn func(string) (int, bool),
) func() {
	origStr := readManagedString
	origBool := readManagedBool
	origInt := readManagedInt
	readManagedString = strFn
	readManagedBool = boolFn
	readManagedInt = intFn
	return func() {
		readManagedString = origStr
		readManagedBool = origBool
		readManagedInt = origInt
	}
}
