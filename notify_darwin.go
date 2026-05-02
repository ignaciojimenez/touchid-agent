//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func escapeForAppleScript(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "$(", "")
	return s
}

func showNotification(message string) {
	message = escapeForAppleScript(message)
	script := fmt.Sprintf(`display notification "%s" with title "touchid-agent"`, message)
	exec.Command("osascript", "-e", script).Run()
}
