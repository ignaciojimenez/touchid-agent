//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func showNotification(message string) {
	message = strings.ReplaceAll(message, `\`, `\\`)
	message = strings.ReplaceAll(message, `"`, `\"`)
	script := fmt.Sprintf(`display notification "%s" with title "touchid-agent"`, message)
	exec.Command("osascript", "-e", script).Run()
}
