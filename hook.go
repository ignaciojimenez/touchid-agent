//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

type HookEnv struct {
	Label         string
	PubKey        string
	PubKeyFile    string
	TouchRequired bool
}

func runPostHook(hookCmd string, env HookEnv) error {
	if hookCmd == "" {
		return nil
	}

	cmd := exec.Command(hookCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TOUCHID_AGENT_LABEL=%s", env.Label),
		fmt.Sprintf("TOUCHID_AGENT_PUBKEY=%s", env.PubKey),
		fmt.Sprintf("TOUCHID_AGENT_PUBKEY_FILE=%s", env.PubKeyFile),
		fmt.Sprintf("TOUCHID_AGENT_TOUCH_REQUIRED=%s", strconv.FormatBool(env.TouchRequired)),
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("post-create hook failed: %w", err)
	}
	return nil
}
