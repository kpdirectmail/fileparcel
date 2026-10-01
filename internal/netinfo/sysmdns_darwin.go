package netinfo

import (
	"context"
	"os/exec"
	"strings"
)

// systemResponderHost returns macOS's Bonjour name (scutil --get LocalHostName).
func systemResponderHost(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "scutil", "--get", "LocalHostName").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
