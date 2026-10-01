package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// The step-up hint suggests a "token create" command; it must be accepted
// as written (it lacked --name, and --expires defaults to "never", which
// --elevated refuses).
func TestStepUpHintCommandIsValid(t *testing.T) {
	if msg := explainError(core.ErrElevationRequired).Error(); !strings.Contains(msg, stepUpTokenCmd) {
		t.Fatalf("hint does not suggest the command: %s", msg)
	}
	f := newFakeAPI(t)
	f.handle("POST", "/api/v1/me/tokens", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.TokenInput](r)
		writeJSON(w, 201, core.TokenCreated{Token: &core.APIToken{ID: ids.New(ids.PrefixToken), Name: in.Name, Scopes: in.Scopes},
			Secret: "fpt_abc_secret"})
	})
	args := strings.Fields(strings.Trim(stepUpTokenCmd, `"`))
	if args[0] != "fileparcel" {
		t.Fatalf("command %q", stepUpTokenCmd)
	}
	if res := f.run(t, "", args[1:]...); res.code != 0 {
		t.Fatalf("%s: %+v", stepUpTokenCmd, res)
	}
	var in core.TokenInput
	if err := json.Unmarshal(f.body("POST /api/v1/me/tokens"), &in); err != nil || !in.Elevated || in.ExpiresAt == nil {
		t.Fatalf("token body %+v (%v)", in, err)
	}
}
