package usersapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// TestOwnEmailChangeNeedsStepUp: PATCH /admin/users/{own id} follows the
// rules of PATCH /me/profile for the e-mail address — step-up, and the
// previous address gets the email_changed alert — so a hijacked session of a
// role with "Manage accounts" cannot move the security-alert address
// silently. Other people's addresses and the own display name need neither.
func TestOwnEmailChangeNeedsStepUp(t *testing.T) {
	te := newTestEnv(t)
	te.notify.on.Store(true)
	self := "/api/v1/admin/users/" + te.owner.ID

	if st, code := te.as(te.principal(te.owner, false)).do(t, "PATCH", self, core.UserUpdate{Email: ptr("hijack@example.org")}, nil); st != http.StatusForbidden || code != "elevation_required" {
		t.Fatalf("own e-mail without step-up: %d %s", st, code)
	}
	if u, _ := te.d.Users.Get(context.Background(), te.owner.ID); u.Email != "owner@example.com" {
		t.Fatalf("e-mail changed without step-up: %q", u.Email)
	}
	// The same address (another case, surrounding spaces) and the display name are no change of address.
	var u core.User
	if st, code := te.as(te.principal(te.owner, false)).do(t, "PATCH", self, core.UserUpdate{Email: ptr(" Owner@Example.com "), DisplayName: ptr("Olive")}, &u); st != 200 || u.DisplayName != "Olive" {
		t.Fatalf("same address and a name: %d %s %+v", st, code, u)
	}
	// Someone else's address: no step-up, no alert (unchanged).
	if st, code := te.as(te.principal(te.owner, false)).do(t, "PATCH", "/api/v1/admin/users/"+te.member.ID, core.UserUpdate{Email: ptr("m2@example.com")}, nil); st != 200 {
		t.Fatalf("other account's e-mail: %d %s", st, code)
	}
	te.notify.mu.Lock()
	n := len(te.notify.sent)
	te.notify.mu.Unlock()
	if n != 0 {
		t.Fatalf("alerts before the own change: %+v", te.notify.sent)
	}

	if st, code := te.as(te.principal(te.owner, true)).do(t, "PATCH", self, core.UserUpdate{Email: ptr("new@example.org")}, &u); st != 200 || u.Email != "new@example.org" {
		t.Fatalf("elevated own e-mail: %d %s %+v", st, code, u)
	}
	te.notify.mu.Lock()
	sent := append([]map[string]any(nil), te.notify.sent...)
	te.notify.mu.Unlock()
	if len(sent) != 1 || sent[0]["kind"] != "email_changed" || !strings.EqualFold(fmt.Sprint(sent[0]["_to"]), "owner@example.com") || sent[0]["name"] != "n***@example.org" {
		t.Fatalf("alert to the previous address: %+v", sent)
	}
}
