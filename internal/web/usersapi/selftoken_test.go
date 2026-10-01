package usersapi

import (
	"context"
	"net/http"
	"testing"

	"fileparcel/internal/core"
)

// With an API token — even an elevated admin one — PATCH /admin/users/{own
// id} changes neither the own e-mail address nor the display name, as PATCH
// /me/profile refuses them: a leaked token must not redirect the security
// alerts. Other fields of one's own account, and other people's accounts,
// are unaffected.
func TestOwnProfileNotWithTokens(t *testing.T) {
	te := newTestEnv(t)
	tok := te.principal(te.owner, true)
	tok.Via, tok.TokenID, tok.Scopes = core.ViaToken, "tok_x", []string{core.ScopeFilesRead, core.ScopeAdmin}
	self := "/api/v1/admin/users/" + te.owner.ID
	for name, in := range map[string]core.UserUpdate{
		"e-mail":       {Email: ptr("tok-b@example.org")},
		"display name": {DisplayName: ptr("TOKEN SET")},
	} {
		if st, code := te.as(tok).do(t, "PATCH", self, in, nil); st != http.StatusForbidden || code != "forbidden" {
			t.Errorf("own %s with a token: %d %s", name, st, code)
		}
	}
	if u, _ := te.d.Users.Get(context.Background(), te.owner.ID); u.Email != "owner@example.com" || u.DisplayName == "TOKEN SET" {
		t.Fatalf("changed through a token: %+v", u)
	}
	var u core.User
	if st, code := te.as(tok).do(t, "PATCH", "/api/v1/admin/users/"+te.member.ID, core.UserUpdate{DisplayName: ptr("Mia")}, &u); st != 200 || u.DisplayName != "Mia" {
		t.Fatalf("another account with a token: %d %s %+v", st, code, u)
	}
}
