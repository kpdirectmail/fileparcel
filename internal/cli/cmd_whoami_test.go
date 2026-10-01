package cli

// Tests of "fileparcel whoami": the admin socket's full rights, --as, a
// remote token with its role, permissions and scopes.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

func TestWhoamiSocket(t *testing.T) {
	f := newFakeAPI(t)
	addUserRoutes(f) // the first owner is "admin"
	dir := f.socketHome(t)

	res := f.runSocket(t, dir, "", "whoami")
	if res.code != 0 || !strings.Contains(res.stdout, "admin socket (system): full rights") ||
		!strings.Contains(res.stdout, "act as admin, the first owner") {
		t.Fatalf("socket: %+v", res)
	}
	if f.requested("GET /api/v1/me") != 0 {
		t.Error("the system principal needs no /me")
	}
	res = f.runSocket(t, dir, "", "--json", "whoami")
	var v whoamiView
	if err := json.Unmarshal([]byte(res.stdout), &v); err != nil || !v.System || v.Via != core.ViaSocket ||
		v.FilesAs != "admin" || v.User != nil || !v.Staff {
		t.Fatalf("socket --json: %v %+v\n%s", err, v, res.stdout)
	}

	// --as: the account, as /me with X-FP-As tells it.
	res = f.runSocket(t, dir, "", "--as", "alice", "whoami")
	if res.code != 0 || !strings.Contains(res.stdout, "Account:") || !strings.Contains(res.stdout, "alice") ||
		!strings.Contains(res.stdout, "the admin socket (--as alice)") || !strings.Contains(res.stdout, "Design (manager)") {
		t.Fatalf("--as alice: %+v", res)
	}
	if as, _ := f.as("GET /api/v1/me"); as != "alice" {
		t.Errorf("--as alice sent X-FP-As %q", as)
	}
	// An account from a server without roles has no Permissions line.
	if strings.Contains(res.stdout, "Permissions:") {
		t.Errorf("--as alice on a server without roles: %s", res.stdout)
	}
}

func TestWhoamiRemote(t *testing.T) {
	f := newFakeAPI(t)
	me := golden[core.Me](t, "me.json") // Helpdesk (member-based, with server permissions)
	me.Via = core.ViaToken
	f.handle("GET", "/api/v1/me", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, me) })
	res := f.run(t, "", "whoami")
	for _, want := range []string{"Account:", "alice", "Role:", "Helpdesk (rol_01k5z8r3m9d4q7w2x6c1v0b5na), based on member",
		"Permissions:", "users.view", "users.manage", "Groups:", "Finance (manager)", "Two-factor:", "yes",
		"an API token on " + f.srv.URL} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("remote whoami lacks %q:\n%s", want, res.stdout)
		}
	}
	res = f.run(t, "", "--json", "whoami")
	var v whoamiView
	if err := json.Unmarshal([]byte(res.stdout), &v); err != nil || v.System || v.Via != core.ViaToken || v.User == nil ||
		v.User.RoleID != "rol_01k5z8r3m9d4q7w2x6c1v0b5na" || !v.Staff || len(v.Groups) != 1 || v.Server != f.srv.URL {
		t.Fatalf("remote --json: %v %+v\n%s", err, v, res.stdout)
	}
	// Owners and admins have every permission.
	me.User.Role, me.User.RoleID = core.RoleAdmin, string(core.RoleAdmin)
	if res := f.run(t, "", "whoami"); !strings.Contains(res.stdout, "Permissions:") ||
		!strings.Contains(res.stdout, "all") || !strings.Contains(res.stdout, "Role:") {
		t.Errorf("admin: %s", res.stdout)
	}
}

// The token in use is found by the id in its secret, and a token without
// the admin scope of an account with server permissions is explained.
func TestWhoamiToken(t *testing.T) {
	f := newFakeAPI(t)
	id := ids.New(ids.PrefixToken)
	exp := time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC)
	f.handle("GET", "/api/v1/me/tokens", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.APIToken]{Items: []core.APIToken{
			{ID: ids.New(ids.PrefixToken), Name: "other"},
			{ID: id, Name: "laptop", Scopes: []string{core.ScopeFilesRead, core.ScopeShares}, ExpiresAt: &exp},
		}})
	})
	c, err := connectRemote(Options{Server: f.srv.URL, Token: fakeToken})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tok, err := currentToken(context.Background(), c, "fpt_"+strings.TrimPrefix(id, "tok_")+"_secret")
	if err != nil || tok == nil || tok.Name != "laptop" {
		t.Fatalf("currentToken: %+v %v", tok, err)
	}
	if tok, err := currentToken(context.Background(), c, fakeToken); tok != nil || err != nil {
		t.Errorf("a malformed secret names no token: %+v %v", tok, err)
	}
	v := &whoamiView{Via: core.ViaToken, Server: f.srv.URL, Token: tok,
		User: &core.User{Username: "alice", Role: core.RoleMember, RoleID: "rol_x", Permissions: core.NewCapSet(core.Capability("users.view"))}}
	var b strings.Builder
	if err := renderWhoami(&b, v); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"laptop (" + id + ")", "files:read, shares", "Expires:"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("token lines lack %q:\n%s", want, b.String())
		}
	}
	if hint := tokenScopeHint(v); !strings.Contains(hint, `no "admin" scope`) {
		t.Errorf("hint for a staff account without the admin scope: %q", hint)
	}
	v.Token.Scopes = append(v.Token.Scopes, core.ScopeAdmin)
	if hint := tokenScopeHint(v); hint != "" {
		t.Errorf("hint with the admin scope: %q", hint)
	}
	v.Token.Scopes, v.User.Permissions = []string{core.ScopeFilesRead}, 0
	if hint := tokenScopeHint(v); hint != "" {
		t.Errorf("hint for an account without server permissions: %q", hint)
	}
}

func TestTokenIDOf(t *testing.T) {
	id := ids.New(ids.PrefixToken)
	for secret, want := range map[string]string{
		"fpt_" + strings.TrimPrefix(id, "tok_") + "_abcdef": id,
		"fpt_test_token": "",
		"tok_x":          "",
		"":               "",
	} {
		if got := tokenIDOf(secret); got != want {
			t.Errorf("tokenIDOf(%q) = %q, want %q", secret, got, want)
		}
	}
}
