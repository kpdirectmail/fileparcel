package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// The invite note is public: the server shows it on the sign-up page to
// anyone with the link and puts it in the invitation e-mail. The CLI help
// must not call it internal.
func TestInviteNoteHelpSaysPublic(t *testing.T) {
	cmd := newInviteCreateCmd()
	fl := cmd.Flags().Lookup("note")
	if fl == nil {
		t.Fatal("no --note flag")
	}
	if strings.Contains(fl.Usage, "internal") || !strings.Contains(fl.Usage, "sign-up page") || !strings.Contains(fl.Usage, "e-mail") {
		t.Fatalf("--note usage %q", fl.Usage)
	}
	// The link of an active invite is listed again, so it is not "shown once".
	if strings.Contains(cmd.Long, "shown once") {
		t.Fatalf("invite create help: %q", cmd.Long)
	}
}

// invite list prints the link of active invites (absolute), not only in --json.
func TestInviteListShowsLinks(t *testing.T) {
	exp := time.Now().Add(72 * time.Hour).UTC()
	active := core.Invite{ID: "inv_a", Role: core.RoleMember, Status: core.InviteActive, MaxUses: 1, ExpiresAt: exp, URL: "/invite/tokA"}
	expired := core.Invite{ID: "inv_b", Role: core.RoleGuest, Status: core.InviteExpired, MaxUses: 1, ExpiresAt: exp}
	serve := func(invites ...core.Invite) *fakeAPI {
		f := newFakeAPI(t)
		f.handle("GET", "/api/v1/admin/invites", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, core.Page[core.Invite]{Items: invites})
		})
		return f
	}
	f := serve(active, expired)
	res := f.run(t, "", "invite", "list")
	if res.code != 0 || !strings.Contains(res.stdout, "URL") || !strings.Contains(res.stdout, f.srv.URL+"/invite/tokA") {
		t.Fatalf("invite list: %+v", res)
	}
	// Without any link (only inactive invites, or the keys are locked) the
	// column is left out.
	res = serve(expired).run(t, "", "invite", "list", "--all")
	if res.code != 0 || !strings.Contains(res.stdout, "inv_b") || strings.Contains(res.stdout, "URL") {
		t.Fatalf("invite list without links: %+v", res)
	}
}
