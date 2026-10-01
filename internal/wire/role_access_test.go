package wire

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/web"
)

// TestRoleAccessEndToEnd runs file access through roles with the real
// services and router: a role that is a member of a group opens its team
// folder to every holder, a folder shared with a role opens to everyone
// holding it (and lets a guest-based role with shares.links create a link),
// and a role change closes the holder's event stream after announcing it —
// all for sessions opened before the role changed.
func TestRoleAccessEndToEnd(t *testing.T) {
	g := newGuardEnv(t)
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaOffline)
	router := web.NewRouter(g.d)
	do := func(who, method, path string, body any, out any) int {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		r := httptest.NewRequest(method, path, rd)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		g.calls++
		r.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:40000", byte(g.calls>>16), byte(g.calls>>8), byte(g.calls))
		g.creds[who].apply(r)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		if rec.Code < 300 && out != nil {
			if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
				t.Fatalf("%s %s: %s: %v", method, path, rec.Body, err)
			}
		} else if rec.Code >= 300 {
			t.Logf("%s %s as %s: %d %s", method, path, who, rec.Code, rec.Body)
		}
		return rec.Code
	}
	user := func(name string) *core.User {
		t.Helper()
		u, err := g.d.Users.GetByUsername(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	mel, gus, olive := user("mel"), user("gus"), user("olive")

	// A member-based Finance role joins the Finance group; mel gets the role.
	finance, err := g.d.Users.CreateRole(ctx, sys, core.RoleDefInput{Name: "Finance", Base: core.RoleMember})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := g.d.Users.CreateGroup(ctx, sys, core.GroupInput{Name: "Finance"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.d.Users.SetRoleGroup(ctx, sys, finance.ID, grp.ID, core.GroupRoleMember); err != nil {
		t.Fatal(err)
	}
	teamRoot := func(who string) (string, core.Perm) {
		t.Helper()
		var spaces []core.Space
		if st := do(who, "GET", "/api/v1/spaces", nil, &spaces); st != 200 {
			t.Fatalf("spaces as %s: %d", who, st)
		}
		for _, s := range spaces {
			if s.ID == grp.SpaceID {
				return s.RootID, s.Perm
			}
		}
		return "", core.PermNone
	}
	if root, _ := teamRoot("mel"); root != "" {
		t.Fatal("team folder open before the role")
	}

	// mel's event stream, opened before the role change.
	srv := httptest.NewServer(router)
	defer srv.Close()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/events", nil)
	g.creds["mel"].apply(req)
	resp, err := srv.Client().Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("events: %v %v", resp, err)
	}
	defer resp.Body.Close()
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	for g.d.Bus.Subscribers() == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := g.d.Users.Update(ctx, sys, mel.ID, core.UserUpdate{RoleID: ptr(finance.ID)}); err != nil {
		t.Fatal(err)
	}
	// The stream announces the change and ends: EventSource reconnects
	// with the new permissions.
	var got []string
	timeout := time.After(10 * time.Second)
read:
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				break read
			}
			if strings.HasPrefix(l, "event: ") || strings.HasPrefix(l, "data: ") {
				got = append(got, l)
			}
		case <-timeout:
			t.Fatalf("stream still open after the role change; got %v", got)
		}
	}
	want := []string{"event: authz.changed", `data: {"user_ids":["` + mel.ID + `"],"reason":"role_assigned"}`}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("stream got %q, want %q", got, want)
	}

	root, perm := teamRoot("mel")
	if root == "" || perm != core.PermEdit {
		t.Fatalf("team folder through the role: %q %s", root, perm)
	}
	var folder core.Node
	if st := do("mel", "POST", "/api/v1/nodes/"+root+"/folders", core.NameInput{Name: "Invoices"}, &folder); st != 201 && st != 200 {
		t.Fatalf("mkdir in the team folder: %d", st)
	}

	// Olive shares a folder of hers with a guest-based role as manager.
	contractors, err := g.d.Users.CreateRole(ctx, sys, core.RoleDefInput{Name: "Contractors", Base: core.RoleGuest,
		Permissions: &[]core.Capability{core.CapShareLinks}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.d.Users.Update(ctx, sys, gus.ID, core.UserUpdate{RoleID: ptr(contractors.ID)}); err != nil {
		t.Fatal(err)
	}
	var spaces []core.Space
	do("olive", "GET", "/api/v1/spaces", nil, &spaces)
	var briefs core.Node
	for _, s := range spaces {
		if s.Kind == core.SpaceUser && s.OwnerUserID == olive.ID {
			if st := do("olive", "POST", "/api/v1/nodes/"+s.RootID+"/folders", core.NameInput{Name: "Briefs"}, &briefs); st >= 300 {
				t.Fatalf("mkdir: %d", st)
			}
		}
	}
	var grant core.Grant
	if st := do("olive", "POST", "/api/v1/nodes/"+briefs.ID+"/grants", core.GrantInput{SubjectType: core.SubjectRole,
		SubjectID: contractors.ID, Role: core.GrantManager}, &grant); st != 200 && st != 201 {
		t.Fatalf("role grant: %d", st)
	}
	if grant.SubjectName != "Contractors" || grant.Role != core.GrantManager {
		t.Fatalf("grant %+v", grant)
	}
	var shared core.Page[core.Node]
	if st := do("gus", "GET", "/api/v1/shared-with-me", nil, &shared); st != 200 || len(shared.Items) != 1 ||
		shared.Items[0].ID != briefs.ID || shared.Items[0].Perm != core.PermManage {
		t.Fatalf("shared with the role: %d %+v", st, shared.Items)
	}
	var link core.Share
	if st := do("gus", "POST", "/api/v1/shares", core.ShareInput{NodeID: briefs.ID}, &link); st != 201 || link.URL == "" {
		t.Fatalf("link by a guest-based role with shares.links: %d %+v", st, link)
	}
	if st := do("gus", "POST", "/api/v1/shares", core.ShareInput{Kind: core.ShareRequest, NodeID: briefs.ID}, nil); st != 403 {
		t.Fatalf("file request without shares.requests: %d", st)
	}
	// Back to a plain guest: the folder closes on the next request.
	if _, err := g.d.Users.Update(ctx, sys, gus.ID, core.UserUpdate{RoleID: ptr("guest")}); err != nil {
		t.Fatal(err)
	}
	if st := do("gus", "GET", "/api/v1/nodes/"+briefs.ID, nil, nil); st != 404 {
		t.Fatalf("former holder opens the folder: %d", st)
	}
}
