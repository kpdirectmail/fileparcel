package cli

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// Group names that differ only in non-ASCII case ("Équipe", "équipe") could
// coexist before the server compared them by casefold(NFC) (SQLite's NOCASE
// folds ASCII only). The CLI takes the exact name and refuses to guess
// between folded matches: `-y group delete équipe` used to delete "Équipe".
func TestResolveGroupFoldedNames(t *testing.T) {
	f := newFakeAPI(t)
	a, b, d := ids.New(ids.PrefixGroup), ids.New(ids.PrefixGroup), ids.New(ids.PrefixGroup)
	f.handle("GET", "/api/v1/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Group]{Items: []core.Group{{ID: d, Name: "Design"}, {ID: a, Name: "Équipe"}, {ID: b, Name: "équipe"}}})
	})
	f.handle("DELETE", "/api/v1/admin/groups/{id}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	c := remoteClient(t, f)
	ctx := context.Background()

	for ref, want := range map[string]string{"Équipe": a, "équipe": b, "Équipe": a, "design": d, " DESIGN ": d} {
		if g, err := resolveGroup(ctx, c, ref); err != nil || g.ID != want {
			t.Errorf("resolveGroup(%q) = %+v, %v; want %s", ref, g, err, want)
		}
	}
	_, err := resolveGroup(ctx, c, "ÉQUIPE")
	if !errors.Is(err, core.ErrInvalid) || !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), b) {
		t.Fatalf("ambiguous name: %v", err)
	}
	if _, err := resolveGroup(ctx, c, "Nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown name: %v", err)
	}

	if res := f.run(t, "", "-y", "group", "delete", "ÉQUIPE"); res.code == 0 || f.requestedPrefix("DELETE ") != 0 {
		t.Fatalf("ambiguous delete: exit %d, requests %v\n%s", res.code, f.requests, res.stderr)
	}
	if res := f.run(t, "", "-y", "group", "delete", "équipe"); res.code != 0 || f.requested("DELETE /api/v1/admin/groups/"+b) != 1 ||
		f.requested("DELETE /api/v1/admin/groups/"+a) != 0 {
		t.Fatalf("delete équipe: exit %d, requests %v\n%s", res.code, f.requests, res.stderr)
	}
}

// "/Team/<group>" follows the same rule as resolveGroup.
func TestTeamRootFoldedNames(t *testing.T) {
	f := newFakeAPI(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	var roots []string
	for _, name := range []string{"Équipe", "équipe"} {
		sp := core.Space{ID: ids.New(ids.PrefixSpace), Kind: core.SpaceGroup, GroupID: ids.New(ids.PrefixGroup), Name: name,
			CreatedAt: now, Perm: core.PermEdit}
		root := &fakeNode{Node: core.Node{ID: ids.New(ids.PrefixNode), SpaceID: sp.ID, Kind: core.KindFolder, Name: name,
			CreatedAt: now, UpdatedAt: now, Perm: sp.Perm}}
		f.nodes[root.ID] = root
		sp.RootID = root.ID
		f.spaces = append(f.spaces, sp)
		roots = append(roots, root.ID)
	}
	r := newResolver(remoteClient(t, f))
	ctx := context.Background()
	for in, want := range map[string]string{"/Team/Équipe": roots[0], "/Team/équipe": roots[1], "/Team/design": f.teamRoot()} {
		if tg, err := r.resolve(ctx, in); err != nil || tg.Node == nil || tg.Node.ID != want {
			t.Errorf("%s: %+v %v; want %s", in, tg, err, want)
		}
	}
	if _, err := r.resolve(ctx, "/Team/ÉQUIPE"); !errors.Is(err, core.ErrInvalid) || !strings.Contains(err.Error(), "matches several groups") {
		t.Fatalf("ambiguous team folder: %v", err)
	}
}

// A requested invitation e-mail that was not queued is reported: the
// invitation exists, so the command succeeds, but it must not look sent.
func TestInviteCreateEmailNotSent(t *testing.T) {
	f := newFakeAPI(t)
	f.handle("POST", "/api/v1/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 201, core.InviteCreated{Invite: &core.Invite{ID: ids.New(ids.PrefixInvite), Role: core.RoleMember, MaxUses: 1,
			Email: "bob@example.com", ExpiresAt: time.Now().Add(time.Hour), EmailError: "the mail queue is full; try again later"},
			URL: "/invite/tok123"})
	})
	res := f.run(t, "", "invite", "create", "--email", "bob@example.com", "--send")
	if res.code != 0 || !strings.Contains(res.stdout, "/invite/tok123") ||
		!strings.Contains(res.stderr, "not sent (the mail queue is full; try again later)") {
		t.Fatalf("invite create: %+v", res)
	}
}
