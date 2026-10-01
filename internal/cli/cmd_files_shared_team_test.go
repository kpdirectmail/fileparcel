package cli

import (
	"net/http"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// "/Team/<group>" also names a team folder the acting user reaches through a
// grant (to them, a group or a role) without being a member of the group:
// the resolver falls back to GET /shared-with-me, where the team folder's
// root carries the group's name. Deeper shared folders never count as team
// folders, and a server without the route leaves the usual error.
func TestTeamPathThroughSharedGrant(t *testing.T) {
	f := newFakeAPI(t)
	spaceID := ids.New(ids.PrefixSpace)
	root := &fakeNode{Node: core.Node{ID: ids.New(ids.PrefixNode), SpaceID: spaceID, Kind: core.KindFolder, Name: "Finance",
		Perm: core.PermManage}}
	f.mu.Lock()
	f.nodes[root.ID] = root
	f.mu.Unlock()
	f.addFile(root.ID, "budget.xlsx", []byte("numbers"))
	// A folder named like a group, shared from deeper inside someone's files.
	deep := f.addFolder(f.myRoot(), "Marketing")
	f.handle(http.MethodGet, "/api/v1/shared-with-me", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		items := []core.Node{root.Node, f.nodes[deep].Node}
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, core.Page[core.Node]{Items: items})
	})

	for _, p := range []string{"/Team/Finance", "/Team/finance"} {
		res := f.run(t, "", "files", "ls", p)
		if res.code != 0 || !strings.Contains(res.stdout, "budget.xlsx") {
			t.Fatalf("files ls %s: %d %q %q", p, res.code, res.stdout, res.stderr)
		}
	}
	if res := f.run(t, "", "files", "ls", "/Team/Marketing"); res.code == 0 || !strings.Contains(res.stderr, `no team folder "Marketing"`) {
		t.Fatalf("a shared folder that is not a team folder: %d %q %q", res.code, res.stdout, res.stderr)
	}
	// Member of the group: the space wins, no extra request.
	before := f.requested("GET /api/v1/shared-with-me")
	if res := f.run(t, "", "files", "ls", "/Team/Design"); res.code != 0 || f.requested("GET /api/v1/shared-with-me") != before {
		t.Fatalf("files ls /Team/Design: %d %q (shared-with-me asked %d times)", res.code, res.stderr,
			f.requested("GET /api/v1/shared-with-me")-before)
	}
}
