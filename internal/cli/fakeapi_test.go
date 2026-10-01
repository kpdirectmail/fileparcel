package cli

// A fake FileParcel REST API (httptest) speaking the core shapes, used to
// test the commands end to end over the remote transport (--server/--token):
// an in-memory file tree (spaces, folders, files with content, trash,
// versions), the parted upload protocol, archives, jobs and a hook for
// per-test extra routes.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/cli/clikit"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// fakeToken is the bearer token the fake API accepts.
const fakeToken = "fpt_test_token"

// fakeTransport is the request header by which the fake's handlers tell
// admin socket requests ("socket") from remote ones.
const fakeTransport = "X-Fake-Transport"

type fakeNode struct {
	core.Node
	data     []byte
	versions []core.FileVersion
	vdata    map[string][]byte
}

type fakeUpFile struct {
	state core.UploadFileState
	parts map[int][]byte
	mtime int64
}

type fakeBatch struct {
	batch core.UploadBatch
	in    core.BatchInput
	files []*fakeUpFile
}

type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server
	r   chi.Router

	mu       sync.Mutex
	me       core.Me
	spaces   []core.Space
	nodes    map[string]*fakeNode
	pageSize int // children page size (small, to exercise pagination)

	// uploads
	partSize, smallMax int64
	parallel           int
	batches            map[string]*fakeBatch
	upFiles            map[string]*fakeUpFile
	partFailures       map[string]int         // "upf/n" → remaining 503 answers
	partPuts           map[string]int         // "upf/n" → PUT count
	preDone            func(rel string) []int // parts already present at batch creation
	preData            func(rel string, n int) []byte
	zipJobStates       []string                      // states returned by successive job polls
	aborted            []string                      // aborted batch ids
	partHook           func(upf string, n int) error // optional error injection
	zipUnknown         bool                          // a server from before zip passwords (422 unknown field)
	zipMin             int                           // storage.zip_password_min (0: the default 12)

	// downloads
	rangeHeaders []string
	tickets      map[string]core.ArchiveInput

	// jobs
	jobs map[string]*fakeJob

	// requests records "METHOD path" of every request.
	requests []string
	// bodies records the raw JSON body of every request by "METHOD path".
	bodies map[string][]byte
	// actAs records the X-FP-As header of every request ("METHOD path" →
	// the last value; "" when absent).
	actAs map[string]string
	// queries records the raw query of the last request to "METHOD path".
	queries map[string]string
	// permAs, when set, decides GET /nodes/{id} for a request with X-FP-As:
	// the node's permission for that user (PermNone answers 404).
	permAs func(as string, n *fakeNode) core.Perm
}

type fakeJob struct {
	states []string // successive states; the last one sticks
	job    core.Job
	polls  int
}

// newFakeAPI starts a fake server with one user ("alice"), her personal
// space and one team folder ("Design").
func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{
		t: t, nodes: map[string]*fakeNode{}, pageSize: 2,
		partSize: 64 << 10, smallMax: 64 << 10, parallel: 3,
		batches: map[string]*fakeBatch{}, upFiles: map[string]*fakeUpFile{},
		partFailures: map[string]int{}, partPuts: map[string]int{},
		tickets: map[string]core.ArchiveInput{}, jobs: map[string]*fakeJob{},
		bodies: map[string][]byte{}, actAs: map[string]string{}, queries: map[string]string{},
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	uid := ids.New(ids.PrefixUser)
	mySpace := core.Space{ID: ids.New(ids.PrefixSpace), Kind: core.SpaceUser, OwnerUserID: uid, Name: "alice", CreatedAt: now, Perm: core.PermOwner}
	gid := ids.New(ids.PrefixGroup)
	teamSpace := core.Space{ID: ids.New(ids.PrefixSpace), Kind: core.SpaceGroup, GroupID: gid, Name: "Design", CreatedAt: now, Perm: core.PermManage}
	for _, sp := range []*core.Space{&mySpace, &teamSpace} {
		root := &fakeNode{Node: core.Node{ID: ids.New(ids.PrefixNode), SpaceID: sp.ID, Kind: core.KindFolder, Name: sp.Name,
			CreatedAt: now, UpdatedAt: now, Perm: sp.Perm}}
		f.nodes[root.ID] = root
		sp.RootID = root.ID
	}
	f.spaces = []core.Space{mySpace, teamSpace}
	f.me = core.Me{User: &core.User{ID: uid, Username: "alice", Role: core.RoleOwner}, SpaceID: mySpace.ID,
		GroupSpaceIDs: map[string]string{gid: teamSpace.ID},
		Groups:        []core.Group{{ID: gid, Name: "Design", SpaceID: teamSpace.ID, MyRole: core.GroupRoleManager}}, Via: core.ViaToken}

	r := chi.NewRouter()
	r.Use(f.middleware)
	// Like the server's API router: a route it does not have is a JSON 404.
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { writeErr(w, core.NotFoundf("no such API endpoint")) })
	f.r = r
	f.routes()
	f.srv = httptest.NewServer(r)
	t.Cleanup(f.srv.Close)
	return f
}

// myRoot / teamRoot return the root folder ids.
func (f *fakeAPI) myRoot() string   { return f.spaces[0].RootID }
func (f *fakeAPI) teamRoot() string { return f.spaces[1].RootID }

func (f *fakeAPI) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fakeToken && strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, core.ErrUnauthorized)
			return
		}
		key := r.Method + " " + r.URL.Path
		f.mu.Lock()
		f.requests = append(f.requests, key)
		f.actAs[key] = r.Header.Get("X-FP-As")
		f.queries[key] = r.URL.RawQuery
		f.mu.Unlock()
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") && r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.bodies[key] = b
			f.mu.Unlock()
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		next.ServeHTTP(w, r)
	})
}

// handle registers an extra route (for per-test admin endpoints).
func (f *fakeAPI) handle(method, pattern string, h http.HandlerFunc) {
	f.r.MethodFunc(method, pattern, h)
}

// requested reports how many requests matched "METHOD path".
func (f *fakeAPI) requested(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r == key {
			n++
		}
	}
	return n
}

// requestedPrefix counts requests starting with prefix ("PUT /api/v1/uploads/").
func (f *fakeAPI) requestedPrefix(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

// body returns the last JSON body sent to "METHOD path".
func (f *fakeAPI) body(key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[key]
}

// query returns the raw query of the last request to "METHOD path".
func (f *fakeAPI) query(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries[key]
}

// as returns the X-FP-As header of the last request to "METHOD path"
// (ok false when there was none).
func (f *fakeAPI) as(key string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.actAs[key]
	return v, ok
}

// socketHome serves the fake API on the admin socket of a new home as well
// (the admin socket transport: no token, X-FP-As for --as) and returns the
// home directory for --home.
func (f *fakeAPI) socketHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fpcli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h, err := home.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	if err := config.Default(config.NewInstallID()).SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	if len(h.Socket()) > 100 {
		t.Skipf("socket path %s is too long for this test", h.Socket())
	}
	l, err := net.Listen("unix", h.Socket())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+fakeToken) // the socket needs no token
		r.Header.Set(fakeTransport, "socket")
		f.r.ServeHTTP(w, r)
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { srv.Close() })
	return h.Dir()
}

// runSocket runs the command tree against the fake over the admin socket of
// dir (from socketHome).
func (f *fakeAPI) runSocket(t *testing.T, dir, stdin string, args ...string) cliResult {
	t.Helper()
	return runArgs(t, stdin, append([]string{"--home", dir, "--no-color"}, args...)...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	ce := core.AsError(err)
	if ce == nil {
		ce = core.ErrInternal
	}
	writeJSON(w, ce.HTTPStatus(), map[string]any{"error": map[string]string{"code": ce.Code, "message": ce.Message, "field": ce.Field}})
}

func decodeBody[T any](r *http.Request) (T, error) {
	var v T
	err := json.NewDecoder(r.Body).Decode(&v)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return v, err
}

// ---------- tree helpers (call with f.mu held) ----------

func (f *fakeAPI) childrenOf(id string) []*fakeNode {
	var out []*fakeNode
	for _, n := range f.nodes {
		if n.ParentID == id && n.TrashedAt == nil {
			out = append(out, n)
		}
	}
	slices.SortFunc(out, func(a, b *fakeNode) int {
		if a.IsDir() != b.IsDir() {
			if a.IsDir() {
				return -1
			}
			return 1
		}
		return strings.Compare(names.Key(a.Name), names.Key(b.Name))
	})
	return out
}

func (f *fakeAPI) childByName(parent, name string) *fakeNode {
	key := names.Key(name)
	for _, n := range f.childrenOf(parent) {
		if names.Key(n.Name) == key {
			return n
		}
	}
	return nil
}

// spacePath returns "/a/b" of n within its space ("" for a root).
func (f *fakeAPI) spacePath(n *fakeNode) string {
	var parts []string
	for cur := n; cur != nil && cur.ParentID != ""; cur = f.nodes[cur.ParentID] {
		parts = append([]string{cur.Name}, parts...)
	}
	return "/" + strings.Join(parts, "/")
}

func (f *fakeAPI) newNode(parent *fakeNode, kind, name string, data []byte) *fakeNode {
	now := time.Now().UTC().Truncate(time.Second)
	n := &fakeNode{Node: core.Node{ID: ids.New(ids.PrefixNode), SpaceID: parent.SpaceID, ParentID: parent.ID, Kind: kind,
		Name: name, CreatedAt: now, UpdatedAt: now, Perm: parent.Perm}}
	if kind == core.KindFile {
		f.setContent(n, data)
	}
	f.nodes[n.ID] = n
	return n
}

// setContent adds a new version with data (older versions are kept).
func (f *fakeAPI) setContent(n *fakeNode, data []byte) {
	h := clikit.NewContentHasher()
	h.Write(data)
	v := core.FileVersion{ID: ids.New(ids.PrefixVersion), NodeID: n.ID, Size: int64(len(data)), ContentHash: h.Sum(), CreatedAt: time.Now().UTC()}
	for i := range n.versions {
		n.versions[i].Current = false
	}
	v.Current = true
	n.versions = append(n.versions, v)
	if n.vdata == nil {
		n.vdata = map[string][]byte{}
	}
	n.vdata[v.ID] = data
	n.data, n.Size, n.ContentHash, n.VersionID = data, v.Size, v.ContentHash, v.ID
}

// addFile / addFolder create nodes below a parent (test setup).
func (f *fakeAPI) addFolder(parentID, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newNode(f.nodes[parentID], core.KindFolder, name, nil).ID
}

func (f *fakeAPI) addFile(parentID, name string, data []byte) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newNode(f.nodes[parentID], core.KindFile, name, data).ID
}

// lookup returns the node at a space-relative path ("Docs/a.txt") below root.
func (f *fakeAPI) lookup(root, rel string) *fakeNode {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur := f.nodes[root]
	for _, seg := range strings.Split(strings.Trim(rel, "/"), "/") {
		if seg == "" {
			continue
		}
		if cur = f.childByName(cur.ID, seg); cur == nil {
			return nil
		}
	}
	return cur
}

func (f *fakeAPI) view(n *fakeNode) core.Node {
	v := n.Node
	if n.IsDir() {
		c := int64(len(f.childrenOf(n.ID)))
		v.ChildCount = &c
	}
	return v
}

// ---------- routes ----------

func (f *fakeAPI) routes() {
	r := f.r
	r.Get("/api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(fakeTransport) == "socket" && r.Header.Get("X-FP-As") == "" {
			// The admin socket's system principal: no account, no files.
			writeJSON(w, 200, core.Me{User: &core.User{Username: "system", DisplayName: "System", Role: core.RoleSystem}, Via: core.ViaSocket})
			return
		}
		writeJSON(w, 200, f.me)
	})
	r.Get("/api/v1/spaces", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, f.spaces) })
	r.Get("/api/v1/network/urls", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, []core.AccessURL{{URL: "https://fileparcel.local:8443/", Kind: core.URLKindMDNS, Recommended: true}})
	})
	r.Get("/api/v1/nodes/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := f.nodes[chi.URLParam(r, "id")]
		if n == nil || n.TrashedAt != nil {
			writeErr(w, core.NotFoundf("not found"))
			return
		}
		v := f.view(n)
		if as := r.Header.Get("X-FP-As"); as != "" && f.permAs != nil {
			if v.Perm = f.permAs(as, n); v.Perm == core.PermNone {
				writeErr(w, core.NotFoundf("not found"))
				return
			}
		}
		writeJSON(w, 200, v)
	})
	r.Get("/api/v1/nodes/{id}/children", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := f.nodes[chi.URLParam(r, "id")]
		if n == nil || !n.IsDir() {
			writeErr(w, core.NotFoundf("folder not found"))
			return
		}
		kids := f.childrenOf(n.ID)
		start, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
		end := min(start+f.pageSize, len(kids))
		items := []core.Node{}
		for _, k := range kids[start:end] {
			items = append(items, f.view(k))
		}
		next := ""
		if end < len(kids) {
			next = strconv.Itoa(end)
		}
		writeJSON(w, 200, core.Page[core.Node]{Items: items, NextCursor: next})
	})
	r.Get("/api/v1/nodes/{id}/breadcrumbs", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []core.Node
		for cur := f.nodes[chi.URLParam(r, "id")]; cur != nil; cur = f.nodes[cur.ParentID] {
			out = append([]core.Node{cur.Node}, out...)
		}
		writeJSON(w, 200, out)
	})
	r.Get("/api/v1/nodes/{id}/stats", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		st := core.FolderStats{NodeID: chi.URLParam(r, "id")}
		var walk func(id string)
		walk = func(id string) {
			for _, k := range f.childrenOf(id) {
				if k.IsDir() {
					st.Folders++
					walk(k.ID)
				} else {
					st.Files++
					st.Bytes += k.Size
				}
			}
		}
		walk(st.NodeID)
		writeJSON(w, 200, st)
	})
	r.Post("/api/v1/nodes/{id}/folders", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.NameInput](r)
		f.mu.Lock()
		defer f.mu.Unlock()
		p := f.nodes[chi.URLParam(r, "id")]
		if p == nil {
			writeErr(w, core.NotFoundf("folder not found"))
			return
		}
		if _, _, err := names.Clean(in.Name); err != nil {
			writeErr(w, core.Invalid("name", err.Error()))
			return
		}
		if f.childByName(p.ID, in.Name) != nil {
			writeErr(w, core.Errorf(core.ErrConflict, "%q already exists", in.Name))
			return
		}
		writeJSON(w, 201, f.view(f.newNode(p, core.KindFolder, in.Name, nil)))
	})
	r.Patch("/api/v1/nodes/{id}", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.NameInput](r)
		f.mu.Lock()
		defer f.mu.Unlock()
		n := f.nodes[chi.URLParam(r, "id")]
		if n == nil {
			writeErr(w, core.NotFoundf("not found"))
			return
		}
		if o := f.childByName(n.ParentID, in.Name); o != nil && o.ID != n.ID {
			writeErr(w, core.Errorf(core.ErrConflict, "%q already exists", in.Name))
			return
		}
		n.Name = in.Name
		writeJSON(w, 200, f.view(n))
	})
	moveCopy := func(copyMode bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			in, _ := decodeBody[core.MoveInput](r)
			f.mu.Lock()
			defer f.mu.Unlock()
			dest := f.nodes[in.Dest]
			if dest == nil || !dest.IsDir() {
				writeErr(w, core.NotFoundf("destination not found"))
				return
			}
			out := []core.Node{}
			for _, id := range in.IDs {
				n := f.nodes[id]
				if n == nil {
					writeErr(w, core.NotFoundf("not found"))
					return
				}
				name := n.Name
				if o := f.childByName(dest.ID, name); o != nil && (copyMode || o.ID != n.ID) {
					switch in.Conflict {
					case core.ConflictSkip:
						continue
					case core.ConflictRename:
						for i := 1; f.childByName(dest.ID, name) != nil; i++ {
							name = names.Numbered(n.Name, i, n.IsDir())
						}
					default:
						writeErr(w, core.Errorf(core.ErrConflict, "%q already exists", name))
						return
					}
				}
				if copyMode {
					c := f.newNode(dest, n.Kind, name, n.data)
					out = append(out, f.view(c))
					continue
				}
				n.ParentID, n.SpaceID, n.Name = dest.ID, dest.SpaceID, name
				out = append(out, f.view(n))
			}
			writeJSON(w, 200, out)
		}
	}
	r.Post("/api/v1/nodes/move", moveCopy(false))
	r.Post("/api/v1/nodes/copy", moveCopy(true))
	r.Post("/api/v1/nodes/trash", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.NodeIDsInput](r)
		f.mu.Lock()
		defer f.mu.Unlock()
		now := time.Now().UTC()
		for _, id := range in.IDs {
			n := f.nodes[id]
			if n == nil {
				writeErr(w, core.NotFoundf("not found"))
				return
			}
			n.Path = f.spacePath(n)
			n.TrashedAt, n.TrashRoot = &now, true
		}
		w.WriteHeader(http.StatusNoContent)
	})
	r.Get("/api/v1/trash", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		items := []core.Node{}
		for _, n := range f.nodes {
			if n.TrashRoot {
				items = append(items, n.Node)
			}
		}
		slices.SortFunc(items, func(a, b core.Node) int { return strings.Compare(a.Name, b.Name) })
		writeJSON(w, 200, core.Page[core.Node]{Items: items})
	})
	r.Post("/api/v1/trash/restore", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.NodeIDsInput](r)
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []core.Node{}
		for _, id := range in.IDs {
			if n := f.nodes[id]; n != nil && n.TrashRoot {
				n.TrashedAt, n.TrashRoot, n.Path = nil, false, ""
				out = append(out, n.Node)
			}
		}
		writeJSON(w, 200, out)
	})
	r.Post("/api/v1/trash/purge", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.NodeIDsInput](r)
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, id := range in.IDs {
			delete(f.nodes, id)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	r.Delete("/api/v1/trash", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for id, n := range f.nodes {
			if n.TrashRoot {
				delete(f.nodes, id)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	r.Get("/api/v1/search", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		q := strings.ToLower(r.URL.Query().Get("q"))
		items := []core.Node{}
		for _, n := range f.nodes {
			if n.ParentID != "" && n.TrashedAt == nil && strings.Contains(strings.ToLower(n.Name), q) {
				v := n.Node
				v.Path = f.spacePath(n)
				items = append(items, v)
			}
		}
		slices.SortFunc(items, func(a, b core.Node) int { return strings.Compare(a.Path, b.Path) })
		writeJSON(w, 200, core.Page[core.Node]{Items: items})
	})
	r.Get("/api/v1/nodes/{id}/versions", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := f.nodes[chi.URLParam(r, "id")]
		if n == nil {
			writeErr(w, core.NotFoundf("not found"))
			return
		}
		writeJSON(w, 200, n.versions)
	})
	r.Get("/api/v1/nodes/{id}/content", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		n := f.nodes[chi.URLParam(r, "id")]
		if rg := r.Header.Get("Range"); rg != "" {
			f.rangeHeaders = append(f.rangeHeaders, rg+"|"+r.Header.Get("If-Range"))
		}
		var data []byte
		etag := ""
		if n != nil {
			data, etag = n.data, n.VersionID
			if v := r.URL.Query().Get("version"); v != "" {
				data, etag = n.vdata[v], v
			}
		}
		f.mu.Unlock()
		if n == nil || n.IsDir() {
			writeErr(w, core.NotFoundf("not found"))
			return
		}
		w.Header().Set("ETag", strconv.Quote(etag))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, n.Name, time.Time{}, bytes.NewReader(data))
	})
	r.Post("/api/v1/archives", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.ArchiveInput](r)
		tk := ids.Token(16)
		f.mu.Lock()
		f.tickets[tk] = in
		f.mu.Unlock()
		writeJSON(w, 200, core.ArchiveTicketResponse{Ticket: tk, URL: "/api/v1/archives/" + tk})
	})
	r.Get("/api/v1/archives/{ticket}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		in, ok := f.tickets[chi.URLParam(r, "ticket")]
		delete(f.tickets, chi.URLParam(r, "ticket"))
		f.mu.Unlock()
		if !ok {
			writeErr(w, core.NotFoundf("ticket not found"))
			return
		}
		w.Header().Set("Content-Type", "application/"+in.Format)
		fmt.Fprintf(w, "ARCHIVE %s %s %s", in.Format, in.Name, strings.Join(in.NodeIDs, ","))
	})
	f.uploadRoutes()
	job := func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		j := f.jobs[chi.URLParam(r, "id")]
		if j == nil {
			writeErr(w, core.NotFoundf("job not found"))
			return
		}
		i := min(j.polls, len(j.states)-1)
		j.polls++
		j.job.State = j.states[i]
		if j.job.State == core.JobRunning {
			j.job.ProgressDone, j.job.ProgressTotal = int64(j.polls), int64(len(j.states))
		}
		writeJSON(w, 200, j.job)
	}
	r.Get("/api/v1/jobs/{id}", job)
	r.Get("/api/v1/admin/jobs/{id}", job)
}

// addJob registers a job whose polls return states in order.
func (f *fakeAPI) addJob(kind string, result any, states ...string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := ids.New(ids.PrefixJob)
	j := core.Job{ID: id, Kind: kind, CreatedAt: time.Now().UTC()}
	if result != nil {
		j.Result, _ = json.Marshal(result)
	}
	if slices.Contains(states, core.JobFailed) {
		j.Error = "simulated failure"
	}
	f.jobs[id] = &fakeJob{states: states, job: j}
	return id
}

// ---------- uploads ----------

func (f *fakeAPI) uploadRoutes() {
	r := f.r
	addFiles := func(b *fakeBatch, in []core.UploadFileInput) ([]core.UploadFileState, error) {
		var out []core.UploadFileState
		for _, fi := range in {
			if _, err := names.SplitRelPath(fi.RelPath); err != nil {
				return nil, core.Invalid("rel_path", err.Error())
			}
			kind := fi.Kind
			if kind == "" {
				kind = core.UploadKindFile
			}
			st := core.UploadFileState{ID: ids.New(ids.PrefixUploadFile), BatchID: b.batch.ID, ClientRef: fi.ClientRef,
				RelPath: fi.RelPath, Kind: kind, Size: fi.Size, PartsDone: []int{}, State: core.UploadPending}
			uf := &fakeUpFile{parts: map[int][]byte{}, mtime: fi.MTime}
			if kind == core.UploadKindFile && fi.Size > f.smallMax {
				st.PartCount = int((fi.Size + f.partSize - 1) / f.partSize)
				if f.preDone != nil {
					for _, n := range f.preDone(fi.RelPath) {
						uf.parts[n] = f.preData(fi.RelPath, n)
						st.PartsDone = append(st.PartsDone, n)
					}
				}
			}
			if kind == core.UploadKindDir {
				st.State = core.UploadCommitted
				if b.batch.Mode != core.UploadModeZip {
					dir := f.nodes[b.batch.FolderID]
					for _, s := range strings.Split(fi.RelPath, "/") {
						next := f.childByName(dir.ID, s)
						if next == nil {
							next = f.newNode(dir, core.KindFolder, s, nil)
						}
						dir = next
					}
				}
			}
			// As the server (uploads/preflight.go): under conflict skip a
			// file whose name is taken is declared skipped, nothing is sent.
			if kind == core.UploadKindFile && b.batch.Mode != core.UploadModeZip && b.batch.Conflict == core.ConflictSkip {
				cur := f.nodes[b.batch.FolderID]
				for _, s := range strings.Split(fi.RelPath, "/") {
					if cur = f.childByName(cur.ID, s); cur == nil {
						break
					}
				}
				if cur != nil {
					st.State = core.UploadSkipped
				}
			}
			uf.state = st
			b.files = append(b.files, uf)
			f.upFiles[st.ID] = uf
			out = append(out, st)
		}
		return out, nil
	}
	r.Post("/api/v1/upload-batches", func(w http.ResponseWriter, r *http.Request) {
		in, err := decodeBody[core.BatchInput](r)
		if err != nil {
			writeErr(w, core.Invalid("", err.Error()))
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		folder := f.nodes[in.FolderID]
		if folder == nil || !folder.IsDir() {
			writeErr(w, core.NotFoundf("folder not found"))
			return
		}
		// The zip fields as the server checks them (zip-password-final §4.1).
		zipEnc := ""
		if in.ZipPassword != "" || in.ZipEncryption != "" {
			field := "zip_password"
			if in.ZipPassword == "" {
				field = "zip_encryption"
			}
			switch zipEnc = in.ZipEncryption; {
			case f.zipUnknown:
				writeErr(w, core.Invalid(field, "unknown field"))
				return
			case in.Mode != core.UploadModeZip:
				writeErr(w, core.Invalid(field, "a password needs mode zip"))
				return
			case zipEnc != "" && zipEnc != core.ZipEncAES256 && zipEnc != core.ZipEncZipCrypto:
				writeErr(w, core.Invalid("zip_encryption", "must be aes256 or zipcrypto"))
				return
			case len([]rune(in.ZipPassword.Reveal())) < cmp.Or(f.zipMin, 12):
				writeErr(w, core.Invalid("zip_password", fmt.Sprintf("the password must be at least %d characters long", cmp.Or(f.zipMin, 12))))
				return
			case zipEnc == "":
				zipEnc = core.ZipEncAES256
			}
		}
		b := &fakeBatch{in: in, batch: core.UploadBatch{ID: ids.New(ids.PrefixUploadBatch), FolderID: in.FolderID, Mode: in.Mode,
			ZipName: in.ZipName, ZipEncryption: zipEnc, Conflict: in.Conflict, State: core.BatchOpen, PartSize: f.partSize,
			Parallel: f.parallel, SmallMax: f.smallMax}}
		sts, err := addFiles(b, in.Files)
		if err != nil {
			writeErr(w, err)
			return
		}
		f.batches[b.batch.ID] = b
		out := b.batch
		out.Files = sts
		writeJSON(w, 201, out)
	})
	r.Post("/api/v1/upload-batches/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		in, err := decodeBody[[]core.UploadFileInput](r)
		if err != nil {
			writeErr(w, core.Invalid("", err.Error()))
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		b := f.batches[chi.URLParam(r, "id")]
		if b == nil {
			writeErr(w, core.NotFoundf("batch not found"))
			return
		}
		b.in.Files = append(b.in.Files, in...)
		sts, err := addFiles(b, in)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, sts)
	})
	readBody := func(r *http.Request) ([]byte, error) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if got := r.Header.Get("X-FP-SHA256"); got != hex.EncodeToString(sum[:]) {
			return nil, core.Invalid("sha256", "digest mismatch: header "+got)
		}
		return data, nil
	}
	r.Put("/api/v1/upload-batches/{id}/small", func(w http.ResponseWriter, r *http.Request) {
		data, err := readBody(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		b := f.batches[chi.URLParam(r, "id")]
		if b == nil {
			writeErr(w, core.NotFoundf("batch not found"))
			return
		}
		ref := r.URL.Query().Get("ref")
		for _, uf := range b.files {
			if uf.state.ClientRef == ref {
				if int64(len(data)) != uf.state.Size || uf.state.Size > f.smallMax {
					writeErr(w, core.Invalid("size", "size mismatch"))
					return
				}
				uf.parts[0] = data
				f.commitFile(b, uf)
				writeJSON(w, 200, uf.state)
				return
			}
		}
		writeErr(w, core.NotFoundf("no such file in the batch"))
	})
	r.Put("/api/v1/uploads/{id}/parts/{n}", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		n, _ := strconv.Atoi(chi.URLParam(r, "n"))
		key := fmt.Sprintf("%s/%d", id, n)
		f.mu.Lock()
		f.partPuts[key]++
		fail := f.partFailures[key]
		if fail > 0 {
			f.partFailures[key]--
		}
		hook := f.partHook
		f.mu.Unlock()
		if fail > 0 {
			_, _ = io.Copy(io.Discard, r.Body)
			writeErr(w, core.ErrUnavailable)
			return
		}
		if hook != nil {
			if err := hook(id, n); err != nil {
				_, _ = io.Copy(io.Discard, r.Body)
				writeErr(w, err)
				return
			}
		}
		data, err := readBody(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		uf := f.upFiles[id]
		if uf == nil || n < 0 || n >= uf.state.PartCount {
			writeErr(w, core.NotFoundf("no such part"))
			return
		}
		want := min(f.partSize, uf.state.Size-int64(n)*f.partSize)
		if int64(len(data)) != want {
			writeErr(w, core.Invalid("size", fmt.Sprintf("part %d: got %d bytes, want %d", n, len(data), want)))
			return
		}
		uf.parts[n] = data
		if !slices.Contains(uf.state.PartsDone, n) {
			uf.state.PartsDone = append(uf.state.PartsDone, n)
		}
		uf.state.State = core.UploadUploading
		w.WriteHeader(http.StatusNoContent)
	})
	r.Post("/api/v1/uploads/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		uf := f.upFiles[chi.URLParam(r, "id")]
		if uf == nil {
			writeErr(w, core.NotFoundf("upload not found"))
			return
		}
		if len(uf.parts) != uf.state.PartCount {
			writeErr(w, core.Errorf(core.ErrConflict, "parts missing: have %d of %d", len(uf.parts), uf.state.PartCount))
			return
		}
		f.commitFile(f.batches[uf.state.BatchID], uf)
		writeJSON(w, 200, uf.state)
	})
	r.Post("/api/v1/upload-batches/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b := f.batches[chi.URLParam(r, "id")]
		if b == nil {
			writeErr(w, core.NotFoundf("batch not found"))
			return
		}
		for _, uf := range b.files {
			if uf.state.Kind == core.UploadKindFile && uf.state.State != core.UploadCommitted && uf.state.State != core.UploadSkipped &&
				uf.state.State != core.UploadUploaded {
				writeErr(w, core.Errorf(core.ErrConflict, "%s is not complete", uf.state.RelPath))
				return
			}
		}
		if b.batch.Mode == core.UploadModeZip {
			states := f.zipJobStates
			if len(states) == 0 {
				states = []string{core.JobRunning, core.JobSucceeded}
			}
			id := ids.New(ids.PrefixJob)
			f.jobs[id] = &fakeJob{states: states, job: core.Job{ID: id, Kind: core.JobUploadZip}}
			b.batch.State, b.batch.JobID = core.BatchFinalizing, id
			// The zip "job" builds the archive right away (only the job state
			// is polled) and commits it with the batch's conflict policy, as
			// the server does: rename → "NAME (1).zip", skip → no node and
			// every file skipped, fail → the job fails.
			folder := f.nodes[b.batch.FolderID]
			var buf bytes.Buffer
			for _, uf := range b.files {
				fmt.Fprintf(&buf, "%s:%d;", uf.state.RelPath, uf.state.Size)
			}
			name, state := b.batch.ZipName, core.UploadCommitted
			var node *fakeNode
			if ex := f.childByName(folder.ID, name); ex != nil {
				switch b.batch.Conflict {
				case core.ConflictSkip:
					state = core.UploadSkipped
				case core.ConflictReplace:
					f.setContent(ex, buf.Bytes())
					node = ex
				case core.ConflictFail:
					f.jobs[id].states = []string{core.JobFailed}
					state = ""
				default:
					for i := 1; f.childByName(folder.ID, name) != nil; i++ {
						name = names.Numbered(b.batch.ZipName, i, false)
					}
				}
			}
			if node == nil && state == core.UploadCommitted {
				node = f.newNode(folder, core.KindFile, name, buf.Bytes())
			}
			if node != nil {
				b.batch.ResultNodeID = node.ID
				node.ZipEncryption = b.batch.ZipEncryption
			}
			for _, uf := range b.files {
				if state != "" && uf.state.Kind == core.UploadKindFile {
					uf.state.State = state
				}
			}
			writeJSON(w, 200, map[string]string{"state": core.BatchFinalizing, "job_id": id, "id": b.batch.ID})
			return
		}
		b.batch.State = core.BatchDone
		out := b.batch
		for _, uf := range b.files {
			out.Files = append(out.Files, uf.state)
		}
		writeJSON(w, 200, out)
	})
	r.Get("/api/v1/upload-batches/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b := f.batches[chi.URLParam(r, "id")]
		if b == nil {
			writeErr(w, core.NotFoundf("batch not found"))
			return
		}
		out := b.batch
		if out.State == core.BatchFinalizing {
			out.State = core.BatchDone
		}
		for _, uf := range b.files {
			out.Files = append(out.Files, uf.state)
		}
		writeJSON(w, 200, out)
	})
	r.Delete("/api/v1/upload-batches/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := chi.URLParam(r, "id")
		f.aborted = append(f.aborted, id)
		if b := f.batches[id]; b != nil {
			b.batch.State = core.BatchAborted
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// commitFile assembles an uploaded file into the tree (mode files), creating
// missing folders and applying the batch's conflict policy. f.mu is held.
func (f *fakeAPI) commitFile(b *fakeBatch, uf *fakeUpFile) {
	uf.state.State = core.UploadUploaded
	if b.batch.Mode == core.UploadModeZip {
		return
	}
	var data []byte
	for i := 0; i < max(uf.state.PartCount, 1); i++ {
		data = append(data, uf.parts[i]...)
	}
	dir := f.nodes[b.batch.FolderID]
	segs := strings.Split(uf.state.RelPath, "/")
	for _, s := range segs[:len(segs)-1] {
		next := f.childByName(dir.ID, s)
		if next == nil {
			next = f.newNode(dir, core.KindFolder, s, nil)
		}
		dir = next
	}
	name := segs[len(segs)-1]
	if ex := f.childByName(dir.ID, name); ex != nil {
		switch b.batch.Conflict {
		case core.ConflictSkip:
			uf.state.State = core.UploadSkipped
			return
		case core.ConflictReplace:
			f.setContent(ex, data)
			uf.state.State, uf.state.NodeID = core.UploadCommitted, ex.ID
			return
		case core.ConflictFail:
			uf.state.State, uf.state.Error = core.UploadFailed, "exists"
			return
		}
		for i := 1; f.childByName(dir.ID, name) != nil; i++ {
			name = names.Numbered(segs[len(segs)-1], i, false)
		}
	}
	n := f.newNode(dir, core.KindFile, name, data)
	if uf.mtime > 0 {
		t := time.UnixMilli(uf.mtime).UTC()
		n.ClientMtime = &t
	}
	uf.state.State, uf.state.NodeID = core.UploadCommitted, n.ID
}

// ---------- running commands ----------

// cliResult is the outcome of one command run.
type cliResult struct {
	code           int
	stdout, stderr string
}

// runCLI runs the command tree with args against the fake server (remote
// transport) and returns exit code and output. stdin is optional.
func (f *fakeAPI) run(t *testing.T, stdin string, args ...string) cliResult {
	t.Helper()
	full := append([]string{"--server", f.srv.URL, "--token", fakeToken, "--no-color"}, args...)
	return runArgs(t, stdin, full...)
}

// runArgs runs the command tree with args (no transport flags added).
func runArgs(t *testing.T, stdin string, args ...string) cliResult {
	t.Helper()
	t.Setenv(TokenEnv, "")
	t.Setenv("NO_COLOR", "1")
	root := NewRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetIn(strings.NewReader(stdin))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code := run(ctx, root, args, &errb)
	return cliResult{code: code, stdout: out.String(), stderr: errb.String()}
}
