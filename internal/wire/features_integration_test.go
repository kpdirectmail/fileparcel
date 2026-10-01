package wire

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
	"fileparcel/internal/web/opsapi"
)

// v4 cross-feature integration (implementation plan §12.1): roles and
// permissions (A), password-protected zips (C), Tailscale Funnel/Serve (D)
// and the migrations of P0, driven together through a real server whose
// tailscaled is a fake (startFunnelServer). Each feature has its own tests;
// these check the places where they meet.

// v4Client is a browser-like session on the main HTTPS listener: the
// session cookie (rotated by step-up) and its CSRF token.
type v4Client struct {
	fs     *funnelServer
	name   string
	cookie string // "__Host-fp_session=…"
	csrf   string
}

// signIn opens a password session of user on the main listener.
func (fs *funnelServer) signIn(user string) *v4Client {
	fs.t.Helper()
	c := &v4Client{fs: fs, name: user}
	var res core.LoginResult
	code, raw, hdr := call(fs.t, fs.main, http.MethodPost, fs.https+"/api/v1/auth/login", nil,
		map[string]string{"username": user, "password": password(user)}, &res)
	if code != http.StatusOK || res.MFARequired || res.EnrollRequired {
		fs.t.Fatalf("sign-in of %s: %d %s", user, code, raw)
	}
	c.takeCookie(hdr)
	c.csrf = res.CSRF
	if c.cookie == "" {
		fs.t.Fatalf("sign-in of %s: no session cookie", user)
	}
	return c
}

func (c *v4Client) takeCookie(h http.Header) {
	for _, ck := range (&http.Response{Header: h}).Cookies() {
		if ck.Name == "__Host-fp_session" && ck.Value != "" {
			c.cookie = ck.Name + "=" + ck.Value
		}
	}
}

func (c *v4Client) headers() map[string]string {
	h := map[string]string{"Cookie": c.cookie}
	if c.csrf != "" {
		h["X-FP-CSRF"] = c.csrf
	}
	return h
}

// do sends a JSON request on the main listener; out receives a 2xx answer.
func (c *v4Client) do(method, path string, body, out any) (int, []byte) {
	c.fs.t.Helper()
	code, raw, hdr := call(c.fs.t, c.fs.main, method, c.fs.https+path, c.headers(), body, out)
	c.takeCookie(hdr)
	return code, raw
}

// elevate steps the session up with its password (the token is rotated).
func (c *v4Client) elevate() {
	c.fs.t.Helper()
	var res core.ElevateResult
	if code, raw := c.do(http.MethodPost, "/api/v1/auth/elevate", map[string]string{"password": password(c.name)}, &res); code != http.StatusOK {
		c.fs.t.Fatalf("step-up of %s: %d %s", c.name, code, raw)
	}
	if res.CSRF != "" {
		c.csrf = res.CSRF
	}
}

// putSmall uploads data as the file ref of an open batch (the small path).
func (c *v4Client) putSmall(batchID, ref string, data []byte) {
	c.fs.t.Helper()
	sum := sha256.Sum256(data)
	req, err := http.NewRequest(http.MethodPut, c.fs.https+"/api/v1/upload-batches/"+batchID+"/small?ref="+url.QueryEscape(ref),
		bytes.NewReader(data))
	if err != nil {
		c.fs.t.Fatal(err)
	}
	for k, v := range c.headers() {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-FP-SHA256", hex.EncodeToString(sum[:]))
	resp, err := c.fs.main.Do(req)
	if err != nil {
		c.fs.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		c.fs.t.Fatalf("small upload %s: %d %s", ref, resp.StatusCode, raw)
	}
}

// v4Stream is an open GET /api/v1/events of a session: the events it
// received ("<topic> <data>") and whether the server ended it.
type v4Stream struct {
	mu     sync.Mutex
	events []string
	done   chan struct{}
}

// stream opens the session's event stream and waits until the server has
// subscribed it to the bus.
func (c *v4Client) stream() *v4Stream {
	c.fs.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	before := c.fs.d.Bus.Subscribers()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.fs.https+"/api/v1/events", nil)
	if err != nil {
		c.fs.t.Fatal(err)
	}
	req.Header.Set("Cookie", c.cookie)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := (&http.Client{Transport: c.fs.main.Transport}).Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		cancel()
		c.fs.t.Fatalf("events of %s: %v %v", c.name, resp, err)
	}
	s := &v4Stream{done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		topic := ""
		for sc.Scan() {
			l := sc.Text()
			switch {
			case strings.HasPrefix(l, "event: "):
				topic = strings.TrimPrefix(l, "event: ")
			case strings.HasPrefix(l, "data: "):
				s.mu.Lock()
				s.events = append(s.events, topic+" "+strings.TrimPrefix(l, "data: "))
				s.mu.Unlock()
			}
		}
	}()
	c.fs.t.Cleanup(func() { cancel(); <-s.done })
	deadline := time.Now().Add(10 * time.Second)
	for c.fs.d.Bus.Subscribers() <= before {
		if time.Now().After(deadline) {
			c.fs.t.Fatalf("the event stream of %s did not subscribe", c.name)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return s
}

// got returns the data of the first received event of topic.
func (s *v4Stream) got(topic string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if t, data, _ := strings.Cut(e, " "); t == topic {
			return data, true
		}
	}
	return "", false
}

// wait waits up to d for an event of topic.
func (s *v4Stream) wait(topic string, d time.Duration) (string, bool) {
	deadline := time.Now().Add(d)
	for {
		if data, ok := s.got(topic); ok {
			return data, true
		}
		if time.Now().After(deadline) {
			return "", false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// closed reports whether the server ended the stream within d.
func (s *v4Stream) closed(d time.Duration) bool {
	select {
	case <-s.done:
		return true
	case <-time.After(d):
		return false
	}
}

func (s *v4Stream) topics() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.events {
		t, _, _ := strings.Cut(e, " ")
		out = append(out, t)
	}
	return out
}

// TestV4CrossFeature runs the plan §12.1 scenarios on one server in order:
// a custom role with network.manage runs Tailscale Funnel but cannot weaken
// its sign-in; the settings API refuses a delegate by permission before the
// managed-key rule; ingress.changed follows the permission and a role edit
// closes the affected stream; a guest-based role with a folder grant
// uploads a protected zip that a public link then shows over Funnel, where
// no session reaches the app; the doctor names a staff role without 2FA
// while administration over Funnel is allowed.
func TestV4CrossFeature(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a server")
	}
	fs := startFunnelServer(t)
	ctx := context.Background()

	// Password-only sessions for the staff accounts below (the default
	// policy would ask them to enrol a second factor first); the doctor
	// reports them without one at the end.
	if code, raw := fs.adminCall(http.MethodPatch, "/admin/settings", map[string]any{"auth.require_2fa": "off"}, nil); code != http.StatusOK {
		t.Fatalf("auth.require_2fa off: %d %s", code, raw)
	}

	// Roles: netops (Member + network.manage), helpers (Member +
	// settings.manage: a delegate without network.manage) and contractors
	// (based on Guest, no permission at all).
	roles := map[string]core.RoleDef{}
	for name, in := range map[string]core.RoleDefInput{
		"netops":      {Name: "netops", Base: core.RoleMember, Permissions: ptr(core.MemberCaps.With(core.CapNetworkManage).List())},
		"helpers":     {Name: "helpers", Base: core.RoleMember, Permissions: ptr(core.MemberCaps.With(core.CapSettingsManage).List())},
		"contractors": {Name: "contractors", Base: core.RoleGuest, Permissions: &[]core.Capability{}},
	} {
		var r core.RoleDef
		if code, raw := fs.adminCall(http.MethodPost, "/admin/roles", in, &r); code != http.StatusCreated {
			t.Fatalf("create role %s: %d %s", name, code, raw)
		}
		roles[name] = r
	}
	if !roles["netops"].Staff || roles["contractors"].Staff || roles["contractors"].Permissions != 0 {
		t.Fatalf("roles %+v", roles)
	}
	users := map[string]*core.User{}
	for name, roleID := range map[string]string{"nina": roles["netops"].ID, "sam": roles["helpers"].ID,
		"mel": "member", "gus": roles["contractors"].ID, "adam": "admin"} {
		var res core.UserCreated
		if code, raw := fs.adminCall(http.MethodPost, "/admin/users", core.NewUser{Username: name, Password: password(name),
			RoleID: roleID}, &res); code != http.StatusCreated || res.User == nil || res.User.RoleID != roleID {
			t.Fatalf("create %s: %d %s", name, code, raw)
		}
		users[name] = res.User
	}

	// The team folder /Team/X: mel manages the group Team and creates X.
	var team core.Group
	if code, raw := fs.adminCall(http.MethodPost, "/admin/groups", core.GroupInput{Name: "Team"}, &team); code != http.StatusCreated {
		t.Fatalf("group: %d %s", code, raw)
	}
	if code, raw := fs.adminCall(http.MethodPut, "/admin/groups/"+team.ID+"/members/"+users["mel"].ID,
		core.RoleInput{Role: core.GroupRoleManager}, nil); code != http.StatusNoContent {
		t.Fatalf("mel into Team: %d %s", code, raw)
	}

	nina, sam, mel, gus, adam := fs.signIn("nina"), fs.signIn("sam"), fs.signIn("mel"), fs.signIn("gus"), fs.signIn("adam")
	var spaces []core.Space
	if code, raw := mel.do(http.MethodGet, "/api/v1/spaces", nil, &spaces); code != http.StatusOK {
		t.Fatalf("spaces of mel: %d %s", code, raw)
	}
	teamRoot := ""
	for _, s := range spaces {
		if s.ID == team.SpaceID {
			teamRoot = s.RootID
		}
	}
	var x core.Node
	if code, raw := mel.do(http.MethodPost, "/api/v1/nodes/"+teamRoot+"/folders", core.NameInput{Name: "X"}, &x); teamRoot == "" ||
		code >= 300 {
		t.Fatalf("mkdir /Team/X: %d %s", code, raw)
	}
	if code, raw := mel.do(http.MethodPost, "/api/v1/nodes/"+x.ID+"/grants", core.GrantInput{SubjectType: core.SubjectRole,
		SubjectID: roles["contractors"].ID, Role: core.GrantEditor}, nil); code >= 300 {
		t.Fatalf("editor grant to contractors: %d %s", code, raw)
	}

	// Funnel needs step-up, for a delegate as for an administrator.
	if code, raw := nina.do(http.MethodPut, "/api/v1/admin/network/funnel", core.FunnelInput{Mode: core.FunnelShares,
		Confirm: "public"}, nil); code != http.StatusForbidden || !strings.Contains(string(raw), "elevation_required") {
		t.Fatalf("funnel without step-up: %d %s", code, raw)
	}
	nina.elevate()
	adam.elevate()
	ninaEvents, melEvents := nina.stream(), mel.stream()

	t.Run("netops runs Funnel", func(t *testing.T) {
		var st core.IngressStatus
		if code, raw := nina.do(http.MethodPut, "/api/v1/admin/network/funnel", core.FunnelInput{Mode: core.FunnelShares,
			Confirm: "public"}, &st); code != http.StatusOK || st.Funnel.State != core.IngressStateActive {
			t.Fatalf("netops enables Funnel: %d %s", code, raw)
		}
		// ingress.changed reaches network.manage, not a plain member.
		if _, ok := ninaEvents.wait(events.TopicIngressChanged, 10*time.Second); !ok {
			t.Fatalf("no ingress.changed for netops: %v", ninaEvents.topics())
		}
		time.Sleep(time.Second)
		if _, ok := melEvents.got(events.TopicIngressChanged); ok {
			t.Fatalf("a member received ingress.changed: %v", melEvents.topics())
		}

		// Weakening sign-in over Funnel is the built-in administrators'.
		weaken := func(c *v4Client, in core.FunnelInput) (int, []byte) {
			in.Confirm = "public"
			return c.do(http.MethodPut, "/api/v1/admin/network/funnel", in, nil)
		}
		const refusal = "only an owner or administrator can weaken sign-in over the public Funnel address"
		if code, raw := weaken(nina, core.FunnelInput{Mode: core.FunnelShares, Require2FA: ptr(false)}); code != http.StatusForbidden ||
			!strings.Contains(string(raw), refusal) {
			t.Fatalf("netops turns require_2fa off: %d %s", code, raw)
		}
		if code, raw := weaken(nina, core.FunnelInput{Mode: core.FunnelApp}); code != http.StatusOK {
			t.Fatalf("netops switches to app mode: %d %s", code, raw)
		}
		if code, raw := weaken(nina, core.FunnelInput{Mode: core.FunnelApp, AllowAdmin: ptr(true)}); code != http.StatusForbidden ||
			!strings.Contains(string(raw), refusal) {
			t.Fatalf("netops turns allow_admin on: %d %s", code, raw)
		}
		page, err := fs.d.Audit.Query(ctx, core.AuditQuery{Action: core.ActNetworkFunnel, Outcome: core.OutcomeDenied})
		if err != nil {
			t.Fatal(err)
		}
		denied := 0
		for _, r := range page.Items {
			if r.ActorID == users["nina"].ID && strings.Contains(string(r.Details), `"reason":"rbac"`) {
				denied++
			}
		}
		if denied != 2 {
			t.Fatalf("network.funnel denied/rbac entries of netops: %d (%+v)", denied, page.Items)
		}
		// Back to share links only for the next subtest.
		if code, raw := weaken(nina, core.FunnelInput{Mode: core.FunnelShares}); code != http.StatusOK {
			t.Fatalf("netops back to shares: %d %s", code, raw)
		}
	})

	t.Run("settings: permission before the managed rule", func(t *testing.T) {
		body := map[string]any{"funnel.mode": "app"}
		if code, raw := sam.do(http.MethodPatch, "/api/v1/admin/settings", body, nil); code != http.StatusForbidden {
			t.Fatalf("a delegate without network.manage: %d %s", code, raw)
		}
		if code, raw := sam.do(http.MethodGet, "/api/v1/admin/network", nil, nil); code != http.StatusForbidden {
			t.Fatalf("GET /admin/network without network.manage: %d %s", code, raw)
		}
		if code, raw := adam.do(http.MethodPatch, "/api/v1/admin/settings", body, nil); code != http.StatusConflict ||
			!strings.Contains(string(raw), "funnel.mode") {
			t.Fatalf("an administrator: %d %s", code, raw)
		}
	})

	t.Run("protected zip from a guest-based role over Funnel", func(t *testing.T) {
		var me core.Me
		if code, raw := gus.do(http.MethodGet, "/api/v1/me", nil, &me); code != http.StatusOK || !me.Features["internet_links"] ||
			me.Features["links"] || me.Staff {
			t.Fatalf("/me of contractors: %d %s", code, raw)
		}
		const zipPassword = "integration zip passphrase"
		file := []byte("brief for the contractors\n")
		var batch core.UploadBatch
		if code, raw := gus.do(http.MethodPost, "/api/v1/upload-batches", core.BatchInput{FolderID: x.ID, Mode: core.UploadModeZip,
			ZipName: "Brief.zip", ZipPassword: core.Secret(zipPassword), Files: []core.UploadFileInput{{ClientRef: "a",
				RelPath: "Brief/a.txt", Size: int64(len(file))}}}, &batch); code != http.StatusCreated ||
			batch.ZipEncryption != core.ZipEncAES256 || strings.Contains(string(raw), zipPassword) {
			t.Fatalf("protected batch in /Team/X: %d %s", code, raw)
		}
		gus.putSmall(batch.ID, "a", file)
		if code, raw := gus.do(http.MethodPost, "/api/v1/upload-batches/"+batch.ID+"/complete", nil, &batch); code >= 300 ||
			batch.JobID == "" {
			t.Fatalf("complete: %d %s", code, raw)
		}
		var job core.Job
		deadline := time.Now().Add(60 * time.Second)
		for {
			if code, raw := gus.do(http.MethodGet, "/api/v1/jobs/"+batch.JobID, nil, &job); code != http.StatusOK {
				t.Fatalf("job: %d %s", code, raw)
			}
			if job.State == core.JobSucceeded || job.State == core.JobFailed || time.Now().After(deadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		var result struct {
			NodeID     string `json:"node_id"`
			Encryption string `json:"encryption"`
		}
		_ = json.Unmarshal(job.Result, &result)
		if job.State != core.JobSucceeded || result.NodeID == "" || result.Encryption != core.ZipEncAES256 ||
			strings.Contains(string(job.Params)+string(job.Result), zipPassword) {
			t.Fatalf("zip job %+v", job)
		}
		var node core.Node
		if code, raw := gus.do(http.MethodGet, "/api/v1/nodes/"+result.NodeID, nil, &node); code != http.StatusOK ||
			node.ZipEncryption != core.ZipEncAES256 || node.ParentID != x.ID {
			t.Fatalf("the zip node: %d %s", code, raw)
		}

		// No share links without shares.links, internet or not.
		if code, raw := gus.do(http.MethodPost, "/api/v1/shares", core.ShareInput{Kind: core.ShareLink, NodeID: node.ID}, nil); code != http.StatusForbidden {
			t.Fatalf("a link by a role without shares.links: %d %s", code, raw)
		}
		// mel's link carries the Funnel address, and the internet sees the
		// protection.
		var link core.Share
		if code, raw := mel.do(http.MethodPost, "/api/v1/shares", core.ShareInput{Kind: core.ShareLink, NodeID: node.ID}, &link); code != http.StatusCreated ||
			!strings.HasPrefix(link.URL, "https://node.tail.ts.net/s/") {
			t.Fatalf("mel's link: %d %s", code, raw)
		}
		token := strings.TrimPrefix(link.URL, "https://node.tail.ts.net/s/")
		var info core.PublicShareInfo
		if code, raw := fs.funnelCall(http.MethodGet, "/s/"+token+"/api", nil, nil, &info); code != http.StatusOK || info.Node == nil ||
			info.Node.ZipEncryption != core.ZipEncAES256 {
			t.Fatalf("the link over Funnel: %d %s", code, raw)
		}
		// An administrator's session reaches nothing of the app over
		// Funnel "shares" mode, the v4 routes included.
		for _, p := range []string{"/api/v1/me", "/api/v1/roles", "/api/v1/admin/roles", "/api/v1/admin/capabilities",
			"/api/v1/admin/grants", "/api/v1/admin/network/tailscale", "/api/v1/admin/users/" + users["gus"].ID + "/access"} {
			if code, raw := fs.funnelCall(http.MethodGet, p, map[string]string{"Cookie": adam.cookie}, nil, nil); code != http.StatusNotFound ||
				!strings.Contains(string(raw), "no such API endpoint") {
				t.Errorf("%s with the admin cookie over Funnel: %d %s", p, code, raw)
			}
		}
		if code, raw := fs.funnelCall(http.MethodPost, "/api/v1/upload-batches", map[string]string{"Cookie": gus.cookie,
			"X-FP-CSRF": gus.csrf}, core.BatchInput{FolderID: x.ID, Mode: core.UploadModeZip, ZipPassword: "another zip passphrase",
			Files: []core.UploadFileInput{{ClientRef: "b", RelPath: "b.txt", Size: 1}}}, nil); code != http.StatusNotFound {
			t.Errorf("an upload batch over Funnel: %d %s", code, raw)
		}
	})

	t.Run("administration over Funnel and the doctor", func(t *testing.T) {
		var st core.IngressStatus
		if code, raw := adam.do(http.MethodPut, "/api/v1/admin/network/funnel", core.FunnelInput{Mode: core.FunnelApp,
			AllowAdmin: ptr(true), Confirm: "public"}, &st); code != http.StatusOK || !st.AllowAdmin {
			t.Fatalf("an administrator allows administration over Funnel: %d %s", code, raw)
		}
		var rep opsapi.DoctorReport
		if code, raw := fs.adminCall(http.MethodGet, "/admin/system/doctor", nil, &rep); code != http.StatusOK {
			t.Fatalf("doctor: %d %s", code, raw)
		}
		checks := map[string]opsapi.DoctorCheck{}
		for _, c := range rep.Checks {
			checks[c.ID] = c
		}
		if c := checks["admin_2fa"]; c.Status != opsapi.CheckWarn || !strings.Contains(c.Message, "nina") ||
			strings.Contains(c.Message, "mel") || strings.Contains(c.Message, "gus") {
			t.Errorf("admin_2fa: %+v", c)
		}
		if c := checks["network.funnel"]; c.Status != opsapi.CheckWarn || !strings.Contains(c.Message, "administration is allowed") ||
			!strings.Contains(c.Message, "nina") || strings.Contains(c.Message, "mel") {
			t.Errorf("network.funnel: %+v", c)
		}
	})

	t.Run("a role edit closes the holder's stream", func(t *testing.T) {
		var r core.RoleDef
		if code, raw := fs.adminCall(http.MethodPatch, "/admin/roles/"+roles["netops"].ID, core.RoleDefUpdate{
			RemovePermissions: []core.Capability{core.CapNetworkManage}}, &r); code != http.StatusOK || r.Staff {
			t.Fatalf("netops loses network.manage: %d %s", code, raw)
		}
		if data, ok := ninaEvents.wait(events.TopicAuthzChanged, 10*time.Second); !ok || !strings.Contains(data, roles["netops"].ID) {
			t.Fatalf("authz.changed for netops: %q %v", data, ninaEvents.topics())
		}
		if !ninaEvents.closed(10 * time.Second) {
			t.Fatal("the stream of netops is still open after the role edit")
		}
		if melEvents.closed(500 * time.Millisecond) {
			t.Fatal("the stream of an unaffected member was closed")
		}
		if code, raw := nina.do(http.MethodGet, "/api/v1/admin/network", nil, nil); code != http.StatusForbidden {
			t.Fatalf("GET /admin/network after the edit: %d %s", code, raw)
		}
		// Only an administrator can turn Funnel off now; tailscaled is back
		// to its foreign entry.
		if code, raw := nina.do(http.MethodPut, "/api/v1/admin/network/funnel", core.FunnelInput{Mode: core.FunnelOff}, nil); code != http.StatusForbidden {
			t.Fatalf("former netops turns Funnel off: %d %s", code, raw)
		}
		if code, raw := adam.do(http.MethodPut, "/api/v1/admin/network/funnel", core.FunnelInput{Mode: core.FunnelOff}, nil); code != http.StatusOK {
			t.Fatalf("an administrator turns Funnel off: %d %s", code, raw)
		}
		if !sameJSON(t, fs.fake.Config(), foreignEntry) {
			t.Fatalf("serve config after disable: %s", fs.fake.Config())
		}
	})
}

// TestV4UpgradeDatabases opens v3-era databases with the v4 binary (plan
// §12.1 "migration"): a v3 database (schema version 1) migrates to
// 1 init, 2 roles, 3 zip_password, 4 fts_name_key with its search, grants
// and upload batches intact; a database carrying the unreleased review
// numbering (2, 'fts_name_key') is refused before anything runs (P0a: no
// renumber fix-up, since no build with that numbering was released).
func TestV4UpgradeDatabases(t *testing.T) {
	ctx := context.Background()
	ms, err := db.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	// v3Home writes a v3 database into a new home: 0001 recorded as
	// version 1 (plus the review's FTS migration recorded as version 2 when
	// reviewFTS is set) and rows in every table 0002–0004 touch.
	miaID, gusID, designID := ids.New(ids.PrefixUser), ids.New(ids.PrefixUser), ids.New(ids.PrefixGroup)
	miaRoot, fileID, grantID, batchID := ids.New(ids.PrefixNode), ids.New(ids.PrefixNode), ids.New(ids.PrefixGrant),
		ids.New(ids.PrefixUploadBatch)
	q := func(id string) string { return "'" + id + "'" }
	v3Home := func(t *testing.T, reviewFTS bool) *home.Home {
		t.Helper()
		h := newTestHome(t)
		d, err := db.Open(h.DB())
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		now := db.Ms(time.Now())
		exp := now + int64(time.Hour/time.Millisecond)
		stmts := []string{`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT, applied_at INTEGER)`,
			ms[0].SQL, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (1, 'init', ?1)`}
		if reviewFTS {
			stmts = append(stmts, ms[3].SQL, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (2, 'fts_name_key', ?1)`)
		}
		stmts = append(stmts,
			`INSERT INTO users(id, username, role, webauthn_handle, created_at, updated_at) VALUES
				('usr_o','olivia','owner',X'01',?1,?1), ('usr_m','mia','member',X'03',?1,?1), ('usr_g','gus','guest',X'04',?1,?1)`,
			`INSERT INTO groups(id, name, created_at, created_by) VALUES ('grp_1','Design',?1,'usr_o')`,
			`INSERT INTO group_members(group_id, user_id, role, added_at) VALUES ('grp_1','usr_m','manager',?1)`,
			`INSERT INTO spaces(id, kind, owner_user_id, name, created_at) VALUES ('spc_u','user','usr_m','My files',?1)`,
			`INSERT INTO spaces(id, kind, group_id, name, created_at) VALUES ('spc_g','group','grp_1','Design',?1)`,
			`INSERT INTO nodes(id, space_id, parent_id, kind, name, name_key, created_at, updated_at) VALUES
				('nod_ur','spc_u',NULL,'folder','','',?1,?1), ('nod_gr','spc_g',NULL,'folder','','',?1,?1),
				('nod_f','spc_u','nod_ur','file','Straße.txt','strasse.txt',?1,?1)`,
			`INSERT INTO keyring(id, purpose, mk_id, wrapped, state, created_at) VALUES ('kek_1','blob','mk_1',X'00','active',?1)`,
			`INSERT INTO blobs(id, state, size, cipher, kek_id, wrapped_dek, created_at) VALUES ('b1','ready',5,1,'kek_1',X'00',?1)`,
			`INSERT INTO file_versions(id, node_id, blob_id, size, created_at, created_by) VALUES ('ver_1','nod_f','b1',5,?1,'usr_m')`,
			`UPDATE nodes SET version_id = 'ver_1', size = 5 WHERE id = 'nod_f'`,
			`INSERT INTO node_grants(id, node_id, subject_type, subject_id, role, created_by, created_at, expires_at) VALUES
				('gnt_u','nod_f','user','usr_g','viewer','usr_m',?1,NULL), ('gnt_g','nod_ur','group','grp_1','editor','usr_m',?1,?2)`,
			`INSERT INTO upload_batches(id, user_id, folder_id, mode, zip_name, conflict, state, created_at, updated_at, expires_at)
				VALUES ('upb_1','usr_m','nod_ur','zip','Trip','rename','open',?1,?1,?2)`)
		// Real ids: the services refuse malformed ones before any lookup.
		ren := strings.NewReplacer("'usr_o'", q(ids.New(ids.PrefixUser)), "'usr_m'", q(miaID), "'usr_g'", q(gusID),
			"'grp_1'", q(designID), "'spc_u'", q(ids.New(ids.PrefixSpace)), "'spc_g'", q(ids.New(ids.PrefixSpace)),
			"'nod_ur'", q(miaRoot), "'nod_gr'", q(ids.New(ids.PrefixNode)), "'nod_f'", q(fileID),
			"'ver_1'", q(ids.New(ids.PrefixVersion)), "'gnt_u'", q(grantID), "'gnt_g'", q(ids.New(ids.PrefixGrant)),
			"'upb_1'", q(batchID))
		for _, q := range stmts {
			q = ren.Replace(q)
			if strings.Contains(q, "?1") {
				_, err = d.Exec(ctx, q, now, exp)
			} else {
				_, err = d.Exec(ctx, q)
			}
			if err != nil {
				t.Fatalf("%.60s: %v", q, err)
			}
		}
		return h
	}
	migrations := func(t *testing.T, d *db.DB) string {
		t.Helper()
		rows, err := d.Query(ctx, `SELECT version, name FROM schema_migrations ORDER BY version`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var v int
			var name sql.NullString
			if err := rows.Scan(&v, &name); err != nil {
				t.Fatal(err)
			}
			out = append(out, strings.TrimSpace(strconv.Itoa(v)+" "+name.String))
		}
		return strings.Join(out, ", ")
	}

	t.Run("v3", func(t *testing.T) {
		h := v3Home(t, false)
		d, cleanup, err := Build(ctx, h, app.ModeOffline)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if got := migrations(t, d.DB); got != "1 init, 2 roles, 3 zip_password, 4 fts_name_key" {
			t.Fatalf("schema_migrations: %s", got)
		}
		mia := &core.Principal{UserID: miaID, Username: "mia", Role: core.RoleMember, Via: core.ViaSession, AuthLevel: core.AuthLevelFull}
		found, err := d.Files.Search(ctx, mia, core.SearchQuery{Q: "STRASSE"})
		if err != nil || len(found.Items) != 1 || found.Items[0].ID != fileID || found.Items[0].ZipEncryption != "" {
			t.Fatalf("search after the upgrade: %+v %v", found.Items, err)
		}
		grants, err := d.Files.Grants(ctx, mia, fileID)
		// The folder's group grant (inherited, expiring) and the file's own.
		if err != nil || len(grants) != 2 || grants[0].SubjectType != core.SubjectGroup || grants[0].SubjectName != "Design" ||
			grants[0].Role != core.GrantEditor || grants[0].ExpiresAt == nil || grants[1].ID != grantID ||
			grants[1].SubjectType != core.SubjectUser || grants[1].SubjectName != "gus" || grants[1].Role != core.GrantViewer {
			t.Fatalf("grants after the upgrade: %+v %v", grants, err)
		}
		b, err := d.Uploads.GetBatch(ctx, core.UploadActor{P: mia}, batchID)
		if err != nil || b.State != core.BatchOpen || b.ZipName != "Trip" || b.ZipEncryption != "" {
			t.Fatalf("batch after the upgrade: %+v %v", b, err)
		}
		// Every account keeps its built-in role (role_id NULL).
		u, err := d.Users.GetByUsername(ctx, "mia")
		if err != nil || u.RoleID != "member" || u.RoleName == "" {
			t.Fatalf("mia after the upgrade: %+v %v", u, err)
		}
		// The new schema is usable at once: a custom role, a role grant and
		// the group membership it brings.
		sys := core.SystemPrincipal(core.ViaOffline)
		finance, err := d.Users.CreateRole(ctx, sys, core.RoleDefInput{Name: "Finance", Base: core.RoleGuest})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Users.SetRoleGroup(ctx, sys, finance.ID, designID, core.GroupRoleMember); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Users.Update(ctx, sys, gusID, core.UserUpdate{RoleID: ptr(finance.ID)}); err != nil {
			t.Fatal(err)
		}
		members, err := d.Users.Members(ctx, designID)
		if err != nil || !slices.ContainsFunc(members, func(m core.GroupMember) bool { return m.UserID == gusID && !m.Direct }) {
			t.Fatalf("members of Design through the role: %+v %v", members, err)
		}
	})

	t.Run("review numbering", func(t *testing.T) {
		h := v3Home(t, true)
		_, cleanup, err := Build(ctx, h, app.ModeOffline)
		cleanup()
		if err == nil || !strings.Contains(err.Error(), `db: migration 0002 is "fts_name_key" in the database but "roles" in this binary`) {
			t.Fatalf("Build: %v", err)
		}
		d, err := db.Open(h.DB())
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		if got := migrations(t, d); got != "1 init, 2 fts_name_key" {
			t.Fatalf("schema_migrations after the refusal: %s", got)
		}
		var n int
		if err := d.QueryRow(ctx, `SELECT count(*) FROM sqlite_master WHERE name IN ('roles', 'role_groups')`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("tables of 0002 after the refusal: %d %v", n, err)
		}
	})
}
