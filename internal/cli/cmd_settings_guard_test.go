package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
)

// guardedSettingsAPI registers a settings API whose guards refuse changes of
// auth.passkeys, mdns.name and network.access_mode with 409 conflict unless
// ?force=true, and answers every PATCH with warnings. It returns the force
// value of each request, by "METHOD key".
func guardedSettingsAPI(f *fakeAPI, warnings []string) *sync.Map {
	forces := &sync.Map{}
	catalog := []core.SettingView{
		{Key: "auth.passkeys", Section: "auth", Type: "bool", Value: json.RawMessage("true"), Default: json.RawMessage("true")},
		{Key: "mdns.name", Section: "mdns", Type: "string", Value: json.RawMessage(`""`), Default: json.RawMessage(`""`)},
		{Key: "network.access_mode", Section: "network", Type: "enum", Value: json.RawMessage(`"any"`), Default: json.RawMessage(`"allowlist"`)},
		{Key: "tls.extra_sans", Section: "tls", Type: "strings", Value: json.RawMessage(`[]`), Default: json.RawMessage(`[]`)},
	}
	guarded := func(key string) bool {
		return key == "auth.passkeys" || key == "mdns.name" || key == "network.access_mode"
	}
	f.handle("GET", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, catalog) })
	f.handle("PATCH", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[map[string]json.RawMessage](r)
		force := r.URL.Query().Get("force")
		res := core.SettingsResult{Applied: []string{}, RestartRequired: []string{}, Warnings: warnings}
		for k := range in {
			forces.Store("PATCH "+k, force)
			if guarded(k) && force != "true" {
				writeErr(w, &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: k,
					Message: "1 account(s) have no second factor other than a passkey; confirm the change to make it anyway"})
				return
			}
			res.Applied = append(res.Applied, k)
		}
		writeJSON(w, 200, res)
	})
	f.handle("DELETE", "/api/v1/admin/settings/{key}", func(w http.ResponseWriter, r *http.Request) {
		k, force := chi.URLParam(r, "key"), r.URL.Query().Get("force")
		forces.Store("DELETE "+k, force)
		if guarded(k) && force != "true" {
			writeErr(w, &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: k,
				Message: "this change would lock you out"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return forces
}

// A change a server guard refuses (409) can be confirmed from the CLI:
// config set / config unset / mdns name take --force, which sends ?force,
// and the refusal points at it.
func TestSettingsGuardForce(t *testing.T) {
	f := newFakeAPI(t)
	forces := guardedSettingsAPI(f, nil)
	for _, tc := range []struct {
		args []string
		req  string
	}{
		{[]string{"config", "set", "auth.passkeys", "false"}, "PATCH auth.passkeys"},
		{[]string{"config", "unset", "network.access_mode"}, "DELETE network.access_mode"},
		{[]string{"mdns", "name", "files"}, "PATCH mdns.name"},
	} {
		res := f.run(t, "", tc.args...)
		if res.code != ExitFailure || !strings.Contains(res.stderr, "--force") {
			t.Fatalf("%v without --force: %+v", tc.args, res)
		}
		if v, _ := forces.Load(tc.req); v != "" {
			t.Fatalf("%v sent force=%v", tc.args, v)
		}
		res = f.run(t, "", append(tc.args, "--force")...)
		if res.code != 0 {
			t.Fatalf("%v --force: %+v", tc.args, res)
		}
		if v, _ := forces.Load(tc.req); v != "true" {
			t.Fatalf("%v --force sent force=%v", tc.args, v)
		}
	}
	// Commands without --force send none.
	if res := f.run(t, "", "config", "set", "tls.extra_sans", "a.lan"); res.code != 0 {
		t.Fatalf("unguarded: %+v", res)
	}
	if v, _ := forces.Load("PATCH tls.extra_sans"); v != "" {
		t.Fatalf("force=%v", v)
	}
}

// The PATCH /admin/settings warnings (a name the local CA may not sign is
// stored but never reaches the certificate) reach the CLI user: on stderr,
// and in the --json document of config set.
func TestSettingsWarningsShown(t *testing.T) {
	const warning = "the local certificate cannot cover this name: files.example.org"
	f := newFakeAPI(t)
	guardedSettingsAPI(f, []string{warning})
	f.handle("GET", "/api/v1/admin/certs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.CertStatus{Leaf: &core.CertInfo{Subject: "fileparcel"}, CAConstrained: true,
			PermittedDNS: []string{".local"}})
	})

	res := f.run(t, "", "config", "set", "tls.extra_sans", "files.example.org")
	if res.code != 0 || !strings.Contains(res.stderr, "warning: "+warning) {
		t.Fatalf("config set: %+v", res)
	}
	res = f.run(t, "", "--json", "config", "set", "tls.extra_sans", "files.example.org")
	var out core.SettingsResult
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &out) != nil || len(out.Warnings) != 1 || out.Warnings[0] != warning {
		t.Fatalf("config set --json: %+v", res)
	}
	// cert sans has its own check; the server's warning is not repeated by it.
	res = f.run(t, "", "cert", "sans", "--add", "files.example.org")
	if res.code != 0 || strings.Count(res.stderr, "warning:") != 1 || !strings.Contains(res.stderr, warning) {
		t.Fatalf("cert sans: %+v", res)
	}
}
