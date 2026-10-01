package settingsapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"fileparcel/internal/core"
)

// The per-key checks of PATCH/DELETE /admin/settings (implementation plan
// R14): the permission check runs over every key before the managed check
// of any key, and keys the catalog does not know are left to the store.
func TestRunKeyChecksOrder(t *testing.T) {
	views := map[string]core.SettingView{
		"funnel.mode":       {Key: "funnel.mode", Section: "funnel", Managed: "PUT /api/v1/admin/network/funnel"},
		"server.https_port": {Key: "server.https_port", Section: "server"},
		"storage.fsync":     {Key: "storage.fsync", Section: "storage"},
	}
	errPerm, errManaged := errors.New("403"), errors.New("409")
	perm := func(v core.SettingView) error {
		if v.Section == "server" {
			return errPerm
		}
		return nil
	}
	managed := func(v core.SettingView) error {
		if v.Managed != "" {
			return errManaged
		}
		return nil
	}
	var seen []string
	record := func(v core.SettingView) error { seen = append(seen, v.Key); return nil }
	for _, c := range []struct {
		keys []string
		want error
	}{
		// funnel.mode sorts before server.https_port: still 403 first.
		{[]string{"funnel.mode", "server.https_port"}, errPerm},
		{[]string{"funnel.mode", "storage.fsync"}, errManaged},
		{[]string{"storage.fsync"}, nil},
		{[]string{"unknown.key", "storage.fsync"}, nil},
	} {
		seen = nil
		if err := runKeyChecks(views, c.keys, record, perm, managed); !errors.Is(err, c.want) && err != c.want {
			t.Errorf("%v: %v, want %v", c.keys, err, c.want)
		}
		for _, k := range seen {
			if _, ok := views[k]; !ok {
				t.Errorf("%v: check ran on the unknown key %s", c.keys, k)
			}
		}
	}
}

// A built-in administrator sees every setting (listable), before and after
// package A fills in caps.go.
func TestAdminListsEverySetting(t *testing.T) {
	te := newTestEnv(t)
	var list []core.SettingView
	if res := te.do(t, te.admin(true), http.MethodGet, "/api/v1/admin/settings", nil, &list); res.status != http.StatusOK {
		t.Fatalf("list: %d", res.status)
	}
	cat, err := te.st.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != len(cat) || len(cat) == 0 {
		t.Fatalf("listed %d of %d settings", len(list), len(cat))
	}
}

// GET /admin/network carries the v4 lists vpns and exposures as arrays, never
// null (the web UI and the CLI iterate them without a check).
func TestNetworkOverviewV4Arrays(t *testing.T) {
	te := newTestEnv(t)
	r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network", nil, nil)
	if r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.body)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(r.body, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"vpns", "exposures"} {
		if v := string(raw[k]); len(v) == 0 || v[0] != '[' {
			t.Errorf("%s = %s, want an array", k, v)
		}
	}
}
