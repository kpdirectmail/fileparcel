package meapi_test

import (
	"maps"
	"net/http"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/web/pages"
)

// GET /me carries the whole feature map of the page boot (pages.Features),
// not a subset, so the client's merge (/me winning) cannot disagree with it.
func TestMeFeaturesAreThePageFeatures(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "meg", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("meg", pw)
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	want := pages.Features(nil, &core.Principal{Role: core.RoleMember, AuthLevel: core.AuthLevelFull})
	for _, k := range []string{"thumbnails", "mtls_self_service", "share_password_required"} {
		if _, ok := me.Features[k]; !ok {
			t.Errorf("/me lacks %s: %v", k, me.Features)
		}
	}
	if !maps.Equal(me.Features, want) {
		t.Errorf("/me features %v, pages.Features (defaults) %v", me.Features, want)
	}
}
