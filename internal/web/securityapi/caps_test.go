package securityapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// A custom role with certs.manage ("Certificates") reaches every certificate
// route an administrator does, except uploading or removing a custom
// certificate and the key routes (administrators only); over an API token
// it needs the admin scope.
func TestCertsManageDelegate(t *testing.T) {
	hs := newHarness(t)
	for _, rt := range routes {
		if rt.guard != gAdmin && rt.guard != gAdminElevated {
			continue
		}
		adminOnly := strings.Contains(rt.path, "/admin/keys") || strings.Contains(rt.path, "/admin/certs/custom")
		rec := hs.do(t, rt.method, rt.path, rt.body, as("certmgr"), from("192.168.1.20:5555"))
		code := errCode(rec)
		switch {
		case adminOnly && (rec.Code != http.StatusForbidden || code != "forbidden"):
			t.Errorf("%s %s: %d %s, want 403 (administrators only)", rt.method, rt.path, rec.Code, rec.Body.String())
		case !adminOnly && rec.Code == http.StatusForbidden:
			t.Errorf("%s %s: %d %s", rt.method, rt.path, rec.Code, rec.Body.String())
		}
		rec = hs.do(t, rt.method, rt.path, rt.body, as("certmgr-files"), from("192.168.1.20:5555"))
		var e struct {
			Error struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		if !adminOnly && (rec.Code != http.StatusForbidden || e.Error.Message != `token lacks scope "admin"`) {
			t.Errorf("%s %s without the admin scope: %d %s", rt.method, rt.path, rec.Code, rec.Body.String())
		}
	}
}

// DELETE /admin/client-certs/{id} revokes anyone's certificate for a holder
// of certs.manage; DELETE /me/client-certs/{id} stays limited to the
// caller's own certificates, for them as for administrators.
func TestCertsManageRevoke(t *testing.T) {
	hs := newHarness(t)
	hs.certs.certs = []core.ClientCert{
		{ID: "ccr_a", UserID: "usr_alice", Name: "a"},
		{ID: "ccr_c", UserID: "usr_carl", Name: "c"},
	}
	if rec := hs.do(t, "DELETE", "/api/v1/me/client-certs/ccr_a", nil, as("certmgr")); rec.Code != http.StatusNotFound {
		t.Fatalf("/me revoke of another's certificate: %d %s", rec.Code, rec.Body.String())
	}
	if rec := hs.do(t, "DELETE", "/api/v1/me/client-certs/ccr_c", nil, as("certmgr")); rec.Code != http.StatusNoContent {
		t.Fatalf("/me revoke of the own certificate: %d %s", rec.Code, rec.Body.String())
	}
	if by := hs.certs.revokeBy[len(hs.certs.revokeBy)-1]; by.Can(core.CapCertsManage) || by.IsAdmin() ||
		by.RoleID != string(core.RoleMember) {
		t.Fatalf("the /me principal was not narrowed: %+v %v", by, by.RoleCaps())
	}
	if rec := hs.do(t, "DELETE", "/api/v1/admin/client-certs/ccr_a", nil, as("certmgr")); rec.Code != http.StatusNoContent {
		t.Fatalf("admin revoke: %d %s", rec.Code, rec.Body.String())
	}
	if len(hs.certs.revoked) != 2 {
		t.Fatalf("revoked %v", hs.certs.revoked)
	}
}
