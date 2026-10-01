package shares

import (
	"testing"

	"fileparcel/internal/core"
)

// TestUpdateAuditNamesKindAndDisabled: share.update entries carry the kind
// of the share and, when it was closed or reopened, which of the two — the
// activity feeds use them ("Closed the file request for …").
func TestUpdateAuditNamesKindAndDisabled(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	folder := f.Mkdir(f.aliceRoot, "Inbox")
	r, _ := f.create(alice, core.ShareInput{Kind: core.ShareRequest, NodeID: folder})

	details := func() map[string]any {
		t.Helper()
		e, ok := f.Audit.Find(core.ActShareUpdate)
		d, _ := e.Details.(map[string]any)
		if !ok || d == nil {
			t.Fatalf("no share.update entry: %+v", e)
		}
		return d
	}
	if _, err := f.svc.Update(f.ctx, alice, r.ID, core.ShareUpdate{Disabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if d := details(); d["kind"] != core.ShareRequest || d["disabled"] != true {
		t.Fatalf("close: %+v", d)
	}
	if _, err := f.svc.Update(f.ctx, alice, r.ID, core.ShareUpdate{Disabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if d := details(); d["kind"] != core.ShareRequest || d["disabled"] != false {
		t.Fatalf("reopen: %+v", d)
	}
	if _, err := f.svc.Update(f.ctx, alice, r.ID, core.ShareUpdate{Title: ptr("Photos")}); err != nil {
		t.Fatal(err)
	}
	if d := details(); d["kind"] != core.ShareRequest {
		t.Fatalf("title: %+v", d)
	} else if _, ok := d["disabled"]; ok {
		t.Fatalf("title change reports disabled: %+v", d)
	}
}
