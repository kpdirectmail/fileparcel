package backup

import (
	"context"
	"encoding/json"
	"testing"
)

// TestConfigReportsIdentityRecipient: with backup.recipients emptied (reset,
// "config unset", a restored database) every backup is still encrypted to the
// stored identity, so Config reports its public key — the Backups page and
// "backup identity show" said there was no recipient at all.
func TestConfigReportsIdentityRecipient(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	c, err := te.svc.Config(ctx)
	if err != nil || c.HasIdentity || c.IdentityRecipient != "" {
		t.Fatalf("no identity yet: %+v %v", c, err)
	}
	rec, _, err := te.svc.GenerateIdentity(ctx, te.admin())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := te.env.Settings.Set(ctx, te.sys(), map[string]json.RawMessage{SettingRecipients: json.RawMessage(`[]`)}); err != nil {
		t.Fatal(err)
	}
	c, err = te.svc.Config(ctx)
	if err != nil || len(c.Recipients) != 0 || !c.HasIdentity || c.IdentityRecipient != rec {
		t.Fatalf("recipients emptied: %+v %v (want identity recipient %s)", c, err, rec)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m["identity_recipient"] != rec {
		t.Fatalf("JSON: %s", b)
	}
}
