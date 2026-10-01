package users

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func TestLockDuration(t *testing.T) {
	base := 15 * time.Minute
	cases := []struct {
		level int
		want  time.Duration
	}{{0, 15 * time.Minute}, {1, 30 * time.Minute}, {2, time.Hour}, {6, 16 * time.Hour}, {7, 24 * time.Hour}, {60, 24 * time.Hour}}
	for _, c := range cases {
		if got := lockDuration(base, c.level); got != c.want {
			t.Errorf("level %d: %v want %v", c.level, got, c.want)
		}
	}
}

func TestLoginFailureLockout(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.settings.set(settingLockoutThreshold, int64(3))
	te.settings.set(settingLockoutBaseMin, int64(1))
	te.notify.enabled.Store(true)
	u := te.mkUser(t, "alice", core.RoleMember, withEmail("alice@example.com"))

	fail := func() *time.Time {
		t.Helper()
		lu, err := te.svc.RecordLoginFailure(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return lu
	}
	for i := 1; i <= 2; i++ {
		if fail() != nil {
			t.Fatalf("locked after %d failures", i)
		}
	}
	lu := fail()
	if lu == nil || !lu.Equal(te.clock.Now().Add(time.Minute)) {
		t.Fatalf("first lock %v", lu)
	}
	cur, _ := te.svc.Get(ctx, u.ID)
	if !cur.Locked(te.clock.Now()) || cur.LockLevel != 1 || cur.FailedLogins != 0 {
		t.Fatalf("state %+v", cur)
	}
	if e, ok := te.audit.last(core.ActAuthLockout); !ok || e.TargetID != u.ID || e.Outcome != core.OutcomeDenied {
		t.Fatalf("audit %+v", e)
	}
	mails := te.notify.mails()
	if len(mails) != 1 || mails[0].tmpl != "security_alert" || mails[0].data["kind"] != "lockout" || mails[0].to[0] != "alice@example.com" {
		t.Fatalf("alert %+v", mails)
	}
	// Failures during the lock change nothing.
	if again := fail(); again == nil || !again.Equal(*lu) {
		t.Fatalf("during lock %v", again)
	}
	if n := len(te.notify.mails()); n != 1 {
		t.Fatalf("%d alerts", n)
	}
	// After expiry the next lock doubles.
	te.clock.Advance(time.Minute)
	fail()
	fail()
	lu2 := fail()
	if lu2 == nil || !lu2.Equal(te.clock.Now().Add(2*time.Minute)) {
		t.Fatalf("second lock %v", lu2)
	}
	// Admin unlock (audited) and success reset.
	if err := te.svc.Unlock(ctx, as(te.mkUser(t, "admin", core.RoleAdmin)), u.ID); err != nil {
		t.Fatal(err)
	}
	cur, _ = te.svc.Get(ctx, u.ID)
	if cur.Locked(te.clock.Now()) || cur.LockLevel != 0 || cur.FailedLogins != 0 {
		t.Fatalf("after unlock %+v", cur)
	}
	if _, ok := te.audit.last(core.ActUserUnlock); !ok {
		t.Fatal("unlock not audited")
	}
	fail()
	if err := te.svc.RecordLoginSuccess(ctx, u.ID, core.ReqMeta{IP: netip.MustParseAddr("192.0.2.7")}); err != nil {
		t.Fatal(err)
	}
	cur, _ = te.svc.Get(ctx, u.ID)
	if cur.FailedLogins != 0 || cur.LastLoginIP != "192.0.2.7" || cur.LastLoginAt == nil || !cur.LastLoginAt.Equal(te.clock.Now()) {
		t.Fatalf("after success %+v", cur)
	}
	if _, err := te.svc.RecordLoginFailure(ctx, "usr_missing"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := te.svc.RecordLoginSuccess(ctx, "usr_missing", core.ReqMeta{}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing success: %v", err)
	}
	// Unlock of an unlocked account is a no-op (not audited).
	te.audit.reset()
	if err := te.svc.Unlock(ctx, system(), u.ID); err != nil || len(te.audit.actions()) != 0 {
		t.Fatalf("noop unlock %v %v", err, te.audit.actions())
	}
}

// The lockout alert and the auth.lockout audit row exist to tell the user
// and the administrator where the attempts came from, so both must name the
// address. A brute-forced sign-in has no signed-in principal of its own:
// auth.countFailure puts the request meta into the context for exactly this.
func TestLockoutAlertNamesTheClientAddress(t *testing.T) {
	te := newTestEnv(t)
	te.settings.set(settingLockoutThreshold, int64(2))
	te.notify.enabled.Store(true)
	u := te.mkUser(t, "vic", core.RoleMember, withEmail("vic@example.com"))
	ctx := core.WithPrincipal(context.Background(), &core.Principal{
		IP: netip.MustParseAddr("203.0.113.55"), UserAgent: "curl/8", RequestID: "req-9"})
	for range 2 {
		if _, err := te.svc.RecordLoginFailure(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	mails := te.notify.mails()
	if len(mails) != 1 || mails[0].data["kind"] != "lockout" || mails[0].data["ip"] != "203.0.113.55" {
		t.Fatalf("alert without the address: %+v", mails)
	}
	e, ok := te.audit.last(core.ActAuthLockout)
	if !ok || e.IP != "203.0.113.55" || e.UserAgent != "curl/8" || e.RequestID != "req-9" {
		t.Fatalf("audit row without the client: %+v", e)
	}
}

func TestLockoutDefaults(t *testing.T) {
	te := newTestEnv(t) // settings unset → 10 failures, 15 minutes
	u := te.mkUser(t, "bob", core.RoleMember)
	for i := 0; i < 9; i++ {
		if lu, err := te.svc.RecordLoginFailure(context.Background(), u.ID); err != nil || lu != nil {
			t.Fatalf("failure %d: %v %v", i, lu, err)
		}
	}
	lu, err := te.svc.RecordLoginFailure(context.Background(), u.ID)
	if err != nil || lu == nil || lu.Sub(te.clock.Now()) != 15*time.Minute {
		t.Fatalf("lock %v %v", lu, err)
	}
	// No e-mail without an address / with notify disabled.
	if len(te.notify.mails()) != 0 {
		t.Fatal("unexpected mail")
	}
}
