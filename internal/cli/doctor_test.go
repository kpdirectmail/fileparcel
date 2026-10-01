package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

// lcDoctorJSON runs `doctor --json` (plus args) and decodes the report.
func lcDoctorJSON(t *testing.T, h *home.Home, args ...string) (lcDoctorReport, int) {
	t.Helper()
	r := lcRun(t, "", append([]string{"--json", "doctor", "--home", h.Dir()}, args...)...)
	var rep lcDoctorReport
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
		t.Fatalf("doctor output: %v\n%s\n%s", err, r.out, r.err)
	}
	return rep, r.code
}

// lcStatuses maps check id → status.
func lcStatuses(rep lcDoctorReport) map[string]string {
	m := map[string]string{}
	for _, c := range rep.Checks {
		m[c.ID] = c.Status
	}
	return m
}

func TestDoctorNotAHome(t *testing.T) {
	lcIsolateHost(t)
	dir := t.TempDir()
	h, _ := home.New(dir)
	rep, code := lcDoctorJSON(t, h)
	if code != ExitFailure || rep.OK || rep.Failures != 1 || len(rep.Checks) != 1 || rep.Checks[0].ID != "home" ||
		!strings.Contains(rep.Checks[0].Message, "fileparcel.toml") {
		t.Fatalf("exit %d, %+v", code, rep)
	}
}

func TestDoctorBareHome(t *testing.T) {
	lcIsolateHost(t)
	h := lcBareHome(t)
	rep, code := lcDoctorJSON(t, h)
	st := lcStatuses(rep)
	want := map[string]string{"home": lcOK, "permissions": lcOK, "keys.file": lcFail, "binary": lcInfo,
		"server": lcInfo, "service": lcInfo, "cert.ca": lcFail, "cert.leaf": lcFail, "ports": lcOK}
	for id, s := range want {
		if st[id] != s {
			t.Errorf("%s = %q, want %q", id, st[id], s)
		}
	}
	if code != ExitFailure || rep.OK || rep.Failures != 3 {
		t.Fatalf("exit %d failures %d: %v", code, rep.Failures, st)
	}

	// Human output: one line per check, hints, summary.
	r := lcRun(t, "", "doctor", "--home", h.Dir())
	if r.code != ExitFailure || !strings.Contains(r.out, "[FAIL] Master key file: keys/master.key is missing") ||
		!strings.Contains(r.out, "       → Restore the home") || !strings.Contains(r.out, "3 failed,") {
		t.Fatalf("human output (exit %d):\n%s", r.code, r.out)
	}
}

func TestDoctorFix(t *testing.T) {
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	rep, code := lcDoctorJSON(t, h)
	if code != 0 || !rep.OK {
		t.Fatalf("fresh home: exit %d %+v", code, rep)
	}
	st := lcStatuses(rep)
	for _, id := range []string{"home", "keys.file", "cert.ca", "cert.leaf", "server"} {
		if st[id] != lcOK && !(id == "server" && st[id] == lcInfo) {
			t.Errorf("fresh home: %s = %s", id, st[id])
		}
	}

	// Break permissions and leave stale files of a "crashed" server.
	if err := os.Chmod(h.DataDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.KeysFile(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.Config(), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.PIDFile(), []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, code = lcDoctorJSON(t, h)
	st = lcStatuses(rep)
	if code != 0 || st["permissions"] != lcWarn || st["server"] != lcWarn || rep.Fixed != 0 {
		t.Fatalf("broken home: exit %d %v", code, st)
	}
	var perm lcCheck
	for _, c := range rep.Checks {
		if c.ID == "permissions" {
			perm = c
		}
	}
	for _, frag := range []string{"data/ is 0755 (want 0700)", "keys/master.key is 0644 (want 0600)", "fileparcel.toml is 0666"} {
		if !strings.Contains(perm.Message, frag) {
			t.Errorf("permissions message lacks %q: %s", frag, perm.Message)
		}
	}

	rep, code = lcDoctorJSON(t, h, "--fix")
	st = lcStatuses(rep)
	if code != 0 || st["permissions"] != lcOK || st["server"] != lcInfo || rep.Fixed != 2 {
		t.Fatalf("--fix: exit %d fixed %d %v", code, rep.Fixed, st)
	}
	for p, want := range map[string]os.FileMode{h.DataDir(): 0o700, h.KeysFile(): 0o600, h.Config(): home.ModeConfig} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s not repaired: %v %v", p, fi.Mode(), err)
		}
	}
	if _, err := os.Stat(h.PIDFile()); !os.IsNotExist(err) {
		t.Errorf("stale pid file not removed: %v", err)
	}
	// Idempotent: nothing left to fix.
	if rep, _ = lcDoctorJSON(t, h, "--fix"); rep.Fixed != 0 {
		t.Fatalf("second --fix repaired %d", rep.Fixed)
	}
}

func TestDoctorCertsSymlinkRestore(t *testing.T) {
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	link := filepath.Join(t.TempDir(), "bin", "fileparcel")
	rec := &svc.Installed{Kind: svc.KindNone, Home: h.Dir(), Symlink: link}
	if err := svc.WriteInstalled(h, rec); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.RestoreFile()+".failed", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Expiry thresholds: pretend it is 10 years later.
	d := &lcDoctor{h: h, host: svc.CurrentHost(), now: time.Now().AddDate(10, 1, 0)}
	st := lcStatuses(*d.run(context.Background()))
	if st["cert.ca"] != lcFail || st["cert.leaf"] != lcFail || st["symlink"] != lcWarn {
		t.Fatalf("later: %v", st)
	}
	// Leaf expiring within 14 days.
	cert, err := lcReadCert(filepath.Join(h.CertsDir(), "server", "leaf.crt"))
	if err != nil {
		t.Fatal(err)
	}
	d = &lcDoctor{h: h, host: svc.CurrentHost(), now: cert.NotAfter.Add(-24 * time.Hour)}
	if st := lcStatuses(*d.run(context.Background())); st["cert.leaf"] != lcWarn {
		t.Fatalf("expiring leaf: %v", st)
	}
	// The CA warns 90 days ahead, as in the server's doctor.
	ca, err := lcReadCert(svc.CACertPath(h))
	if err != nil {
		t.Fatal(err)
	}
	d = &lcDoctor{h: h, host: svc.CurrentHost(), now: ca.NotAfter.Add(-60 * 24 * time.Hour)}
	if st := lcStatuses(*d.run(context.Background())); st["cert.ca"] != lcWarn {
		t.Fatalf("expiring CA: %v", st)
	}
	// The link exists and points at the binary.
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.Binary(), link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(link)+string(os.PathListSeparator)+os.Getenv("PATH"))
	d = &lcDoctor{h: h, host: svc.CurrentHost(), now: time.Now()}
	if st := lcStatuses(*d.run(context.Background())); st["symlink"] != lcOK || st["restore.failed"] != lcWarn {
		t.Fatalf("symlink ok: %v", st)
	}
	os.Remove(h.RestoreFile() + ".failed")
	if err := os.WriteFile(h.RestoreFile(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	d = &lcDoctor{h: h, host: svc.CurrentHost(), now: time.Now()}
	if st := lcStatuses(*d.run(context.Background())); st["restore.pending"] != lcInfo || st["restore.failed"] != "" {
		t.Fatalf("pending restore: %v", st)
	}
	if _, err := lcReadCert(h.Config()); err == nil {
		t.Fatal("non-PEM accepted")
	}
}

func TestDoctorRecordedServiceMissing(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("no systemctl")
	}
	lcIsolateHost(t)
	h := lcBareHome(t)
	// Recorded (without boot, so no linger check or fix) but not registered
	// in the isolated user unit dir.
	if err := svc.WriteInstalled(h, &svc.Installed{Kind: svc.KindSystemdUser, Home: h.Dir()}); err != nil {
		t.Fatal(err)
	}
	d := &lcDoctor{h: h, host: svc.CurrentHost(), now: time.Now()}
	rep := d.run(context.Background())
	var c lcCheck
	for _, x := range rep.Checks {
		if x.ID == "service" {
			c = x
		}
	}
	if c.Status != lcFail || !strings.Contains(c.Message, "recorded but not registered") {
		t.Fatalf("service check %+v", c)
	}
}

func TestRenderDoctor(t *testing.T) {
	NewRootCmd()
	t.Setenv("NO_COLOR", "1")
	rep := &lcDoctorReport{Failures: 1, Warnings: 1, Fixed: 1, Checks: []lcCheck{
		{ID: "a", Name: "A", Status: lcOK, Message: "fine", Fixed: true},
		{ID: "b", Name: "B", Status: lcWarn, Message: "hmm\x1b[2J", Hint: "do\tthis"},
		{ID: "c", Name: "C", Status: lcFail, Message: "bad"},
		{ID: "d", Name: "D", Status: "weird", Message: "?"},
	}}
	var b bytes.Buffer
	if err := lcRenderDoctor(&b, rep); err != nil {
		t.Fatal(err)
	}
	want := "[ok  ] A: fine (fixed)\n[warn] B: hmm[2J\n       → do this\n[FAIL] C: bad\n[weird] D: ?\n\n1 failed, 1 warnings, 1 fixed.\n"
	if b.String() != want {
		t.Fatalf("got:\n%q\nwant:\n%q", b.String(), want)
	}
	if lcRel("") != "the home directory" || lcRel("data") != "data/" {
		t.Fatal("lcRel")
	}
}

// The local restore checks carry the server's IDs, so a failed (or pending)
// restore on a running server is listed and counted once, not twice; the
// server's certificate checks are replaced by the local ones the same way.
func TestDoctorServerChecksNotDuplicated(t *testing.T) {
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	marker := `{"file":"fp-2026.fpbk","error":"wrong identity","failed_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(h.RestoreFile()+".failed", []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.RestoreFile(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"checks":[
			{"id":"restore.failed","name":"Scheduled restore","status":"warn","message":"The last scheduled restore failed"},
			{"id":"restore.pending","name":"Pending restore","status":"info","message":"A restore is scheduled"},
			{"id":"cert.ca","name":"Local certificate authority","status":"ok","message":"x"},
			{"id":"cert.leaf","name":"Server certificate","status":"ok","message":"x"},
			{"id":"disk.free","name":"Disk space","status":"ok","message":"plenty"}]}`))
	}))
	defer srv.Close()
	c, err := Connect(Options{Server: srv.URL, Token: "fpt_test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	d := &lcDoctor{h: h, host: svc.CurrentHost(), now: time.Now()}
	d.checkCerts()
	d.checkRestore()
	d.serverChecks(context.Background(), c)
	seen := map[string]int{}
	warnings := 0
	for _, ck := range d.checks {
		seen[ck.ID]++
		if ck.Status == lcWarn {
			warnings++
		}
		if ck.ID == "restore.failed" && !strings.Contains(ck.Message, "wrong identity") {
			t.Errorf("failed restore without its reason: %q", ck.Message)
		}
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("%s listed %d times", id, n)
		}
	}
	if seen["restore.failed"] != 1 || seen["restore.pending"] != 1 || seen["disk.free"] != 1 || warnings != 1 {
		t.Fatalf("checks %v, %d warnings", seen, warnings)
	}
}

// A port this user may not bind (below 1024 without CAP_NET_BIND_SERVICE)
// is not "in use by another program": only EADDRINUSE fails the check.
func TestDoctorPortsPermissionDenied(t *testing.T) {
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	cfg, err := config.Load(h)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.HTTPSPort, cfg.Server.HTTPPort = 443, 80
	old := lcProbePort
	defer func() { lcProbePort = old }()
	probe := func(errs map[int]error) *lcCheck {
		t.Helper()
		lcProbePort = func(p int) error { return errs[p] }
		d := &lcDoctor{h: h, host: svc.CurrentHost(), now: time.Now(), cfg: cfg}
		d.checkPorts()
		if len(d.checks) != 1 || d.checks[0].ID != "ports" {
			t.Fatalf("checks %+v", d.checks)
		}
		return &d.checks[0]
	}
	denied := &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EACCES)}
	inUse := &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	if c := probe(map[int]error{443: denied, 80: denied}); c.Status != lcInfo ||
		!strings.Contains(c.Message, "cannot be tested as this user: 443, 80") || strings.Contains(c.Message, "in use") {
		t.Fatalf("denied: %+v", c)
	}
	if c := probe(map[int]error{443: inUse, 80: denied}); c.Status != lcFail ||
		!strings.Contains(c.Message, "in use by another program: 443") || !strings.Contains(c.Message, "as this user: 80") {
		t.Fatalf("in use: %+v", c)
	}
	if c := probe(nil); c.Status != lcOK || c.Message != "free" {
		t.Fatalf("free: %+v", c)
	}
}

// A broken fileparcel.toml fails the home check, but the service record is
// still read: the checks that depend on it do not report "no service".
func TestDoctorBrokenConfigKeepsServiceRecord(t *testing.T) {
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	link := filepath.Join(t.TempDir(), "bin", "fileparcel")
	if err := svc.WriteInstalled(h, &svc.Installed{Kind: svc.KindNone, Home: h.Dir(), Symlink: link}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(h.Config(), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("\n[server\n")
	f.Close()
	d := &lcDoctor{h: h, host: svc.CurrentHost(), now: time.Now()}
	rep := d.run(context.Background())
	st := lcStatuses(*rep)
	if st["home"] != lcFail || st["symlink"] != lcWarn || rep.OK {
		t.Fatalf("broken config: %v", st)
	}
	for _, c := range rep.Checks {
		if strings.HasPrefix(c.ID, "firewall") && strings.Contains(c.Hint, "port 0") {
			t.Errorf("firewall hint with an unknown port: %q", c.Hint)
		}
	}
}

// The plaintext Tailscale key (certs/tailscale/key.pem) is a secret like
// the leaf key; the public certificate next to it is not.
func TestDoctorTailscaleKeyPermissions(t *testing.T) {
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	dir := filepath.Join(h.CertsDir(), "tailscale")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, crt := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	for _, p := range []string{key, crt} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, _ := lcDoctorJSON(t, h)
	var perm lcCheck
	for _, c := range rep.Checks {
		if c.ID == "permissions" {
			perm = c
		}
	}
	if perm.Status != lcWarn || !strings.Contains(perm.Message, "certs/tailscale/key.pem is 0644 (want 0600)") ||
		strings.Contains(perm.Message, "cert.pem") {
		t.Fatalf("permissions: %+v", perm)
	}
	lcDoctorJSON(t, h, "--fix")
	for p, want := range map[string]os.FileMode{key: 0o600, crt: 0o644} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %04o", p, fi.Mode(), err, want)
		}
	}
}
