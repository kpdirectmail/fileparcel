package installer

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"fileparcel/internal/home"
	"fileparcel/internal/svc"
	"fileparcel/internal/tslocal/tslocaltest"
)

// foreignServe is a serve entry of another program on port 10000.
const foreignServe = `"node.tail.ts.net:10000":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}`

// tailscaleHome installs FileParcel into a fresh directory, records a
// published Funnel entry in its marker and puts that entry (next to a
// foreign one) into a fake tailscaled the installer talks to.
func tailscaleHome(t *testing.T) (*env, *home.Home, *tslocaltest.Fake) {
	t.Helper()
	e := newEnv(t, "linux", 1000)
	dir := e.dir("fp")
	must(t, e.in.Install(context.Background(), InstallOptions{Dir: dir, Yes: true}))
	h := mustHome(t, dir)
	proxy := "unix:" + filepath.Join(h.RunDir(), "ts-funnel.sock")
	marker := `{"version":1,"node_id":"nTESTNODE1CNTRL","dns_name":"node.tail.ts.net","backend":"unix","state":"applied",` +
		`"entries":[{"kind":"funnel","host_port":"node.tail.ts.net:443","port":443,"proxy":"` + proxy + `","funnel":true}]}`
	must(t, os.MkdirAll(h.ServiceDir(), 0o700))
	must(t, os.WriteFile(filepath.Join(h.ServiceDir(), "tailscale.json"), []byte(marker), 0o600))
	fake := tslocaltest.New(t)
	fake.SetConfig(`{"TCP":{"443":{"HTTPS":true},"10000":{"HTTPS":true}},"Web":{"node.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"` +
		proxy + `"}}},` + foreignServe + `},"AllowFunnel":{"node.tail.ts.net:443":true}}`)
	e.in.Tailscale = fake.Client()
	e.out.Reset()
	return e, h, fake
}

// jsonEqual compares two JSON documents by value.
func jsonEqual(t *testing.T, got, want string) bool {
	t.Helper()
	var a, b any
	if err := json.Unmarshal([]byte(got), &a); err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatalf("%v: %s", err, want)
	}
	return reflect.DeepEqual(a, b)
}

// Uninstall (also keeping the data) removes FileParcel's Funnel/Serve
// entries before the service stops, leaves foreign entries alone and
// deletes the marker; --dry-run lists the step and changes nothing.
func TestUninstallRemovesTailscaleEntries(t *testing.T) {
	e, h, fake := tailscaleHome(t)
	before := fake.Config()

	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, DryRun: true}))
	plan := e.out.String()
	step := "Remove FileParcel's Tailscale Funnel/Serve entries"
	if i, j := strings.Index(plan, step), strings.Index(plan, "Stop and unregister"); i < 0 || j < 0 || i > j {
		t.Fatalf("the removal step is not listed before the service stops:\n%s", plan)
	}
	if fake.Config() != before || len(fake.Posts()) != 0 {
		t.Fatal("a dry run changed tailscaled")
	}

	e.out.Reset()
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true}))
	if want := `{"TCP":{"10000":{"HTTPS":true}},"Web":{` + foreignServe + `}}`; !jsonEqual(t, fake.Config(), want) {
		t.Fatalf("serve config after uninstall:\n got %s\nwant %s", fake.Config(), want)
	}
	for _, p := range fake.Posts() {
		if p.IfMatch == "" {
			t.Fatal("a serve-config write without If-Match")
		}
	}
	if _, err := os.Stat(filepath.Join(h.ServiceDir(), "tailscale.json")); !os.IsNotExist(err) {
		t.Fatalf("marker left behind: %v", err)
	}
	if !h.Exists() || strings.Contains(e.out.String(), "Tailscale:") {
		t.Fatalf("summary:\n%s", e.out.String())
	}
}

// A removal tailscaled refuses does not stop the uninstall: the summary
// warns with the command that removes the entry by hand (with sudo when
// tailscaled wants root for Unix-socket targets), and the marker stays.
func TestUninstallTailscaleRemovalFailure(t *testing.T) {
	e, h, fake := tailscaleHome(t)
	fake.FailNextPost(http.StatusUnauthorized,
		"must be root, or be an operator and able to run 'sudo tailscale' to serve a path or Unix socket")
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, Yes: true}))
	out := e.out.String()
	if !strings.Contains(out, "uninstalled from") ||
		!strings.Contains(out, "Tailscale: could not remove FileParcel's Tailscale entries (run sudo tailscale serve --yes --https=443 --set-path=/ off)") {
		t.Fatalf("summary:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(h.ServiceDir(), "tailscale.json")); err != nil {
		t.Fatalf("marker: %v", err)
	}
	// The steps after it ran: the home is marked as not installed.
	if rec, err := svc.ReadInstalled(h); err != nil || rec.Kind != svc.KindNone || !rec.Incomplete {
		t.Fatalf("record after the failed removal: %+v %v", rec, err)
	}
}

// Without a marker nothing of Tailscale is planned (and tailscaled is not
// asked).
func TestUninstallWithoutTailscaleMarker(t *testing.T) {
	e, h, fake := tailscaleHome(t)
	must(t, os.Remove(filepath.Join(h.ServiceDir(), "tailscale.json")))
	must(t, e.in.Uninstall(context.Background(), UninstallOptions{Home: h, DryRun: true}))
	if strings.Contains(e.out.String(), "Tailscale Funnel/Serve") || len(fake.Requests()) != 0 {
		t.Fatalf("plan:\n%s\nrequests %d", e.out.String(), len(fake.Requests()))
	}
}
