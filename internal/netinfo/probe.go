package netinfo

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Probe cache lifetimes (DESIGN §10.1).
const (
	binaryTTL  = 5 * time.Minute  // installed binaries
	processTTL = 60 * time.Second // running processes
	configTTL  = 5 * time.Minute  // tinc and innernet configuration
	routeTTL   = 60 * time.Second // effective default route (or until the interface set changes)
)

// hostProbe gathers the classification signals that are not properties of
// one interface (DESIGN §10.1): which interfaces carry the effective
// default route, installed binaries and running processes (weak signals),
// and the interface names of tinc and innernet networks. Every func is
// replaceable in tests; a nil func reports nothing.
type hostProbe struct {
	defaultRouteIfaces func(ctx context.Context) (map[int]bool, error) // ifindex → carries an effective default route
	hasBinary          func(name string) bool                          // on PATH or in its usual place; cached
	processNamed       func(comm string) bool                          // a running process of that name; cached
	tincIfaces         func() []string                                 // tinc network interfaces; cached
	innernetIfaces     func() []string                                 // innernet network interfaces; cached
}

// newHostProbe returns the system probe with its caches.
func newHostProbe() *hostProbe {
	bins := &binaryCache{now: time.Now, found: map[string]binaryEntry{}}
	procs := &ttlValue[map[string]bool]{ttl: processTTL, fetch: runningProcesses}
	tinc := &ttlValue[[]string]{ttl: configTTL, fetch: func() []string {
		return tincInterfaces([]string{"/etc/tinc", "/usr/local/etc/tinc"})
	}}
	inner := &ttlValue[[]string]{ttl: configTTL, fetch: func() []string {
		return innernetInterfaces([]string{"/etc/innernet", "/etc/innernet-server"})
	}}
	return &hostProbe{
		defaultRouteIfaces: systemDefaultRouteIfaces,
		hasBinary:          bins.has,
		processNamed:       func(comm string) bool { return procs.get()[comm] },
		tincIfaces:         tinc.get,
		innernetIfaces:     inner.get,
	}
}

// ttlValue caches the result of fetch for ttl.
type ttlValue[T any] struct {
	ttl   time.Duration
	fetch func() T
	now   func() time.Time // nil: time.Now

	mu  sync.Mutex
	at  time.Time
	ok  bool
	val T
}

func (c *ttlValue[T]) get() T {
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ok || now().Sub(c.at) >= c.ttl {
		c.val, c.at, c.ok = c.fetch(), now(), true
	}
	return c.val
}

// binaryPlaces are where a binary is looked for when it is not on PATH (a
// service manager's PATH is short) — the usual system directories plus the
// install locations of the products classify asks about.
var binaryPlaces = map[string][]string{
	"vpnclient":    {"/usr/local/vpnclient/vpnclient", "/opt/vpnclient/vpnclient"},
	"zerotier-cli": {"/Library/Application Support/ZeroTier/One/zerotier-cli"},
}

var binaryDirs = []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt/homebrew/bin", "/bin", "/sbin"}

type binaryEntry struct {
	ok bool
	at time.Time
}

// binaryCache answers hasBinary, remembering each answer for binaryTTL.
type binaryCache struct {
	now   func() time.Time
	mu    sync.Mutex
	found map[string]binaryEntry
}

func (c *binaryCache) has(name string) bool {
	c.mu.Lock()
	e, ok := c.found[name]
	c.mu.Unlock()
	if ok && c.now().Sub(e.at) < binaryTTL {
		return e.ok
	}
	found := lookBinary(name)
	c.mu.Lock()
	c.found[name] = binaryEntry{ok: found, at: c.now()}
	c.mu.Unlock()
	return found
}

// lookBinary reports whether an executable name exists on PATH, in a
// system directory or in its product's usual place.
func lookBinary(name string) bool {
	if name == "" || strings.ContainsRune(name, '/') {
		return false
	}
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	places := slices.Clone(binaryPlaces[name])
	for _, d := range binaryDirs {
		places = append(places, filepath.Join(d, name))
	}
	for _, p := range places {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

// maxConfigRead bounds one configuration file read by a probe.
const maxConfigRead = 64 << 10

// readSmall reads a regular file of at most limit bytes.
func readSmall(path string, limit int64) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil || int64(len(b)) > limit {
		return nil, false
	}
	return b, true
}

// tincInterfaces returns the interface names of the tinc networks under
// dirs: a network's "Interface =" from <dir>/<net>/tinc.conf, else the
// network name (tinc's default).
func tincInterfaces(dirs []string) []string {
	var out []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for i, e := range entries {
			if i >= 64 {
				break
			}
			if !e.IsDir() {
				continue
			}
			b, ok := readSmall(filepath.Join(dir, e.Name(), "tinc.conf"), maxConfigRead)
			if !ok {
				continue
			}
			name := e.Name()
			if v := confValue(b, "interface"); v != "" {
				name = v
			}
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// confValue returns the value of the first "Key = value" line of a
// tinc-style configuration (key compared case-insensitively).
func confValue(b []byte, key string) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// innernetInterfaces returns the innernet network names: every
// <dir>/<name>.conf (the client's /etc/innernet, the server's
// /etc/innernet-server); the interface carries the network's name.
func innernetInterfaces(dirs []string) []string {
	var out []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for i, e := range entries {
			if i >= 64 {
				break
			}
			name, ok := strings.CutSuffix(e.Name(), ".conf")
			if ok && name != "" && e.Type().IsRegular() && !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// routeCache keeps the default-route probe's answer for routeTTL, or until
// the interface set changes (key).
type routeCache struct {
	mu  sync.Mutex
	key string
	at  time.Time
	m   map[int]bool
}

// get returns the cached answer for key, calling fetch when it is stale.
// A failed probe caches "no default route known" (nothing becomes egress).
// A caller's cancellation is never recorded, and it gets the last answer
// (even a stale one, or one for another interface set): an empty answer
// would turn every exit tunnel into an offered interface for one snapshot
// (network.changed, a certificate reissue, and back).
func (c *routeCache) get(ctx context.Context, key string, now time.Time, fetch func(context.Context) (map[int]bool, error)) map[int]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m != nil && c.key == key && now.Sub(c.at) < routeTTL {
		return c.m
	}
	if ctx.Err() != nil && c.m != nil {
		return c.m
	}
	m, err := fetch(ctx)
	if err != nil && ctx.Err() != nil {
		if c.m != nil {
			return c.m // cancelled: try again next time
		}
		return map[int]bool{}
	}
	if err != nil || m == nil {
		m = map[int]bool{}
	}
	c.key, c.at, c.m = key, now, m
	return m
}
