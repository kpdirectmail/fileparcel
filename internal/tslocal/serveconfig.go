package tslocal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// ServeConfig is tailscale's ipn.ServeConfig as FileParcel edits it: a
// surgical merge. Everything it does not model is written back exactly as
// read: unknown top-level keys and Services (other), Foreground sessions,
// and every TCP/Web entry that is not changed (json.RawMessage values, kept
// byte for byte). Foreground is decoded read-only (Entries, Conflict).
//
// The zero value is an empty configuration. GET answers "null" when nothing
// is configured; UnmarshalJSON accepts it.
type ServeConfig struct {
	// ETag is the Etag header of the GET that read the configuration; the
	// POST sends it as If-Match (never empty). "" for a configuration read
	// with the CLI.
	ETag string

	other       map[string]json.RawMessage // Services and future keys
	TCP         map[string]json.RawMessage // "443" → raw TCPPortHandler
	Web         map[string]json.RawMessage // "name:443" → raw WebServerConfig
	AllowFunnel map[string]bool            // "name:443" → Funnel on
	Foreground  map[string]json.RawMessage // session id → raw nested ServeConfig (never modified)
}

// TCPPortHandler is ipn.TCPPortHandler.
type TCPPortHandler struct {
	HTTPS         bool   `json:",omitempty"`
	HTTP          bool   `json:",omitempty"`
	TCPForward    string `json:",omitempty"`
	TerminateTLS  string `json:",omitempty"`
	ProxyProtocol int    `json:",omitzero"`
}

// WebServerConfig is ipn.WebServerConfig (mount → raw HTTPHandler).
type WebServerConfig struct {
	Handlers map[string]json.RawMessage
}

// HTTPHandler is the part of ipn.HTTPHandler FileParcel reads.
type HTTPHandler struct {
	Path     string `json:",omitempty"`
	Proxy    string `json:",omitempty"`
	Text     string `json:",omitempty"`
	Redirect string `json:",omitempty"`
}

// ServeEntry is one flattened serve/funnel entry (Entries).
type ServeEntry struct {
	HostPort   string // Web key "name:port"; "" for a TCP forward
	Port       int
	Funnel     bool // AllowFunnel of HostPort in the configuration the entry belongs to
	Foreground bool // part of a foreground `tailscale serve` session
	HTTP       bool // plain-HTTP port (TCP handler HTTP:true)
	Service    string
	Mount      string // "/" …; "" for a TCP forward
	Proxy      string
	Path       string // file/directory handler
	Text       string // static text handler
	Redirect   string
	TCPForward string
	// TerminateTLS is the TLS name of a TLS-terminated TCP forward.
	TerminateTLS string
}

// Target describes what the entry serves (for messages).
func (e ServeEntry) Target() string {
	switch {
	case e.Proxy != "":
		return e.Proxy
	case e.Path != "":
		return "path:" + e.Path
	case e.Redirect != "":
		return "redirect:" + e.Redirect
	case e.Text != "":
		return "text"
	case e.TCPForward != "":
		return "tcp:" + e.TCPForward
	}
	return "unknown"
}

// UsesLocalPath reports whether the entry serves a Unix socket or a file
// path: tailscaled then requires root or a sudo-capable operator for every
// change of the configuration (DESIGN §10.6).
func (e ServeEntry) UsesLocalPath() bool {
	return e.Path != "" || strings.HasPrefix(e.Proxy, "unix:") || strings.HasPrefix(e.TCPForward, "unix:")
}

// UnmarshalJSON implements json.Unmarshaler; "null" is an empty
// configuration. ETag is kept.
func (sc *ServeConfig) UnmarshalJSON(b []byte) error {
	etag := sc.ETag
	*sc = ServeConfig{ETag: etag}
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return fmt.Errorf("tailscale serve config: %w", err)
	}
	for k, v := range top {
		var err error
		switch k {
		case "TCP":
			sc.TCP, err = rawMap(v)
		case "Web":
			sc.Web, err = rawMap(v)
		case "Foreground":
			sc.Foreground, err = rawMap(v)
		case "AllowFunnel":
			if !isNull(v) {
				err = json.Unmarshal(v, &sc.AllowFunnel)
			}
		default:
			if sc.other == nil {
				sc.other = map[string]json.RawMessage{}
			}
			sc.other[k] = v
		}
		if err != nil {
			return fmt.Errorf("tailscale serve config: %s: %w", k, err)
		}
	}
	return nil
}

func isNull(v json.RawMessage) bool { return string(bytes.TrimSpace(v)) == "null" }

func rawMap(v json.RawMessage) (map[string]json.RawMessage, error) {
	if isNull(v) {
		return nil, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// MarshalJSON implements json.Marshaler. Raw values are written exactly as
// they were read (encoding/json would re-compact and HTML-escape them).
func (sc *ServeConfig) MarshalJSON() ([]byte, error) {
	if sc == nil {
		return []byte("null"), nil
	}
	vals := map[string][]byte{}
	for k, v := range sc.other {
		vals[k] = v
	}
	for k, m := range map[string]map[string]json.RawMessage{"TCP": sc.TCP, "Web": sc.Web, "Foreground": sc.Foreground} {
		if len(m) > 0 {
			vals[k] = marshalRawMap(m)
		}
	}
	if len(sc.AllowFunnel) > 0 {
		b, err := json.Marshal(sc.AllowFunnel)
		if err != nil {
			return nil, err
		}
		vals["AllowFunnel"] = b
	}
	return marshalObject(vals), nil
}

func marshalRawMap(m map[string]json.RawMessage) []byte {
	vals := make(map[string][]byte, len(m))
	for k, v := range m {
		vals[k] = v
	}
	return marshalObject(vals)
}

// marshalObject writes {"k":v,…} with sorted keys and the values verbatim.
func marshalObject(vals map[string][]byte) []byte {
	keys := slices.Sorted(maps.Keys(vals))
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vals[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

// Clone returns a deep copy (raw values are shared: they are never
// modified in place).
func (sc *ServeConfig) Clone() *ServeConfig {
	if sc == nil {
		return &ServeConfig{}
	}
	return &ServeConfig{
		ETag: sc.ETag, other: maps.Clone(sc.other), TCP: maps.Clone(sc.TCP), Web: maps.Clone(sc.Web),
		AllowFunnel: maps.Clone(sc.AllowFunnel), Foreground: maps.Clone(sc.Foreground),
	}
}

// Equal reports whether sc and o encode to the same JSON (the ETag is ignored).
func (sc *ServeConfig) Equal(o *ServeConfig) bool {
	a, err1 := sc.MarshalJSON()
	b, err2 := o.MarshalJSON()
	return err1 == nil && err2 == nil && bytes.Equal(a, b)
}

// Empty reports whether the configuration serves nothing.
func (sc *ServeConfig) Empty() bool {
	return sc == nil || (len(sc.TCP) == 0 && len(sc.Web) == 0 && len(sc.AllowFunnel) == 0 &&
		len(sc.Foreground) == 0 && len(sc.other) == 0)
}

// Services returns the raw Services map of the configuration (nil when none).
func (sc *ServeConfig) Services() json.RawMessage {
	if sc == nil {
		return nil
	}
	return sc.other["Services"]
}

// tcpHandler decodes TCP[port]; exact reports whether it is exactly
// {"HTTPS":true} (no other field, known or unknown).
func tcpHandler(raw json.RawMessage) (h TCPPortHandler, exact bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		_ = json.Unmarshal(raw, &h)
		return h, false
	}
	return h, h == TCPPortHandler{HTTPS: true}
}

// webHandlers decodes the handlers of a raw WebServerConfig.
func webHandlers(raw json.RawMessage) map[string]json.RawMessage {
	var w WebServerConfig
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil
	}
	return w.Handlers
}

func httpHandler(raw json.RawMessage) HTTPHandler {
	var h HTTPHandler
	_ = json.Unmarshal(raw, &h)
	return h
}

// portOf returns the port of a HostPort key ("name:443" → 443; 0 when none).
func portOf(hostPort string) int {
	i := strings.LastIndexByte(hostPort, ':')
	if i < 0 {
		return 0
	}
	p, err := strconv.Atoi(hostPort[i+1:])
	if err != nil {
		return 0
	}
	return p
}

// Entries returns every entry of the configuration, including those of
// Foreground sessions (Foreground=true) and Services (Service=name), in a
// stable order.
func (sc *ServeConfig) Entries() []ServeEntry {
	if sc == nil {
		return nil
	}
	out := entriesOf(sc.TCP, sc.Web, sc.AllowFunnel, false, "")
	for _, id := range slices.Sorted(maps.Keys(sc.Foreground)) {
		var fg ServeConfig
		if err := fg.UnmarshalJSON(sc.Foreground[id]); err != nil {
			continue
		}
		out = append(out, entriesOf(fg.TCP, fg.Web, fg.AllowFunnel, true, "")...)
	}
	if raw := sc.Services(); raw != nil {
		var svcs map[string]struct {
			TCP map[string]json.RawMessage
			Web map[string]json.RawMessage
		}
		if json.Unmarshal(raw, &svcs) == nil {
			for _, name := range slices.Sorted(maps.Keys(svcs)) {
				s := svcs[name]
				out = append(out, entriesOf(s.TCP, s.Web, nil, false, name)...)
			}
		}
	}
	return out
}

func entriesOf(tcp, web map[string]json.RawMessage, funnel map[string]bool, fg bool, service string) []ServeEntry {
	var out []ServeEntry
	httpPorts := map[int]bool{}
	for _, k := range slices.Sorted(maps.Keys(tcp)) {
		port, _ := strconv.Atoi(k)
		h, _ := tcpHandler(tcp[k])
		if h.HTTP {
			httpPorts[port] = true
		}
		if h.TCPForward != "" {
			out = append(out, ServeEntry{Port: port, Foreground: fg, Service: service,
				TCPForward: h.TCPForward, TerminateTLS: h.TerminateTLS})
		}
	}
	for _, hp := range slices.Sorted(maps.Keys(web)) {
		hs := webHandlers(web[hp])
		port := portOf(hp)
		for _, mount := range slices.Sorted(maps.Keys(hs)) {
			h := httpHandler(hs[mount])
			out = append(out, ServeEntry{HostPort: hp, Port: port, Funnel: funnel[hp], Foreground: fg,
				HTTP: httpPorts[port], Service: service, Mount: mount,
				Proxy: h.Proxy, Path: h.Path, Text: h.Text, Redirect: h.Redirect})
		}
	}
	return out
}

// Conflict reports whether a FileParcel entry on (hostPort, port) would
// clash with something FileParcel does not own (owned tells FileParcel's
// proxy targets apart), and names it. First match wins:
//  1. a Foreground session serves the port or the HostPort (tailscaled
//     refuses background listeners there);
//  2. TCP[port] exists and is not exactly {"HTTPS":true} (HTTP, a TCP
//     forward, TLS-terminated TCP: a port's serve type cannot change);
//  3. Web[hostPort] has any handler (any mount) that is not owned (with
//     Funnel on, a foreign mount would become public as well).
func (sc *ServeConfig) Conflict(hostPort string, port int, owned func(proxy string) bool) (target string, conflict bool) {
	if sc == nil {
		return "", false
	}
	key := strconv.Itoa(port)
	for _, id := range slices.Sorted(maps.Keys(sc.Foreground)) {
		var fg ServeConfig
		if err := fg.UnmarshalJSON(sc.Foreground[id]); err != nil {
			continue
		}
		_, tcp := fg.TCP[key]
		_, web := fg.Web[hostPort]
		if tcp || web {
			t := "a foreground `tailscale serve` session"
			for _, e := range entriesOf(fg.TCP, fg.Web, fg.AllowFunnel, true, "") {
				if e.HostPort == hostPort || (e.HostPort == "" && e.Port == port) {
					t += " (" + e.Target() + ")"
					break
				}
			}
			return t, true
		}
	}
	if raw, ok := sc.TCP[key]; ok {
		if h, exact := tcpHandler(raw); !exact {
			switch {
			case h.TCPForward != "":
				return "tcp:" + h.TCPForward, true
			case h.HTTP:
				return "a plain-HTTP serve on port " + key, true
			default:
				return "a TCP handler on port " + key, true
			}
		}
	}
	if raw, ok := sc.Web[hostPort]; ok {
		hs := webHandlers(raw)
		for _, mount := range slices.Sorted(maps.Keys(hs)) {
			h := httpHandler(hs[mount])
			if h.Proxy == "" || owned == nil || !owned(h.Proxy) {
				e := ServeEntry{Mount: mount, Proxy: h.Proxy, Path: h.Path, Text: h.Text, Redirect: h.Redirect}
				return e.Target() + " (mount " + mount + ")", true
			}
		}
	}
	return "", false
}

// SetEntry points the mount "/" of hostPort at proxy: TCP[port] becomes
// {"HTTPS":true} when absent (an existing one is kept byte for byte),
// Web[hostPort] {"Handlers":{"/":{"Proxy":proxy}}} (other mounts kept), and
// AllowFunnel[hostPort] is set for Funnel and deleted for Serve. An entry
// that already reads so is left byte for byte. The caller has checked
// Conflict first.
func (sc *ServeConfig) SetEntry(hostPort string, port int, proxy string, funnel bool) {
	key := strconv.Itoa(port)
	if sc.TCP == nil {
		sc.TCP = map[string]json.RawMessage{}
	}
	if _, ok := sc.TCP[key]; !ok {
		sc.TCP[key] = json.RawMessage(`{"HTTPS":true}`)
	}
	if sc.Web == nil {
		sc.Web = map[string]json.RawMessage{}
	}
	want := HTTPHandler{Proxy: proxy}
	hs := map[string]json.RawMessage{}
	if raw, ok := sc.Web[hostPort]; ok {
		hs = webHandlers(raw)
		if hs == nil {
			hs = map[string]json.RawMessage{}
		}
	}
	if cur, ok := hs["/"]; !ok || !exactHandler(cur, want) {
		hb, _ := json.Marshal(want)
		hs["/"] = hb
		sc.Web[hostPort] = marshalObject(map[string][]byte{"Handlers": marshalRawMap(hs)})
	}
	if funnel {
		if sc.AllowFunnel == nil {
			sc.AllowFunnel = map[string]bool{}
		}
		sc.AllowFunnel[hostPort] = true
	} else {
		delete(sc.AllowFunnel, hostPort)
	}
}

// exactHandler reports whether raw is exactly want (no other field).
func exactHandler(raw json.RawMessage, want HTTPHandler) bool {
	var h map[string]json.RawMessage
	if json.Unmarshal(raw, &h) != nil {
		return false
	}
	got := httpHandler(raw)
	b, _ := json.Marshal(want)
	var w map[string]json.RawMessage
	_ = json.Unmarshal(b, &w)
	return got == want && len(h) == len(w)
}

// RemoveEntry deletes FileParcel's entry on (hostPort, port): the mount "/"
// only if its proxy is owned; Web[hostPort] and AllowFunnel[hostPort] once
// no handler is left; TCP[port] only if it is exactly {"HTTPS":true} and no
// other Web key uses the port (tailscale's own RemoveWebHandler would delete
// it unconditionally). It reports whether the mount was removed.
func (sc *ServeConfig) RemoveEntry(hostPort string, port int, owned func(proxy string) bool) (removed bool) {
	raw, ok := sc.Web[hostPort]
	if !ok {
		return false
	}
	hs := webHandlers(raw)
	cur, ok := hs["/"]
	if !ok {
		return false
	}
	if h := httpHandler(cur); h.Proxy == "" || owned == nil || !owned(h.Proxy) {
		return false
	}
	delete(hs, "/")
	if len(hs) > 0 {
		sc.Web[hostPort] = marshalObject(map[string][]byte{"Handlers": marshalRawMap(hs)})
		return true
	}
	delete(sc.Web, hostPort)
	delete(sc.AllowFunnel, hostPort)
	key := strconv.Itoa(port)
	if raw, ok := sc.TCP[key]; ok {
		if _, exact := tcpHandler(raw); exact {
			suffix := ":" + key
			used := false
			for hp := range sc.Web {
				if strings.HasSuffix(hp, suffix) {
					used = true
					break
				}
			}
			if !used {
				delete(sc.TCP, key)
			}
		}
	}
	return true
}

// FunnelOn reports whether AllowFunnel is set for hostPort.
func (sc *ServeConfig) FunnelOn(hostPort string) bool { return sc != nil && sc.AllowFunnel[hostPort] }

// Proxy returns the proxy target of the mount "/" of hostPort and whether
// TCP[port] is exactly HTTPS ("" when there is no such mount).
func (sc *ServeConfig) Proxy(hostPort string, port int) (proxy string, httpsPort bool) {
	if sc == nil {
		return "", false
	}
	if raw, ok := sc.TCP[strconv.Itoa(port)]; ok {
		_, httpsPort = tcpHandler(raw)
	}
	raw, ok := sc.Web[hostPort]
	if !ok {
		return "", httpsPort
	}
	if cur, ok := webHandlers(raw)["/"]; ok {
		return httpHandler(cur).Proxy, httpsPort
	}
	return "", httpsPort
}
