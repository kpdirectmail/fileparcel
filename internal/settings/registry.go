// Package settings is the runtime settings catalog (DESIGN §11): a registry
// of setting definitions (Def), filled by the owning packages from init(), and
// the Store that implements core.Settings.
//
// Registering a setting (in the owning package's settings.go):
//
//	func init() {
//	    settings.Register(settings.Def{Key: "storage.trash_days", Section: "storage", Order: 40,
//	        Type: settings.TypeInt, Default: 30, Min: 0, Max: 3650,
//	        Label: "Trash retention (days)", Description: "…"})
//	}
//
// There is no central catalog file. The Def/Register API is frozen.
//
// The Store (store.go) persists values in the settings table as canonical
// JSON, seals secret values with Keys.SealField, bridges Bootstrap keys
// (server.*, log.level) onto fileparcel.toml and serves reads from an
// in-memory atomic snapshot that is rebuilt after every change and reloaded
// on settings.changed.
package settings

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Type is the value type of a setting. JSON encodings and the Go type passed
// to Def.Validate:
//
//	TypeBool      true/false           bool
//	TypeInt       integer              int64      (Min/Max enforced when Max > Min)
//	TypeString    string               string
//	TypeStrings   ["a","b"]            []string
//	TypeDuration  "15m" (Go syntax)    time.Duration
//	TypeEnum      one of Enum          string
//	TypeCIDRs     ["10.0.0.0/8","::1"] []string   (CIDRs or single IPs)
//	TypeSecret    string (sealed)      string     (implies Secret)
//	TypeCron      "0 3 * * *" or ""    string     (5 fields)
//	TypeColor     "#2563eb"            string     (#rgb or #rrggbb)
//	TypeEmail     "a@b.c" or ""        string
//	TypeURL       "https://…" or ""    string     (absolute http/https)
type Type string

// Setting types.
const (
	TypeBool     Type = "bool"
	TypeInt      Type = "int"
	TypeString   Type = "string"
	TypeStrings  Type = "strings"
	TypeDuration Type = "duration"
	TypeEnum     Type = "enum"
	TypeCIDRs    Type = "cidrs"
	TypeSecret   Type = "secret"
	TypeCron     Type = "cron"
	TypeColor    Type = "color"
	TypeEmail    Type = "email"
	TypeURL      Type = "url"
)

// Def defines one setting.
type Def struct {
	// Key is "section.name" (lowercase, dotted), e.g. "storage.trash_days".
	Key string
	// Section groups settings in the UI (general, network, mdns, tls, acme,
	// tailscale, funnel, mtls, auth, ratelimit, storage, sharing, keys,
	// backup, email, audit, server). See SectionOrder.
	Section string
	// Order sorts settings within a section (ascending).
	Order int
	Type  Type
	// Default is the default value in its natural Go form (30, true, "auto",
	// []string{}, "15m" for durations). Required (use "" / []string{} for empty).
	Default any
	// Min/Max bound TypeInt values; enforced only when Max > Min.
	Min, Max int64
	// Restart marks settings that take effect only after a restart.
	Restart bool
	// Secret values are sealed at rest and masked in the catalog/audit.
	Secret bool
	// Enum lists the allowed values of TypeEnum.
	Enum []string
	// Label and Description are shown in the admin UI.
	Label, Description string
	// Validate is an optional extra check on the decoded value (Go types as
	// documented on Type). Return a user-facing error.
	Validate func(v any) error
	// Bootstrap marks keys stored in fileparcel.toml instead of the DB
	// (server.*, log.level; the "bootstrap bridge"). The key must exist in
	// config.Keys().
	Bootstrap bool
	// Managed names the route that owns the key, e.g. "PUT
	// /api/v1/admin/network/funnel" (the funnel.* keys). PATCH/DELETE
	// /admin/settings refuse such keys with 409 and the catalog shows them
	// read-only (core.SettingView.Managed); Store.Set from the owning
	// service is unaffected. "" = an ordinary key.
	Managed string
}

// SectionOrder is the UI order of sections; unknown sections sort after these.
var SectionOrder = []string{
	"general", "network", "mdns", "tls", "acme", "tailscale", "funnel", "mtls", "auth", "ratelimit",
	"storage", "sharing", "keys", "backup", "email", "audit", "server",
}

var (
	regMu sync.RWMutex
	reg   = map[string]*Def{}
)

var keyRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Register adds a setting definition. It panics on programmer errors
// (invalid key, duplicate key, unknown type, default that fails validation),
// so misconfigurations surface at startup/tests. Call it from init().
func Register(d Def) {
	if !keyRe.MatchString(d.Key) {
		panic(fmt.Sprintf("settings: invalid key %q", d.Key))
	}
	if d.Section == "" {
		d.Section, _, _ = strings.Cut(d.Key, ".")
	}
	if d.Label == "" {
		d.Label = d.Key
	}
	if d.Type == TypeSecret {
		d.Secret = true
	}
	switch d.Type {
	case TypeBool, TypeInt, TypeString, TypeStrings, TypeDuration, TypeEnum, TypeCIDRs,
		TypeSecret, TypeCron, TypeColor, TypeEmail, TypeURL:
	default:
		panic(fmt.Sprintf("settings: %s: unknown type %q", d.Key, d.Type))
	}
	if d.Type == TypeEnum && len(d.Enum) == 0 {
		panic(fmt.Sprintf("settings: %s: enum without values", d.Key))
	}
	if d.Default == nil {
		panic(fmt.Sprintf("settings: %s: nil default", d.Key))
	}
	raw, err := json.Marshal(d.Default)
	if err != nil {
		panic(fmt.Sprintf("settings: %s: default: %v", d.Key, err))
	}
	if _, _, err := d.Decode(raw); err != nil {
		panic(fmt.Sprintf("settings: %s: invalid default: %v", d.Key, err))
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := reg[d.Key]; dup {
		panic(fmt.Sprintf("settings: duplicate key %q", d.Key))
	}
	dd := d
	dd.Enum = slices.Clone(d.Enum)
	reg[d.Key] = &dd
}

// Lookup returns the definition of key.
func Lookup(key string) (Def, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	d, ok := reg[key]
	if !ok {
		return Def{}, false
	}
	return *d, true
}

// Defs returns every definition sorted by section (SectionOrder), Order, Key.
func Defs() []Def {
	regMu.RLock()
	out := make([]Def, 0, len(reg))
	for _, d := range reg {
		out = append(out, *d)
	}
	regMu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		si, sj := sectionIndex(out[i].Section), sectionIndex(out[j].Section)
		if si != sj {
			return si < sj
		}
		if out[i].Section != out[j].Section {
			return out[i].Section < out[j].Section
		}
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func sectionIndex(s string) int {
	if i := slices.Index(SectionOrder, s); i >= 0 {
		return i
	}
	return len(SectionOrder)
}

// DefaultJSON returns the canonical JSON of the default value.
func (d Def) DefaultJSON() json.RawMessage {
	raw, _ := json.Marshal(d.Default)
	canon, _, err := d.Decode(raw)
	if err != nil {
		return raw
	}
	return canon
}

// Decode validates a JSON value against the definition (type, enum, range,
// Validate) and returns its canonical JSON and the decoded Go value (see Type).
func (d Def) Decode(raw json.RawMessage) (json.RawMessage, any, error) {
	v, err := d.decode(raw)
	if err != nil {
		return nil, nil, err
	}
	if d.Validate != nil {
		if err := d.Validate(v); err != nil {
			return nil, nil, err
		}
	}
	var canon []byte
	if dur, ok := v.(time.Duration); ok {
		canon, err = json.Marshal(formatDuration(dur))
	} else {
		canon, err = json.Marshal(v)
	}
	if err != nil {
		return nil, nil, err
	}
	return canon, v, nil
}

// formatDuration renders d compactly: 15m, 1h, 1h30m, 90s -> "1m30s".
func formatDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

var (
	colorRe = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
	cronRe  = regexp.MustCompile(`^[0-9*,/\-]+$`)
)

// Generic bounds every value decode enforces, whatever the setting. Settings
// with a tighter limit (network.extra_hosts: 256 names, the access lists:
// 1024, tls.extra_sans and acme.domains: 64) check it in their Validate.
const (
	maxStringLen   = 8192
	maxListEntries = 1024
)

func (d Def) decode(raw json.RawMessage) (any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("value required")
	}
	str := func() (string, error) {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("expected a string")
		}
		if len(s) > maxStringLen {
			return "", fmt.Errorf("value too long")
		}
		return s, nil
	}
	list := func() ([]string, error) {
		var l []string
		if err := json.Unmarshal(raw, &l); err != nil {
			return nil, fmt.Errorf("expected a list of strings")
		}
		// A list setting is bounded here as well as by its own Validate: an
		// unbounded one is a valid PATCH that can take the server down (12 000
		// names in tls.extra_sans produced a 228 KB certificate no TLS client
		// would read).
		if len(l) > maxListEntries {
			return nil, fmt.Errorf("at most %d entries", maxListEntries)
		}
		if l == nil {
			l = []string{}
		}
		for i := range l {
			if len(l[i]) > maxStringLen {
				return nil, fmt.Errorf("entry %d is too long", i+1)
			}
			l[i] = strings.TrimSpace(l[i])
		}
		return l, nil
	}
	switch d.Type {
	case TypeBool:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("expected true or false")
		}
		return b, nil
	case TypeInt:
		var n int64
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("expected an integer")
		}
		if d.Max > d.Min && (n < d.Min || n > d.Max) {
			return nil, fmt.Errorf("must be between %d and %d", d.Min, d.Max)
		}
		return n, nil
	case TypeString, TypeSecret:
		return str()
	case TypeStrings:
		return list()
	case TypeDuration:
		s, err := str()
		if err != nil {
			return nil, err
		}
		dur, err := time.ParseDuration(s)
		if err != nil || dur < 0 {
			return nil, fmt.Errorf("expected a duration like \"15m\" or \"24h\"")
		}
		return dur, nil
	case TypeEnum:
		s, err := str()
		if err != nil {
			return nil, err
		}
		if !slices.Contains(d.Enum, s) {
			return nil, fmt.Errorf("must be one of: %s", strings.Join(d.Enum, ", "))
		}
		return s, nil
	case TypeCIDRs:
		l, err := list()
		if err != nil {
			return nil, err
		}
		for _, c := range l {
			if !validCIDROrIP(c) {
				return nil, fmt.Errorf("%q is not a CIDR or IP address", c)
			}
		}
		return l, nil
	case TypeCron:
		s, err := str()
		if err != nil {
			return nil, err
		}
		s = strings.Join(strings.Fields(s), " ")
		if s == "" {
			return s, nil
		}
		f := strings.Fields(s)
		if len(f) != 5 {
			return nil, fmt.Errorf("expected 5 cron fields (minute hour day month weekday)")
		}
		for _, x := range f {
			if !cronRe.MatchString(x) {
				return nil, fmt.Errorf("invalid cron field %q", x)
			}
		}
		return s, nil
	case TypeColor:
		s, err := str()
		if err != nil {
			return nil, err
		}
		if !colorRe.MatchString(s) {
			return nil, fmt.Errorf("expected a colour like #2563eb")
		}
		return strings.ToLower(s), nil
	case TypeEmail:
		s, err := str()
		if err != nil {
			return nil, err
		}
		if s == "" {
			return s, nil
		}
		a, err := mail.ParseAddress(s)
		if err != nil || a.Name != "" || a.Address != s {
			return nil, fmt.Errorf("expected an e-mail address")
		}
		return s, nil
	case TypeURL:
		s, err := str()
		if err != nil {
			return nil, err
		}
		if s == "" {
			return s, nil
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("expected an absolute http(s) URL")
		}
		return s, nil
	}
	return nil, fmt.Errorf("unknown type %q", d.Type)
}

func validCIDROrIP(s string) bool {
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}
