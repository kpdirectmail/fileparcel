// Package config loads, validates and atomically rewrites the bootstrap
// configuration file <HOME>/fileparcel.toml (DESIGN §11.1). The file also marks
// the directory as a FileParcel home.
//
// Every key can be overridden by an environment variable named
// FILEPARCEL_<SECTION>_<KEY> (upper case), e.g. FILEPARCEL_SERVER_HTTPS_PORT=9443
// or FILEPARCEL_LOG_LEVEL=debug. List values are comma separated
// (FILEPARCEL_SERVER_BIND="127.0.0.1,::1"). The top-level install_id cannot be
// overridden. Overridden keys are reported by Overridden() so the UI can show
// "overridden by env", and Save() never persists an env-provided value.
//
// Runtime settings live in the database (package settings); a few of them
// (server.*, log.level) are bridged onto this file via Get/Set + Save.
package config

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"fileparcel/internal/home"
)

// EnvPrefix is the prefix of environment overrides.
const EnvPrefix = "FILEPARCEL_"

// DefaultHeader is written at the top of a new fileparcel.toml. An existing
// file's leading comment block (comment lines followed by a blank line) is
// preserved verbatim by Save instead.
const DefaultHeader = `# FileParcel bootstrap configuration.
# This file also marks this directory as a FileParcel home - do not delete it.
# Most settings live in the database: use the admin UI or "fileparcel config".
# Environment overrides: FILEPARCEL_<SECTION>_<KEY>, e.g. FILEPARCEL_SERVER_HTTPS_PORT=9443.`

// Config is the typed content of fileparcel.toml.
type Config struct {
	// InstallID identifies this installation (random 16 bytes, hex). Generated at init.
	InstallID   string            `toml:"install_id" json:"install_id"`
	Server      ServerConfig      `toml:"server" json:"server"`
	Log         LogConfig         `toml:"log" json:"log"`
	AdminSocket AdminSocketConfig `toml:"admin_socket" json:"admin_socket"`
	Runtime     RuntimeConfig     `toml:"runtime" json:"runtime"`

	path       string         // file this config was loaded from / saves to
	header     string         // preserved leading comment block
	file       *Config        // values as read from disk (before env overrides)
	env        map[string]any // key -> value applied from the environment
	overridden []string       // sorted keys overridden by the environment
	warnings   []string       // non-fatal load problems (unknown keys)
	extra      map[string]any // keys found in the file but not modelled here
}

// ServerConfig is the [server] section.
type ServerConfig struct {
	// Name is the mDNS label, CA name and default WebAuthn RP ID base (DNS label).
	Name string `toml:"name" json:"name" comment:"mDNS label, CA name, default WebAuthn RP ID base"`
	// HTTPSPort is the main (TLS) port.
	HTTPSPort int `toml:"https_port" json:"https_port"`
	// HTTPPort is the optional plain-HTTP redirect/ACME port; 0 disables it.
	HTTPPort int `toml:"http_port" json:"http_port" comment:"0 = no redirect listener"`
	// Bind lists the listen addresses (IP literals); "::" = dual-stack all interfaces.
	Bind []string `toml:"bind" json:"bind" comment:"dual-stack all interfaces; the allowlist does the filtering"`
	// SamePortRedirect answers plain HTTP on the HTTPS port with a 308 redirect.
	SamePortRedirect bool `toml:"same_port_redirect" json:"same_port_redirect"`
	// PublicURL is an optional canonical URL used for links and WebAuthn.
	PublicURL string `toml:"public_url" json:"public_url" comment:"optional canonical URL for links / WebAuthn"`
	// TrustedProxies lists IPs/CIDRs whose X-Forwarded-For is honoured.
	TrustedProxies []string `toml:"trusted_proxies" json:"trusted_proxies"`
}

// LogConfig is the [log] section.
type LogConfig struct {
	Level     string `toml:"level" json:"level" comment:"debug|info|warn|error"`
	Format    string `toml:"format" json:"format" comment:"text|json"`
	File      bool   `toml:"file" json:"file" comment:"also write logs/fileparcel.log (size-rotated)"`
	MaxSizeMB int    `toml:"max_size_mb" json:"max_size_mb"`
	MaxFiles  int    `toml:"max_files" json:"max_files"`
}

// AdminSocketConfig is the [admin_socket] section.
type AdminSocketConfig struct {
	Enabled bool `toml:"enabled" json:"enabled"`
}

// RuntimeConfig is the [runtime] section.
type RuntimeConfig struct {
	// GOMemLimitMB sets GOMEMLIMIT; 0 = auto (min(1 GiB, 25% RAM)).
	GOMemLimitMB int `toml:"gomemlimit_mb" json:"gomemlimit_mb" comment:"0 = auto (min(1 GiB, 25% RAM))"`
}

// NewInstallID returns a fresh random install id (16 bytes, lowercase hex).
func NewInstallID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Default returns the default configuration (DESIGN §11.1) with the given
// install id. It has no path; use SaveTo to write it.
func Default(installID string) *Config {
	return &Config{
		InstallID: installID,
		Server: ServerConfig{
			Name:             "fileparcel",
			HTTPSPort:        8443,
			HTTPPort:         8080,
			Bind:             []string{"::"},
			SamePortRedirect: true,
			PublicURL:        "",
			TrustedProxies:   []string{},
		},
		Log: LogConfig{
			Level:     "info",
			Format:    "text",
			File:      true,
			MaxSizeMB: 50,
			MaxFiles:  5,
		},
		AdminSocket: AdminSocketConfig{Enabled: true},
		Runtime:     RuntimeConfig{GOMemLimitMB: 0},
		header:      DefaultHeader,
	}
}

// Load reads <HOME>/fileparcel.toml, fills missing keys with defaults, applies
// environment overrides and validates the result. Unknown keys are not fatal
// (so a rolled-back binary can still start); they are listed by Warnings().
func Load(h *home.Home) (*Config, error) {
	return LoadFile(h.Config())
}

// LoadFile is Load for an explicit path.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config: %s not found; run \"fileparcel init --home DIR\": %w", path, err)
		}
		return nil, fmt.Errorf("config: %w", err)
	}
	c, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	c.path = path
	if err := c.applyEnv(os.LookupEnv); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Parse decodes TOML content over the defaults without applying environment
// overrides or validating. The leading comment block is kept as the header.
func Parse(data []byte) (*Config, error) {
	c := Default("")
	c.header = extractHeader(data)
	dec := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		var sm *toml.StrictMissingError
		if !errors.As(err, &sm) {
			return nil, err
		}
		// Keys this binary does not model are kept verbatim so Save cannot
		// silently delete what another (e.g. newer) version wrote, or what an
		// operator pre-seeded. An unknown table is reported as a whole, so
		// its subtree comes along.
		var raw map[string]any
		if err := toml.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
		for _, e := range sm.Errors {
			key := e.Key()
			c.warnings = append(c.warnings, "unknown key "+strings.Join(key, "."))
			if v, ok := lookupPath(raw, key); ok {
				setPath(&c.extra, key, v)
			}
		}
	}
	if c.Server.Bind == nil {
		c.Server.Bind = []string{}
	}
	if c.Server.TrustedProxies == nil {
		c.Server.TrustedProxies = []string{}
	}
	c.file = c.clone()
	return c, nil
}

// Reread reads the file c was loaded from (or last saved to) again, for a
// change that must apply to the file as it is now rather than to what c holds
// (an operator may edit it while the server runs: "fileparcel config edit").
// It returns the new Config, with c's environment overrides applied on top
// (the values recorded when c was loaded, so what is overridden does not
// change), and the file content as read, for RestoreFile. It does not
// validate. fs.ErrNotExist when the file is gone.
func (c *Config) Reread() (*Config, []byte, error) {
	if c.path == "" {
		return nil, nil, errors.New("config: Reread: no path")
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	n, err := Parse(data)
	if err != nil {
		return nil, nil, fmt.Errorf("config: %s: %w", c.path, err)
	}
	n.path = c.path
	n.env = make(map[string]any, len(c.env))
	for _, key := range c.overridden {
		v := c.env[key]
		if err := n.Set(key, v); err != nil {
			return nil, nil, err
		}
		n.env[key] = v
	}
	n.overridden = slices.Clone(c.overridden)
	return n, data, nil
}

// RestoreFile atomically puts data (the content Reread returned) back as the
// config's file, undoing a Save exactly: unlike saving an older Config, it
// cannot lose what the file held that the Config did not.
func (c *Config) RestoreFile(data []byte) error {
	if c.path == "" {
		return errors.New("config: RestoreFile: no path")
	}
	if err := writeFileAtomic(c.path, data, home.ModeConfig); err != nil {
		return fmt.Errorf("config: restore %s: %w", c.path, err)
	}
	return nil
}

// extractHeader returns the leading block of comment lines if it is followed
// by a blank line (so per-key comments emitted by the encoder are not taken).
func extractHeader(data []byte) string {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#"):
			lines = append(lines, line)
		case trimmed == "":
			if len(lines) > 0 {
				return strings.Join(lines, "\n")
			}
		default:
			return ""
		}
	}
	return ""
}

// Path returns the file the config was loaded from (or last saved to).
func (c *Config) Path() string { return c.path }

// Warnings returns non-fatal problems found while loading (e.g. unknown keys).
func (c *Config) Warnings() []string { return slices.Clone(c.warnings) }

// Overridden returns the sorted dotted keys ("server.https_port") whose value
// currently comes from an environment variable.
func (c *Config) Overridden() []string { return slices.Clone(c.overridden) }

// IsOverridden reports whether key is overridden by the environment.
func (c *Config) IsOverridden(key string) bool { return slices.Contains(c.overridden, key) }

// EnvName returns the environment variable that overrides key
// ("server.https_port" -> "FILEPARCEL_SERVER_HTTPS_PORT").
func EnvName(key string) string {
	return EnvPrefix + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// Save atomically rewrites the file the config was loaded from (write to
// "<file>.tmp", fsync, rename, fsync directory), preserving the header comment
// block. Env-provided values are not persisted: for an overridden key whose
// value still equals the env value, the on-disk value is kept.
func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("config: Save: no path (use SaveTo)")
	}
	return c.SaveTo(c.path)
}

// SaveTo writes the config to path (atomically, mode 0640) and makes path the
// config's path for later Save calls.
func (c *Config) SaveTo(path string) error {
	out := c.clone()
	for _, key := range c.overridden {
		cur, _ := c.Get(key)
		envVal := c.env[key]
		if c.file != nil && equalValues(cur, envVal) {
			fv, _ := c.file.Get(key)
			_ = out.Set(key, fv)
		}
	}
	body, err := toml.Marshal(out)
	if err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	if len(c.extra) > 0 {
		body, err = mergeExtras(body, c.extra)
		if err != nil {
			return fmt.Errorf("config: encode unknown keys: %w", err)
		}
	}
	header := c.header
	if header == "" {
		header = DefaultHeader
	}
	var buf bytes.Buffer
	buf.WriteString(strings.TrimRight(header, "\n"))
	buf.WriteString("\n\n")
	buf.Write(body)
	if err := writeFileAtomic(path, buf.Bytes(), home.ModeConfig); err != nil {
		return fmt.Errorf("config: save %s: %w", path, err)
	}
	c.path = path
	// The file now reflects the persisted values.
	c.file = out
	return nil
}

func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// clone returns a deep copy (without the load metadata).
func (c *Config) clone() *Config {
	n := &Config{
		InstallID:   c.InstallID,
		Server:      c.Server,
		Log:         c.Log,
		AdminSocket: c.AdminSocket,
		Runtime:     c.Runtime,
	}
	n.Server.Bind = slices.Clone(c.Server.Bind)
	n.Server.TrustedProxies = slices.Clone(c.Server.TrustedProxies)
	if n.Server.Bind == nil {
		n.Server.Bind = []string{}
	}
	if n.Server.TrustedProxies == nil {
		n.Server.TrustedProxies = []string{}
	}
	if c.extra != nil {
		n.extra = make(map[string]any, len(c.extra))
		for k, v := range c.extra {
			n.extra[k] = v
		}
	}
	return n
}

// Clone returns a deep copy of the configuration values, keeping path, header
// and override information.
func (c *Config) Clone() *Config {
	n := c.clone()
	n.path, n.header = c.path, c.header
	if c.file != nil {
		n.file = c.file.clone()
	}
	n.env = make(map[string]any, len(c.env))
	for k, v := range c.env {
		n.env[k] = v
	}
	n.overridden = slices.Clone(c.overridden)
	n.warnings = slices.Clone(c.warnings)
	return n
}

// ---------- unknown keys ----------
//
// Keys the binary does not model are kept across a Save so a rolled-back
// binary (or an operator's pre-seeded key) does not lose them the first time
// a bootstrap setting changes. They are rendered separately from the typed
// struct, because only marshalling the struct emits the per-key `comment:`
// tags, and spliced into the table they came from.

// lookupPath returns the value at the dotted key path inside a decoded document.
func lookupPath(m map[string]any, key []string) (any, bool) {
	var cur any = m
	for _, k := range key {
		sub, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = sub[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// setPath stores v at the dotted key path, creating intermediate tables.
func setPath(dst *map[string]any, key []string, v any) {
	if len(key) == 0 {
		return
	}
	if *dst == nil {
		*dst = map[string]any{}
	}
	m := *dst
	for _, k := range key[:len(key)-1] {
		sub, _ := m[k].(map[string]any)
		if sub == nil {
			sub = map[string]any{}
			m[k] = sub
		}
		m = sub
	}
	m[key[len(key)-1]] = v
}

// tomlBlock is a table of an encoded document: its header line ("" for the
// keys before the first table) and the lines that follow it.
type tomlBlock struct {
	header string
	lines  []string
}

// splitTOML splits an encoder-produced document into tables. It is only used
// on the output of toml.Marshal, which emits no multi-line strings or arrays
// here, so a line starting with "[" always begins a table.
func splitTOML(doc []byte) []tomlBlock {
	blocks := []tomlBlock{{}}
	for _, line := range strings.Split(strings.TrimRight(string(doc), "\n"), "\n") {
		if strings.HasPrefix(line, "[") {
			blocks = append(blocks, tomlBlock{header: line})
			continue
		}
		i := len(blocks) - 1
		blocks[i].lines = append(blocks[i].lines, line)
	}
	return blocks
}

// mergeExtras folds the keys this version does not model back into the
// encoded document, each into the table it came from.
func mergeExtras(body []byte, extra map[string]any) ([]byte, error) {
	enc, err := toml.Marshal(extra)
	if err != nil {
		return nil, err
	}
	blocks := splitTOML(body)
	for _, b := range splitTOML(enc) {
		lines := trimBlank(b.lines)
		if len(lines) == 0 {
			continue
		}
		i := slices.IndexFunc(blocks, func(o tomlBlock) bool { return o.header == b.header })
		if i < 0 {
			blocks = append(blocks, tomlBlock{header: b.header, lines: lines})
			continue
		}
		blocks[i].lines = append(trimBlank(blocks[i].lines), lines...)
	}
	var buf bytes.Buffer
	for _, b := range blocks {
		if b.header != "" {
			if buf.Len() > 0 {
				buf.WriteString("\n")
			}
			buf.WriteString(b.header)
			buf.WriteString("\n")
		}
		for _, l := range trimBlank(b.lines) {
			buf.WriteString(l)
			buf.WriteString("\n")
		}
	}
	return buf.Bytes(), nil
}

// trimBlank drops leading and trailing blank lines.
func trimBlank(lines []string) []string {
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}
