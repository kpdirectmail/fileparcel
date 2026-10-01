package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"time"

	"filippo.io/age"

	"fileparcel/internal/core"
	"fileparcel/internal/settings"
)

// ageIdentity is a short alias used in signatures.
type ageIdentity = age.Identity

// defaultSettings is a read-only core.Settings serving the registered
// defaults. It backs the temporary environment of deep verification (the
// key service and blob store of a backup must not see this server's
// settings or secrets).
type defaultSettings struct{}

var _ core.Settings = defaultSettings{}

func (defaultSettings) value(key string) any {
	d, ok := settings.Lookup(key)
	if !ok || d.Secret {
		return nil
	}
	_, v, err := d.Decode(d.DefaultJSON())
	if err != nil {
		return nil
	}
	return v
}

func (d defaultSettings) Raw(key string) (json.RawMessage, error) {
	def, ok := settings.Lookup(key)
	if !ok {
		return nil, core.NotFoundf("unknown setting %q", key)
	}
	if def.Secret {
		return json.RawMessage(`""`), nil
	}
	return def.DefaultJSON(), nil
}

func (d defaultSettings) Int(key string) int64 { n, _ := d.value(key).(int64); return n }

func (d defaultSettings) Bool(key string) bool { b, _ := d.value(key).(bool); return b }

func (d defaultSettings) String(key string) string {
	switch v := d.value(key).(type) {
	case string:
		return v
	case time.Duration:
		return v.String()
	}
	return ""
}

func (d defaultSettings) Strings(key string) []string {
	l, _ := d.value(key).([]string)
	if l == nil {
		return []string{}
	}
	return l
}

func (d defaultSettings) Duration(key string) time.Duration {
	v, _ := d.value(key).(time.Duration)
	return v
}

func (defaultSettings) Secret(string) (string, error) { return "", nil }

func (defaultSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, core.Errorf(core.ErrForbidden, "read-only settings")
}

func (defaultSettings) Reset(context.Context, *core.Principal, string) error {
	return core.Errorf(core.ErrForbidden, "read-only settings")
}

func (defaultSettings) Catalog(context.Context) ([]core.SettingView, error) { return nil, nil }

// nopAudit discards audit entries (temporary verification environments).
type nopAudit struct{}

var _ core.Audit = nopAudit{}

func (nopAudit) Record(context.Context, core.AuditEntry)                  {}
func (nopAudit) RecordTx(context.Context, *sql.Tx, core.AuditEntry) error { return nil }
func (nopAudit) Verify(context.Context) (*core.AuditVerify, error) {
	return &core.AuditVerify{OK: true}, nil
}
func (nopAudit) Prune(context.Context, time.Time) (int, error)                    { return 0, nil }
func (nopAudit) Export(context.Context, core.AuditQuery, string, io.Writer) error { return nil }
func (nopAudit) Query(context.Context, core.AuditQuery) (core.Page[core.AuditRecord], error) {
	return core.NewPage[core.AuditRecord](nil, ""), nil
}
