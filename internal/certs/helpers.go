package certs

import (
	"encoding/pem"
	"net/url"
	"strings"

	"fileparcel/internal/settings"
)

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// Setting accessors that tolerate a missing settings store (early init,
// tests) by falling back to the registered default.

func (svc *Service) settingString(key string) string {
	if svc.env.Settings != nil {
		if v := svc.env.Settings.String(key); v != "" {
			return v
		}
		if _, err := svc.env.Settings.Raw(key); err == nil {
			return ""
		}
	}
	if d, ok := settings.Lookup(key); ok {
		if s, ok := d.Default.(string); ok {
			return s
		}
	}
	return ""
}

func (svc *Service) settingBool(key string) bool {
	if svc.env.Settings != nil {
		if _, err := svc.env.Settings.Raw(key); err == nil {
			return svc.env.Settings.Bool(key)
		}
	}
	if d, ok := settings.Lookup(key); ok {
		b, _ := d.Default.(bool)
		return b
	}
	return false
}

func (svc *Service) settingInt(key string, def int64) int64 {
	if svc.env.Settings != nil {
		if _, err := svc.env.Settings.Raw(key); err == nil {
			return svc.env.Settings.Int(key)
		}
	}
	return def
}

func (svc *Service) settingStrings(key string) []string {
	if svc.env.Settings != nil {
		return svc.env.Settings.Strings(key)
	}
	return nil
}

// mtlsMode returns the effective mtls.mode (off for unknown values).
func (svc *Service) mtlsMode() string {
	switch m := svc.settingString(KeyMTLSMode); m {
	case MTLSOptional, MTLSRequired:
		return m
	}
	return MTLSOff
}

// publicURLHost returns the host of server.public_url ("" when unset).
func (svc *Service) publicURLHost() string {
	if c := svc.env.Config; c != nil && c.Server.PublicURL != "" {
		if u, err := url.Parse(c.Server.PublicURL); err == nil {
			return strings.ToLower(u.Hostname())
		}
	}
	return ""
}
