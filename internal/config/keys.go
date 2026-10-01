package config

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// keyField locates a dotted key inside Config.
type keyField struct {
	key   string
	index []int
	env   bool // may be overridden by the environment
}

var keyTable = buildKeyTable()

func buildKeyTable() []keyField {
	var out []keyField
	t := reflect.TypeFor[Config]()
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := tomlName(f)
		if f.Type.Kind() == reflect.Struct {
			for j := range f.Type.NumField() {
				sf := f.Type.Field(j)
				if !sf.IsExported() {
					continue
				}
				out = append(out, keyField{key: name + "." + tomlName(sf), index: []int{i, j}, env: true})
			}
			continue
		}
		out = append(out, keyField{key: name, index: []int{i}, env: false})
	}
	return out
}

func tomlName(f reflect.StructField) string {
	tag := f.Tag.Get("toml")
	if n, _, _ := strings.Cut(tag, ","); n != "" {
		return n
	}
	return strings.ToLower(f.Name)
}

func lookupKey(key string) (keyField, bool) {
	for _, k := range keyTable {
		if k.key == key {
			return k, true
		}
	}
	return keyField{}, false
}

// Keys returns every dotted key of the file ("install_id", "server.name", …)
// in file order.
func Keys() []string {
	out := make([]string, len(keyTable))
	for i, k := range keyTable {
		out[i] = k.key
	}
	return out
}

// Get returns the current value of a dotted key ("server.https_port"). Values
// are int, bool, string or []string (a copy). ok is false for unknown keys.
func (c *Config) Get(key string) (v any, ok bool) {
	k, ok := lookupKey(key)
	if !ok {
		return nil, false
	}
	fv := reflect.ValueOf(c).Elem().FieldByIndex(k.index)
	if fv.Kind() == reflect.Slice {
		return slices.Clone(fv.Interface().([]string)), true
	}
	return fv.Interface(), true
}

// Set assigns a dotted key. v may be the exact field type or a compatible
// value: any integer or integral float / json.Number / numeric string for int
// fields; bool or "true"/"false" for bools; []string, []any of strings or a
// comma-separated string for lists. Set does not validate ranges (call
// Validate) and does not save (call Save).
func (c *Config) Set(key string, v any) error {
	k, ok := lookupKey(key)
	if !ok {
		return fmt.Errorf("config: unknown key %q", key)
	}
	fv := reflect.ValueOf(c).Elem().FieldByIndex(k.index)
	if err := assign(fv, v); err != nil {
		return fmt.Errorf("config: %s: %w", key, err)
	}
	return nil
}

func assign(fv reflect.Value, v any) error {
	switch fv.Kind() {
	case reflect.Int:
		n, err := toInt(v)
		if err != nil {
			return err
		}
		fv.SetInt(n)
	case reflect.Bool:
		switch b := v.(type) {
		case bool:
			fv.SetBool(b)
		case string:
			pb, err := strconv.ParseBool(strings.TrimSpace(b))
			if err != nil {
				return fmt.Errorf("invalid boolean %q", b)
			}
			fv.SetBool(pb)
		default:
			return fmt.Errorf("expected boolean, got %T", v)
		}
	case reflect.String:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", v)
		}
		fv.SetString(s)
	case reflect.Slice:
		var list []string
		switch x := v.(type) {
		case []string:
			list = slices.Clone(x)
		case []any:
			for _, e := range x {
				s, ok := e.(string)
				if !ok {
					return fmt.Errorf("expected list of strings, got element %T", e)
				}
				list = append(list, s)
			}
		case string:
			list = splitList(x)
		case nil:
			list = []string{}
		default:
			return fmt.Errorf("expected list of strings, got %T", v)
		}
		if list == nil {
			list = []string{}
		}
		fv.Set(reflect.ValueOf(list))
	default:
		return fmt.Errorf("unsupported field kind %s", fv.Kind())
	}
	return nil
}

func toInt(v any) (int64, error) {
	switch n := v.(type) {
	case int:
		return int64(n), nil
	case int8:
		return int64(n), nil
	case int16:
		return int64(n), nil
	case int32:
		return int64(n), nil
	case int64:
		return n, nil
	case uint:
		return int64(n), nil
	case uint16:
		return int64(n), nil
	case uint32:
		return int64(n), nil
	case uint64:
		if n > math.MaxInt64 {
			return 0, fmt.Errorf("integer out of range")
		}
		return int64(n), nil
	case float64:
		if n != math.Trunc(n) || math.IsInf(n, 0) || math.IsNaN(n) {
			return 0, fmt.Errorf("expected integer, got %v", n)
		}
		return int64(n), nil
	case json.Number:
		return n.Int64()
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid integer %q", n)
		}
		return i, nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", v)
	}
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func equalValues(a, b any) bool { return reflect.DeepEqual(a, b) }

// applyEnv applies FILEPARCEL_<SECTION>_<KEY> overrides using lookup (os.LookupEnv).
func (c *Config) applyEnv(lookup func(string) (string, bool)) error {
	c.env = map[string]any{}
	c.overridden = nil
	for _, k := range keyTable {
		if !k.env {
			continue
		}
		raw, ok := lookup(EnvName(k.key))
		if !ok {
			continue
		}
		if err := c.Set(k.key, raw); err != nil {
			return fmt.Errorf("config: environment %s: %w", EnvName(k.key), err)
		}
		v, _ := c.Get(k.key)
		c.env[k.key] = v
		c.overridden = append(c.overridden, k.key)
	}
	slices.Sort(c.overridden)
	return nil
}

// ApplyEnv re-applies environment overrides from lookup (normally
// os.LookupEnv). Load calls it automatically; it is exported for tests and for
// callers that build a Config with Parse.
func (c *Config) ApplyEnv(lookup func(string) (string, bool)) error { return c.applyEnv(lookup) }
