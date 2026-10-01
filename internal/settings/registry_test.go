package settings

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDecodeTypes(t *testing.T) {
	type tc struct {
		d     Def
		in    string
		canon string
		bad   bool
	}
	cases := []tc{
		{Def{Type: TypeBool}, `true`, `true`, false},
		{Def{Type: TypeBool}, `"true"`, ``, true},
		{Def{Type: TypeInt, Min: 0, Max: 10}, `7`, `7`, false},
		{Def{Type: TypeInt, Min: 0, Max: 10}, `11`, ``, true},
		{Def{Type: TypeInt}, `1.5`, ``, true},
		{Def{Type: TypeInt}, `-99999`, `-99999`, false}, // no bounds when Max <= Min
		{Def{Type: TypeString}, `"x"`, `"x"`, false},
		{Def{Type: TypeStrings}, `[" a ","b"]`, `["a","b"]`, false},
		{Def{Type: TypeStrings}, `null`, ``, true},
		{Def{Type: TypeStrings}, `[]`, `[]`, false},
		{Def{Type: TypeDuration}, `"90m"`, `"1h30m"`, false},
		{Def{Type: TypeDuration}, `"15m"`, `"15m"`, false},
		{Def{Type: TypeDuration}, `"2h"`, `"2h"`, false},
		{Def{Type: TypeDuration}, `"soon"`, ``, true},
		{Def{Type: TypeEnum, Enum: []string{"a", "b"}}, `"b"`, `"b"`, false},
		{Def{Type: TypeEnum, Enum: []string{"a", "b"}}, `"c"`, ``, true},
		{Def{Type: TypeCIDRs}, `["10.0.0.0/8","::1"]`, `["10.0.0.0/8","::1"]`, false},
		{Def{Type: TypeCIDRs}, `["10.0.0.0/33"]`, ``, true},
		{Def{Type: TypeCron}, `"0  3 * * *"`, `"0 3 * * *"`, false},
		{Def{Type: TypeCron}, `""`, `""`, false},
		{Def{Type: TypeCron}, `"0 3 * *"`, ``, true},
		{Def{Type: TypeColor}, `"#2563EB"`, `"#2563eb"`, false},
		{Def{Type: TypeColor}, `"red"`, ``, true},
		{Def{Type: TypeEmail}, `"a@b.c"`, `"a@b.c"`, false},
		{Def{Type: TypeEmail}, `"Bob <a@b.c>"`, ``, true},
		{Def{Type: TypeURL}, `"https://x.example/p"`, `"https://x.example/p"`, false},
		{Def{Type: TypeURL}, `"javascript:alert(1)"`, ``, true},
		{Def{Type: TypeSecret}, `"s3cret"`, `"s3cret"`, false},
	}
	for i, c := range cases {
		canon, _, err := c.d.Decode(json.RawMessage(c.in))
		if c.bad {
			if err == nil {
				t.Errorf("case %d (%s %s): accepted", i, c.d.Type, c.in)
			}
			continue
		}
		if err != nil || string(canon) != c.canon {
			t.Errorf("case %d (%s %s): got %s %v want %s", i, c.d.Type, c.in, canon, err, c.canon)
		}
	}
	d := Def{Type: TypeInt, Validate: func(v any) error {
		if v.(int64)%2 != 0 {
			return errors.New("must be even")
		}
		return nil
	}}
	if _, _, err := d.Decode(json.RawMessage(`3`)); err == nil {
		t.Fatal("Validate not called")
	}
	_, v, _ := Def{Type: TypeDuration}.Decode(json.RawMessage(`"15m"`))
	if v.(time.Duration) != 15*time.Minute {
		t.Fatal("duration value")
	}
}

func TestRegisterAndStore(t *testing.T) {
	Register(Def{Key: "zztest.flag", Type: TypeBool, Default: true, Label: "Flag"})
	Register(Def{Key: "zztest.name", Section: "general", Order: 1, Type: TypeString, Default: "x"})
	Register(Def{Key: "zztest.secret", Type: TypeSecret, Default: ""})
	mustPanic := func(d Def) {
		defer func() {
			if recover() == nil {
				t.Errorf("Register(%+v) did not panic", d)
			}
		}()
		Register(d)
	}
	mustPanic(Def{Key: "zztest.flag", Type: TypeBool, Default: true}) // duplicate
	mustPanic(Def{Key: "Bad Key", Type: TypeBool, Default: true})
	mustPanic(Def{Key: "zztest.nodef", Type: TypeInt})
	mustPanic(Def{Key: "zztest.baddef", Type: TypeInt, Default: "x"})
	mustPanic(Def{Key: "zztest.enum", Type: TypeEnum, Default: "a"})
	mustPanic(Def{Key: "zztest.type", Type: "weird", Default: 1})

	d, ok := Lookup("zztest.secret")
	if !ok || !d.Secret || d.Section != "zztest" {
		t.Fatalf("%+v", d)
	}
	s, _ := New(nil)
	if !s.Bool("zztest.flag") || s.String("zztest.name") != "x" || s.Int("nope.key") != 0 || s.Strings("nope.key") == nil {
		t.Fatal("getters")
	}
	if _, err := s.Raw("nope.key"); err == nil {
		t.Fatal("unknown key")
	}
	cat, _ := s.Catalog(context.Background())
	for _, v := range cat {
		if v.Key == "zztest.secret" && (string(v.Value) != "null" || v.IsSet) {
			t.Fatalf("secret not masked: %+v", v)
		}
	}
	defs := Defs()
	gi, zi := -1, -1
	for i, d := range defs {
		switch d.Key {
		case "zztest.name":
			gi = i
		case "zztest.flag":
			zi = i
		}
	}
	if gi < 0 || zi < 0 || gi > zi {
		t.Fatal("section order: general must sort before unknown sections")
	}
}

// Every list value is bounded, whatever the setting: an unbounded one is a
// valid PATCH that can take the server down (12 000 names in tls.extra_sans
// produced a certificate no TLS client would read).
func TestListValuesAreBounded(t *testing.T) {
	build := func(n int) json.RawMessage {
		l := make([]string, n)
		for i := range l {
			l[i] = "n"
		}
		raw, _ := json.Marshal(l)
		return raw
	}
	for _, typ := range []Type{TypeStrings, TypeCIDRs} {
		d := Def{Type: typ}
		if _, _, err := d.Decode(build(maxListEntries + 1)); err == nil {
			t.Errorf("%s: %d entries accepted", typ, maxListEntries+1)
		}
	}
	long, _ := json.Marshal([]string{strings.Repeat("x", maxStringLen+1)})
	if _, _, err := (Def{Type: TypeStrings}).Decode(long); err == nil {
		t.Error("an oversized list entry was accepted")
	}
	if _, _, err := (Def{Type: TypeStrings}).Decode(build(maxListEntries)); err != nil {
		t.Errorf("%d entries refused: %v", maxListEntries, err)
	}
}
