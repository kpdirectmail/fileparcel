package settings

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"
)

// A managed key (Def.Managed) reaches the catalog as SettingView.Managed,
// and the store itself still accepts writes from the owning service (the
// 409 is the settings API's).
func TestManagedKeyInCatalog(t *testing.T) {
	const route = "PUT /api/v1/admin/network/zzmanaged"
	Register(Def{Key: "zzmanaged.mode", Section: "funnel", Order: 1, Type: TypeEnum, Default: "off",
		Enum: []string{"off", "on"}, Managed: route})
	Register(Def{Key: "zzmanaged.plain", Section: "funnel", Order: 2, Type: TypeBool, Default: false})
	if d, _ := Lookup("zzmanaged.mode"); d.Managed != route {
		t.Fatalf("Lookup lost Managed: %+v", d)
	}
	s, _ := New(nil)
	if _, err := s.Set(context.Background(), nil, map[string]json.RawMessage{"zzmanaged.mode": json.RawMessage(`"on"`)}); err != nil {
		t.Fatalf("service write of a managed key: %v", err)
	}
	cat, err := s.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, v := range cat {
		switch v.Key {
		case "zzmanaged.mode":
			seen++
			if v.Managed != route || string(v.Value) != `"on"` {
				t.Fatalf("managed view %+v", v)
			}
		case "zzmanaged.plain":
			seen++
			if v.Managed != "" {
				t.Fatalf("plain view %+v", v)
			}
			if b, _ := json.Marshal(v); bytes.Contains(b, []byte(`"managed"`)) {
				t.Fatalf("managed is omitted for ordinary keys: %s", b)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("%d of 2 keys in the catalog", seen)
	}
}

// The funnel section (package tsingress) follows tailscale in the UI order.
func TestFunnelSectionOrder(t *testing.T) {
	ts, fu, mt := slices.Index(SectionOrder, "tailscale"), slices.Index(SectionOrder, "funnel"), slices.Index(SectionOrder, "mtls")
	if ts < 0 || fu != ts+1 || mt != fu+1 {
		t.Fatalf("SectionOrder %v", SectionOrder)
	}
}
