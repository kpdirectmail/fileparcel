package qr

import (
	"strings"
	"testing"
)

func TestSVGAndDataURI(t *testing.T) {
	svg, err := SVG("https://fileparcel.local:8443/", Options{Title: "Open <FileParcel>"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(svg)
	if !strings.HasPrefix(s, "<svg") || !strings.Contains(s, "<path") || strings.Contains(s, "<FileParcel>") {
		t.Fatalf("unexpected svg: %.200s", s)
	}
	uri, err := DataURI("hello")
	if err != nil || !strings.HasPrefix(uri, "data:image/svg+xml;base64,") {
		t.Fatalf("data uri: %v %q", err, uri)
	}
}

func TestEncodeLimits(t *testing.T) {
	if _, err := Encode(""); err == nil {
		t.Fatal("expected error for empty input")
	}
	if _, err := Encode(strings.Repeat("a", MaxLen+1)); err == nil {
		t.Fatal("expected error for oversize input")
	}
	c, err := Encode("abc")
	if err != nil || c.Size < 21 {
		t.Fatalf("size %v %v", c, err)
	}
	// finder pattern top-left corner is dark
	if !c.Dark(0, 0) || c.Dark(-1, 0) {
		t.Fatal("finder pattern / bounds check failed")
	}
}

func TestTerminal(t *testing.T) {
	s, err := Terminal("https://example.local", false)
	if err != nil || strings.Count(s, "\n") < 10 {
		t.Fatalf("terminal: %v\n%s", err, s)
	}
}
