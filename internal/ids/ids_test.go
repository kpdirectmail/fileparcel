package ids

import (
	"bytes"
	"crypto/rand"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestNewFormatAndOrder(t *testing.T) {
	prev := ""
	seen := map[string]bool{}
	for i := 0; i < 10000; i++ {
		id := New(PrefixNode)
		if len(id) != len("nod_")+SuffixLen || !strings.HasPrefix(id, "nod_") {
			t.Fatalf("bad id %q", id)
		}
		if !Valid(PrefixNode, id) || Valid(PrefixUser, id) {
			t.Fatalf("Valid(%q)", id)
		}
		if strings.ToLower(id) != id {
			t.Fatalf("not lowercase: %q", id)
		}
		if id <= prev {
			t.Fatalf("not monotonic: %q after %q", id, prev)
		}
		if seen[id] {
			t.Fatalf("duplicate %q", id)
		}
		seen[id] = true
		prev = id
	}
	if Prefix("usr_abc") != "usr" || Prefix("nounderscore") != "" {
		t.Fatal("Prefix")
	}
}

func TestUUIDv7Bits(t *testing.T) {
	u := NewUUIDv7()
	if u[6]>>4 != 7 {
		t.Fatalf("version nibble %x", u[6]>>4)
	}
	if u[8]>>6 != 2 {
		t.Fatalf("variant bits %b", u[8]>>6)
	}
	id := New(PrefixUser)
	ts, ok := Time(id)
	if !ok || time.Since(ts) > time.Minute || ts.After(time.Now().Add(time.Second)) {
		t.Fatalf("Time(%q) = %v %v", id, ts, ok)
	}
}

func TestBase32RoundTripAndSort(t *testing.T) {
	var list [][16]byte
	for i := 0; i < 200; i++ {
		var b [16]byte
		_, _ = rand.Read(b[:])
		list = append(list, b)
	}
	list = append(list, [16]byte{}, [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	var enc []string
	for _, b := range list {
		s := Encode32(b)
		if len(s) != SuffixLen {
			t.Fatalf("len %d", len(s))
		}
		back, err := Decode32(s)
		if err != nil || back != b {
			t.Fatalf("roundtrip %x -> %s -> %x (%v)", b, s, back, err)
		}
		if back2, err := Decode32(strings.ToUpper(s)); err != nil || back2 != b {
			t.Fatal("case-insensitive decode")
		}
		enc = append(enc, s)
	}
	// Encoding preserves byte order.
	sort.Slice(list, func(i, j int) bool { return bytes.Compare(list[i][:], list[j][:]) < 0 })
	sort.Strings(enc)
	for i := range list {
		if Encode32(list[i]) != enc[i] {
			t.Fatal("order not preserved")
		}
	}
	if Encode32([16]byte{}) != strings.Repeat("0", 26) {
		t.Fatal("zero encoding")
	}
	if Encode32([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) != "7"+strings.Repeat("z", 25) {
		t.Fatal("max encoding")
	}
	for _, bad := range []string{"", "8" + strings.Repeat("0", 25), strings.Repeat("0", 25) + "u", strings.Repeat("0", 27)} {
		if _, err := Decode32(bad); err == nil {
			t.Fatalf("Decode32(%q) accepted", bad)
		}
	}
	if Valid(PrefixUser, "usr_"+strings.Repeat("0", 25)+"U") {
		t.Fatal("uppercase suffix must be invalid")
	}
}

func TestBlobID(t *testing.T) {
	id := NewBlobID()
	if !ValidBlobID(id) || len(id) != 32 {
		t.Fatalf("blob id %q", id)
	}
	if id == NewBlobID() {
		t.Fatal("not random")
	}
	for _, bad := range []string{"", strings.Repeat("A", 32), strings.Repeat("0", 31), "../" + strings.Repeat("0", 29), strings.Repeat("g", 32)} {
		if ValidBlobID(bad) {
			t.Fatalf("ValidBlobID(%q)", bad)
		}
	}
	raw, err := BlobIDBytes(id)
	if err != nil || len(raw) != 16 {
		t.Fatal(err)
	}
	if _, err := BlobIDBytes("zz"); err == nil {
		t.Fatal("BlobIDBytes accepted invalid id")
	}
}

func TestToken(t *testing.T) {
	if TokenLen(32) != 43 || TokenLen(16) != 22 {
		t.Fatalf("TokenLen %d %d", TokenLen(32), TokenLen(16))
	}
	seen := map[string]bool{}
	counts := map[byte]int{}
	for i := 0; i < 2000; i++ {
		tok := Token(32)
		if len(tok) != 43 || !ValidToken(tok) {
			t.Fatalf("token %q", tok)
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
		for j := 0; j < len(tok); j++ {
			counts[tok[j]]++
		}
	}
	if len(counts) != 62 {
		t.Fatalf("alphabet coverage %d", len(counts))
	}
	if ValidToken("") || ValidToken("abc-def") {
		t.Fatal("ValidToken")
	}
}

func TestHashAndEqual(t *testing.T) {
	h := HashToken("abc")
	if len(h) != 32 || !bytes.Equal(h, HashToken("abc")) || bytes.Equal(h, HashToken("abd")) {
		t.Fatal("HashToken")
	}
	if !Equal("abc", "abc") || Equal("abc", "abd") || Equal("abc", "ab") {
		t.Fatal("Equal")
	}
	if !EqualBytes([]byte{1}, []byte{1}) || EqualBytes([]byte{1}, []byte{2}) {
		t.Fatal("EqualBytes")
	}
}
