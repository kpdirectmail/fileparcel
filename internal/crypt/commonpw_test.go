package crypt

import "testing"

func TestCommonPasswordList(t *testing.T) {
	if n := len(commonPasswords()); n < 1900 || n > 2100 {
		t.Fatalf("embedded list has %d entries", n)
	}
	for pw := range commonPasswords() {
		if pw == "" || pw[0] == '#' {
			t.Fatalf("comment or empty line in the set: %q", pw)
		}
	}
}

func TestIsCommonPassword(t *testing.T) {
	common := []string{"password", "Password", "PASSWORD2024!", "p@ssw0rd", "P4ssw0rd99", "Summer2024", "123password",
		"iloveyou!!", "qwertyuiop", "1q2w3e4r", "football1", "baseball#1",
		// .zip passwords of 12+ characters that are still just a common word
		// with affixes (zip-password-final §4.1).
		"Password1234!", "  password  ", "pass word", "Qwertyuiop123"}
	for _, pw := range common {
		if !IsCommonPassword(pw) {
			t.Errorf("%q should be common", pw)
		}
	}
	fine := []string{"correct horse battery staple", "Tr4mpoline-Galaxy", "my cat eats 3 socks", "x9$Lq!2vRm#8", "", "   "}
	for _, pw := range fine {
		if IsCommonPassword(pw) {
			t.Errorf("%q should not be common", pw)
		}
	}
}

func TestStripAffixes(t *testing.T) {
	cases := map[string]string{
		"2024password!!":  "password",
		"pass1234567word": "pass1234567word", // inner digits stay
		"1234567password": "7password",       // at most maxAffixLen per end
		"!!!":             "",
		"café99":          "café",
	}
	for in, want := range cases {
		if got := stripAffixes(in); got != want {
			t.Errorf("stripAffixes(%q) = %q, want %q", in, got, want)
		}
	}
}
