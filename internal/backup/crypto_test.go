package backup

import (
	"strings"
	"testing"

	"filippo.io/age"
)

// TestRecipientErrorNeverEchoesASecretKey: an identity pasted where a
// recipient belongs was repeated in full in the error (an X25519 key is 74
// characters, under the 80 the echo keeps), which reaches the 422 response
// and the CLI's stderr. age.ParseRecipients leaves its input out for this
// reason; a mistyped public key is still echoed.
func TestRecipientErrorNeverEchoesASecretKey(t *testing.T) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pq, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{x.String(), pq.String()} {
		_, data, _ := strings.Cut(key, "-1") // the secret part after the prefix
		for _, in := range []string{
			key,
			strings.ToLower(key),
			"  " + key + "\n",
			"# created: 2026-01-01\n# public key: age1xyz\n" + key,
		} {
			errs := map[string]error{"parseRecipients": nil, "validRecipients": nil}
			_, errs["parseRecipients"] = parseRecipients(in)
			errs["validRecipients"] = validRecipients([]string{in})
			for fn, err := range errs {
				if err == nil {
					t.Fatalf("%s accepted an identity", fn)
				}
				msg := strings.ToUpper(err.Error())
				for i := 0; i+16 <= len(data); i += 8 {
					if strings.Contains(msg, strings.ToUpper(data[i:i+16])) {
						t.Fatalf("%s echoes the secret key: %q", fn, err)
					}
				}
				if !strings.Contains(err.Error(), "identity") {
					t.Errorf("%s does not say what was entered: %q", fn, err)
				}
			}
		}
	}
	if _, err := parseRecipients("age1notvalid"); err == nil || !strings.Contains(err.Error(), "age1notvalid") {
		t.Fatalf("a mistyped recipient is no longer echoed: %v", err)
	}
}
