package backup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"

	"fileparcel/internal/core"
)

// Tunables (variables so tests can lower the scrypt cost).
var (
	// scryptWorkFactor is log2(N) for passphrase-encrypted backups (age default 18).
	scryptWorkFactor = 18
	// scryptMaxWorkFactor bounds the work factor accepted when decrypting (DoS guard).
	scryptMaxWorkFactor = 22
)

// maxPrevIdentities bounds how many superseded identities backup.identity
// keeps for decrypting older backups.
const maxPrevIdentities = 5

// ageMagic is the first line of every age file.
const ageMagic = "age-encryption.org/v1\n"

// parseRecipients parses one or more age recipients (one per line; "#"
// comments allowed). Only native X25519 and hybrid recipients are accepted.
// The rejected input is echoed to help with typos, except when it holds an
// identity (a secret key pasted by mistake): the error reaches API responses
// and the CLI's stderr, so, like age.ParseRecipients, it never repeats one.
func parseRecipients(s string) ([]age.Recipient, error) {
	rs, err := age.ParseRecipients(strings.NewReader(s))
	if err != nil || len(rs) == 0 {
		if u := strings.ToUpper(s); strings.Contains(u, "AGE-SECRET-KEY-") || strings.Contains(u, "AGE-PLUGIN-") {
			return nil, errors.New("this is an age identity (secret key), not a recipient; enter its public key (age1…) and keep the identity secret")
		}
		return nil, fmt.Errorf("%q is not a valid age recipient (age1…)", truncate(strings.TrimSpace(s), 80))
	}
	return rs, nil
}

// errRecipientMix is why a recipient list mixes post-quantum and classic keys.
var errRecipientMix = errors.New("post-quantum (age1pq1…) and classic (age1…) recipients can't be mixed; use only one kind")

// checkRecipientMix refuses a recipient list age cannot encrypt to: hybrid
// post-quantum recipients and X25519 ones together (age.Encrypt fails with
// "incompatible recipients", so every backup would fail).
func checkRecipientMix(rs []age.Recipient) error {
	pq, classic := false, false
	for _, r := range rs {
		if _, ok := r.(*age.HybridRecipient); ok {
			pq = true
		} else {
			classic = true
		}
	}
	if pq && classic {
		return errRecipientMix
	}
	return nil
}

// hasHybrid reports whether rs holds a post-quantum (hybrid) recipient.
func hasHybrid(rs []age.Recipient) bool {
	return slices.ContainsFunc(rs, func(r age.Recipient) bool { _, ok := r.(*age.HybridRecipient); return ok })
}

// parseIdentities parses an age identity file (one AGE-SECRET-KEY per line,
// "#" comments allowed).
func parseIdentities(s string) ([]age.Identity, error) {
	ids, err := age.ParseIdentities(strings.NewReader(s))
	if err != nil || len(ids) == 0 {
		return nil, core.Invalid("identity", "not a valid age identity (AGE-SECRET-KEY-1…)")
	}
	return ids, nil
}

// primaryRecipient returns the recipient string of the first identity of an
// identity file ("" when it has none or it is not an X25519/hybrid identity).
func primaryRecipient(identityFile string) string {
	ids, err := age.ParseIdentities(strings.NewReader(identityFile))
	if err != nil || len(ids) == 0 {
		return ""
	}
	switch id := ids[0].(type) {
	case *age.X25519Identity:
		return id.Recipient().String()
	case *age.HybridIdentity:
		return id.Recipient().String()
	}
	return ""
}

// identityLines returns the secret-key lines of an identity file (comments dropped).
func identityLines(identityFile string) []string {
	var out []string
	for _, l := range strings.Split(identityFile, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// recipientOf returns the recipient of one identity line ("" if unknown).
func recipientOf(identityLine string) string { return primaryRecipient(identityLine) }

// newIdentityFile builds the backup.identity value for a new identity,
// keeping up to maxPrevIdentities superseded identities (decryption only).
func newIdentityFile(newID, old string, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# FileParcel backup identity, created %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# public key: %s\n", recipientOf(newID))
	b.WriteString(newID)
	b.WriteString("\n")
	prev := identityLines(old)
	if len(prev) > maxPrevIdentities {
		prev = prev[:maxPrevIdentities]
	}
	if len(prev) > 0 {
		b.WriteString("# previous identities (decrypt older backups only)\n")
		for _, l := range prev {
			if l == newID {
				continue
			}
			b.WriteString(l)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// encryptionPlan is how a new backup is encrypted.
type encryptionPlan struct {
	mode       string // core.BackupX25519 | core.BackupPassphrase
	recipients []age.Recipient
	public     []string // recipient strings (x25519 mode)
}

// credsIdentities turns restore credentials into age identities.
func credsIdentities(c core.RestoreCreds) ([]age.Identity, error) {
	var out []age.Identity
	if strings.TrimSpace(c.Identity) != "" {
		ids, err := parseIdentities(c.Identity)
		if err != nil {
			return nil, err
		}
		out = append(out, ids...)
	}
	if c.Passphrase != "" {
		si, err := age.NewScryptIdentity(c.Passphrase)
		if err != nil {
			return nil, core.Invalid("passphrase", "invalid passphrase")
		}
		si.SetMaxWorkFactor(scryptMaxWorkFactor)
		out = append(out, si)
	}
	return out, nil
}

// decryptError maps age decryption failures to API errors.
func decryptError(err error) error {
	var nm *age.NoIdentityMatchError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &nm), errors.Is(err, age.ErrIncorrectIdentity):
		return core.Errorf(core.ErrForbidden, "the backup cannot be decrypted with this identity or passphrase")
	}
	var ce *core.Error
	if errors.As(err, &ce) {
		return err
	}
	return core.Wrap(core.ErrCorrupt, "the backup file is damaged or not a FileParcel backup", err)
}

// headerInfo summarizes the plaintext age header of a file.
type headerInfo struct {
	stanzas []string // stanza types: "X25519", "scrypt", "mlkem768x25519", …
}

// encryption returns the backups.encryption value for the header.
func (h headerInfo) encryption() string {
	if slices.Contains(h.stanzas, "scrypt") {
		return core.BackupPassphrase
	}
	return core.BackupX25519
}

// readAgeHeader checks that r starts with a well-formed age header and
// returns the stanza types. It consumes the header from r.
func readAgeHeader(r io.Reader) (headerInfo, error) {
	var hi headerInfo
	hdr, err := age.ExtractHeader(r)
	if err != nil {
		return hi, core.Wrap(core.ErrInvalid, "not an age-encrypted FileParcel backup", err)
	}
	if !bytes.HasPrefix(hdr, []byte(ageMagic)) {
		return hi, core.Errorf(core.ErrInvalid, "not an age-encrypted FileParcel backup")
	}
	sc := bufio.NewScanner(bytes.NewReader(hdr))
	for sc.Scan() {
		line := sc.Text()
		if rest, ok := strings.CutPrefix(line, "-> "); ok {
			typ, _, _ := strings.Cut(rest, " ")
			hi.stanzas = append(hi.stanzas, typ)
		}
	}
	if len(hi.stanzas) == 0 {
		return hi, core.Errorf(core.ErrInvalid, "the backup has no recipients")
	}
	return hi, nil
}

// ctxReader aborts reads once ctx is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// ctxWriter aborts writes once ctx is done.
type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (c ctxWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}

// truncate shortens s to at most n bytes (plus "…") without splitting a
// UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
