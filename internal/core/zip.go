package core

import (
	"fmt"
	"io"
	"log/slog"
)

// Password-protected .zip on upload (DESIGN §8.1): the encryption of a
// protected zip (UploadBatch.ZipEncryption, Node.ZipEncryption,
// FileVersion.ZipEncryption; "" = not protected).
const (
	ZipEncAES256    = "aes256"    // WinZip AE-2, AES-256
	ZipEncZipCrypto = "zipcrypto" // traditional PKWARE encryption (weak; compatibility)
)

// redacted is what fmt and slog print for a Secret.
const redacted = "[redacted]"

// Secret is a write-only string (passwords in request bodies). JSON encodes
// and decodes it as a plain string (the CLI sends it); fmt and slog print
// "[redacted]". Use Reveal to read the value.
type Secret string

// Format writes "[redacted]" for every verb (%v %+v %#v %s %q …; fmt
// consults Formatter before GoStringer, also on struct fields).
func (s Secret) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, redacted) }

// LogValue keeps the value out of slog output.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// Reveal returns the value.
func (s Secret) Reveal() string { return string(s) }

// LogValue describes the batch for slog without the password (without it,
// slog.JSONHandler would json.Marshal the struct, which includes the
// Secret's value): folder_id, mode, zip_name, conflict, uploader, files (the
// count), zip_encryption and zip_password_set.
func (in BatchInput) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("folder_id", in.FolderID),
		slog.String("mode", in.Mode),
		slog.String("zip_name", in.ZipName),
		slog.String("conflict", string(in.Conflict)),
		slog.String("uploader", in.Uploader),
		slog.Int("files", len(in.Files)),
		slog.String("zip_encryption", in.ZipEncryption),
		slog.Bool("zip_password_set", in.ZipPassword != ""),
	)
}
