package uploads

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ziputil"
)

// Password-protected zip-on-upload (DESIGN §8.1 "Password-protected zips"):
// a zip-mode batch may carry a password, which is validated when the batch
// is created, sealed at once with the field KEK into
// upload_batches.zip_password_enc (AAD bound to the batch id) and set to
// NULL by the same statement that moves the batch out of open/finalizing
// (done, failed, aborted, expired; ExpireStale sweeps anything left). It is
// never part of job params, results, events, audit details, logs or API
// answers; the upload.zip job opens it right before it builds the zip.

// Rules of .zip passwords (the minimum is storage.zip_password_min).
const (
	DefaultZipPasswordMin  = 12
	zipPasswordMinFloor    = 8
	zipPasswordMinCeil     = 64
	zipPasswordMinDistinct = 4
)

// zipPasswordAAD is the additional data binding a sealed .zip password to
// its batch (DESIGN §7.5): a value copied to another row does not open.
func zipPasswordAAD(batchID string) string { return "upload_batches.zip_password_enc|" + batchID }

// checkZipPassword applies the password rules; every error is 422 on the
// field zip_password and none contains the value. Only printable ASCII is
// accepted because unzip programs disagree on how other characters are
// encoded (UTF-8 or the OEM/ANSI code page).
func checkZipPassword(pw string, min int) error {
	for i := 0; i < len(pw); i++ {
		if pw[i] < 0x20 || pw[i] > 0x7e {
			return core.Invalid("zip_password", "use only letters, digits, spaces and the symbols on a US keyboard "+
				"(unzip apps disagree on how other characters are encoded)")
		}
	}
	switch {
	case len(pw) < min:
		return core.Invalid("zip_password", fmt.Sprintf("the password must be at least %d characters long", min))
	case len(pw) > ziputil.MaxPasswordLen:
		return core.Invalid("zip_password", fmt.Sprintf("the password must be at most %d characters long", ziputil.MaxPasswordLen))
	case pw[0] == ' ' || pw[len(pw)-1] == ' ':
		return core.Invalid("zip_password", "the password must not start or end with a space")
	}
	var seen [128]bool
	distinct := 0
	for i := 0; i < len(pw); i++ {
		c := pw[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if !seen[c] {
			seen[c] = true
			distinct++
		}
	}
	if distinct < zipPasswordMinDistinct {
		return core.Invalid("zip_password", "the password is too simple; use more different characters")
	}
	if crypt.IsCommonPassword(pw) {
		return core.Invalid("zip_password", "this password is too common; choose something less predictable")
	}
	return nil
}

// zipProtection validates the zip fields of a new batch and returns the
// encryption it gets ("" = not protected). shareReq is set for public file
// requests, which never produce protected zips (the owner could not open
// them). Settings are read here, when the batch is created; later changes
// do not affect open batches.
func (svc *Service) zipProtection(in core.BatchInput, mode string, shareReq bool) (string, error) {
	pw := in.ZipPassword.Reveal()
	if in.ZipEncryption == "" && pw == "" {
		return "", nil
	}
	field := "zip_password"
	if pw == "" {
		field = "zip_encryption"
	}
	if shareReq {
		return "", core.Invalid(field, "password-protected .zip files are not available for file requests")
	}
	if mode != core.UploadModeZip {
		return "", core.Invalid(field, "a .zip password needs mode zip")
	}
	enc := in.ZipEncryption
	switch enc {
	case "":
		enc = core.ZipEncAES256
	case core.ZipEncAES256, core.ZipEncZipCrypto:
	default:
		return "", core.Invalid("zip_encryption", "zip_encryption must be aes256 or zipcrypto")
	}
	if enc == core.ZipEncZipCrypto && !svc.settingBool(SettingZipLegacyEncryption, DefaultZipLegacyEncryption) {
		return "", core.Invalid("zip_encryption", "ZipCrypto is turned off on this server; use AES-256")
	}
	if pw == "" {
		return "", core.Invalid("zip_password", "enter a password for the .zip")
	}
	if err := checkZipPassword(pw, svc.zipPasswordMin()); err != nil {
		return "", err
	}
	return enc, nil
}

// zipPasswordMin is storage.zip_password_min, clamped to its range.
func (svc *Service) zipPasswordMin() int {
	return int(min(max(svc.settingInt(SettingZipPasswordMin, DefaultZipPasswordMin), zipPasswordMinFloor), zipPasswordMinCeil))
}

// settingBool reads a bool setting (def when no store is wired or the key
// is unknown).
func (svc *Service) settingBool(key string, def bool) bool {
	if svc.env.Settings == nil {
		return def
	}
	if _, err := svc.env.Settings.Raw(key); err != nil {
		return def
	}
	return svc.env.Settings.Bool(key)
}

// sealZipPassword seals pw for the batch batchID (503 keys_locked while the
// keys are locked).
func (svc *Service) sealZipPassword(batchID, pw string) (string, error) {
	if svc.env.Keys == nil {
		return "", core.ErrKeysLocked
	}
	b := []byte(pw)
	defer clear(b)
	return svc.env.Keys.SealField(zipPasswordAAD(batchID), b)
}

// errZipPasswordGone answers a protected batch whose sealed password was
// already wiped (the batch left open/finalizing, or someone cleared it).
var errZipPasswordGone = core.Errorf(core.ErrPrecondition,
	"the password of this upload is no longer available; upload the files again")

// openZipPassword returns the encryption and the password of a batch ("",
// "" for an unprotected one). It reads the columns directly: batchCols never
// includes zip_password_enc. A protected batch without its sealed value is
// 412 precondition_failed; a value that does not open is 500 corrupt; locked
// keys are 503 keys_locked.
func (svc *Service) openZipPassword(ctx context.Context, batchID string) (enc, pw string, err error) {
	var encCol, sealed sql.NullString
	err = svc.env.DB.QueryRow(ctx, `SELECT zip_encryption, zip_password_enc FROM upload_batches WHERE id = ?`, batchID).
		Scan(&encCol, &sealed)
	if db.IsNoRows(err) {
		return "", "", core.NotFoundf("upload batch not found")
	}
	if err != nil {
		return "", "", err
	}
	if encCol.String == "" {
		return "", "", nil
	}
	if sealed.String == "" {
		return "", "", errZipPasswordGone
	}
	if svc.env.Keys == nil {
		return "", "", core.ErrKeysLocked
	}
	raw, err := svc.env.Keys.OpenField(zipPasswordAAD(batchID), sealed.String)
	if err != nil {
		if errors.Is(err, core.ErrKeysLocked) {
			return "", "", err
		}
		return "", "", core.Wrap(core.ErrCorrupt, "the password of this upload could not be decrypted", err)
	}
	pw = string(raw)
	clear(raw)
	return encCol.String, pw, nil
}
