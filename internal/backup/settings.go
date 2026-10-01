package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"fileparcel/internal/core"
	"fileparcel/internal/jobs/cron"
	"fileparcel/internal/settings"
)

// Setting keys owned by the backup package (DESIGN §11.2, section "backup").
const (
	SettingEnabled      = "backup.enabled"
	SettingScheduleMeta = "backup.schedule_meta"
	SettingScheduleFull = "backup.schedule_full"
	SettingKeepLast     = "backup.keep_last"
	SettingKeepDaily    = "backup.keep_daily"
	SettingKeepWeekly   = "backup.keep_weekly"
	SettingKeepMonthly  = "backup.keep_monthly"
	SettingEncryption   = "backup.encryption"
	SettingRecipients   = "backup.recipients"
	SettingIdentity     = "backup.identity"
	SettingPassphrase   = "backup.passphrase"
	SettingCopyTo       = "backup.copy_to"
)

// MinPassphraseLen is the minimum length of backup.passphrase.
const MinPassphraseLen = 12

// scopeNote is appended to every keep_* description: Prune only ever
// considers scheduled backups (see Prune in retention.go), and an operator
// reading "keep this many" needs to know which backups the count is about.
const scopeNote = " Only scheduled backups are pruned; manual, imported, pre-upgrade and final backups are kept until they are deleted by hand."

func init() {
	settings.Register(settings.Def{
		Key: SettingEnabled, Section: "backup", Order: 10, Type: settings.TypeBool, Default: true,
		Label:       "Scheduled backups",
		Description: "Run the metadata and full backup schedules below. Manual backups are always possible.",
	})
	settings.Register(settings.Def{
		Key: SettingScheduleMeta, Section: "backup", Order: 20, Type: settings.TypeCron, Default: "0 3 * * *",
		Validate:    validCron,
		Label:       "Metadata backup schedule",
		Description: "Cron schedule (local time) of metadata backups: database, configuration, keys and certificates, without file contents. Empty = off.",
	})
	settings.Register(settings.Def{
		Key: SettingScheduleFull, Section: "backup", Order: 30, Type: settings.TypeCron, Default: "0 4 * * 0",
		Validate:    validCron,
		Label:       "Full backup schedule",
		Description: "Cron schedule (local time) of full backups, which also contain every (already encrypted) file. Empty = off.",
	})
	settings.Register(settings.Def{
		Key: SettingKeepLast, Section: "backup", Order: 40, Type: settings.TypeInt, Default: 7, Min: 0, Max: 1000,
		Label:       "Keep last",
		Description: "Retention: always keep this many most recent scheduled backups (per scope). 0 = ignore this rule; with all four keep_* values at 0 retention is off and no backup is pruned." + scopeNote,
	})
	settings.Register(settings.Def{
		Key: SettingKeepDaily, Section: "backup", Order: 50, Type: settings.TypeInt, Default: 7, Min: 0, Max: 3650,
		Label:       "Keep daily",
		Description: "Retention: keep the newest backup of each of this many most recent days. 0 = ignore this rule (see Keep last)." + scopeNote,
	})
	settings.Register(settings.Def{
		Key: SettingKeepWeekly, Section: "backup", Order: 60, Type: settings.TypeInt, Default: 4, Min: 0, Max: 520,
		Label:       "Keep weekly",
		Description: "Retention: keep the newest backup of each of this many most recent ISO weeks. 0 = ignore this rule (see Keep last)." + scopeNote,
	})
	settings.Register(settings.Def{
		Key: SettingKeepMonthly, Section: "backup", Order: 70, Type: settings.TypeInt, Default: 6, Min: 0, Max: 1200,
		Label:       "Keep monthly",
		Description: "Retention: keep the newest backup of each of this many most recent months. 0 = ignore this rule (see Keep last)." + scopeNote,
	})
	settings.Register(settings.Def{
		Key: SettingEncryption, Section: "backup", Order: 80, Type: settings.TypeEnum, Default: "x25519",
		Enum:        []string{"x25519", "passphrase"},
		Label:       "Backup encryption",
		Description: "x25519: encrypt to age public keys (scheduled backups need no secret). passphrase: encrypt with the backup passphrase (age scrypt).",
	})
	settings.Register(settings.Def{
		Key: SettingRecipients, Section: "backup", Order: 90, Type: settings.TypeStrings, Default: []string{},
		Validate:    validRecipients,
		Label:       "Backup recipients",
		Description: "age public keys (age1…) that can decrypt backups. The recipient of the backup identity is added automatically. Post-quantum (age1pq1…) and classic keys can't be mixed.",
	})
	settings.Register(settings.Def{
		Key: SettingIdentity, Section: "backup", Order: 100, Type: settings.TypeSecret, Default: "",
		Validate:    validIdentity,
		Label:       "Backup identity",
		Description: "The age secret key used to verify and restore backups. Generate it on the Backups page and store a copy offline.",
	})
	settings.Register(settings.Def{
		Key: SettingPassphrase, Section: "backup", Order: 110, Type: settings.TypeSecret, Default: "",
		Validate:    validPassphrase,
		Label:       "Backup passphrase",
		Description: "Passphrase for passphrase-encrypted backups (at least 12 characters).",
	})
	settings.Register(settings.Def{
		Key: SettingCopyTo, Section: "backup", Order: 120, Type: settings.TypeString, Default: "",
		Validate:    validCopyTo,
		Label:       "Copy backups to",
		Description: "Optional absolute directory outside the FileParcel directory (e.g. a mounted NAS or USB disk) that receives a copy of every new backup.",
	})
}

func validCron(v any) error {
	s, _ := v.(string)
	if s == "" {
		return nil
	}
	if _, err := cron.Parse(s); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "cron: "))
	}
	return nil
}

func validRecipients(v any) error {
	l, _ := v.([]string)
	if len(l) > 32 {
		return errors.New("at most 32 recipients")
	}
	var all []age.Recipient
	for _, r := range l {
		rs, err := parseRecipients(r)
		if err != nil {
			return err
		}
		all = append(all, rs...)
	}
	return checkRecipientMix(all)
}

func validIdentity(v any) error {
	s, _ := v.(string)
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if _, err := age.ParseIdentities(strings.NewReader(s)); err != nil {
		return errors.New("not a valid age identity (AGE-SECRET-KEY-1…)")
	}
	return nil
}

func validPassphrase(v any) error {
	s, _ := v.(string)
	if s != "" && len([]rune(s)) < MinPassphraseLen {
		return errors.New("the backup passphrase must be at least 12 characters")
	}
	return nil
}

// copyToDir normalises a backup.copy_to value: surrounding whitespace and
// trailing separators are removed, because a tab-completed or pasted mount
// point ("/mnt/nas/") means the same directory as "/mnt/nas". Nothing else
// is rewritten — ".." and "." segments stay invalid instead of being
// silently resolved into a different directory.
func copyToDir(s string) string {
	s = strings.TrimSpace(s)
	for len(s) > 1 && os.IsPathSeparator(s[len(s)-1]) {
		s = s[:len(s)-1]
	}
	return s
}

// errCopyToInsideHome refuses a backup.copy_to inside the FileParcel home.
var errCopyToInsideHome = errors.New("the folder is inside the FileParcel directory; choose one outside it (a USB disk, a network share)")

// insideHome reports whether dir is the FileParcel home or lies below it,
// compared lexically and again with symbolic links resolved (as far as the
// paths exist): a "copy" there is no second copy — deleting or pruning the
// backup, or losing the disk, takes both, and in the backups folder itself
// the copy is the backup.
func (s *Service) insideHome(dir string) bool {
	if s.env.Home == nil || dir == "" {
		return false
	}
	home := s.env.Home.Dir()
	if pathWithin(home, dir) {
		return true
	}
	rh, rd := resolveExisting(home), resolveExisting(dir)
	return pathWithin(rh, rd) || pathWithin(home, rd) || pathWithin(rh, dir)
}

// checkCopyTo is the 422 of a copy_to inside the FileParcel home ("" is
// fine: no copy).
func (s *Service) checkCopyTo(dir string) error {
	if dir != "" && s.insideHome(dir) {
		return core.Invalid("copy_to", "must be a folder outside the FileParcel directory ("+s.env.Home.Dir()+
			"): a copy inside it is lost together with the backup")
	}
	return nil
}

// pathWithin reports whether p is dir or below it (lexically, after Clean).
func pathWithin(dir, p string) bool {
	dir, p = filepath.Clean(dir), filepath.Clean(p)
	return dir == p || strings.HasPrefix(p, strings.TrimSuffix(dir, string(filepath.Separator))+string(filepath.Separator))
}

// resolveExisting resolves the symbolic links of the longest existing
// prefix of the absolute path p and appends the rest ("/mnt/usb/new" with
// /mnt a link resolves /mnt/usb); p itself when nothing resolves.
func resolveExisting(p string) string {
	p = filepath.Clean(p)
	rest := ""
	for cur := p; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

func validCopyTo(v any) error {
	s, _ := v.(string)
	if strings.ContainsRune(s, 0) {
		return errors.New("invalid path")
	}
	s = copyToDir(s)
	if s == "" {
		return nil
	}
	if !filepath.IsAbs(s) || filepath.Clean(s) != s {
		return errors.New(`must be an absolute directory path without "." or ".." segments (for example /mnt/nas/fileparcel)`)
	}
	return nil
}
